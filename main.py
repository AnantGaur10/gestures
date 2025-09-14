from flask import Flask, request, jsonify
import os
from datetime import datetime
import hmac
import hashlib
import json
import requests
import base64
import logging
import sys

# Configure basic logging to see everything clearly in Render logs
logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                    format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)

# --- Zoom App Credentials ---
# !!! WARNING: HARDCODING CREDENTIALS FOR DEBUGGING ONLY. REVERT TO ENVIRONMENT VARIABLES FOR PRODUCTION !!!
# ZOOM_CLIENT_ID and ZOOM_CLIENT_SECRET are for OUTGOING OAuth API calls (get_access_token)
ZOOM_CLIENT_ID = "Kv8t01LERE6It9zF3hWt0w"  # From your screenshot
ZOOM_CLIENT_SECRET = "do6EJonHQeN3LKI1oozQHBjZEaHB73As" # From your screenshot (REGENERATE THIS!)

# ZOOM_WEBHOOK_SECRET_TOKEN is for INCOMING Webhook Signature Authentication
# You get this AFTER enabling Webhook Security in Zoom Marketplace app features
ZOOM_WEBHOOK_SECRET_TOKEN = os.environ.get("ZOOM_WEBHOOK_SECRET_TOKEN", "YOUR_GENERATED_WEBHOOK_SECRET_TOKEN_HERE") 
# ^^^ Make sure to replace "YOUR_GENERATED_WEBHOOK_SECRET_TOKEN_HERE" with the actual token ^^^

ZOOM_TOKEN_URL = "https://zoom.us/oauth/token"
ZOOM_ACCOUNT_ID = os.environ.get("ZOOM_ID", "your_zoom_account_id_if_needed_elsewhere")

# Cache for access token (for outgoing API calls)
access_token_cache = {
    'token': None,
    'expires_at': None
}

def get_access_token():
    """
    Get access token using client credentials flow for outgoing API calls.
    Returns the token string on success, None on failure.
    """
    current_time = datetime.now().timestamp()
    
    # Check if we have a valid cached token
    if (access_token_cache['token'] and 
        access_token_cache['expires_at'] and 
        current_time < access_token_cache['expires_at']):
        logging.info("DEBUG: Using cached access token.")
        return access_token_cache['token']
    
    try:
        logging.info("Attempting to request a NEW access token...")
        auth_header_str = f"{ZOOM_CLIENT_ID}:{ZOOM_CLIENT_SECRET}"
        encoded_auth = base64.b64encode(auth_header_str.encode()).decode()
        
        headers = {
            'Authorization': f'Basic {encoded_auth}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'client_credentials', # Correct grant type for Server-to-Server OAuth
        }
        
        logging.debug(f"  Token request URL: {ZOOM_TOKEN_URL}")
        logging.debug(f"  Token request Headers (partial auth): {{'Authorization': 'Basic {encoded_auth[:20]}...', 'Content-Type': '{headers['Content-Type']}'}}")
        logging.debug(f"  Token request Data: {data}")

        response = requests.post(ZOOM_TOKEN_URL, headers=headers, data=data)
        
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access_token')
            expires_in = token_data.get('expires_in', 3600)  # Default 1 hour
            
            # Cache the token
            access_token_cache['token'] = access_token
            access_token_cache['expires_at'] = current_time + expires_in - 300  # 5 min buffer
            
            logging.info(f"✅ New access token obtained (expires in {expires_in} seconds).")
            return access_token
        else:
            logging.error(f"❌ Failed to get access token: Status {response.status_code} - Response: {response.text}")
            return None # Consistently return None on failure
            
    except Exception as e:
        logging.exception(f"❌ Error getting access token: {str(e)}") # Use logging.exception for full traceback
        return None

# --- create_encrypted_token is reused for URL validation ---
def create_encrypted_token(plain_token, secret_token):
    """
    Create encrypted token using HMAC-SHA256.
    Used for endpoint.url_validation in Signature Authentication mode.
    """
    try:
        encrypted_token = hmac.new(
            secret_token.encode('utf-8'),
            plain_token.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return encrypted_token
    except Exception as e:
        logging.exception(f"❌ Error creating encrypted token: {str(e)}")
        return None

@app.route('/', methods=['GET'])
def health_check():
    # Attempt to get an OAuth token to show its status on health check
    token_status_check = get_access_token() 
    
    return jsonify({
        'status': 'Zoom Webhook Server Running - Signature Authentication Mode',
        'timestamp': datetime.now().isoformat(),
        'verification_method': 'Signature Authentication',
        'client_id': ZOOM_CLIENT_ID,
        'token_url': ZOOM_TOKEN_URL,
        'client_secret_set': bool(ZOOM_CLIENT_SECRET and ZOOM_CLIENT_SECRET != 'your-client-secret'),
        'webhook_secret_set': bool(ZOOM_WEBHOOK_SECRET_TOKEN and ZOOM_WEBHOOK_SECRET_TOKEN != 'YOUR_GENERATED_WEBHOOK_SECRET_TOKEN_HERE'),
        'cached_oauth_token_available': bool(access_token_cache['token']),
        'latest_oauth_token_fetch_status': "Success" if token_status_check else "Failed (check logs for details)",
        'server_endpoints': {
            'webhook': '/webhook',
            'health': '/',
            'test_validation': '/test-validation',
            'get_token': '/get-token',
            'debug': '/debug'
        }
    })

@app.route('/webhook', methods=['POST'])
def webhook():
    logging.info(f'🔔 Webhook received: {datetime.now().isoformat()}')
    
    logging.info("📋 Request Headers:")
    for header_name, header_value in request.headers:
        if header_name.lower() in ['x-zm-signature', 'x-zm-request-timestamp', 'content-type', 'user-agent', 'authorization']:
            logging.info(f"   {header_name}: {header_value}")
    
    request_body_bytes = request.get_data() # Keep raw body bytes for signature verification
    logging.info(f"📄 Raw Request body (first 200 chars): {request_body_bytes.decode('utf-8', errors='ignore')[:200]}")

    try:
        # Parse JSON body once
        body = json.loads(request_body_bytes.decode('utf-8')) if request_body_bytes else {}
        logging.info(f'📄 Parsed Request body (full if JSON): {json.dumps(body, indent=2)}')
        
        # --- Handle URL validation challenge FIRST ---
        if body and body.get('event') == 'endpoint.url_validation':
            logging.info('🔍 URL Validation Challenge received.')
            
            payload = body.get('payload', {})
            plain_token = payload.get('plainToken')
            
            if not plain_token:
                logging.error("❌ Missing plainToken in validation payload.")
                return jsonify({'error': 'Missing plainToken in payload for URL validation'}), 400
            
            logging.info(f'✅ Plain token received (prefix): {plain_token[:10]}...')
            
            # Use ZOOM_WEBHOOK_SECRET_TOKEN for URL validation in Signature Auth mode
            if not ZOOM_WEBHOOK_SECRET_TOKEN or ZOOM_WEBHOOK_SECRET_TOKEN == 'YOUR_GENERATED_WEBHOOK_SECRET_TOKEN_HERE':
                logging.error("❌ Webhook Secret Token not properly configured for URL validation.")
                return jsonify({'error': 'Webhook Secret Token not configured for URL validation'}), 500
            
            encrypted_token = create_encrypted_token(plain_token, ZOOM_WEBHOOK_SECRET_TOKEN)
            
            if not encrypted_token:
                logging.error("❌ Failed to create encrypted token for URL validation.")
                return jsonify({'error': 'Failed to create encrypted token for URL validation'}), 500
            
            logging.info(f'🔐 Encrypted token created (prefix): {encrypted_token[:20]}...')
            validation_response = {'plainToken': plain_token, 'encryptedToken': encrypted_token}
            logging.info(f'📤 Validation response sent: {validation_response}')
            return jsonify(validation_response), 200
        
        # --- Handle Signature Authentication for regular webhook events ---
        x_zm_signature = request.headers.get('x-zm-signature')
        x_zm_request_timestamp = request.headers.get('x-zm-request-timestamp')

        if not x_zm_signature or not x_zm_request_timestamp:
            logging.error("❌ Missing x-zm-signature or x-zm-request-timestamp headers for Signature Authentication.")
            return jsonify({'error': 'Unauthorized - Missing signature headers'}), 401

        if not ZOOM_WEBHOOK_SECRET_TOKEN or ZOOM_WEBHOOK_SECRET_TOKEN == 'YOUR_GENERATED_WEBHOOK_SECRET_TOKEN_HERE':
            logging.error("❌ Webhook Secret Token not configured for signature verification.")
            return jsonify({'error': 'Webhook Secret Token not configured'}), 500

        # Node.js used JSON.stringify(req.body)
        # In Python, this means json.dumps(body) to get the JSON string of the parsed body
        # Ensure consistent JSON stringification (no extra spaces, sorted keys for strict matching)
        json_body_string = json.dumps(body, separators=(',', ':'), sort_keys=True)
        message_string = f"v0:{x_zm_request_timestamp}:{json_body_string}"
        
        # Calculate your own signature
        calculated_signature = hmac.new(
            ZOOM_WEBHOOK_SECRET_TOKEN.encode('utf-8'),
            message_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Compare your calculated signature with the one from Zoom
        if f"v0={calculated_signature}" == x_zm_signature:
            logging.info("✅ Signature authentication successful.")
            
            # --- START Event Handling Examples (same as before) ---
            if body:
                event_type = body.get('event')
                logging.info(f'🎯 Processing event type: {event_type}')
                
                payload = body.get('payload', {})
                event_object = payload.get('object', {})
                
                if event_type == 'meeting.started':
                    meeting_id = event_object.get('id')
                    topic = event_object.get('topic', 'No topic')
                    logging.info(f'📅 Meeting started: ID {meeting_id}, Topic: {topic}')
                    handle_meeting_started(meeting_id, event_object.get('uuid'), event_object.get('host_id'), topic, event_object.get('start_time'))
                    
                elif event_type == 'meeting.ended':
                    meeting_id = event_object.get('id')
                    duration = event_object.get('duration', 0)
                    logging.info(f'🔚 Meeting ended: ID {meeting_id}, Duration: {duration} minutes')
                    handle_meeting_ended(meeting_id, event_object.get('uuid'), duration, event_object.get('end_time'))
                    
                elif event_type == 'recording.completed':
                    meeting_id = payload.get('object', {}).get('id')
                    logging.info(f'🎥 Recording completed for meeting: {meeting_id}')
                    # Note: If download_recording_file is uncommented and uses get_access_token,
                    # this is where "fail to get access token" could originate for a regular event.
                    handle_recording_completed(meeting_id, payload.get('object', {}).get('uuid'), payload.get('object', {}).get('topic'), payload.get('object', {}).get('recording_files', []))
                    
                else:
                    logging.info(f'❓ Unhandled event type: {event_type}. Full payload: {json.dumps(payload, indent=2)}')
                    handle_unknown_event(event_type, payload)
                
                return jsonify({'status': 'success', 'message': 'Webhook event processed successfully'}), 200
            else:
                logging.warning("⚠️ Webhook received with no body after signature authentication.")
                return jsonify({'error': 'Empty body after authentication'}), 400
        else:
            logging.error(f"❌ Signature authentication failed.")
            logging.error(f"   Expected signature: {x_zm_signature}")
            logging.error(f"   Calculated signature: v0={calculated_signature}")
            logging.error(f"   Message string (partial): {message_string[:200]}...")
            return jsonify({'error': 'Unauthorized - Invalid signature'}), 401
            
    except json.JSONDecodeError as e:
        logging.error(f"❌ JSON decode error for incoming webhook: {str(e)}. Raw body: {request_body_bytes.decode('utf-8', errors='ignore')}")
        return jsonify({'error': 'Invalid JSON body in webhook request', 'details': str(e)}), 400
    except Exception as error:
        logging.exception(f'❌ Webhook processing error: {str(error)}')
        return jsonify({'error': 'Internal server error during webhook processing', 'details': str(error)}), 500

# --- Debug and Token Endpoints (same as previous version, for OUTGOING API calls) ---
@app.route('/debug', methods=['POST', 'GET'])
def debug_webhook():
    logging.info(f'🐛 Debug endpoint hit: {request.method} at {datetime.now().isoformat()}')
    
    logging.info("📋 All headers for debug:")
    for header_name, header_value in request.headers:
        logging.info(f"   {header_name}: {header_value}")
    
    if request.method == 'POST':
        try:
            body = request.get_json(force=True, silent=True)
            logging.info(f"📄 Request body for debug: {json.dumps(body, indent=2) if body else 'No JSON body'}")
            
            if body and body.get('event') == 'endpoint.url_validation':
                plain_token = body.get('payload', {}).get('plainToken')
                if plain_token:
                    # For debug, we can use the Webhook Secret Token
                    encrypted_token = create_encrypted_token(plain_token, ZOOM_WEBHOOK_SECRET_TOKEN) 
                    logging.info(f"🔐 Debug encryption - Plain: {plain_token[:10]}..., Encrypted: {encrypted_token[:20]}...")
                    
        except Exception as e:
            logging.error(f"❌ Error parsing body for debug: {str(e)}")
            logging.info(f"Raw body for debug: {request.get_data()}")
    
    return jsonify({
        'status': 'debug_ok',
        'method': request.method,
        'timestamp': datetime.now().isoformat(),
        'headers_count': len(request.headers),
        'has_signature_header': 'x-zm-signature' in request.headers,
        'client_secret_set': bool(ZOOM_CLIENT_SECRET and ZOOM_CLIENT_SECRET != 'your-client-secret'),
        'webhook_secret_set': bool(ZOOM_WEBHOOK_SECRET_TOKEN and ZOOM_WEBHOOK_SECRET_TOKEN != 'YOUR_GENERATED_WEBHOOK_SECRET_TOKEN_HERE'),
        'client_id': ZOOM_CLIENT_ID
    }), 200

last_retrieved_token = None 
@app.route('/get-token', methods=['GET'])
def get_token_endpoint():
    """Get access token for testing (for outgoing API calls)"""
    global last_retrieved_token 
    last_retrieved_token = get_access_token() 
    
    if last_retrieved_token: 
        return jsonify({
            'access_token': last_retrieved_token,
            'expires_at': access_token_cache.get('expires_at'),
            'timestamp': datetime.now().isoformat()
        }), 200 
    else:
        return jsonify({
            'error': 'Failed to get access token',
            'error_reason': 'Check server logs for details (likely invalid client_id/secret or app not active).',
            'client_id': ZOOM_CLIENT_ID 
        }), 400 

# --- Event handler functions (unchanged from previous version) ---
def handle_meeting_started(meeting_id, meeting_uuid, host_id, topic, start_time):
    logging.info(f"🔧 Custom handler: Meeting {meeting_id} started. Topic: {topic}")
    pass
def handle_meeting_ended(meeting_id, meeting_uuid, duration, end_time):
    logging.info(f"🔧 Custom handler: Meeting {meeting_id} ended after {duration} minutes.")
    pass
def handle_participant_joined(participant_name, participant_id, participant_user_id, join_time):
    logging.info(f"🔧 Custom handler: {participant_name} joined the meeting.")
    pass
def handle_participant_left(participant_name, participant_id, participant_user_id, leave_time, duration):
    logging.info(f"🔧 Custom handler: {participant_name} left after {duration} minutes.")
    pass
def handle_recording_completed(meeting_id, meeting_uuid, topic, recording_files):
    logging.info(f"🔧 Custom handler: Recording completed for meeting {meeting_id}.")
    for file in recording_files:
        file_type = file.get('file_type')
        download_url = file.get('download_url')
        file_size = file.get('file_size', 0)
        recording_type = file.get('recording_type')
        logging.info(f'  📁 File: {file_type} ({recording_type}) - {file_size} bytes')
        logging.info(f'  🔗 Download: {download_url}')
        # download_recording_file(download_url, file_type, meeting_id) # Calls get_access_token()
def handle_sharing_started(meeting_id, participant, sharing_details):
    logging.info(f"🔧 Custom handler: Screen sharing started in meeting {meeting_id}.")
    pass
def handle_sharing_ended(meeting_id, participant, sharing_details):
    logging.info(f"🔧 Custom handler: Screen sharing ended in meeting {meeting_id}.")
    pass
def handle_unknown_event(event_type, payload):
    logging.info(f"🔧 Custom handler: Unknown event {event_type}.")
    pass

def download_recording_file(download_url, file_type, meeting_id):
    """Example function to download recording files. Calls get_access_token()."""
    try:
        access_token = get_access_token()
        if not access_token:
            logging.error(f"❌ Cannot download file for meeting {meeting_id} - no access token available.")
            return 
        
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        logging.info(f"📥 Attempting to download {file_type} file for meeting {meeting_id} from {download_url}.")
        # response = requests.get(download_url, headers=headers)
        # logging.info(f"Download response status: {response.status_code}")
    except Exception as e:
        logging.exception(f"❌ Error downloading file for meeting {meeting_id}: {str(e)}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    
    logging.info(f'🚀 Starting Zoom Webhook Server with Signature Authentication on port {port}')
    logging.info(f'🔒 Using OAuth Token Authentication method for OUTGOING API calls, Signature for INCOMING Webhooks')
    logging.info(f'📝 Environment variables (hardcoded for current testing, REGENERATE SECRETS!):')
    logging.info(f'   - ZOOM_CLIENT_ID: {ZOOM_CLIENT_ID}')
    logging.info(f'   - ZOOM_CLIENT_SECRET: {"✅ Set (hardcoded)" if ZOOM_CLIENT_SECRET != "your-client-secret" else "❌ Not set properly (hardcoded)"}')
    logging.info(f'   - ZOOM_WEBHOOK_SECRET_TOKEN: {"✅ Set" if ZOOM_WEBHOOK_SECRET_TOKEN != "YOUR_GENERATED_WEBHOOK_SECRET_TOKEN_HERE" else "❌ Not set (or default)"}')
    logging.info(f'   - PORT: {port}')
    
    logging.warning(f'💡 For webhook validation, encrypted token will be created using ZOOM_WEBHOOK_SECRET_TOKEN.')
    logging.warning(f'💡 For regular webhook events, x-zm-signature will be verified using ZOOM_WEBHOOK_SECRET_TOKEN.')
    logging.warning(f'🔗 Webhook URL: https://yourdomain.com/webhook')
    
    if ZOOM_CLIENT_SECRET == 'your-client-secret' or ZOOM_WEBHOOK_SECRET_TOKEN == 'YOUR_GENERATED_WEBHOOK_SECRET_TOKEN_HERE':
        logging.error(f'⚠️  WARNING: Secrets are not properly configured! Please update them.')
        
    app.run(host='0.0.0.0', port=port, debug=True)
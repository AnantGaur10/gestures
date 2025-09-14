from flask import Flask, request, jsonify
import os
from datetime import datetime
import hmac
import hashlib
import json
import requests
import base64

app = Flask(__name__)

# Zoom Webhook credentials for Token Authentication
ZOOM_CLIENT_ID = os.environ.get("ZOOM_CLIENT_ID", "client id")  # From your screenshot
ZOOM_CLIENT_SECRET = os.environ.get("ZOOM_CLIENT_SECRET", "your-client-secret")
ZOOM_TOKEN_URL = "https://zoom.us/oauth/token"
ZOOM_ACCOUNT_ID = os.environ.get("ZOOM_ID", "account id")  # Example account ID
# Cache for access token
access_token_cache = {
    'token': None,
    'expires_at': None
}

def get_access_token():
    """
    Get access token using client credentials flow
    """
    current_time = datetime.now().timestamp()
    
    # Check if we have a valid cached token
    if (access_token_cache['token'] and 
        access_token_cache['expires_at'] and 
        current_time < access_token_cache['expires_at']):
        return access_token_cache['token']
    
    try:
        # Request new access token
        auth_header = f"{ZOOM_CLIENT_ID}:{ZOOM_CLIENT_SECRET}"
        encoded_auth = base64.b64encode(auth_header.encode()).decode()
        
        headers = {
            'Authorization': f'Basic S3Y4dDAxTEVSRTZJdDl6RjNoV3QwdzpkbzZFSm9uSFFlTjNMS2kxb296UUhCalpFYUhCNzNBcw==',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'account_credentials',
            'account_id' : 'eQ9heqG7Q6CJE02Y8p6JWQ'
        }
        
        response = requests.post(ZOOM_TOKEN_URL, headers=headers, data=data)
        
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access_token')
            expires_in = token_data.get('expires_in', 3600)  # Default 1 hour
            
            # Cache the token
            access_token_cache['token'] = access_token
            access_token_cache['expires_at'] = current_time + expires_in - 300  # 5 min buffer
            
            print(f"✅ New access token obtained, expires in {expires_in} seconds")
            return access_token
        else:
            print(f"❌ Failed to get access token: {response.status_code} - {response.text}")
            return response.text
            
    except Exception as e:
        print(f"❌ Error getting access token: {str(e)}")
        return None

def verify_token_auth(auth_header):
    """
    Verify the token in the authorization header
    For Token Authentication, Zoom sends the access token
    """
    if not auth_header:
        print("❌ No authorization header found")
        return False
    
    # Extract token from "Bearer <token>"
    if not auth_header.startswith('Bearer '):
        print("❌ Authorization header does not start with 'Bearer '")
        return False
    
    received_token = auth_header[7:]  # Remove "Bearer " prefix
    
    # For webhook validation, we need to validate this token
    # In production, you might want to validate against Zoom's token endpoint
    # For now, we'll accept any valid-looking token format
    if len(received_token) > 20:  # Basic validation - tokens are typically longer
        print(f"✅ Token authentication - received valid token: {received_token[:20]}...")
        return True
    
    print(f"❌ Token appears invalid: {received_token}")
    return False

def create_encrypted_token(plain_token, secret_token):
    """
    Create encrypted token using HMAC-SHA256
    """
    try:
        encrypted_token = hmac.new(
            secret_token.encode('utf-8'),
            plain_token.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return encrypted_token
    except Exception as e:
        print(f"❌ Error creating encrypted token: {str(e)}")
        return None

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'Zoom Webhook Server Running - Token Authentication Mode',
        'timestamp': datetime.now().isoformat(),
        'verification_method': 'Token Authentication',
        'client_id': ZOOM_CLIENT_ID,
        'token_url': ZOOM_TOKEN_URL,
        'client_secret': ZOOM_CLIENT_SECRET,
        'client_secret_set': bool(ZOOM_CLIENT_SECRET and ZOOM_CLIENT_SECRET != 'your-client-secret'),
        'cached_token_available': bool(access_token_cache['token']),
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
    print(f'🔔 Webhook received: {datetime.now().isoformat()}')
    
    # Log all important headers for debugging
    print("📋 Request Headers:")
    for header_name, header_value in request.headers:
        if header_name.lower() in ['authorization', 'x-zm-signature', 'content-type', 'user-agent', 'x-zm-request-timestamp']:
            print(f"   {header_name}: {header_value}")
    
    try:
        # Get request body
        request_body = request.get_data()
        
        # Try to parse JSON body first
        try:
            body = json.loads(request_body.decode('utf-8')) if request_body else {}
        except json.JSONDecodeError as e:
            print(f"❌ JSON decode error: {str(e)}")
            return jsonify({'error': 'Invalid JSON'}), 400
        
        print(f'📄 Request body: {json.dumps(body, indent=2)}')
        
        # Handle URL validation challenge FIRST (before authentication)
        if body and body.get('event') == 'endpoint.url_validation':
            print('🔍 URL Validation Challenge received')
            
            payload = body.get('payload', {})
            plain_token = payload.get('plainToken')
            
            if not plain_token:
                print("❌ Missing plainToken in validation payload")
                print(f"Full payload: {payload}")
                return jsonify({'error': 'Missing plainToken'}), 400
            
            print(f'✅ Plain token received: {plain_token}')
            
            # For Token Authentication, we use the client secret to create encrypted token
            if not ZOOM_CLIENT_SECRET or ZOOM_CLIENT_SECRET == 'your-client-secret':
                print("❌ Client secret not properly configured")
                return jsonify({'error': 'Client secret not configured'}), 500
            
            # Create encrypted token using client secret
            encrypted_token = create_encrypted_token(plain_token, ZOOM_CLIENT_SECRET)
            
            if not encrypted_token:
                print("❌ Failed to create encrypted token")
                return jsonify({'error': 'Failed to create encrypted token'}), 500
            
            print(f'🔐 Encrypted token created: {encrypted_token}')
            
            # Return validation response
            validation_response = {
                'plainToken': plain_token,
                'encryptedToken': encrypted_token
            }
            
            print(f'📤 Validation response: {validation_response}')
            return jsonify(validation_response), 200
        
        # For non-validation requests, verify token authentication
        auth_header = request.headers.get('authorization')
        
        if not verify_token_auth(auth_header):
            print("❌ Token authentication failed")
            print(f"   Received auth header: {auth_header}")
            return jsonify({'error': 'Unauthorized - Invalid token'}), 401
        
        print("✅ Token authentication successful")
        
        # Handle webhook events
        if body:
            event_type = body.get('event')
            print(f'🎯 Processing event type: {event_type}')
            
            payload = body.get('payload', {})
            event_object = payload.get('object', {})
            
            if event_type == 'meeting.started':
                meeting_id = event_object.get('id')
                meeting_uuid = event_object.get('uuid')
                host_id = event_object.get('host_id')
                topic = event_object.get('topic', 'No topic')
                start_time = event_object.get('start_time')
                
                print(f'📅 Meeting started:')
                print(f'  - Meeting ID: {meeting_id}')
                print(f'  - UUID: {meeting_uuid}')
                print(f'  - Host ID: {host_id}')
                print(f'  - Topic: {topic}')
                print(f'  - Start time: {start_time}')
                
                handle_meeting_started(meeting_id, meeting_uuid, host_id, topic, start_time)
                
            elif event_type == 'meeting.ended':
                meeting_id = event_object.get('id')
                meeting_uuid = event_object.get('uuid')
                duration = event_object.get('duration', 0)
                end_time = event_object.get('end_time')
                
                print(f'🔚 Meeting ended:')
                print(f'  - Meeting ID: {meeting_id}')
                print(f'  - UUID: {meeting_uuid}')
                print(f'  - Duration: {duration} minutes')
                print(f'  - End time: {end_time}')
                
                handle_meeting_ended(meeting_id, meeting_uuid, duration, end_time)
                
            elif event_type == 'meeting.participant_joined':
                participant = event_object.get('participant', {})
                participant_name = participant.get('user_name', 'Unknown')
                participant_id = participant.get('id')
                participant_user_id = participant.get('user_id')
                join_time = participant.get('join_time')
                
                print(f'👋 Participant joined:')
                print(f'  - Name: {participant_name}')
                print(f'  - Participant ID: {participant_id}')
                print(f'  - User ID: {participant_user_id}')
                print(f'  - Join time: {join_time}')
                
                handle_participant_joined(participant_name, participant_id, participant_user_id, join_time)
                
            elif event_type == 'meeting.participant_left':
                participant = event_object.get('participant', {})
                participant_name = participant.get('user_name', 'Unknown')
                participant_id = participant.get('id')
                participant_user_id = participant.get('user_id')
                leave_time = participant.get('leave_time')
                duration = participant.get('duration', 0)
                
                print(f'👋 Participant left:')
                print(f'  - Name: {participant_name}')
                print(f'  - Participant ID: {participant_id}')
                print(f'  - User ID: {participant_user_id}')
                print(f'  - Leave time: {leave_time}')
                print(f'  - Session duration: {duration} minutes')
                
                handle_participant_left(participant_name, participant_id, participant_user_id, leave_time, duration)
                
            elif event_type == 'recording.completed':
                recording_files = payload.get('object', {}).get('recording_files', [])
                meeting_id = payload.get('object', {}).get('id')
                meeting_uuid = payload.get('object', {}).get('uuid')
                topic = payload.get('object', {}).get('topic')
                
                print(f'🎥 Recording completed:')
                print(f'  - Meeting ID: {meeting_id}')
                print(f'  - UUID: {meeting_uuid}')
                print(f'  - Topic: {topic}')
                print(f'  - Number of files: {len(recording_files)}')
                
                handle_recording_completed(meeting_id, meeting_uuid, topic, recording_files)
                
            elif event_type == 'meeting.sharing_started':
                meeting_id = event_object.get('id')
                participant = event_object.get('participant', {})
                sharing_details = event_object.get('sharing_details', {})
                
                print(f'📺 Screen sharing started:')
                print(f'  - Meeting ID: {meeting_id}')
                print(f'  - Participant: {participant.get("user_name", "Unknown")}')
                print(f'  - Sharing details: {sharing_details}')
                
                handle_sharing_started(meeting_id, participant, sharing_details)
                
            elif event_type == 'meeting.sharing_ended':
                meeting_id = event_object.get('id')
                participant = event_object.get('participant', {})
                sharing_details = event_object.get('sharing_details', {})
                
                print(f'📺 Screen sharing ended:')
                print(f'  - Meeting ID: {meeting_id}')
                print(f'  - Participant: {participant.get("user_name", "Unknown")}')
                
                handle_sharing_ended(meeting_id, participant, sharing_details)
                
            else:
                print(f'❓ Unhandled event type: {event_type}')
                print(f'Full payload: {json.dumps(payload, indent=2)}')
                handle_unknown_event(event_type, payload)
        
        return jsonify({'status': 'success', 'message': 'Webhook processed successfully'}), 200
        
    except Exception as error:
        print(f'❌ Webhook processing error: {str(error)}')
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'details': str(error)}), 500

@app.route('/debug', methods=['POST', 'GET'])
def debug_webhook():
    """Debug endpoint to test webhook functionality"""
    print(f'🐛 Debug endpoint hit: {request.method} at {datetime.now().isoformat()}')
    
    # Log all headers
    print("📋 All headers:")
    for header_name, header_value in request.headers:
        print(f"   {header_name}: {header_value}")
    
    # Log request body if POST
    if request.method == 'POST':
        try:
            body = request.get_json(force=True, silent=True)
            print(f"📄 Request body: {json.dumps(body, indent=2) if body else 'No JSON body'}")
            
            # Test encryption if validation payload
            if body and body.get('event') == 'endpoint.url_validation':
                plain_token = body.get('payload', {}).get('plainToken')
                if plain_token:
                    encrypted_token = create_encrypted_token(plain_token, ZOOM_CLIENT_SECRET)
                    print(f"🔐 Test encryption - Plain: {plain_token}, Encrypted: {encrypted_token}")
                    
        except Exception as e:
            print(f"❌ Error parsing body: {str(e)}")
            print(f"Raw body: {request.get_data()}")
    
    return jsonify({
        'status': 'debug_ok',
        'method': request.method,
        'timestamp': datetime.now().isoformat(),
        'headers_count': len(request.headers),
        'has_auth': 'authorization' in request.headers,
        'client_secret_set': bool(ZOOM_CLIENT_SECRET and ZOOM_CLIENT_SECRET != 'your-client-secret'),
        'client_id': ZOOM_CLIENT_ID
    }), 200

@app.route('/test-validation', methods=['POST'])
def test_validation():
    """Test endpoint to simulate Zoom validation"""
    try:
        body = request.get_json()
        plain_token = body.get('plainToken', 'test-token-123')
        
        encrypted_token = create_encrypted_token(plain_token, ZOOM_CLIENT_SECRET)
        
        return jsonify({
            'plainToken': plain_token,
            'encryptedToken': encrypted_token,
            'client_secret_used': bool(ZOOM_CLIENT_SECRET != 'your-client-secret'),
            'client_id': ZOOM_CLIENT_ID,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

token = ""
@app.route('/get-token', methods=['GET'])
def get_token_endpoint():
    """Get access token for testing"""
    token = get_access_token()
    if token:
        return jsonify({
            'access_token': token,
            'expires_at': access_token_cache.get('expires_at'),
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({'error': 'Failed to get access token','error_reason' : token}), 400

# Event handler functions - customize these based on your needs
def handle_meeting_started(meeting_id, meeting_uuid, host_id, topic, start_time):
    """Handle meeting started event"""
    # Add your custom logic here
    # Examples:
    # - Log to database
    # - Send notifications
    # - Initialize meeting-specific resources
    # - Send welcome messages
    print(f"🔧 Custom handler: Meeting {meeting_id} started")
    pass

def handle_meeting_ended(meeting_id, meeting_uuid, duration, end_time):
    """Handle meeting ended event"""
    # Add your custom logic here
    # Examples:
    # - Generate meeting reports
    # - Cleanup resources
    # - Calculate costs
    # - Send meeting summary
    print(f"🔧 Custom handler: Meeting {meeting_id} ended after {duration} minutes")
    pass

def handle_participant_joined(participant_name, participant_id, participant_user_id, join_time):
    """Handle participant joined event"""
    # Add your custom logic here
    # Examples:
    # - Track attendance
    # - Send welcome messages
    # - Update participant lists
    # - Log join events
    print(f"🔧 Custom handler: {participant_name} joined the meeting")
    pass

def handle_participant_left(participant_name, participant_id, participant_user_id, leave_time, duration):
    """Handle participant left event"""
    # Add your custom logic here
    # Examples:
    # - Track attendance duration
    # - Generate individual reports
    # - Update participant status
    # - Calculate session costs
    print(f"🔧 Custom handler: {participant_name} left after {duration} minutes")
    pass

def handle_recording_completed(meeting_id, meeting_uuid, topic, recording_files):
    """Handle recording completed event"""
    # Add your custom logic here
    # Examples:
    # - Download recording files
    # - Process video/audio
    # - Generate transcriptions
    # - Store in cloud storage
    # - Send recording links
    print(f"🔧 Custom handler: Recording completed for meeting {meeting_id}")
    
    for file in recording_files:
        file_type = file.get('file_type')
        download_url = file.get('download_url')
        file_size = file.get('file_size', 0)
        recording_type = file.get('recording_type')
        
        print(f'  📁 File: {file_type} ({recording_type}) - {file_size} bytes')
        print(f'  🔗 Download: {download_url}')
        
        # Example: Download the file
        # download_recording_file(download_url, file_type, meeting_id)

def handle_sharing_started(meeting_id, participant, sharing_details):
    """Handle screen sharing started event"""
    # Add your custom logic here
    print(f"🔧 Custom handler: Screen sharing started in meeting {meeting_id}")
    pass

def handle_sharing_ended(meeting_id, participant, sharing_details):
    """Handle screen sharing ended event"""
    # Add your custom logic here
    print(f"🔧 Custom handler: Screen sharing ended in meeting {meeting_id}")
    pass

def handle_unknown_event(event_type, payload):
    """Handle unknown event types"""
    # Add your custom logic here
    # This is useful for handling new event types that Zoom might add
    print(f"🔧 Custom handler: Unknown event {event_type}")
    pass

def download_recording_file(download_url, file_type, meeting_id):
    """Example function to download recording files"""
    # This is an example implementation
    # You would need to handle authentication and storage
    try:
        # Get access token for API calls
        access_token = get_access_token()
        if not access_token:
            print(f"❌ Cannot download file - no access token")
            return
        
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Note: You might need additional logic here depending on your use case
        print(f"📥 Would download {file_type} file for meeting {meeting_id}")
        # response = requests.get(download_url, headers=headers)
        # Save file logic here
        
    except Exception as e:
        print(f"❌ Error downloading file: {str(e)}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    
    print(f'🚀 Starting Zoom Webhook Server with Token Authentication on port {port}')
    print(f'🔒 Using OAuth Token Authentication method')
    print(f'📝 Environment variables:')
    print(f'   - ZOOM_CLIENT_ID: {ZOOM_CLIENT_ID}')
    print(f'   - ZOOM_CLIENT_SECRET: {"✅ Set" if ZOOM_CLIENT_SECRET != "your-client-secret" else "❌ Not set properly"}')
    print(f'   - PORT: {port}')
    print(f'')
    print(f'📡 Available endpoints:')
    print(f'   - GET  /           - Health check and server info')
    print(f'   - POST /webhook    - Main webhook endpoint')
    print(f'   - POST /debug      - Debug webhook requests')
    print(f'   - POST /test-validation - Test token encryption')
    print(f'   - GET  /get-token  - Get OAuth access token')
    print(f'')
    print(f'💡 For validation, encrypted token will be created using CLIENT_SECRET as salt')
    print(f'🔗 Webhook URL: https://yourdomain.com/webhook')
    print(f'')
    
    # Verify client secret is set
    if ZOOM_CLIENT_SECRET == 'your-client-secret':
        print(f'⚠️  WARNING: ZOOM_CLIENT_SECRET is not set properly!')
        print(f'   Please set it to your actual client secret from Zoom Marketplace')
        print(f'   export ZOOM_CLIENT_SECRET="your-actual-secret"')
        print(f'')
    
    app.run(host='0.0.0.0', port=port, debug=True)
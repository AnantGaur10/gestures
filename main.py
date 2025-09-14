from flask import Flask, request, jsonify
import os
from datetime import datetime
import hmac
import hashlib
import json

app = Flask(__name__)

# Zoom Webhook credentials
ZOOM_WEBHOOK_SECRET_TOKEN = os.environ.get("ZOOM_WEBHOOK_SECRET_TOKEN", "your-secret-token")
ZOOM_VERIFICATION_TOKEN = os.environ.get("ZOOM_VERIFICATION_TOKEN", "your-verification-token")


def verify_webhook_signature(request_body, signature, secret_token):
    """
    Verify the webhook signature using HMAC-SHA256
    This is the standard Zoom webhook verification method
    """
    try:
        # Create HMAC signature
        expected_signature = hmac.new(
            secret_token.encode('utf-8'),
            request_body,
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures (use hmac.compare_digest for security)
        return hmac.compare_digest(signature, expected_signature)
    except Exception as e:
        print(f"Signature verification error: {str(e)}")
        return False

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'Zoom Webhook Server Running with Rivet-style Verification',
        'timestamp': datetime.now().isoformat(),
        'verification_method': 'HMAC-SHA256',
        'webhook_secret_token_set': ZOOM_WEBHOOK_SECRET_TOKEN,
        'verification_token_set': ZOOM_VERIFICATION_TOKEN,
    })

@app.route('/webhook', methods=['POST'])


def webhook():
    
    print(f'Webhook received: {datetime.now().isoformat()}')
    
    try:
        # Get raw request body for signature verification
        request_body = request.get_data()
            
        # Get signature from headers
        signature = request.headers.get('x-zm-signature')
        if not signature:
            print("Missing x-zm-signature header")
            return jsonify({'error': 'Missing signature'}), 401
        
        # Verify webhook signature
        if not verify_webhook_signature(request_body, signature, ZOOM_WEBHOOK_SECRET_TOKEN):
            print("Invalid webhook signature")
            return jsonify({'error': 'Invalid signature'}), 401
        
        print("✅ Webhook signature verified successfully")
        
        # Parse JSON body
        try:
            body = json.loads(request_body.decode('utf-8'))
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {str(e)}")
            return jsonify({'error': 'Invalid JSON'}), 400
        
        print(f'Request body: {body}')
        
        # Handle URL validation challenge
        if body and body.get('event') == 'endpoint.url_validation':
            print('URL Validation Challenge received')
            
            # Verify challenge token
            challenge_token = body.get('payload', {}).get('plainToken')
            encrypted_token = hmac.new(
                ZOOM_WEBHOOK_SECRET_TOKEN.encode('utf-8'),     # Your webhook secret as the key
                challenge_token.encode('utf-8'),      # Plain token from Zoom as the message
                hashlib.sha256                    # SHA-256 hashing algorithm
            ).hexdigest()  
            if not challenge_token:
                print("Missing challenge token")
                return jsonify({'error': 'Missing challenge token'}), 400
    
            # For Zoom webhooks, return the plain token as encrypted token
            response = {
                'plainToken': challenge_token,
                'encryptedToken': encrypted_token
            }
            print(f'Responding to challenge with: {response}')
            return jsonify(response), 200
        
        # Handle webhook events
        if body:
            event_type = body.get('event')
            print(f'Processing event type: {event_type}')
            
            # Extract common payload data
            payload = body.get('payload', {})
            event_object = payload.get('object', {})
            
            if event_type == 'meeting.started':
                meeting_id = event_object.get('id')
                meeting_uuid = event_object.get('uuid')
                host_id = event_object.get('host_id')
                topic = event_object.get('topic', 'No topic')
                
                print(f'📅 Meeting started:')
                print(f'  - Meeting ID: {meeting_id}')
                print(f'  - UUID: {meeting_uuid}')
                print(f'  - Host ID: {host_id}')
                print(f'  - Topic: {topic}')
                
                # Add your meeting started logic here
                handle_meeting_started(meeting_id, meeting_uuid, host_id, topic)
                
            elif event_type == 'meeting.ended':
                meeting_id = event_object.get('id')
                meeting_uuid = event_object.get('uuid')
                duration = event_object.get('duration', 0)
                
                print(f'🔚 Meeting ended:')
                print(f'  - Meeting ID: {meeting_id}')
                print(f'  - UUID: {meeting_uuid}')
                print(f'  - Duration: {duration} minutes')
                
                # Add your meeting ended logic here
                handle_meeting_ended(meeting_id, meeting_uuid, duration)
                
            elif event_type == 'meeting.participant_joined':
                participant = event_object.get('participant', {})
                participant_name = participant.get('user_name', 'Unknown')
                participant_id = participant.get('id')
                join_time = participant.get('join_time')
                
                print(f'👋 Participant joined:')
                print(f'  - Name: {participant_name}')
                print(f'  - ID: {participant_id}')
                print(f'  - Join time: {join_time}')
                
                # Add your participant joined logic here
                handle_participant_joined(participant_name, participant_id, join_time)
                
            elif event_type == 'meeting.participant_left':
                participant = event_object.get('participant', {})
                participant_name = participant.get('user_name', 'Unknown')
                participant_id = participant.get('id')
                leave_time = participant.get('leave_time')
                duration = participant.get('duration', 0)
                
                print(f'👋 Participant left:')
                print(f'  - Name: {participant_name}')
                print(f'  - ID: {participant_id}')
                print(f'  - Leave time: {leave_time}')
                print(f'  - Session duration: {duration} minutes')
                
                # Add your participant left logic here
                handle_participant_left(participant_name, participant_id, leave_time, duration)
                
            elif event_type == 'recording.completed':
                recording_files = payload.get('object', {}).get('recording_files', [])
                meeting_id = payload.get('object', {}).get('id')
                
                print(f'🎥 Recording completed:')
                print(f'  - Meeting ID: {meeting_id}')
                print(f'  - Number of files: {len(recording_files)}')
                
                # Add your recording completed logic here
                handle_recording_completed(meeting_id, recording_files)
                
            else:
                print(f'❓ Unhandled event type: {event_type}')
                # Log the full payload for debugging
                print(f'Full payload: {json.dumps(payload, indent=2)}')
        
        return jsonify({'status': 'success', 'message': 'Webhook processed'}), 200
        
    except Exception as error:
        print(f'❌ Webhook processing error: {str(error)}')
        return jsonify({'error': 'Internal server error'}), 500

# Event handler functions - customize these based on your needs
def handle_meeting_started(meeting_id, meeting_uuid, host_id, topic):
    """Handle meeting started event"""
    # Add your custom logic here
    # e.g., log to database, send notifications, etc.
    pass

def handle_meeting_ended(meeting_id, meeting_uuid, duration):
    """Handle meeting ended event"""
    # Add your custom logic here
    # e.g., generate reports, cleanup resources, etc.
    pass

def handle_participant_joined(participant_name, participant_id, join_time):
    """Handle participant joined event"""
    # Add your custom logic here
    # e.g., track attendance, send welcome messages, etc.
    pass

def handle_participant_left(participant_name, participant_id, leave_time, duration):
    """Handle participant left event"""
    # Add your custom logic here
    # e.g., track attendance, calculate session time, etc.
    pass

def handle_recording_completed(meeting_id, recording_files):
    """Handle recording completed event"""
    # Add your custom logic here
    # e.g., download recordings, process video files, etc.
    for file in recording_files:
        file_type = file.get('file_type')
        download_url = file.get('download_url')
        print(f'  - File type: {file_type}, Download URL: {download_url}')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    print(f'🚀 Starting Zoom Webhook Server with Default Header verification on port {port}')
    print(f'🔒 Using Authorization Bearer token verification')
    print(f'📝 Make sure to set these environment variables:')
    print(f'   - ZOOM_WEBHOOK_SECRET_TOKEN (your webhook secret token)')
    print(f'   - ZOOM_VERIFICATION_TOKEN (your verification token, if needed)')
    print(f'🔑 Expected Authorization header: Bearer {ZOOM_WEBHOOK_SECRET_TOKEN}')
    app.run(host='0.0.0.0', port=port, debug=True)
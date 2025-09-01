from flask import Flask, request, jsonify
import hashlib
import hmac
import json
import os
from datetime import datetime

app = Flask(__name__)

# For API Secret Token validation, use your app's Client Secret
WEBHOOK_SECRET_TOKEN = os.environ.get('ZOOM_CLIENT_SECRET', 'your_client_secret_here')

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'Zoom Webhook Server Running',
        'timestamp': datetime.now().isoformat(),
        'secret' : WEBHOOK_SECRET_TOKEN
    })

@app.route('/webhook', methods=['POST'])
def webhook():
    print(f'Webhook received: {datetime.now().isoformat()}')
    
    try:
        # Get headers
        timestamp = request.headers.get('x-zm-request-timestamp')
        signature = request.headers.get('x-zm-signature')
        
        print(f'Headers - Timestamp: {timestamp}, Signature: {"present" if signature else "missing"}')
        
        # Get request body
        body_data = request.get_data()
        body = request.get_json()
        
        print(f'Request body: {json.dumps(body, indent=2)}')
        
        # Handle URL validation challenge
        if body.get('event') == 'endpoint.url_validation':
            print('URL Validation Challenge received')
            
            plain_token = body['payload']['plainToken']
            encrypted_token = generate_encrypted_token(plain_token, WEBHOOK_SECRET_TOKEN)
            
            response = {
                'plainToken': plain_token,
                'encryptedToken': encrypted_token
            }
            
            print('Sending validation response')
            return jsonify(response), 200
        
        # Verify webhook signature for actual events
        if signature and timestamp:
            is_valid = verify_webhook_signature(body_data, timestamp, signature, WEBHOOK_SECRET_TOKEN)
            
            if not is_valid:
                print('Invalid webhook signature')
                return jsonify({'error': 'Invalid signature'}), 401
            
            print('Webhook signature verified successfully')
        
        # Handle different event types
        event_type = body.get('event')
        print(f'Event type: {event_type}')
        
        # Process your webhook events here
        if event_type == 'meeting.started':
            meeting_id = body['payload']['object']['id']
            print(f'Meeting started: {meeting_id}')
            
        elif event_type == 'meeting.ended':
            meeting_id = body['payload']['object']['id']
            print(f'Meeting ended: {meeting_id}')
            
        elif event_type == 'meeting.participant_joined':
            participant_name = body['payload']['object']['participant']['user_name']
            print(f'Participant joined: {participant_name}')
            
        elif event_type == 'meeting.participant_left':
            participant_name = body['payload']['object']['participant']['user_name']
            print(f'Participant left: {participant_name}')
            
        else:
            print(f'Unhandled event type: {event_type}')
        
        # Always respond with 200 to acknowledge receipt
        return jsonify({'received': True}), 200
        
    except Exception as error:
        print(f'Webhook processing error: {str(error)}')
        return jsonify({'error': 'Bad request'}), 400

def generate_encrypted_token(plain_token, secret_token):
    """Generate encrypted token for URL validation"""
    message = plain_token.encode('utf-8')
    secret = secret_token.encode('utf-8')
    
    hash_object = hmac.new(secret, message, hashlib.sha256)
    return hash_object.hexdigest()

def verify_webhook_signature(body, timestamp, signature, secret_token):
    """Verify webhook signature"""
    try:
        # Create the message string
        message = f'v0:{timestamp}:{body.decode("utf-8")}'
        
        # Create HMAC signature
        secret = secret_token.encode('utf-8')
        expected_signature = hmac.new(
            secret, 
            message.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest()
        
        # Zoom sends signature in format "v0=hash"
        expected_signature_formatted = f'v0={expected_signature}'
        
        # Compare signatures
        return hmac.compare_digest(expected_signature_formatted, signature)
        
    except Exception as e:
        print(f'Signature verification error: {str(e)}')
        return False

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    print(f'Starting Zoom Webhook Server on port {port}')
    print(f'Webhook URL will be: http://your-domain.com/webhook')
    
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=True)

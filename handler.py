import boto3
import os
import base64
import re
import hmac
import hashlib
from datetime import datetime, timezone
from urllib.parse import parse_qs
from urllib.request import urlopen, Request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

# Environment variables

# S3 bucket for storing message logs and media
# Example: "my-twilio-logs-bucket"
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME')

# Twilio Account SID from your Twilio console
# Example: "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')

# Twilio Auth Token from your Twilio console (used for signature validation and media downloads)
# Example: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')

# Email address for notifications (must be verified in SES). Also used as sender.
# Example: "alerts@example.com"
NOTIFICATION_EMAIL = os.environ.get('NOTIFICATION_EMAIL')

# Set to "true" to attach full log file to notification emails
# Example: "true" or "false"
ATTACH_LOG_FILE = os.environ.get('ATTACH_LOG_FILE', '').lower() == 'true'

# Comma-separated list of phone numbers allowed to send messages
# Example: "+12025551234,+12025559876"
ALLOWED_PHONE_NUMBERS = [n.strip() for n in os.environ.get('ALLOWED_PHONE_NUMBERS', '').split(',') if n.strip()]

# Your Lambda Function URL (used for Twilio signature validation)
# Example: "https://abc123xyz.lambda-url.us-east-1.on.aws/"
WEBHOOK_URL = os.environ.get('WEBHOOK_URL')


def parse_twilio_payload(event):
    """
    Parse the incoming Twilio webhook payload.
    Twilio sends data as application/x-www-form-urlencoded.
    """
    event_body = event.get('body', '')

    if event.get('isBase64Encoded', False):
        event_body = base64.b64decode(event_body).decode('utf-8')

    parsed = parse_qs(event_body, keep_blank_values=True)

    # Convert lists to single values
    return {key: value[0] for key, value in parsed.items()}


def validate_twilio_signature(url, params, signature, auth_token):
    """
    Validate that the request came from Twilio using HMAC-SHA1.
    """
    if not signature or not auth_token or not url:
        return False

    # Build the string to sign: URL + sorted params
    s = url
    for key in sorted(params.keys()):
        s += key + params[key]

    # HMAC-SHA1 and base64 encode
    expected = base64.b64encode(
        hmac.new(auth_token.encode(), s.encode(), hashlib.sha1).digest()
    ).decode()

    # Constant-time comparison
    return hmac.compare_digest(expected, signature)


def sanitize_phone_number(phone_number):
    """
    Sanitize phone number for use as filename.
    Removes '+' and any non-alphanumeric characters.
    """
    return ''.join(c for c in phone_number if c.isalnum())


def parse_actions(body):
    """
    Parse actions from message body.
    Format: /<action1>/<action2>/<action3> <message text>

    Returns:
        tuple: (actions_list, message_text, raw_body)
    """
    if not body:
        return [], '', ''

    raw_body = body

    # Match actions at start: /action1/action2/action3 followed by optional space and message
    match = re.match(r'^((?:/\w+)+)(?:\s+(.*))?$', body, re.DOTALL)

    if match:
        actions_str = match.group(1)
        message_text = match.group(2) or ''
        # Split by / and filter out empty strings
        actions = [a for a in actions_str.split('/') if a]
        return actions, message_text.strip(), raw_body
    else:
        # No actions found, entire body is the message
        return [], body, raw_body


def read_log_from_s3(s3_client, bucket, key):
    """
    Read existing log file from S3. Returns empty string if file doesn't exist.
    """
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        return response['Body'].read().decode('utf-8')
    except s3_client.exceptions.NoSuchKey:
        return ''
    except Exception as e:
        print(f"Error reading log file: {e}")
        return ''


def write_log_to_s3(s3_client, bucket, key, content):
    """
    Write log content to S3.
    """
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=content.encode('utf-8'),
        ContentType='text/plain'
    )


def send_notification_email(message_sid, log_entry, full_log=None):
    """
    Send email notification for logged message.
    If full_log provided and ATTACH_LOG_FILE is true, attach it.
    Best-effort: logs errors but doesn't raise.
    """
    if not NOTIFICATION_EMAIL:
        print("NOTIFICATION_EMAIL not configured, skipping email notification")
        return

    try:
        ses_client = boto3.client('ses', region_name='us-east-1')
        subject = f"Assistant {message_sid} Stored"

        if ATTACH_LOG_FILE and full_log:
            # Build multipart message with attachment
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = NOTIFICATION_EMAIL
            msg['To'] = NOTIFICATION_EMAIL

            # Body
            msg.attach(MIMEText(log_entry, 'plain'))

            # Attachment
            attachment = MIMEApplication(full_log.encode('utf-8'))
            attachment.add_header('Content-Disposition', 'attachment', filename='message_log.log')
            msg.attach(attachment)

            ses_client.send_raw_email(
                Source=NOTIFICATION_EMAIL,
                Destinations=[NOTIFICATION_EMAIL],
                RawMessage={'Data': msg.as_string()}
            )
        else:
            # Simple email without attachment
            ses_client.send_email(
                Source=NOTIFICATION_EMAIL,
                Destination={'ToAddresses': [NOTIFICATION_EMAIL]},
                Message={
                    'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                    'Body': {'Text': {'Data': log_entry, 'Charset': 'UTF-8'}}
                }
            )

        print(f"Notification email sent for {message_sid}")

    except Exception as e:
        print(f"Error sending notification email: {e}")


def download_and_save_media(s3_client, bucket, media_url, content_type, message_sid, index):
    """
    Download media from Twilio and save to S3.
    Returns the S3 key if successful, None otherwise.
    """
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        print("Twilio credentials not configured, skipping media download")
        return None

    try:
        # Create basic auth header
        credentials = f"{TWILIO_ACCOUNT_SID}:{TWILIO_AUTH_TOKEN}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()

        request = Request(media_url)
        request.add_header('Authorization', f'Basic {encoded_credentials}')

        # Download the media
        with urlopen(request) as response:
            media_data = response.read()

        # Determine file extension from content type
        ext_map = {
            'image/jpeg': 'jpg',
            'image/png': 'png',
            'image/gif': 'gif',
            'image/webp': 'webp',
            'video/mp4': 'mp4',
            'video/3gpp': '3gp',
            'video/quicktime': 'mov',
        }
        extension = ext_map.get(content_type, content_type.split('/')[-1])

        # Save to S3
        s3_key = f"media/{message_sid}_{index}.{extension}"
        s3_client.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=media_data,
            ContentType=content_type
        )

        print(f"Saved media to {s3_key}")
        return s3_key

    except Exception as e:
        print(f"Error downloading media: {e}")
        return None


def handler(event, context):
    """
    Lambda handler for processing incoming Twilio SMS messages.
    Logs each message to an S3 file named after the originating phone number.
    """
    print(f"Received event: {event}")

    if not S3_BUCKET_NAME:
        print("Error: S3_BUCKET_NAME environment variable not set")
        return {
            'statusCode': 500,
            'body': 'Server configuration error'
        }

    if not TWILIO_AUTH_TOKEN:
        print("Error: TWILIO_AUTH_TOKEN environment variable not set")
        return {
            'statusCode': 500,
            'body': 'Server configuration error'
        }

    if not ALLOWED_PHONE_NUMBERS:
        print("Error: ALLOWED_PHONE_NUMBERS environment variable not set")
        return {
            'statusCode': 500,
            'body': 'Server configuration error'
        }

    if not WEBHOOK_URL:
        print("Error: WEBHOOK_URL environment variable not set")
        return {
            'statusCode': 500,
            'body': 'Server configuration error'
        }

    try:
        # Parse the Twilio payload
        payload = parse_twilio_payload(event)

        # Validate Twilio signature
        headers = event.get('headers', {})
        twilio_signature = headers.get('x-twilio-signature', '')
        if not validate_twilio_signature(WEBHOOK_URL, payload, twilio_signature, TWILIO_AUTH_TOKEN):
            print("Invalid Twilio signature")
            return {
                'statusCode': 403,
                'body': 'Invalid signature'
            }

        from_number = payload.get('From', '')

        if not from_number:
            print("No 'From' number in payload")
            return {
                'statusCode': 400,
                'body': 'Missing From number'
            }

        if from_number not in ALLOWED_PHONE_NUMBERS:
            print(f"Rejected message from unauthorized number: {from_number}")
            return {
                'statusCode': 403,
                'body': 'Unauthorized'
            }

        # Create log filename from phone number
        sanitized_number = sanitize_phone_number(from_number)
        log_key = f"logs/{sanitized_number}.log"

        # Get current timestamp (UTC)
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

        # Extract message fields
        message_sid = payload.get('MessageSid', '')
        to_number = payload.get('To', '')
        body = payload.get('Body', '')
        from_city = payload.get('FromCity', '')
        from_state = payload.get('FromState', '')
        from_country = payload.get('FromCountry', '')

        location = ','.join(filter(None, [from_city, from_state, from_country]))

        # Parse actions from message body
        actions, message_text, _ = parse_actions(body)
        actions_str = ','.join(actions) if actions else ''

        s3_client = boto3.client('s3')

        # Process any attached media first so we can log the S3 keys
        num_media = int(payload.get('NumMedia', 0))
        media_keys = []
        for i in range(num_media):
            media_url = payload.get(f'MediaUrl{i}')
            content_type = payload.get(f'MediaContentType{i}', 'application/octet-stream')
            if media_url:
                s3_key = download_and_save_media(s3_client, S3_BUCKET_NAME, media_url, content_type, message_sid, i)
                if s3_key:
                    media_keys.append(s3_key)

        media_keys_str = ','.join(media_keys) if media_keys else ''

        # Build log entry with Twilio metadata (tab-delimited, message always last)
        # Format: timestamp \t message_sid \t to \t location \t actions \t num_media \t media_keys \t message_text
        log_entry = f"{timestamp}\t{message_sid}\t{to_number}\t{location}\t{actions_str}\t{num_media}\t{media_keys_str}\t{message_text}\n"

        # Read existing log, append new entry, write back
        existing_log = read_log_from_s3(s3_client, S3_BUCKET_NAME, log_key)
        updated_log = existing_log + log_entry
        write_log_to_s3(s3_client, S3_BUCKET_NAME, log_key, updated_log)

        # Send email notification
        send_notification_email(message_sid, log_entry, updated_log if ATTACH_LOG_FILE else None)

        print(f"Logged message from {from_number} | actions: {actions} | media: {num_media} | text: {message_text[:50] if message_text else '(empty)'}")

        # Return empty TwiML response (no reply)
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/xml'
            },
            'body': '<?xml version="1.0" encoding="UTF-8"?><Response></Response>'
        }

    except Exception as e:
        print(f"Error processing message: {e}")
        return {
            'statusCode': 500,
            'body': 'Error processing message'
        }

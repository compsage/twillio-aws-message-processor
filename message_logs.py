#!/usr/bin/env python3
"""
Fetch and display message logs from S3.

Usage:
    python get_logs.py                    # List all log files
    python get_logs.py <phone_number>     # Get logs for specific number (e.g., 12025551234)
    python get_logs.py --latest           # Get most recently modified log
"""

import boto3
import sys
from dotenv import load_dotenv

load_dotenv()

# Configuration - update these or use environment variables
BUCKET_NAME = "twillio-messages"  # Update with your bucket name
REGION = "us-east-1"


def list_logs(s3_client, bucket):
    """List all log files in the bucket."""
    response = s3_client.list_objects_v2(Bucket=bucket, Prefix="logs/")

    if 'Contents' not in response:
        print("No log files found.")
        return []

    logs = []
    for obj in response['Contents']:
        key = obj['Key']
        if key.endswith('.log'):
            logs.append({
                'key': key,
                'phone': key.replace('logs/', '').replace('.log', ''),
                'modified': obj['LastModified'],
                'size': obj['Size']
            })

    return sorted(logs, key=lambda x: x['modified'], reverse=True)


def get_log_content(s3_client, bucket, key):
    """Fetch and return log file content."""
    response = s3_client.get_object(Bucket=bucket, Key=key)
    return response['Body'].read().decode('utf-8')


def print_log(content):
    """Pretty print log content."""
    print("\n" + "="*80)
    print("TIMESTAMP\t\t\tMSG_ID\t\t\t\t\t\tTO\t\t\tLOCATION\tACTIONS\tMEDIA\tMEDIA_KEYS\tMESSAGE")
    print("="*80)

    for line in content.strip().split('\n'):
        if line:
            print(line)

    print("="*80 + "\n")


def main():
    s3_client = boto3.client('s3', region_name=REGION)

    # List all logs
    if len(sys.argv) == 1:
        logs = list_logs(s3_client, BUCKET_NAME)
        if logs:
            print("\nAvailable log files:")
            print("-" * 60)
            for log in logs:
                print(f"  {log['phone']:15} | Modified: {log['modified']} | Size: {log['size']} bytes")
            print("-" * 60)
            print(f"\nUsage: python {sys.argv[0]} <phone_number>")
            print(f"       python {sys.argv[0]} --latest")
        return

    arg = sys.argv[1]

    # Get latest log
    if arg == '--latest':
        logs = list_logs(s3_client, BUCKET_NAME)
        if not logs:
            return
        key = logs[0]['key']
        print(f"Fetching latest log: {logs[0]['phone']}")
    else:
        # Get specific phone number log
        phone = ''.join(c for c in arg if c.isalnum())  # Sanitize input
        key = f"logs/{phone}.log"
        print(f"Fetching log for: {phone}")

    try:
        content = get_log_content(s3_client, BUCKET_NAME, key)
        print_log(content)
    except s3_client.exceptions.NoSuchKey:
        print(f"Error: Log file not found: {key}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()

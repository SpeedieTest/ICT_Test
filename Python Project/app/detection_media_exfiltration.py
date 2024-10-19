from datetime import datetime

# Function to analyze logs and detect possible exfiltration to a media device
def analyse_exfiltration(logs):
    # List to store alert messages for potential exfiltration events
    alerts = []
    # List of known exfiltration paths to monitor
    exfiltration_paths = destination_paths
    # List of sensitive file paths that are important to monitor
    sensitive_paths = sensitive_file_paths
    # List to store detailed information about each alert
    alert_details = []

    # Iterate through logs to identify potential exfiltration events
    for log in logs:
        # Check if the event involves copying a file and if both source and destination paths are present
        if log.get('event', '').lower() == 'copied' and log.get('destination_path') and log.get('file_path'):
            # Check if the destination path matches any of the known exfiltration paths
            for dest_path in exfiltration_paths:
                if dest_path in log['destination_path']:
                    # Check if the source path matches any of the sensitive file paths
                    for src_path in sensitive_paths:
                        if src_path in log['file_path']:
                            user = log.get('user', 'N/A')
                            # Create an alert message for potential data exfiltration
                            alert_message = f"Alert: Potential data exfiltration by {user} to media device"
                            detected_timestamp = log.get('timestamp', 'N/A')
                            columns = ['Timestamp', 'Hostname', 'User', 'Event', 'File Name', 'File Path', 'Destination Path', 'Original Log']
                            alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'file_system', 'columns': columns})
                            
                            # Collect detailed logs for the alert (only the current log)
                            alert_details.append({
                                'alert_message': alert_message,
                                'detected_timestamp': detected_timestamp,
                                'logs': [
                                    {
                                        'timestamp': log.get('timestamp', 'N/A'),  # Timestamp of the event
                                        'hostname': log.get('hostname', 'N/A'),    # Hostname where the event occurred
                                        'user': log.get('user', 'N/A'),            # User involved in the event
                                        'event': log.get('event', 'N/A'),          # Type of event (e.g., Copied)
                                        'file_name': log.get('file_name', 'N/A'),  # Name of the file involved
                                        'file_path': log.get('file_path', 'N/A'),  # Source path of the file
                                        'destination_path': log.get('destination_path', 'N/A'),  # Destination path
                                        'original_log': log.get('original_log', 'N/A')  # Original log entry
                                    }
                                ]
                            })
                            break  # Stop checking further sensitive paths once a match is found
                    break  # Stop checking further destination paths once a match is found

    # Sort alerts by detected timestamp
    alerts.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))
    alert_details.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))

    # Return the list of alerts and detailed alert information
    return alerts, alert_details


# ------------------------------- LIST OF DESTINATION PATHS AND SENSITIVE PATHS ----------------------------------------------------------

# List of destination paths for potential exfiltration or normal activity
destination_paths = [
    '/media/usb/', '/external_drive/', '/mnt/backup/', '/media/cdrom/', '/mnt/network_share/'
]

# List of base paths for sensitive file paths (locations where sensitive data might reside)
sensitive_file_paths = [
    '/etc/passwd', '/etc/shadow', '/var/log/auth.log', '/var/log/secure', '/var/www/html/admin/', 
    '/usr/local/share/confidential/', '/home/admin/docs/financials/', '/home/admin/docs/hr/', 
    '/srv/db/backups/', '/srv/ftp/sensitive/', '/opt/secrets/', '/opt/vault/', 
    '/var/lib/mysql/financial_data/', '/var/backups/important/', '/usr/share/nginx/secrets/', 
    '/mnt/secure_drive/encryption_keys/', '/mnt/backup/confidential/', '/var/lib/postgresql/sensitive/', 
    '/home/admin/secret_projects/', '/usr/local/etc/private/'
]
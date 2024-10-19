from datetime import datetime

# Function to analyze logs and detect mass download events
def analyse_mass_download(logs):
    # List to store generated alert messages
    alerts = []
    # List to store detailed information about each alert
    alert_details = []

    # Iterate through logs to identify download events
    for log in logs:
        if log.get('service') == 'ftp' and log.get('file_direction') == '_' and log.get('transfer_completion') == 'o':
            source_ip = log.get('source_ip', 'N/A')
            user = log.get('user', 'N/A')
            try:
                file_size = float(log.get('file_size', 0)) / (1024 ** 3)  # Convert file size to GB
            except ValueError:
                continue  # Skip log if file size is not a valid number
            timestamp_str = log.get('timestamp', '')
            try:
                timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            except ValueError:
                continue  # Skip log if timestamp format is incorrect
            
            # Check if the file size exceeds 250GB
            if file_size > 250:
                alert_message = f"Alert: Mass download detected from IP {source_ip} by user {user} with a single download exceeding 250GB"
                detected_timestamp = timestamp.strftime("%b %d %H:%M:%S")
                columns = ["Timestamp", "User", "Source IP", "File Name", "File Path", "File Size (GB)", "Original Log"]
                alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'ftp', 'columns': columns})
                
                # Collect detailed logs for the alert
                alert_logs = [
                    {
                        'timestamp': log.get('timestamp', 'N/A'),
                        'user': log.get('user', 'N/A'),
                        'source_ip': log.get('source_ip', 'N/A'),
                        'file_name': log.get('file_name', 'N/A'),
                        'file_path': log.get('file_path', 'N/A'),
                        'file_size_gb': round(file_size, 2),
                        'original_log': log.get('original_log', 'N/A')
                    }
                ]
                alert_details.append({
                    'alert_message': alert_message,
                    'detected_timestamp': detected_timestamp,
                    'logs': alert_logs
                })

    # Sort alerts by detected timestamp
    if alerts:
        alerts.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))
    if alert_details:
        alert_details.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))

    # Return the list of alerts and detailed alert information
    return alerts, alert_details
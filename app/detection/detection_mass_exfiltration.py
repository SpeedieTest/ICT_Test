from datetime import datetime, timedelta

# Function to analyze logs and detect mass exfiltration events across 24 hours for a single user
def analyse_mass_exfiltration(logs):
    # Dictionary to store download events per user
    user_downloads = {}
    # List to store generated alert messages
    alerts = []
    # List to store detailed information about each alert
    alert_details = []

    # Iterate through logs to identify download events
    for log in logs:
        if log.get('service') == 'ftp' and log.get('file_direction') == '_' and log.get('transfer_completion') == 'o':
            user = log.get('user', 'N/A')
            file_size = int(log.get('file_size', 0)) / (1024 ** 3)  # Convert file size to GB
            timestamp_str = log.get('timestamp', '')
            try:
                timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            except ValueError:
                continue  # Skip log if timestamp format is incorrect

            # Add log entry to user downloads dictionary
            if user not in user_downloads:
                user_downloads[user] = []
            user_downloads[user].append({'timestamp': timestamp, 'file_size': file_size, 'log': log})

    # Analyze user downloads to identify mass exfiltration over 24 hours
    for user, downloads in user_downloads.items():
        downloads.sort(key=lambda x: x['timestamp'])  # Sort downloads by timestamp
        total_size = 0
        start_time = None
        logs_in_24_hours = []

        for i, download in enumerate(downloads):
            if start_time is None:
                start_time = download['timestamp']
                total_size = download['file_size']
                logs_in_24_hours = [download['log']]
            elif download['timestamp'] - start_time <= timedelta(hours=24):
                total_size += download['file_size']
                logs_in_24_hours.append(download['log'])
            else:
                start_time = download['timestamp']
                total_size = download['file_size']
                logs_in_24_hours = [download['log']]

            # Check if the total download size exceeds 250GB within 24 hours and there is more than one log
            if total_size > 500 and len(logs_in_24_hours) > 1:
                detected_timestamp = download['timestamp'].strftime("%b %d %H:%M:%S")
                alert_message = f"Alert: Mass exfiltration detected by user {user} with downloads exceeding 500GB within 24 hours"
                columns = ["Timestamp", "User", "Source IP", "File Name", "File Path", "File Size (GB)", "Original Log"]
                alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'ftp', 'columns': columns})

                # Collect detailed logs for the alert
                alert_logs = []
                for log_entry in logs_in_24_hours:
                    alert_logs.append({
                        'timestamp': log_entry.get('timestamp', 'N/A'),
                        'user': log_entry.get('user', 'N/A'),
                        'source_ip': log_entry.get('source_ip', 'N/A'),
                        'file_name': log_entry.get('file_name', 'N/A'),
                        'file_path': log_entry.get('file_path', 'N/A'),
                        'file_size_gb': round(int(log_entry.get('file_size', 0)) / (1024 ** 3), 2),
                        'original_log': log_entry.get('original_log', 'N/A')
                    })

                alert_details.append({
                    'alert_message': alert_message,
                    'detected_timestamp': detected_timestamp,
                    'logs': alert_logs
                })
                break  # Stop once an alert is generated for this user

    # Sort alerts by detected timestamp
    alerts.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))
    alert_details.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))

    # Return the list of alerts and detailed alert information
    return alerts, alert_details

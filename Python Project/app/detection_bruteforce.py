from datetime import datetime, timedelta

# Function to analyze logs and detect brute force attacks
def analyse_bruteforce(logs):
    alerts = []
    user_attempts = {}
    alert_details = []

    # Iterate through logs to identify failed login attempts
    for log in logs:
        if log.get('service') == 'ssh' and log.get('status') == 'Failed':
            username = log.get('username', 'N/A')
            if username == 'N/A':
                continue  # Skip if username is not available
            timestamp_str = log.get('timestamp', '')
            try:
                timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            except ValueError:
                continue  # Skip log if timestamp format is incorrect

            # Track the number of failed attempts per username
            if username not in user_attempts:
                user_attempts[username] = []
            user_attempts[username].append((timestamp, log))

    # Generate alerts for usernames with multiple failed attempts within 10 minutes
    for username, attempts in user_attempts.items():
        attempts.sort(key=lambda x: x[0])
        for i in range(len(attempts) - 9):  # Check for at least 10 attempts
            if attempts[i + 9][0] - attempts[i][0] <= timedelta(minutes=10):
                alert_message = f"Alert: Possible brute force attack targeting user {username} with 10 failed login attempts within 10 minutes"
                detected_timestamp = attempts[-1][0].strftime("%b %d %H:%M:%S")
                columns = ["Timestamp", "Hostname", "Username", "Source IP", "Status", "Port", "Original Log"]
                alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'ssh', 'columns': columns})
                
                # Collect detailed logs for the alert
                alert_logs = [
                    {
                        'timestamp': attempt[1].get('timestamp', 'N/A'),
                        'hostname': attempt[1].get('hostname', 'N/A'),
                        'username': username,
                        'source_ip': attempt[1].get('source_ip', 'N/A'),
                        'status': attempt[1].get('status', 'N/A'),
                        'port': attempt[1].get('port', 'N/A'),
                        'original_log': attempt[1].get('original_log', 'N/A')
                    }
                    for attempt in attempts[i:i + 10]
                ]
                alert_details.append({
                    'alert_message': alert_message,
                    'detected_timestamp': detected_timestamp,
                    'logs': alert_logs
                })
                break

    # Sort alerts by detected timestamp
    alerts.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))
    alert_details.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))

    # Return the list of alerts and detailed alert information
    return alerts, alert_details
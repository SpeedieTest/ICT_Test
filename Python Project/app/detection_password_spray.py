from datetime import datetime, timedelta

# Function to analyze logs and detect password spray attacks
def analyse_password_spray(logs):
    # Dictionary to store failed login attempts per IP address
    ip_attempts = {}
    # List to store generated alert messages
    alerts = []
    # List to store detailed information about each alert
    alert_details = []

    # Iterate through logs to identify failed login attempts
    for log in logs:
        if log.get('service') == 'ssh' and log.get('status') == 'Failed':
            source_ip = log.get('source_ip', 'N/A')
            username = log.get('username', 'N/A')
            timestamp_str = log.get('timestamp', '')
            try:
                timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            except ValueError:
                continue  # Skip log if timestamp format is incorrect

            # Track failed attempts per IP and username
            if source_ip not in ip_attempts:
                ip_attempts[source_ip] = {}
            if username not in ip_attempts[source_ip]:
                ip_attempts[source_ip][username] = []
            ip_attempts[source_ip][username].append(timestamp)

    # Generate alerts for IPs with at least 5 users having 10 failed attempts each within 60 minutes
    for ip, users in ip_attempts.items():
        users_with_failed_attempts = 0
        alert_logs = []

        for username, attempts in users.items():
            attempts.sort()
            for i in range(len(attempts) - 9):  # Check for at least 10 attempts
                if attempts[i + 9] - attempts[i] <= timedelta(minutes=60):
                    users_with_failed_attempts += 1
                    alert_logs.extend(attempts[i:i + 10])
                    break  # Stop once an alert is generated for this username

        # Check if there are at least 5 users with 10 failed attempts each
        if users_with_failed_attempts >= 5:
            detected_timestamp = max(alert_logs).strftime("%b %d %H:%M:%S")
            alert_message = f"Alert: Possible password spray attack from IP {ip} with at least 5 users each having 10 failed login attempts within 60 minutes"
            columns = ["Timestamp", "Hostname", "Username", "Source IP", "Status", "Port", "Original Log"]
            alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'ssh', 'columns': columns})

            # Collect detailed logs for the alert
            detailed_logs = []
            for log in logs:
                if log.get('source_ip') == ip and log.get('status') == 'Failed':
                    detailed_logs.append({
                        'timestamp': log.get('timestamp', 'N/A'),
                        'hostname': log.get('hostname', 'N/A'),
                        'username': log.get('username', 'N/A'),
                        'source_ip': log.get('source_ip', 'N/A'),
                        'status': log.get('status', 'N/A'),
                        'port': log.get('port', 'N/A'),
                        'original_log': log.get('original_log', 'N/A')
                    })

            alert_details.append({
                'alert_message': alert_message,
                'detected_timestamp': detected_timestamp,
                'logs': detailed_logs
            })

    # Sort alerts by detected timestamp
    alerts.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))
    alert_details.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))

    # Return the list of alerts and detailed alert information
    return alerts, alert_details

from datetime import datetime

# Function to analyze syslog logs and detect file executions with 'tmp' in the file path
def analyse_tmp_execution(logs):
    # List to store generated alert messages
    alerts = []
    # List to store detailed information about each alert
    alert_details = []

    # Iterate through logs to identify file paths containing 'tmp'
    for log in logs:
        if log.get('service') == 'syslog' and 'tmp' in log.get('file_path', '').lower():
            detected_timestamp = log.get('timestamp', 'N/A')
            alert_message = f"Alert: File executed from a temporary directory {log.get('file_path', 'N/A')} by user {log.get('user', 'N/A')}"
            columns = ["Timestamp", "Hostname", "File Path", "File Name", "User", "Original Log"]
            alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'syslog', 'columns': columns})

            # Collect detailed log for the alert
            detailed_logs = [{
                'timestamp': log.get('timestamp', 'N/A'),
                'hostname': log.get('hostname', 'N/A'),
                'file_path': log.get('file_path', 'N/A'),
                'file_name': log.get('file_name', 'N/A'),
                'user': log.get('user', 'N/A'),
                'original_log': log.get('original_log', 'N/A')
            }]

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

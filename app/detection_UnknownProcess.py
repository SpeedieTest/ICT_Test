from datetime import datetime

# Function to analyze kernel logs and detect unusual processes
def analyse_unknown_process(logs):
    # List to store generated alert messages
    alerts = []
    # List to store detailed information about each alert
    alert_details = []

    # Iterate through logs to identify unusual network service events
    for log in logs:
        if log.get('service') == 'kernel' and 'starting unusual network service' in log.get('event', '').lower():
            detected_timestamp = log.get('timestamp', 'N/A')
            alert_message = f"Alert: Unusual network service started by process {log.get('process', 'N/A')} on {log.get('hostname', 'N/A')}"
            columns = ["Timestamp", "Hostname", "Process", "PID", "Event", "Original Log"]
            alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'kernel', 'columns': columns})

            # Collect detailed log for the alert
            detailed_logs = [{
                'timestamp': log.get('timestamp', 'N/A'),
                'hostname': log.get('hostname', 'N/A'),
                'process': log.get('process', 'N/A'),
                'pid': log.get('pid', 'N/A'),
                'event': log.get('event', 'N/A'),
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

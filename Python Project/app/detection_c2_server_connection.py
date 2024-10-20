from datetime import datetime

# Function to analyze iptables logs and detect potential Command and Control (C2) server connections
def analyse_c2_server_connections(logs):
    # Dictionary to track repeated connections from the same source IP to the same destination IP
    connection_tracker = {}
    # List to store generated alert messages
    alerts = []
    # List to store detailed information about each alert
    alert_details = []

    # Iterate through logs to identify repeated connections
    for log in logs:
        if log.get('service') == 'iptables':
            src_ip = log.get('src_ip', 'N/A')
            dst_ip = log.get('dst_ip', 'N/A')
            connection_key = f"{src_ip}->{dst_ip}"

            if connection_key not in connection_tracker:
                connection_tracker[connection_key] = []
            connection_tracker[connection_key].append(log)

    # Generate alerts for repeated connections
    for connection_key, connection_logs in connection_tracker.items():
        if len(connection_logs) > 1:  # Alert if there are repeated connections
            src_ip, dst_ip = connection_key.split('->')
            detected_timestamp = connection_logs[-1].get('timestamp', 'N/A')
            connection_count = len(connection_logs)
            alert_message = f"Alert: Repeated connections detected from {src_ip} to {dst_ip} ({connection_count} times)"
            columns = ["Timestamp", "Hostname", "Source IP", "Source Port", "Destination IP", "Destination Port", "Original Log"]
            alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'iptables', 'columns': columns})

            # Collect detailed logs for the alert
            detailed_logs = []
            for log in connection_logs:
                detailed_logs.append({
                    'timestamp': log.get('timestamp', 'N/A'),
                    'hostname': log.get('hostname', 'N/A'),
                    'source_ip': log.get('src_ip', 'N/A'),
                    'source_port': log.get('src_port', 'N/A'),
                    'destination_ip': log.get('dst_ip', 'N/A'),
                    'destination_port': log.get('dst_port', 'N/A'),
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

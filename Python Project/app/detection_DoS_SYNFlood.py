from datetime import datetime, timedelta

# Function to analyze NetFlow logs and detect potential DoS SYN Flood attacks
def analyse_dos_syn_flood(logs):
    # Dictionary to track SYN packets from the same source IP to destination IP
    syn_tracker = {}
    # List to store generated alert messages
    alerts = []
    # List to store detailed information about each alert
    alert_details = []

    # Iterate through logs to identify SYN flood attacks
    for log in logs:
        if log.get('service') == 'netflow' and log.get('tcp_flags') == 'SYN':
            src_ip = log.get('src_ip', 'N/A')
            dst_ip = log.get('dst_ip', 'N/A')
            timestamp = datetime.strptime(log.get('timestamp', 'N/A'), "%b %d %H:%M:%S")

            if (src_ip, dst_ip) not in syn_tracker:
                syn_tracker[(src_ip, dst_ip)] = []
            syn_tracker[(src_ip, dst_ip)].append(timestamp)

    # Generate alerts for source IPs with at least 50 SYN packets within a 10-minute window
    for (src_ip, dst_ip), timestamps in syn_tracker.items():
        timestamps.sort()
        for i in range(len(timestamps) - 49):  # Check for at least 50 SYN packets
            if timestamps[i + 49] - timestamps[i] <= timedelta(minutes=10):
                detected_timestamp = timestamps[i + 49].strftime("%b %d %H:%M:%S")
                syn_count = len([t for t in timestamps if t >= timestamps[i] and t <= timestamps[i] + timedelta(minutes=10)])
                alert_message = f"Alert: Potential DoS SYN Flood attack from {src_ip} to {dst_ip} with {syn_count} SYN packets within 10 minutes"
                columns = ["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "TCP Flags", "Original Log"]
                alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'netflow', 'columns': columns})

                # Collect detailed logs for the alert
                detailed_logs = []
                for timestamp in timestamps[i:i + syn_count]:
                    for log in logs:
                        if log.get('service') == 'netflow' and log.get('src_ip') == src_ip and log.get('dst_ip') == dst_ip and datetime.strptime(log.get('timestamp', 'N/A'), "%b %d %H:%M:%S") == timestamp:
                            detailed_logs.append({
                                'timestamp': log.get('timestamp', 'N/A'),
                                'source_ip': log.get('src_ip', 'N/A'),
                                'destination_ip': log.get('dst_ip', 'N/A'),
                                'source_port': log.get('src_port', 'N/A'),
                                'destination_port': log.get('dst_port', 'N/A'),
                                'tcp_flags': log.get('tcp_flags', 'N/A'),
                                'original_log': log.get('original_log', 'N/A')
                            })

                alert_details.append({
                    'alert_message': alert_message,
                    'detected_timestamp': detected_timestamp,
                    'logs': detailed_logs
                })
                break

    # Sort alerts by detected timestamp
    alerts.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))
    alert_details.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))

    # Return the list of alerts and detailed alert information
    return alerts, alert_details
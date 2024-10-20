import os
from datetime import datetime
from .identify_log_type import identify_log_type
from .detection_UnknownProcess import analyse_unknown_process
from .detection_tmpExecution import analyse_tmp_execution
from .detection_DoS_SYNFlood import analyse_dos_syn_flood
from .detection_DDoS_SYNFlood import analyse_ddos_syn_flood
from .detection_bruteforce import analyse_bruteforce
from .detection_password_spray import analyse_password_spray
from .detection_c2_server_connection import analyse_c2_server_connections
from .detection_malware_identified import analyse_malware_detection

# Function to read all log files in a folder
def read_logs_from_folder(folder_path):
    logs = []

    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)

        if os.path.isfile(file_path):
            with open(file_path, 'r') as file:
                for line in file:
                    log_data = identify_log_type(line)
                    if log_data:
                        logs.append(log_data)

    return logs

# Function to generate alerts
def generate_alerts(alerts):
    for alert in alerts:
        print(alert['alert_message'])
        # Here, you could extend this to send email notifications or save alerts to a file.

# Function to process logs and generate alerts
def process_logs(log_folder_path):
    # Read the log files from the folder
    logs = read_logs_from_folder(log_folder_path)

    if logs:
        # Analyze the logs for potential DoS SYN Flood alerts
        dos_syn_flood_alerts, dos_syn_flood_details = analyse_dos_syn_flood(logs)
        # Analyze for DDoS SYN Flood attacks
        ddos_syn_flood_alerts, ddos_syn_flood_details = analyse_ddos_syn_flood(logs)
        # Analyze the logs for potential brute force alerts
        brute_force_alerts, brute_force_details = analyse_bruteforce(logs)
        # Analyze the logs for potential password spray alerts
        password_spray_alerts, password_spray_details = analyse_password_spray(logs)
        # Analyze the logs for potential C2 server connection alerts
        c2_server_alerts, c2_server_details = analyse_c2_server_connections(logs)
        # Analyze the logs for potential malware detection alerts
        malware_alerts, malware_details = analyse_malware_detection(logs)

        # Analyze for unknown processes in kernel logs
        unknown_process_alerts, unknown_process_details = analyse_unknown_process(logs)
        # Analyze for tmp directory execution in syslog
        tmp_execution_alerts, tmp_execution_details = analyse_tmp_execution(logs)

        

        # Combine all alerts and details
        all_alerts = (
            brute_force_alerts + password_spray_alerts + dos_syn_flood_alerts +  ddos_syn_flood_alerts + c2_server_alerts + malware_alerts + unknown_process_alerts + tmp_execution_alerts
        )
        all_alert_details = (
            brute_force_details + password_spray_details + dos_syn_flood_details + ddos_syn_flood_details + c2_server_details + malware_details + unknown_process_details + tmp_execution_details
        )

        # Sort alerts by detected timestamp
        all_alerts.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))
        all_alert_details.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))

        # Generate alerts based on the analysis
        generate_alerts(all_alerts)

        return all_alerts, all_alert_details
    else:
        print("No logs found or failed to read log files.")
        return [], []

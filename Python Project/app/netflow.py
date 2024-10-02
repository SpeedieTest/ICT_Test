import os
import random
from datetime import datetime, timedelta


def generate_synthetic_logs(timestamp, source_ip, destination_ip, source_port, destination_port, no_connections, time_period):
    logs = []
    for i in range(num_logs):
        formatted_timestamp = start_timestamp.strftime('%b %d %H:%M:%S')

        process_id = random.randint(10000, 50000)
        port = random.randint(1024, 65535)

        if event_outcome == 'success':
            log = f"{formatted_timestamp} {host_name} sshd[{process_id}]: Accepted password for {user_acc} from {source_ip} port {port} ssh2"
        else:
            log = f"{formatted_timestamp} {host_name} sshd[{process_id}]: Failed password for {user_acc} from {source_ip} port {port} ssh2"

        logs.append((start_timestamp, log))

    return logs




def save_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    # Check for existing files and increment log number
    while os.path.exists(f"logs/netflowlogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/netflowlogs_{log_number}.txt"

    # Inspect logs before saving
    print("Logs to be saved:", logs)  # Debug: Print logs to verify structure

    # Write all logs into a single file
    with open(log_filename, 'w') as file:
        for log in logs:
            if isinstance(log, tuple):
                # If it's a tuple (timestamp, log), write the log part
                file.write(log[1] + '\n')
            else:
                # If it's already a string, just write it directly
                file.write(str(log) + '\n')
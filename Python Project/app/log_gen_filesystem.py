import os
import random
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_hostname, generate_random_source_path, generate_random_exfiltration_path, generate_random_timestamp)

#function to generate a single file system event log
def generate_single_fslog(timestamp, host_name, user_acc, file_name, source_path, destination_path=None):
    logs = []
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')

    if destination_path:
        log = f"{formatted_timestamp} {host_name} {user_acc}: Copied {file_name} from {source_path} to {destination_path}"
    else:
        log = f"{formatted_timestamp} {host_name} {user_acc}: Accessed {file_name} at {source_path}"
    logs.append(log)
    return logs

#function to generate a single file system event log
def generate_log(timestamp, host_name, user_acc, file_name, source_path, destination_path=None):
    logs = []
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')

    if destination_path:
        log = f"{formatted_timestamp} {host_name} {user_acc}: Copied {file_name} from {source_path} to {destination_path}"
    else:
        log = f"{formatted_timestamp} {host_name} {user_acc}: Accessed {file_name} at {source_path}"
    logs.append((timestamp,log))
    return logs

#function to generate daily file system logs with potential exfiltration
def auto_generate_fs_logs(chance_of_exfiltration):
    logs = []
    for _ in range(100): #100 logs
        timestamp = generate_random_timestamp()
        host_name = generate_random_hostname()
        user_acc = generate_random_username()
        source_path = generate_random_source_path()
        file_name = f"file{random.randint(1, 100)}.txt"
        destination_path = None

        #10% chance of data exfiltration
        if random.random() < chance_of_exfiltration:
            destination_path = generate_random_exfiltration_path()

        logs.extend(generate_log(timestamp, host_name, user_acc, file_name, source_path, destination_path))
    
    #sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    #Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]

# Function to save logs into a file
def save_fs_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    while os.path.exists(f"logs/fileSystemLogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/fileSystemLogs_{log_number}.txt"

    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')
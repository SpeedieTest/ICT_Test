import os
import random
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_ip, generate_random_hostname, generate_random_event_outcome, generate_random_timestamp)

def generate_single_filesyslog(start_timestamp, client_ipaddr, file_size, user_name, file_path):
    logs = []
    formatted_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M:%S')
    log = f"{formatted_timestamp} example-server {user_name} copied {file_path} to /media/usb/file.txt"
    logs.append(log)
    return logs

# Function to save logs into a single file
def save_filesys_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    while os.path.exists(f"logs/filesyslogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/filesyslogs_{log_number}.txt"

    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')
import os
import random
from syslog_routes import num_logs
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_hostname, generate_random_event_outcome, generate_random_timestamp)

# Function that generates logs
def generate_synthetic_logs(timestamp_, host_name, user_name, file_path, file_name, bash_id):
        logs = []
        for i in range(num_logs):
            formatted_timestamp = timestamp_.strftime('%b %d %H:%M:%S')
            
            bash_id = random.randint(1,65535)
            
            log = f"{formatted_timestamp} {host_name} bash[{bash_id}]: {file_path} {file_name} executed by {user_name}"
            
        return log
    
# Function to save logs into a single file
def save_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    while os.path.exists(f"logs/sysloglogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/sysloglogs_{log_number}.txt"
    
    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')
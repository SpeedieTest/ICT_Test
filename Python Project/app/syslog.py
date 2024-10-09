import os
import random
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_hostname, generate_random_timestamp, generate_random_filename())

# Function that generates logs
def generate_synthetic_logs(timestamp, host_name, user_name, file_path, file_name):
        logs = []
        
        formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
            
        bash_id = random.randint(10000, 99999)
            
        log = f"{formatted_timestamp} {host_name} bash[{bash_id}]: {file_path} {file_name} executed by {user_name}"

        logs.append(log)

        return logs
    
def generate_daily_activity_logs():
    logs = []

    for _ in range(20):
        user = generate_random_username()
        for _ in range(10):
            login_time = generate_random_timestamp()
            host_name = generate_random_hostname()
            file_path = generate_random_filename()
            file_name = 
            user_name = 

            logs.extend(generate_synthetic_logs(login_time, host_name, user_name, file_path, file_name))

        
        #malicious variable what is considered malicious (this generates the attack)
        login_time = generate_random_timestamp()
        host_name = generate_random_hostname()
        file_path = generate_random_filename()
        file_name = 
        user_name = 

        logs.extend(generate_synthetic_logs(login_time, host_name, user_name, file_path, file_name))
    
    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]


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
import os
import random
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_hostname, generate_random_timestamp, generate_random_filename, generate_random_source_path)

# Function that generates logs
def generate_synthetic_logs(timestamp, host_name, user_name, file_path, file_name):
        logs = []
        
        formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
            
        bash_id = random.randint(10000, 99999)
            
        log = f"{formatted_timestamp} {host_name} bash[{bash_id}]: {file_path}/{file_name} executed by {user_name}"

        logs.append(log)

        return logs
    
def generate_daily_activity_logs():
    logs = []
    num_logs = random.randint(50, 200)

    for _ in range(num_logs):
        login_time = generate_random_timestamp()
        host_name = generate_random_hostname()
        user_name = generate_random_username()

        if random.random() < tmp_execution_chance:
             file_path - '/tmp'
        else:
             file_path= generate_random_source_path()
        file_name = generate_random_filename()

        logs.extend(generate_synthetic_logs(login_time, host_name, user_name, file_path, file_name))

    # Sort logs by timestamp
    logs.sort()

    return logs


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
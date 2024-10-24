import os
from datetime import datetime, timedelta
import random
from app.value_generator import generate_random_hostname, generate_random_username, generate_random_filepath, generate_random_filename, generate_random_timestamp, generate_random_tmpfilepath

# Function to generate a single Syslog log entry
def generate_single_syslog(timestamp, hostname, username, file_path, file_name):
    logs = []
    
    # Format the timestamp as required (e.g., Sep 19 15:01:35)
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
    
    # Random process ID for the log
    process_id = random.randint(10000, 99999)

    # Create the log entry
    log = f"{formatted_timestamp} {hostname} bash[{process_id}]: {file_path}{file_name} executed by {username}"
    
    logs.append(log)
    return logs

# Function to auto-generate syslog entries for a normal business day
def auto_generate_syslog_logs(tmp_execution_chance):
    logs = []
    num_logs = random.randint(50, 200)  # A small company might generate 50-200 syslog logs per day

    # Generate random syslog entries
    for _ in range(num_logs):
        timestamp = generate_random_timestamp()
        hostname = generate_random_hostname()
        username = generate_random_username()
        # Decide if the file will be executed from /tmp
        if random.random() < tmp_execution_chance:
            file_path = generate_random_tmpfilepath()
        else:
            file_path = generate_random_filepath()
        file_name = generate_random_filename()

        # Generate and add the log to the logs list
        logs.extend(generate_single_syslog(timestamp, hostname, username, file_path, file_name))

    # Sort logs by timestamp
    logs.sort()

    return logs

# Function to save Syslog logs into a file
def save_syslog_logs(logs):
    os.makedirs('logs', exist_ok=True)  # Ensure the 'logs' directory exists
    log_number = 1

    # Check for existing files and increment log number
    while os.path.exists(f"logs/syslog_logs_{log_number}.txt"):
        log_number += 1

    log_filename = f"logs/syslog_logs_{log_number}.txt"

    # Write the logs into the file
    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')
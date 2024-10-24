import os
from datetime import datetime, timedelta
import random
from app.value_generator import generate_random_hostname, generate_random_processname, generate_random_kernellogmessage

# Function to generate a single Kernel log entry
def generate_single_kernellog(timestamp, host_name, process_name):
    logs = []
    
    formatted_timestamp, uptime, process_id = generate_values(timestamp)

    # Create the log entry
    log = f"{formatted_timestamp} {host_name} kernel: [{uptime}] {process_name}[{process_id}]: starting unusual network service"
    
    logs.append(log)
    return logs

def generate_values(timestamp):
    # Format the timestamp as required (e.g., Sep 20 14:12:20)
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
    # Random values for the kernel log message components
    uptime = round(random.uniform(10000, 1000000), 6)  # Simulate kernel uptime
    process_id = random.randint(10000, 99999)          # Random process ID
    return formatted_timestamp, uptime, process_id

# Function to auto-generate normal activity for a small company
def auto_generate_kernel_logs(unusual_network_service_chance):
    logs = []
    num_logs = random.randint(50, 200)  # A small company might generate 50-200 kernel logs per day

    # Generate random kernel logs
    for _ in range(num_logs):
        timestamp = datetime.now() - timedelta(days=random.randint(0, 2), hours=random.randint(0, 23), minutes=random.randint(0, 59))
        host_name = generate_random_hostname()
        process_name = generate_random_processname()
        log_message = generate_random_kernellogmessage()

        # Add a chance for unusual network service starting
        if random.random() < unusual_network_service_chance:
            log_message = "starting unusual network service"

        formatted_timestamp, uptime, process_id = generate_values(timestamp)
        
        # Generate and add the log to the logs list
        log = f"{formatted_timestamp} {host_name} kernel: [{uptime}] {process_name}[{process_id}]: {log_message}"
    
        logs.append(log)

    # Sort logs by timestamp
    logs.sort()

    return logs

# Function to save Kernel logs into a file
def save_kernel_logs(logs):
    os.makedirs('logs', exist_ok=True)  # Ensure the 'logs' directory exists
    log_number = 1

    # Check for existing files and increment log number
    while os.path.exists(f"logs/kernel_logs_{log_number}.txt"):
        log_number += 1

    log_filename = f"logs/kernel_logs_{log_number}.txt"

    # Write the logs into the file
    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')
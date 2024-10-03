import os
import random
from datetime import datetime, timedelta
from .value_generator import (generate_random_ip, generate_random_timestamp)





def generate_synthetic_logs(start_timestamp, host_name, source_ip, user_acc, event_outcome, num_logs):
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


def generate_daily_activity_logs():
    logs = []
    # Generate logs for 20 users
    for _ in range(20):
        user = generate_random_username()
        for _ in range(10):
            login_time = generate_random_timestamp()
            source_ip = generate_random_ip(external_chance=0.1)
            logs.extend(generate_synthetic_logs(login_time, generate_random_hostname(), source_ip, user, 'success', 1))

        # Random chance for brute force attack (80% chance for external IP)
        if random.random() < 0.2:
            brute_force_time = generate_random_timestamp()
            source_ip = generate_random_ip(external_chance=0.8)
            logs.extend(generate_synthetic_logs(brute_force_time, generate_random_hostname(), source_ip, user, 'fail', random.randint(5, 10)))

    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]




def save_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    while os.path.exists(f"logs/netflowlogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/netflowlogs_{log_number}.txt"

    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')

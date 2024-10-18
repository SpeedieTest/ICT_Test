import os
import random
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_ip, generate_random_hostname, generate_random_event_outcome, generate_random_timestamp)

# Function to generate synthetic logs
def generate_single_sshlog(start_timestamp, host_name, source_ip, user_acc, event_outcome, num_logs):
    logs = []
    for i in range(num_logs):
        formatted_timestamp = start_timestamp.strftime('%b %d %H:%M:%S')

        process_id = random.randint(10000, 50000)
        port = random.randint(1024, 65535)

        if event_outcome == 'success':
            log = f"{formatted_timestamp} {host_name} sshd[{process_id}]: Accepted password for {user_acc} from {source_ip} port {port} ssh2"
        else:
            log = f"{formatted_timestamp} {host_name} sshd[{process_id}]: Failed password for {user_acc} from {source_ip} port {port} ssh2"

        logs.append(log)

    return logs

# Function to generate synthetic logs
def generate_logs(start_timestamp, host_name, source_ip, user_acc, event_outcome, num_logs):
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


# Function to generate daily activity logs for 20 users, with password spray attack possibility
def auto_generate_ssh_logs(ip_external_chance_normal, ip_external_chance_bruteforce, bruteforce_chance, spray_attack_chance):
    logs = []
    # Generate logs for 20 users
    users = [generate_random_username() for _ in range(20)]
    
    for user in users:
        # Generate normal login attempts for each user
        for _ in range(10):
            login_time = generate_random_timestamp()
            source_ip = generate_random_ip(ip_external_chance_normal)
            logs.extend(generate_logs(login_time, generate_random_hostname(), source_ip, user, generate_random_event_outcome(), 1))

        # Random chance for brute force attack (80% chance for external IP)
        if random.random() < bruteforce_chance:
            brute_force_time = generate_random_timestamp()
            source_ip = generate_random_ip(ip_external_chance_bruteforce)
            logs.extend(generate_logs(brute_force_time, generate_random_hostname(), source_ip, user, 'fail', random.randint(5, 20)))

        # Random chance for password spray attack
        if random.random() < spray_attack_chance:
            # Generate password spray attack
            spray_attack_ip = generate_random_ip(ip_external_chance_bruteforce)  # Use external IP for attack
            spray_attack_users = random.sample(users, k=5)  # Select at least 5 random users
            spray_attack_time = generate_random_timestamp()
            spray_attempts_per_user = 10  # At least 10 failed attempts per user
            total_attempts = spray_attempts_per_user * len(spray_attack_users)
            
            # Spread the attack over time, max 1 minute apart
            for i in range(total_attempts):
                current_user = spray_attack_users[i % len(spray_attack_users)]  # Cycle through users
                spray_attack_time += timedelta(seconds=random.randint(1, 60))  # Max 1 minute apart
                logs.extend(generate_logs(spray_attack_time, generate_random_hostname(), spray_attack_ip, current_user, 'fail', 1))

    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]

# Function to save logs into a single file
def save_ssh_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    while os.path.exists(f"logs/sshloginlogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/sshloginlogs_{log_number}.txt"

    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')

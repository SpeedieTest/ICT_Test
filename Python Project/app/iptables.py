import os
import random
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_ip, generate_random_hostname, generate_random_event_outcome, generate_random_timestamp, generate_random_port, generate_random_packet_length)

def generate_iptables_logs(start_timestamp, host_name, source_ip, source_port, destination_ip, destination_port, packet_length):
    logs = []
    formatted_timestamp = start_timestamp.strftime('%b %d %H:%M:%S')

    log = f"{formatted_timestamp} {host_name} iptables: IN=eth0 OUT=eth0 SRC={source_ip} DST={destination_ip} LEN={packet_length} TOS=0x00 PREC=0x00 TTL=64 ID=54324 DF PROTO=TCP SPT={source_port} DPT={destination_port} WINDOW=65535 RES=0x00 ACK URGP=0"
    
    logs.append((start_timestamp, log))

    return logs
    
# Generate 10 random iptables logs
def generate_random_iptables_logs():
    logs = []
    start_time = generate_random_timestamp()

    for hour in range(24):
        timestamp = start_time + timedelta(hours=hour)
        # random chance for malicious log file
        if random.random() < 0.2:
            # adjust values to be indicitive of a malicious log
            # random_timestamp = timestamp
            source_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
            destination_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            host_name = generate_random_hostname()
            source_port = generate_random_port()
            destination_port = f"8080" # 8080 typically used as malicious port
            packet_length = f"{random.randint(50000, 65535)}"
            logs.extend(generate_iptables_logs(timestamp, host_name, source_ip, source_port, destination_ip, destination_port, packet_length))
        else:
            # Generate each random value and assign to a variable
            # random_timestamp = generate_random_timestamp()
            source_ip = generate_random_ip()
            destination_ip = "8.8.8.8"
            host_name = generate_random_hostname()
            source_port = generate_random_port()
            destination_port = "80"
            packet_length = generate_random_packet_length()
            logs.extend(generate_iptables_logs(timestamp, host_name, source_ip, source_port, destination_ip, destination_port, packet_length))

    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]

def save_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    
    while os.path.exists(f"logs/iptableslogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/iptableslogs_{log_number}.txt"

    with open(log_filename, 'a') as file:
        for log in logs:
            file.write(log + '\n')
# want mix of ip addresses to simulate network traffic
# different internal and external
# eg: source or destination is required to be internal and other one could be internal or external
# eg: defined external address for lets say, web server, would have normal activityy but theres 50% chance that a beacon attack occurs where from certain timestamp, the same log should run every hour 
# still needs to generate normal network activity alongside the malicious attack
# fix destination ip for normal network activity to not be a hardcoded value (should be a range of internal ip addresses in a subnet to look somewhat normal)
# needs to generate more than 24 logs, maybe 240?

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

BUSINESS_HOURS_START = 9  # 9 AM
BUSINESS_HOURS_END = 17    # 5 PM

def generate_random_iptables_logs():
    logs = []
    # Ensure that the logs start generating atleast before the start of the day for realism xD
    random_hour = random.randint(0, 8)  
    random_minute = random.randint(0, 59)
    
    # Set the start time to a random time of the day
    start_time = datetime.now().replace(hour=random_hour, minute=random_minute, second=0, microsecond=0)

    # Variables to hold the current values for malicious logs
    current_source_ip = None
    current_destination_ip = None
    current_host_name = None
    current_source_port = None
    current_destination_port = None
    current_packet_length = None
    initial_malicious_timestamp = start_time  # Use the random start time

    # Set the end of the malicious log generation to 11:59 PM of the same day
    end_of_day = initial_malicious_timestamp.replace(hour=23, minute=59, second=59)

    while initial_malicious_timestamp <= end_of_day:
        # If it's a malicious log, use the previously set values
        if current_source_ip is None:
            # Generate values for the first malicious log entry
            source_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
            destination_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            host_name = generate_random_hostname()
            source_port = generate_random_port()
            destination_port = "8080"  # 8080 typically used as a malicious port
            packet_length = f"{random.randint(50000, 65535)}"

            # Save these values for future use
            current_source_ip = source_ip
            current_destination_ip = destination_ip
            current_host_name = host_name
            current_source_port = source_port
            current_destination_port = destination_port
            current_packet_length = packet_length

        # Use the timestamp for the malicious log
        timestamp = initial_malicious_timestamp
        logs.extend(generate_iptables_logs(timestamp, current_host_name, current_source_ip, current_source_port, current_destination_ip, current_destination_port, current_packet_length))
        
        # Increment the timestamp by one hour for the next malicious log entry
        initial_malicious_timestamp += timedelta(hours=1)

    # Generate random normal logs for other times of the day
    for _ in range(250):  # Amount of normal logs that are generated
        timestamp = generate_random_timestamp()
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

import os
from datetime import datetime, timedelta

def generate_iptables_logs(start_timestamp, host_name, source_ip, source_port, destination_ip, destination_port, packet_length):
    logs = []
    formatted_timestamp = start_timestamp.strftime('%b %d %H:%M:%S')

    log = f"{formatted_timestamp} {host_name} iptables: IN=eth0 OUT=eth0 SRC={source_ip} DST={destination_ip} LEN={packet_length} SPT={source_port} DPT={destination_port}"
    
    logs.append((start_timestamp, log))

    return logs
    

def save_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    
    while os.path.exists(f"logs/iptablelogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/iptablelogs_{log_number}.txt"

    with open(log_filename, 'w') as file:
        for _, log in logs:
            file.write(log + '\n')
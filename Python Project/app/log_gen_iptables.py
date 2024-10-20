import os
import random
from datetime import timedelta
from .value_generator import (generate_random_ip, generate_random_hostname, generate_random_timestamp, generate_random_interface, generate_random_external_ip)

def generate_iptables_logs(start_timestamp, host_name, source_ip, destination_ip, source_port, destination_port, packet_length):
    logs = []
    formatted_timestamp = start_timestamp.strftime('%b %d %H:%M:%S')

    # Other constants for the log
    IN_INTERFACE = generate_random_interface()  # Example interface like 'eth0'
    OUT_INTERFACE = generate_random_interface()  # Example interface like 'eth1'
    TOS = "0x00"
    PREC = "0x00"
    TTL = "64"
    ID = str(random.randint(10000, 60000))  # Random ID
    PROTO = "TCP"
    WINDOW = "65535"
    RES = "0x00"
    FLAGS = "ACK"
    URGP = "0"

    # Creating the log in the desired format
    log = f"{formatted_timestamp} {host_name} iptables: IN={IN_INTERFACE} OUT={OUT_INTERFACE} SRC={source_ip} DST={destination_ip} LEN={packet_length} TOS={TOS} PREC={PREC} TTL={TTL} ID={ID} DF PROTO={PROTO} SPT={source_port} DPT={destination_port} WINDOW={WINDOW} RES={RES} {FLAGS} URGP={URGP}"
    
    logs.append((start_timestamp, log))

    return logs


def generate_random_iptables_logs(c2_attack_chance):
    logs = []
    company_external_ip = "198.26.177.2" # Example external company IP
    potential_c2_server = generate_random_external_ip() 

    # 198.26.177.2Generate random normal logs for other times of the day
    for _ in range(100):  # Amount of normal logs that are generated
        timestamp = generate_random_timestamp()
        source_ip = generate_random_ip()
        destination_ip = generate_random_external_ip() 
        host_name = generate_random_hostname()

        # 80% chance of internal IP connecting to external company IP, 20% chance for other external IP
        if random.random() < 0.8:
            destination_ip = company_external_ip

        source_port = random.randint(1024, 65535)
        destination_port = random.randint(1024, 65535)
        packet_length = random.randint(40, 1500)

        logs.extend(generate_iptables_logs(timestamp, host_name, source_ip, destination_ip, source_port, destination_port, packet_length))

        # Check for C2 connection (internal IP trying to connect to external C2 server)
        if source_ip.startswith('192.168') or source_ip.startswith('10'):  # Ensure source is internal
            if random.random() < c2_attack_chance:
                # Log repeated at the same time for each hour the rest of the day
                for _ in range(23):  # Assuming the day starts at the initial timestamp
                    timestamp += timedelta(hours=1)
                    logs.extend(generate_iptables_logs(timestamp, host_name, source_ip, potential_c2_server, source_port, destination_port, packet_length))
    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]

def save_iptables_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    
    while os.path.exists(f"logs/iptableslogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/iptableslogs_{log_number}.txt"

    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')

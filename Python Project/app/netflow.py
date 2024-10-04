import os
import random
import ipaddress
from datetime import datetime, timedelta
from .value_generator import (generate_random_timestamp, generate_random_ip, generate_random_cidr, generate_random_addresses, generate_random_port)

def generate_synthetic_logs(timestamp, source_ip, destination_ip, source_port, destination_port, no_connections):
    logs = []

    #generate array of ips from input
    ip_addresses = generate_ips(source_ip, no_connections)


    count = 0
    for _ in range(no_connections + 1):
        formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
        log = f" {formatted_timestamp} {ip_addresses[count]}:{source_port} attempted to connect to {destination_ip}:{destination_port}"
        logs.append(log)
        if (len(ip_addresses) > 1):
            count += count

    return logs


def generate_daily_activity_logs():
    logs = []

    # Generate random log values
    source_port = generate_random_port()
    destination_port = generate_random_port()
    no_connections = random.randint(1, 254)
    timestamp = generate_random_timestamp()

    #generate array of ips at random
    source_addresses = generate_random_addresses(no_connections)
    destination_addresses = generate_random_addresses(no_connections)

    count = 0
    for source_address in source_addresses:
        formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
        log = f" {formatted_timestamp} {source_address}:{source_port} attempted to connect to {destination_addresses[count]}:{destination_port}"
        logs.append(log)
        if (len(source_addresses) > 1):
            count += count

    #generate attack
    attack_time = generate_random_timestamp()
    source_ip = generate_random_ip(1) + generate_random_cidr()
    destination_ip = generate_random_ip(0)
    destination_port = 8080
    
    logs.extend(generate_synthetic_logs(attack_time, source_ip, destination_ip, source_port, destination_port, no_connections, 1440))
        
    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return logs

def generate_ips(ip_address: str, no_connections: int):
    # Try to interpret input as a single IP address
    try:
        ip = ipaddress.ip_address(ip_address)
        return [str(ip)]  # Return a list with the single IP address
    
    # If it's not a single IP, treat it as a network range
    except ValueError:
        network = ipaddress.ip_network(ip_address, strict=False)
        hosts = list(network.hosts())  # Get all hosts in the network
        
        # Return only up to `no_connections` number of IPs
        return [str(ip) for ip in hosts[:no_connections]]

def save_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    while os.path.exists(f"logs/netflowlogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/netflowlogs_{log_number}.txt"

    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')

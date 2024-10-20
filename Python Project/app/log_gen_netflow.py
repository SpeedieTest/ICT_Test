import os
import random
import ipaddress  # Import to handle CIDR and IP addresses
from datetime import timedelta
from .value_generator import (generate_random_external_ip, generate_random_timestamp, generate_random_internal_ip)

# Function to generate a random IP from a given CIDR network range
def generate_random_ip_from_cidr(cidr):
    network = ipaddress.ip_network(cidr, strict=False)
    return str(random.choice(list(network.hosts())))

# Function to generate multiple NetFlow log entries within a time period
def generate_single_netflowlog(start_timestamp, src_ip, dst_ip, src_port, dst_port, numb_connect, time_period):
    logs = []

    for _ in range(numb_connect):
        # Generate a random timestamp between start_timestamp and end_timestamp
        random_time_offset = random.uniform(0, time_period)
        current_timestamp = start_timestamp + timedelta(minutes=random_time_offset)
        formatted_timestamp = current_timestamp.strftime('%b %d %H:%M:%S')

        protocol = 'SYN'
        packet_size = random.randint(40, 1500)  # Random packet size in bytes

        # Check if the src_ip is in CIDR format
        try:
            # If src_ip is a valid network, generate a random IP from that range
            ipaddress.ip_network(src_ip, strict=False)
            src_ip_for_log = generate_random_ip_from_cidr(src_ip)
        except ValueError:
            # src_ip is not in CIDR notation, use it as is
            src_ip_for_log = src_ip

        log = f"{formatted_timestamp}    {src_ip_for_log}     {dst_ip}      {src_port}     {dst_port}        {protocol}     {packet_size} bytes"
        logs.append((current_timestamp, log))

    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]

# Helper function to generate log with timestamp for sorting
def generate_log(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size):
    logs = []
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
    log = f"{formatted_timestamp}    {src_ip}     {dst_ip}      {src_port}     {dst_port}        {protocol}     {packet_size} bytes"
    logs.append((timestamp, log)) 
    return logs


def generate_DoS_netflowlog(start_timestamp, src_ip, dst_ip, src_port, dst_port, numb_connect, time_period):
    logs = []

    for _ in range(numb_connect):
        # Generate a random timestamp between start_timestamp and end_timestamp
        random_time_offset = random.uniform(0, time_period)
        current_timestamp = start_timestamp + timedelta(minutes=random_time_offset)
        formatted_timestamp = current_timestamp.strftime('%b %d %H:%M:%S')

        protocol = 'SYN'
        packet_size = random.randint(40, 1500)  # Random packet size in bytes

        # Check if the src_ip is in CIDR format
        try:
            # If src_ip is a valid network, generate a random IP from that range
            ipaddress.ip_network(src_ip, strict=False)
            src_ip_for_log = generate_random_ip_from_cidr(src_ip)
        except ValueError:
            # src_ip is not in CIDR notation, use it as is
            src_ip_for_log = src_ip

        log = f"{formatted_timestamp}    {src_ip_for_log}     {dst_ip}      {src_port}     {dst_port}        {protocol}     {packet_size} bytes"
        logs.append((current_timestamp, log))

    # Extract just the log messages, discarding the timestamp
    return logs

# Function to generate and save multiple NetFlow logs with external traffic simulation
def auto_generate_netflow_logs(syn_flood_dos_chance, syn_flood_ddos_chance):
    logs = []
    num_logs = random.randint(100, 500)  # A small company might see 100-500 NetFlow logs per day
    company_external_ip = "198.26.177.2"  # Company’s external IP

    for _ in range(num_logs):
        timestamp = generate_random_timestamp()
        src_ip = generate_random_external_ip()  # Default to external source IP
        dst_ip = generate_random_external_ip()  # Default to external destination IP

        # Randomly decide whether the traffic is internal-to-external or external-to-internal
        traffic_type = random.choice(['internal-external', 'external-internal'])

        if traffic_type == 'internal-external':
            dst_ip = company_external_ip  # Destination is the company's external IP
        elif traffic_type == 'external-internal':
            src_ip = company_external_ip  # Source is the company's external IP

        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53])  # Common ports like HTTP, HTTPS, SSH, DNS
        protocol = random.choice(['SYN', 'ACK', 'FIN', 'PSH', 'RST', 'URG'])
        packet_size = random.randint(40, 1500)  # Packet size in bytes

        logs.extend(generate_log(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size))

        # SYN flood DoS attack: If triggered, generate many logs from one internal IP to the company's external IP
        if random.random() < syn_flood_dos_chance:
            dos_start_time = timestamp
            dos_source_port = random.randint(1024, 65535)
            dos_src_ip = generate_random_internal_ip()
            dos_numb_logs = random.randint(50, 100)  # Number of SYN packets in DoS attack
            dos_dst_port = 80  # Targeting HTTP service

            logs.extend(generate_DoS_netflowlog(dos_start_time, dos_src_ip, company_external_ip, dos_source_port, dos_dst_port, dos_numb_logs, 5))

        # SYN flood DDoS attack: If triggered, generate many logs from multiple external IPs to the company's external IP
        if random.random() < syn_flood_ddos_chance:
            ddos_start_time = timestamp
            ddos_source_port = random.randint(1024, 65535)
            ddos_numb_logs = random.randint(200, 500)  # Number of SYN packets in DDoS attack
            ddos_dst_port = 80  # Targeting HTTP service

            # Generate multiple external IPs for the DDoS
            for _ in range(50):  # 50 different external IPs participating in DDoS
                ddos_src_ip = generate_random_external_ip()
                logs.extend(generate_DoS_netflowlog(ddos_start_time, ddos_src_ip, company_external_ip, ddos_source_port, ddos_dst_port, ddos_numb_logs // 50, 5))

    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]

# Function to save NetFlow logs into a file
def save_netflow_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    while os.path.exists(f"logs/netflow_logs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/netflow_logs_{log_number}.txt"

    # Write the logs into a single file
    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')
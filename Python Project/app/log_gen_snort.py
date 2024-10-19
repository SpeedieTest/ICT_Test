import os
import random
from datetime import timedelta
from .value_generator import generate_random_ip, generate_random_interface, generate_random_external_ip, generate_random_timestamp, generate_random_hostname

# Function to generate a single iptables log entry
def generate_single_iptableslog(timestamp, host_name, src_ip, dst_ip, src_port, dst_port, packet_len):
    logs = []
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
    
    # Other constants for the log
    IN_INTERFACE = generate_random_interface()  # Example interface like 'eth0'
    OUT_INTERFACE = generate_random_interface()  # Example interface like 'eth1'
    TOS = "0x00"
    PREC = "0x00"
    TTL = "64"
    ID = str(random.randint(10000, 60000))  # Random ID
    DF = "DF"
    PROTO = "TCP"
    WINDOW = "65535"
    RES = "0x00"
    FLAGS = "ACK"
    URGP = "0"

    # Creating the log in the desired format
    log = f"{formatted_timestamp} {host_name} iptables: IN={IN_INTERFACE} OUT={OUT_INTERFACE} SRC={src_ip} DST={dst_ip} LEN={packet_len} TOS={TOS} PREC={PREC} TTL={TTL} ID={ID} DF PROTO={PROTO} SPT={src_port} DPT={dst_port} WINDOW={WINDOW} RES={RES} {FLAGS} URGP={URGP}"
    
    logs.append(log)

    return logs


def generate_log(timestamp, host_name, src_ip, dst_ip, src_port, dst_port, packet_len):
    logs = []
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
    
    # Other constants for the log
    IN_INTERFACE = generate_random_interface()  # Example interface like 'eth0'
    OUT_INTERFACE = generate_random_interface()  # Example interface like 'eth1'
    TOS = "0x00"
    PREC = "0x00"
    TTL = "64"
    ID = str(random.randint(10000, 60000))  # Random ID
    DF = "DF"
    PROTO = "TCP"
    WINDOW = "65535"
    RES = "0x00"
    FLAGS = "ACK"
    URGP = "0"

    # Creating the log in the desired format
    log = f"{formatted_timestamp} {host_name} iptables: IN={IN_INTERFACE} OUT={OUT_INTERFACE} SRC={src_ip} DST={dst_ip} LEN={packet_len} TOS={TOS} PREC={PREC} TTL={TTL} ID={ID} DF PROTO={PROTO} SPT={src_port} DPT={dst_port} WINDOW={WINDOW} RES={RES} {FLAGS} URGP={URGP}"
    logs.append((timestamp,log))

    return logs

# Function to save iptables logs into a file
def save_iptables_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    # Check for existing files and increment log number
    while os.path.exists(f"logs/iptables_logs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/iptables_logs_{log_number}.txt"

    # Write the logs into a single file
    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')

# Example function to generate and save multiple iptables logs
def auto_generate_iptables_logs():
    logs = []
    company_external_ip = "198.51.100.1"  # Example external company IP
    potential_c2_server = generate_random_external_ip()  # Random external IP as C2 server
    internal_to_c2_chance = 0.05  # 5% chance for C2 connection

    for _ in range(100):  # Generating 100 logs
        timestamp = generate_random_timestamp()
        host_name = generate_random_hostname()
        src_ip = generate_random_ip()  # Source IP can be internal or external
        dst_ip = generate_random_external_ip()  # Ensure destination is external

        # 80% chance of internal IP connecting to external company IP, 20% chance for other external IP
        if random.random() < 0.8:
            dst_ip = company_external_ip

        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)
        packet_len = random.randint(40, 1500)  # Random packet length

        logs.extend(generate_log(timestamp, host_name, src_ip, dst_ip, src_port, dst_port, packet_len))

        # Check for C2 connection (internal IP trying to connect to external C2 server)
        if src_ip.startswith('192.168') or src_ip.startswith('10'):  # Ensure source is internal
            if random.random() < internal_to_c2_chance:
                # Log repeated at the same time for each hour the rest of the day
                for _ in range(23):  # Assuming the day starts at the initial timestamp
                    timestamp += timedelta(hours=1)
                    logs.extend(generate_log(timestamp, host_name, src_ip, potential_c2_server, src_port, dst_port, packet_len))

    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]
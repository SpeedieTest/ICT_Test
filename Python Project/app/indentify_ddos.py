import pandas as pd
from collections import defaultdict
from datetime import datetime

# Thresholds for potential DDoS detection
DDOS_IP_THRESHOLD = 20     # Number of unique source IPs targeting a single destination IP
SYN_THRESHOLD = 100        # Number of SYN packets within the time window
TIME_WINDOW = 60           # Time window in seconds
BYTE_THRESHOLD = 500000    # Max bytes received by a destination IP
PACKET_THRESHOLD = 2000    # Max packets received by a destination IP

def detect_ddos(log_file):
    # Load the NetFlow log file into a DataFrame
    data = pd.read_csv(log_file, delim_whitespace=True, names=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flag', 'bytes'])
    
    # Convert the timestamp to datetime object
    data['timestamp'] = pd.to_datetime(data['timestamp'])
    
    # Dictionaries to track destination IP traffic
    ddos_candidates = defaultdict(set)  # Store source IPs targeting each destination
    traffic_volume = defaultdict(int)   # Track total bytes received by each destination IP
    packet_count = defaultdict(int)     # Track total packet count per destination IP
    syn_count = defaultdict(list)       # Track SYN packet timestamps per destination IP
    
    potential_ddos_attacks = []
    
    # Process each row in the NetFlow data
    for index, row in data.iterrows():
        src_ip = row['src_ip']
        dst_ip = row['dst_ip']
        timestamp = row['timestamp']
        packet_flag = row['flag']
        byte_count = row['bytes']
        
        # Track unique source IPs sending traffic to the same destination IP
        ddos_candidates[dst_ip].add(src_ip)
        
        # Track SYN packets for SYN flood detection on the destination
        if packet_flag == 'SYN':
            syn_count[dst_ip].append(timestamp)
            # Remove timestamps older than TIME_WINDOW
            syn_count[dst_ip] = [t for t in syn_count[dst_ip] if (timestamp - t).total_seconds() <= TIME_WINDOW]
            if len(syn_count[dst_ip]) > SYN_THRESHOLD:
                potential_ddos_attacks.append(f"SYN flood to {dst_ip} detected at {timestamp} with {len(syn_count[dst_ip])} SYN packets")
        
        # Track traffic volume to the destination IP
        traffic_volume[dst_ip] += byte_count
        if traffic_volume[dst_ip] > BYTE_THRESHOLD:
            potential_ddos_attacks.append(f"High traffic volume to {dst_ip} detected at {timestamp} ({traffic_volume[dst_ip]} bytes)")
        
        # Track packet count to the destination IP
        packet_count[dst_ip] += 1
        if packet_count[dst_ip] > PACKET_THRESHOLD:
            potential_ddos_attacks.append(f"High packet count to {dst_ip} detected at {timestamp}")
    
    # After processing, check for DDoS conditions
    for dst_ip, src_ips in ddos_candidates.items():
        if len(src_ips) > DDOS_IP_THRESHOLD:
            potential_ddos_attacks.append(f"Possible DDoS attack on {dst_ip} detected with {len(src_ips)} unique source IPs")

    # Output potential DDoS attacks
    if potential_ddos_attacks:
        for alert in potential_ddos_attacks:
            print(alert)
    else:
        print("No DDoS attacks detected.")

# Example usage
log_file = '/mnt/data/netflow_logs_1.txt'
detect_ddos(log_file)

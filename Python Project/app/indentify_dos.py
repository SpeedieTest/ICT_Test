import pandas as pd
from collections import defaultdict
from datetime import datetime

# Set thresholds for potential DoS detection
SYN_THRESHOLD = 500  # SYN packets within time window
TIME_WINDOW = 600    # Time window in seconds for checking SYN flood
BYTE_THRESHOLD = 100000  # Max total bytes from a single source
PACKET_THRESHOLD = 1000  # Max total packets from a single source

def detect_dos(log_file):
    # Read the NetFlow log into a DataFrame
    data = pd.read_csv(log_file, delim_whitespace=True, names=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flag', 'bytes'])
    
    # Convert the timestamp to a datetime object for easier analysis
    data['timestamp'] = pd.to_datetime(data['timestamp'])
    
    # Dictionaries to track traffic by source IP
    syn_count = defaultdict(list)
    traffic_volume = defaultdict(int)
    packet_count = defaultdict(int)
    
    potential_dos_attacks = []
    
    # Process each row in the NetFlow data
    for index, row in data.iterrows():
        src_ip = row['src_ip']
        timestamp = row['timestamp']
        packet_flag = row['flag']
        byte_count = row['bytes']
        
        # Track SYN packets for SYN flood detection
        if packet_flag == 'SYN':
            syn_count[src_ip].append(timestamp)
            # Remove timestamps older than TIME_WINDOW
            syn_count[src_ip] = [t for t in syn_count[src_ip] if (timestamp - t).total_seconds() <= TIME_WINDOW]
            if len(syn_count[src_ip]) > SYN_THRESHOLD:
                potential_dos_attacks.append(f"SYN flood from {src_ip} at {timestamp}")
        
        # Track traffic volume for large data transfers
        traffic_volume[src_ip] += byte_count
        if traffic_volume[src_ip] > BYTE_THRESHOLD:
            potential_dos_attacks.append(f"High traffic volume from {src_ip} at {timestamp}")
        
        # Track packet count for small packet floods
        packet_count[src_ip] += 1
        if packet_count[src_ip] > PACKET_THRESHOLD:
            potential_dos_attacks.append(f"High packet count from {src_ip} at {timestamp}")
    
    # Output potential DoS attacks
    if potential_dos_attacks:
        for alert in potential_dos_attacks:
            print(alert)
    else:
        print("No DoS attacks detected.")

# Example usage
log_file = '/mnt/data/netflow_logs_1.txt'
detect_dos(log_file)

import os
import random
import hashlib
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_ip, generate_random_hostname, generate_random_event_outcome, generate_random_timestamp, generate_random_port, generate_random_packet_length, generate_random_source_path, base_paths)

def generate_snort_logs(start_timestamp, file_hash, source_ip, source_port, file_name, file_size, file_type, filepath):
    logs = []
    formatted_timestamp = start_timestamp.strftime('%b %d %H:%M:%S')
    destination_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}" # generate_random_external_ip()
    destination_port = 80
    uri = filepath+file_name
    #host = generate_random_host()
    process_id = random.randint(1000, 9999)

    log = f"{formatted_timestamp} IDS-Server snort[{process_id}]: [1:{random.randint(1000000, 2000000)}:3] ET MALWARE Malicious File Detected via HTTP (SHA256:{file_hash}) [Classification: Malware Detected] [Priority: 1] {{TCP}} SRC={source_ip}:{source_port} DST={destination_ip}:{destination_port} FileName={file_name} FileSize={file_size} FileType={file_type} URI={uri} Host=malicious-server.com" #host = generate_random_host()
    logs.append((start_timestamp, log))

    return logs
    
# Helper function to generate log with timestamp for sorting
def generate_log(timestamp, filehash, src_ip, dst_ip, src_port, dst_port, filename, filesize, filetype, uri, host):
    logs = []
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
    log = f"{formatted_timestamp} IDS-Server snort[{random.randint(1000, 9999)}]: [1:{random.randint(1000000, 2000000)}:3] ET MALWARE Malicious File Detected via HTTP (SHA256: {filehash}) [Classification: Malware Detected] [Priority: 1] {{TCP}} SRC={src_ip}:{src_port} DST={dst_ip}:{dst_port} FileName={filename} FileSize={filesize} FileType={filetype} URI={uri} Host={host}"
    logs.append((timestamp, log))
    return logs

# Function that creates a random SHA256 hash
def generate_random_sha256_hash():
    # Generate a random byte string of a specific length
    random_bytes = os.urandom(32)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(random_bytes)
    # Return the hexadecimal representation of the hash
    return sha256_hash.hexdigest()

def generate_random_malicious_path():
    base_path = random.choice(base_paths)
    return f"{base_path}/"

# Generate 10 random snort logs
def generate_random_snort_logs():
    logs = []
    num_logs = random.randint(10, 30)  # A small company might see 10-30 logs per day

    for _ in range(num_logs):
                # Generate each random value and assign to a variable
                random_timestamp = generate_random_timestamp()
                file_hash = generate_random_sha256_hash() # generate_random_filehash(), then can remove above code?
                source_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}" # generate_random_internal_ip()
                source_port = random.randint(1024, 65535)
                file_type = random.choice(['/xdosexec/', '/xpython/', '/plain/', '/mp4/', '/json/', '/csv/', '/zip/', '/gif/', '/pdf/'])
                file_name = f"file_{random.randint(1, 100)}" # generate_random_filename()
                file_size = f"{random.randint(10000, 1000000)}"
                file_path = generate_random_malicious_path() + file_name # uri = generate_random_uri()
                # host = generate_random_host()

                        # Event type logic based on realistic expectations for a small company
                event_type = random.choices(
                    ['ET SCAN', 'ET MALWARE', 'ET POLICY', 'ET WEB'],
                    weights=[70, 10, 15, 5],  # Most events are scan, rare malware detections
                    k=1
                )[0]

                if event_type == 'ET SCAN':
                    log = f"{timestamp.strftime('%b %d %H:%M:%S')} IDS-Server snort[{random.randint(1000, 9999)}]: [1:{random.randint(1000000, 2000000)}:1] ET SCAN Suspicious Traffic Detected from {src_ip} to {dst_ip} [Classification: Misc activity] [Priority: 3] {{TCP}} SRC={src_ip}:{src_port} DST={dst_ip}:{dst_port}"
                elif event_type == 'ET MALWARE':
                    log = f"{timestamp.strftime('%b %d %H:%M:%S')} IDS-Server snort[{random.randint(1000, 9999)}]: [1:{random.randint(1000000, 2000000)}:3] ET MALWARE Malicious File Detected via HTTP (SHA256: {filehash}) [Classification: Malware Detected] [Priority: 1] {{TCP}} SRC={src_ip}:{src_port} DST={dst_ip}:{dst_port} FileName={filename} FileSize={filesize} FileType={filetype} URI={uri} Host={host}"
                elif event_type == 'ET POLICY':
                    log = f"{timestamp.strftime('%b %d %H:%M:%S')} IDS-Server snort[{random.randint(1000, 9999)}]: [1:{random.randint(1000000, 2000000)}:2] ET POLICY Possible Policy Violation detected between {src_ip} and {dst_ip} [Classification: Potential Corporate Policy Violation] [Priority: 2] {{TCP}} SRC={src_ip}:{src_port} DST={dst_ip}:{dst_port}"
                else:
                    log = f"{timestamp.strftime('%b %d %H:%M:%S')} IDS-Server snort[{random.randint(1000, 9999)}]: [1:{random.randint(1000000, 2000000)}:1] ET WEB HTTP traffic detected (SHA256: {filehash}) [Classification: Web traffic] [Priority: 3] {{TCP}} SRC={src_ip}:{src_port} DST={dst_ip}:{dst_port} URI={uri} Host={host}"

                logs.append((timestamp, log))

    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    # Extract just the log messages, discarding the timestamp
    return [log for _, log in logs]

def save_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    
    while os.path.exists(f"logs/snortlogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/snortlogs_{log_number}.txt"

    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')
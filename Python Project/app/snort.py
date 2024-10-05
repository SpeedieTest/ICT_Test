import os
import random
import hashlib
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_ip, generate_random_hostname, generate_random_event_outcome, generate_random_timestamp, generate_random_port, generate_random_packet_length, generate_random_source_path, base_paths)

def generate_snort_logs(start_timestamp, host_name, file_hash, source_ip, source_port, file_name, file_size, file_type, file_path):
    logs = []
    formatted_timestamp = start_timestamp.strftime('%b %d %H:%M:%S')
    host_name = generate_random_hostname()
    process_id = random.randint(1, 32768)
    destination_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

    # associate each of the file types with a suffix
    file_type_suffix_map = {
        "/xdosexec/": "exe",
        "/xpython/": "py",
        "/plain/": "txt",
        "/mp4/": "mp4",
        "/json/": "json",
        "/csv/": "csv",
        "/zip/": "zip",
        "/gif/": "gif",
        "/pdf/": "pdf"
    }

    # Get the file type suffix based on the user's selection
    file_type_suffix = file_type_suffix_map.get(file_type, "unknown")

    # FIX TCP (IT SHOULD HAVE CURLY BRACKETS AROUND THE WORD TCP BUT CANT LOL)
    log = f"{formatted_timestamp} {host_name} snort[{process_id}]: [1:2023445:3] ET MALWARE Malicious File Detected via HTTP (SHA256:{file_hash}) [Classification: Malware Detected] [Priority: 1] TCP SRC={source_ip}:{source_port} DST={destination_ip}:80 FileName={file_name}.{file_type_suffix} FileSize={file_size} FileType={file_type} URI={file_path} Host=malicious-server.com"
    logs.append((start_timestamp, log))

    return logs
    

# Function that creates a random SHA256 hash
def generate_random_sha256_hash():
    # Generate a random byte string of a specific length
    random_bytes = os.urandom(32)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(random_bytes)
    # Return the hexadecimal representation of the hash
    return sha256_hash.hexdigest()

def generate_random_file_type():
    # Generate a random file type from a predefined list
    file_types = ["/xdosexec/", "/xpython/", "/plain/", "/mp4/", "/json/", "/csv/", "/zip/", "/gif/", "/pdf/"]
    return random.choice(file_types)

def generate_random_malicious_path():
    base_path = random.choice(base_paths)
    return f"{base_path}/"

# Generate 10 random snort logs
def generate_random_snort_logs():
    logs = []
    for _ in range(10):
            if random.random() < 0.05:
                # Generate each random value and assign to a variable
                random_timestamp = generate_random_timestamp()
                host_name = generate_random_hostname()
                file_hash = generate_random_sha256_hash()
                source_ip = generate_random_ip()
                source_port = generate_random_port()
                file_type = generate_random_file_type()
                file_type_suffix_map = {
                "/xdosexec/": "exe",
                "/xpython/": "py",
                "/plain/": "txt",
                "/mp4/": "mp4",
                "/json/": "json",
                "/csv/": "csv",
                "/zip/": "zip",
                "/gif/": "gif",
                "/pdf/": "pdf"
                }
                file_type_suffix = file_type_suffix_map.get(file_type.strip, "unknown")
                file_name = f"file_{random.randint(1, 100)}.{file_type_suffix}"
                file_size = f"{random.randint(10000, 1000000)}"
                file_path = generate_random_malicious_path() + file_name
                logs.extend(generate_snort_logs(random_timestamp, host_name, file_hash, source_ip, source_port, file_name, file_size, file_type, file_path))

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

    with open(log_filename, 'a') as file:
        for log in logs:
            file.write(log + '\n')
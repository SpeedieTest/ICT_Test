import os
import random
from datetime import datetime, timedelta
from .value_generator import (generate_random_username, generate_random_ip, generate_random_file_path, generate_random_timestamp)

def generate_single_ftplog(timestamp, client_ip, file_size, username, file_path):
    logs = []
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
    file_size_bytes = file_size * 1024 * 1024 * 1024 #Convert GB to Bytes
    log = f"{formatted_timestamp} {file_size_bytes} {client_ip} {file_path} b _ o r {username} ftp 0 * c"
    logs.append(log)
    return logs

def generate_log(timestamp, client_ip, file_size, username, file_path):
    logs = []
    formatted_timestamp = timestamp.strftime('%b %d %H:%M:%S')
    file_size_bytes = file_size * 1024 * 1024 * 1024
    log = f"{formatted_timestamp} {file_size_bytes} {client_ip} {file_path} b _ o r {username} ftp 0 * c"
    logs.append((timestamp,log))
    return logs

#generate multiple FTP logs
def auto_generate_ftp_logs(mass_download_chance, mass_exfiltration_chance):
    logs = []
    #generate normal logs
    for _ in range(100): #100 logs
        timestamp = generate_random_timestamp()
        client_ip = generate_random_ip()
        file_size = random.randint(1, 100) #file size between 1 and 100GB
        username = generate_random_username()
        file_path = generate_random_file_path()

        logs.extend(generate_log(timestamp, client_ip, file_size, username, file_path))

        #chance of a mass download
        if random.random() < mass_download_chance:
            #simulate a single large download event
            timestamp = generate_random_timestamp()
            client_ip = generate_random_ip()
            mass_download_size = random.randint(250, 500) #mass download size between 250 GB and 500 GB
            username = generate_random_username()
            file_path = generate_random_file_path()

            logs.extend(generate_log(timestamp, client_ip, mass_download_size, username, file_path))
        
        #chance of mass exfiltration
        if random.random() < mass_exfiltration_chance:
            #simulate multiple logs for exfiltration from the same user
            exfiltration_size = random.randint(250, 500) #total exfiltration size between 250 and 500 GB
            num_exfiltration_logs = random.randint(5, 10) #exfiltration occurs over 5 to 10 logs
            per_log_size = exfiltration_size // num_exfiltration_logs

            timestamp = generate_random_timestamp()
            client_ip = generate_random_ip()
            username = generate_random_username()

            for _ in range(num_exfiltration_logs):
                file_path = generate_random_file_path()
                logs.extend(generate_log(timestamp, client_ip, per_log_size, username, file_path))
                timestamp += timedelta(minutes=random.randint(1, 60)) #space out logs over time

    #sort logs by timestamp
    logs.sort(key=lambda x: x[0])

    #extract just the log messages, discarding the timestamp
    return [log for _, log in logs]

# Function to save FTP logs into a file
def save_ftp_logs(logs):
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    while os.path.exists(f"logs/ftpLogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/ftpLogs_{log_number}.txt"

    with open(log_filename, 'w') as file:
        for log in logs:
            file.write(log + '\n')
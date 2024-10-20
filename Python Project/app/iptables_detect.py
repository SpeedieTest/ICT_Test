import os
import re

# Define the path to the logs directory relative to the script's location
log_directory = os.path.join(os.path.dirname(__file__), '..', 'logs')  # Go one directory up and then to 'logs'

# Define the regex pattern to match the log entry
log_pattern = re.compile(
    r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<host_name>[\w-]+) iptables: '
    r'IN=(?P<in_interface>[\w-]+) OUT=(?P<out_interface>[\w-]+) '
    r'SRC=(?P<source_ip>[\d\.]+) DST=(?P<destination_ip>[\d\.]+) '
    r'LEN=(?P<packet_length>\d+) TOS=(?P<TOS>0x[0-9a-fA-F]+) '
    r'PREC=(?P<PREC>0x[0-9a-fA-F]+) TTL=(?P<TTL>\d+) ID=(?P<ID>\d+) '
    r'DF PROTO=(?P<PROTO>[\w]+) SPT=(?P<source_port>\d+) '
    r'DPT=(?P<destination_port>\d+) WINDOW=(?P<WINDOW>\d+) '
    r'RES=(?P<RES>0x[0-9a-fA-F]+) (?P<flags>[\w\s]+) '
    r'URGP=(?P<URGP>\d+)'
)

# Function to process each log file
def process_log_file(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                data = match.groupdict()
                # Print the extracted values
                for key, value in data.items():
                    print(f"{key}: {value}")
                print()  # Add an empty line between entries

# Check if the logs directory exists
if os.path.exists(log_directory):
    # Iterate through each file in the logs directory
    for filename in os.listdir(log_directory):
        if filename.endswith('.txt'):  # Only process .txt files
            log_file_path = os.path.join(log_directory, filename)
            print(f"Processing file: {log_file_path}")
            process_log_file(log_file_path)
else:
    print(f"Logs directory not found: {log_directory}")

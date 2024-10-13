import os
import re

# Define the path to the logs directory relative to the script's location
log_directory = os.path.join(os.path.dirname(__file__), '..', 'logs')  # Adjusted to point to logs directory

# Define the regex pattern to match the Snort log entry
snort_log_pattern = re.compile(
    r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<host_name>[\w-]+) snort\[\d+\]: '
    r'\[(?P<alert_id>\d+:\d+:\d+)\] (?P<event_type>ET \w+) (?P<event_description>[\w\s]+) '
    r'from (?P<source_ip>[\d\.]+) to (?P<destination_ip>[\d\.]+) '
    r'\[Classification: (?P<classification>[\w\s]+)\] \[Priority: (?P<priority>\d+)\] '
    r'\{(?P<protocol>\w+)\} SRC=(?P<src_ip>[\d\.]+):(?P<src_port>\d+) '
    r'DST=(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)'
)

# Function to process each log file
def process_snort_log_file(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            match = snort_log_pattern.match(line)
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
            process_snort_log_file(log_file_path)
else:
    print(f"Logs directory not found: {log_directory}")

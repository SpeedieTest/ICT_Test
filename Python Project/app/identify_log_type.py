import re

# Function to identify the type of log and parse its components
def identify_log_type(log_entry):
    # Define the regex pattern for SSH logs
    ssh_pattern = r'(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) sshd\[\d+\]: (?P<status>Failed|Accepted) password for (?P<username>\S+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
    # Define the regex pattern for FTP logs
    ftp_pattern = r'(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<file_size>\d+) (?P<source_ip>\d+\.\d+\.\d+\.\d+) (?P<file_path>.+)/(?P<file_name>\S+) (?P<transfer_type>[bi]) (?P<file_direction>_) (?P<transfer_completion>[oc]) (?P<file_access_mode>\w) (?P<user>\S+) ftp (?P<transfer_status>\d+) \* (?P<special_action_flags>\w)'
    # Define the regex pattern for file system logs
    file_system_pattern = r'(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<user>\S+): (?P<event>\S+) (?P<file_name>\S+) from (?P<file_path>\S+) to (?P<destination_path>\S+)'
    # Define the regex pattern for iptables logs
    iptables_pattern = r'(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) iptables: IN=(?P<in_interface>\S+) OUT=(?P<out_interface>\S+) SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+) DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+) LEN=(?P<length>\d+) TOS=(?P<tos>\S+) PREC=(?P<prec>\S+) TTL=(?P<ttl>\d+) ID=(?P<id>\d+) DF PROTO=(?P<protocol>\S+) SPT=(?P<src_port>\d+) DPT=(?P<dst_port>\d+) WINDOW=(?P<window>\d+) RES=(?P<res>\S+) (?P<flags>\S+)' 
    # Define the regex pattern for SNORT logs
    snort_pattern = r'(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) snort\[\d+\]: \[\d+:\d+:\d+\] (?P<alert_message>.+?) \[Classification: (?P<classification>.+?)\] \[Priority: (?P<priority>\d+)\] {(?P<protocol>\S+)} SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)(?: FileName=(?P<file_name>\S+))?(?: FileSize=(?P<file_size>\d+))?(?: FileType=(?P<file_type>\S+))?(?: URI=(?P<uri>\S+))?(?: Host=(?P<host>\S+))?'
    # Define the regex pattern for NetFlow logs
    netflow_pattern = r'(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2})\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+(?P<src_port>\d+)\s+(?P<dst_port>\d+)\s+(?P<tcp_flags>\w+)\s+(?P<bytes>\d+) bytes'
    # Define the regex pattern for kernel logs
    kernel_pattern = r'(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) kernel: \[\d+\.\d+\] (?P<process>\S+)\[(?P<pid>\d+)\]: (?P<event>.+)'
    # Define the regex pattern for syslog logs
    syslog_pattern = r'(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) bash\[\d+\]: (?P<file_path>.+/)(?P<file_name>\S+) executed by (?P<user>\S+)'

    # Attempt to match each log entry to the defined patterns
    ssh_match = re.match(ssh_pattern, log_entry)
    ftp_match = re.match(ftp_pattern, log_entry)
    file_system_match = re.match(file_system_pattern, log_entry)
    iptables_match = re.match(iptables_pattern, log_entry)
    snort_match = re.match(snort_pattern, log_entry)
    netflow_match = re.match(netflow_pattern, log_entry)
    kernel_match = re.match(kernel_pattern, log_entry)
    syslog_match = re.match(syslog_pattern, log_entry)

    # If the log entry matches the SSH pattern
    if ssh_match:
        log_data = ssh_match.groupdict()
        log_data['service'] = 'ssh'             # Add a key to indicate the log type
        log_data['original_log'] = log_entry
        return log_data

    # If the log entry matches the FTP pattern
    elif ftp_match:
        log_data = ftp_match.groupdict()
        log_data['service'] = 'ftp'             # Add a key to indicate the log type
        log_data['original_log'] = log_entry
        return log_data

    # If the log entry matches the file system pattern
    elif file_system_match:
        log_data = file_system_match.groupdict()
        log_data['service'] = 'file_system'     # Add a key to indicate the log type
        log_data['original_log'] = log_entry
        return log_data
    
    # If the log entry matches the iptables pattern
    elif iptables_match:
        log_data = iptables_match.groupdict()
        log_data['service'] = 'iptables'        # Add a key to indicate the log type
        log_data['original_log'] = log_entry
        return log_data
    
    # If the log entry matches the SNORT pattern
    elif snort_match:
        log_data = snort_match.groupdict()
        log_data['service'] = 'snort'           # Add a key to indicate the log type
        log_data['original_log'] = log_entry
        return log_data
    
    # If the log entry matches the NetFlow pattern
    elif netflow_match:
        log_data = netflow_match.groupdict()
        log_data['service'] = 'netflow'         # Add a key to indicate the log type
        log_data['original_log'] = log_entry
        return log_data
    
    # If the log entry matches the kernel pattern
    elif kernel_match:
        log_data = kernel_match.groupdict()
        log_data['service'] = 'kernel'          # Add a key to indicate the log type
        log_data['original_log'] = log_entry
        return log_data
    
    # If the log entry matches the syslog pattern
    elif syslog_match:
        log_data = syslog_match.groupdict()
        log_data['service'] = 'syslog'          # Add a key to indicate the log type
        log_data['original_log'] = log_entry
        return log_data

    # If the log entry does not match any known pattern, return None
    else:
        return None

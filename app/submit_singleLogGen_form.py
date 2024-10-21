from datetime import datetime
# Import SSHlogin log creation.
from .log_gen_ssh import generate_single_sshlog, save_ssh_logs, auto_generate_ssh_logs
# Import ftp log creation
from .log_gen_ftp import generate_single_ftplog, save_ftp_logs, auto_generate_ftp_logs
# Import filesystem log creation
from .log_gen_filesystem import generate_single_fslog, save_fs_logs, auto_generate_fs_logs
# iptables Imports
from .log_gen_iptables import generate_iptables_logs, save_iptables_logs, generate_random_iptables_logs
# Snort Imports
from .log_gen_snort import generate_snort_logs, save_snort_logs, auto_generate_snort_logs
# Import netflow log creation
from .log_gen_netflow import generate_single_netflowlog, save_netflow_logs, auto_generate_netflow_logs
# Import Kernel log creation
from .log_gen_kernel import generate_single_kernellog, save_kernel_logs, auto_generate_kernel_logs
# Import Systemlog log creation
from .log_gen_syslog import generate_single_syslog, auto_generate_syslog_logs, save_syslog_logs

def handle_submit_form(request):
    log_type = request.form.get('dropdown')

    # Define a dictionary that maps log_type to the respective function calls
    manual_gen_switch = {
        'option1': handle_ssh_logs,
        'option2': handle_fs_logs,
        'option3': handle_ftp_logs,
        'option4': handle_iptables_logs,
        'option5': handle_snort_logs,
        'option6': handle_netflow_logs,
        'option7': handle_kernel_logs,
        'option8': handle_syslog_logs,
    }

    quick_gen_switch = {
        'option1': lambda: handle_quick_gen('option1'),
        'option2': lambda: handle_quick_gen('option2'),
        'option3': lambda: handle_quick_gen('option3'),
        'option4': lambda: handle_quick_gen('option4'),
        'option5': lambda: handle_quick_gen('option5'),
        'option6': lambda: handle_quick_gen('option6'),
        'option7': lambda: handle_quick_gen('option7'),
        'option8': lambda: handle_quick_gen('option8'),
    }

    # Handle manual generation based on log type
    if 'manualGen' in request.form:
        if log_type in manual_gen_switch:
            return manual_gen_switch[log_type](request)
        return "No valid option selected for manual generation."

    # Handle quick generation
    if 'quickGen' in request.form:
        if log_type in quick_gen_switch:
            return quick_gen_switch[log_type]()
        return "No valid option selected for quick generation."

    return "No valid option selected!"

# Handle Quick Generation for logs using a "switch"-like dictionary
def handle_quick_gen(log_type):
    # Define a dictionary that maps log_type to the respective quick generation function
    quick_gen_switch = {
        'option1': generate_ssh_logs_quick,
        'option2': generate_fs_logs_quick,
        'option3': generate_ftp_logs_quick,
        'option4': generate_iptables_logs_quick,
        'option5': generate_snort_logs_quick,
        'option6': generate_netflow_logs_quick,
        'option7': generate_kernel_logs_quick,
        'option8': generate_syslogs_logs_quick,
    }

    # Use the log_type as a key to call the respective function
    if log_type in quick_gen_switch:
        return quick_gen_switch[log_type]()
    else:
        return "Invalid log type for quick generation."

# Helper function to parse timestamp
def parse_timestamp(timestamp_str):
    try:
        return datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        return None

# ------------------------------------ SSH LOGS ------------------------------------------------------

# Handle SSH log generation
def handle_ssh_logs(request):
    timestamp_str = request.form.get('ssh_timestamp')
    host_name = request.form.get('ssh_hostName')
    source_ip = request.form.get('ssh_sourceIP')
    user_acc = request.form.get('ssh_userAcc')
    event_outcome = request.form.get('ssh_eventOutcome')
    num_logs_str = request.form.get('ssh_NumLogs')

    # Validate number of logs
    try:
        num_logs = int(num_logs_str)
    except (TypeError, ValueError):
        return "Error: Invalid number of logs provided.", 400

    # Parse timestamp
    start_timestamp = parse_timestamp(timestamp_str)
    if not start_timestamp:
        return "Error: Invalid timestamp format.", 400

    # Generate and save SSH logs
    logs = generate_single_sshlog(start_timestamp, host_name, source_ip, user_acc, event_outcome, num_logs)
    save_ssh_logs(logs)

    return "SSH Logs generated successfully!"

# Function to handle quick generation of ssh logs
def generate_ssh_logs_quick():
    # Generate daily SSH activity logs 
    # (ip_external_chance_normal, ip_external_chance_bruteforce, bruteforce_chance, spray_attack_chance)
    logs = auto_generate_ssh_logs(0.1,0.8,0.2, 0.2)  
    save_ssh_logs(logs)  # Save the logs
    return "Daily network activity logs generated successfully!"

# ------------------------------------ FTP LOGS ------------------------------------------------------

# Handle FTP log generation
def handle_ftp_logs(request):
    timestamp_str = request.form.get('ftp_timestamp')
    client_ipaddr = request.form.get('ftp_clientipaddr')
    file_size_str = request.form.get('ftp_filesize')
    user_name = request.form.get('ftp_username')
    file_path = request.form.get('ftp_filePath')
    # Parse timestamp
    start_timestamp = parse_timestamp(timestamp_str)
    if not start_timestamp:
        return "Error: Invalid timestamp format.", 400

    # Validate file size
    try:
        file_size = int(file_size_str)
    except (TypeError, ValueError):
        return "Error: Invalid file size provided.", 400

    # Generate and save FTP logs
    logs = generate_single_ftplog(start_timestamp, client_ipaddr, file_size, user_name, file_path)
    save_ftp_logs(logs)

    return "FTP Logs generated successfully!"

# Function to handle quick generation of FTP logs
def generate_ftp_logs_quick():
    # Generate daily FTP activity logs (mass_download_chance, mass_exfiltration_chance)
    logs = auto_generate_ftp_logs(0.05,0.05)  
    save_ftp_logs(logs)  # Save the logs
    return "Daily file transfer logs generated successfully!"

# ------------------------------------ FILE SYSTEM LOGS ------------------------------------------------------

# Handle FS log generation
def handle_fs_logs(request):
    timestamp_str = request.form.get('fs_timestamp')
    host_name = request.form.get('fs_hostName')
    user_acc = request.form.get('fs_userAcc')
    file_name = request.form.get('fs_fileName')
    source_path = request.form.get('fs_sourcePath')
    dest_path = request.form.get('fs_destionationPath')

    # Parse timestamp
    start_timestamp = parse_timestamp(timestamp_str)
    if not start_timestamp:
        return "Error: Invalid timestamp format.", 400


    # Generate and save FS logs
    logs = generate_single_fslog(start_timestamp, host_name, user_acc, file_name, source_path, dest_path)
    save_fs_logs(logs)

    return "File System Logs generated successfully!"

# Function to handle quick generation of File System logs
def generate_fs_logs_quick():
    # Generate daily File System activity logs (chance_of_exfiltration)
    logs = auto_generate_fs_logs(0.1)  
    save_fs_logs(logs)  # Save the logs
    return "Daily file system logs generated successfully!"

# ------------------------------------ NETFLOW LOGS ------------------------------------------------------

# Handle NetFlow log generation
def handle_netflow_logs(request):
    timestamp_str = request.form.get('netflow_timestamp')
    src_ip = request.form.get('netflow_sourceip')
    dst_ip = request.form.get('netflow_destinationip')
    src_port = request.form.get('netflow_sourceport')
    dst_port = request.form.get('netflow_destinationport')
    numb_connections_str = request.form.get('netflow_numberofconnections')
    time_period_str = request.form.get('netflow_timeperiodinminutes')

    # Parse timestamp
    timestamp = parse_timestamp(timestamp_str)
    if not timestamp:
        return "Error: Invalid timestamp format.", 400

    # Validate input ports and connections
    try:
        src_port = int(src_port)
        dst_port = int(dst_port)
        numb_connect = int(numb_connections_str)
        time_period = int(time_period_str)
    except (ValueError, TypeError):
        return "Error: Invalid source or destination port.", 400

    logs = generate_single_netflowlog(timestamp, src_ip, dst_ip, src_port, dst_port, numb_connect, time_period)
    save_netflow_logs(logs)

    return "NetFlow log generated successfully!"

# Function to handle quick generation of netflow logs
def generate_netflow_logs_quick():
    logs = auto_generate_netflow_logs(0.01,0.1)
    save_netflow_logs(logs)
    return "Daily netflow logs generated successfully!"

# ------------------------------------ KERNEL LOGS ------------------------------------------------------ 

# Handle Kernel log generation
def handle_kernel_logs(request):
    timestamp_str = request.form.get('kernel_timestamp')
    host_name = request.form.get('kernel_hostname')
    process_name = request.form.get('kernel_processname')

    # Parse timestamp
    start_timestamp = parse_timestamp(timestamp_str)
    if not start_timestamp:
        return "Error: Invalid timestamp format.", 400

    # Generate and save Kernel log
    logs = generate_single_kernellog(start_timestamp, host_name, process_name)
    save_kernel_logs(logs)

    return "Kernel Log generated successfully!"

def generate_kernel_logs_quick():
    logs = auto_generate_kernel_logs(0.05)
    save_kernel_logs(logs)
    return "Daily kernel logs generated successfully!"
    

# ------------------------------------ SYSTEMLOGS LOGS ------------------------------------------------------

# Handle Syslog log generation
def handle_syslog_logs(request):
    timestamp_str = request.form.get('syslog_timestamp')
    host_name = request.form.get('syslog_hostname')
    user_name = request.form.get('syslog_username')
    file_path = request.form.get('syslog_filepath')
    file_name = request.form.get('syslog_filename')

    # Parse timestamp Syslog
    timestamp_ = parse_timestamp(timestamp_str)
    if not timestamp_:
        return "Error: Invalid timestamp format.", 400

    # Generate and save Syslog logs
    logs = generate_single_syslog(timestamp_, host_name, user_name, file_path, file_name)
    save_syslog_logs(logs)

    return "Syslogs generated successfully!"

# Function to handle quick generation of Syslog logs
def generate_syslogs_logs_quick():
    # Generate daily Syslog activity logs 
    logs = auto_generate_syslog_logs(0.1)  
    save_syslog_logs(logs)  # Save the logs
    return "Daily sys logs generated successfully!"

# ------------------------------------ IPTABLES LOGS ------------------------------------------------------

def handle_iptables_logs (request):
    timestamp_str = request.form.get('iptables_timestamp')
    host_name = request.form.get('iptables_hostName')
    source_ip = request.form.get('iptables_sourceipaddr')
    source_port = request.form.get('iptables_sourceport')
    destination_ip = request.form.get('iptables_destinationipaddr')
    destination_port = request.form.get('iptables_destinationport')
    packet_length= request.form.get('iptables_packetlength')

    #Parse timestamp
    timestamp = parse_timestamp(timestamp_str)
    if not timestamp:
        return "Error: Invalid timestamp format.", 400

    # Generate iptables logs
    logs = generate_iptables_logs(timestamp, host_name, source_ip, source_port, destination_ip, destination_port, packet_length)

    # extract just the log message
    log_messages = [log for _, log in logs]
    # Save logs to a file
    save_iptables_logs(log_messages)

    return "iptables Logs generated successfully!"


def generate_iptables_logs_quick():
    logs = generate_random_iptables_logs(0.05)
    save_iptables_logs(logs)
    return "Random iptables logs generated successfuly!"

# ------------------------------------ SNORT LOGS ------------------------------------------------------

def handle_snort_logs (request):
    timestamp_str = request.form.get('snort_timestamp')
    file_hash = request.form.get('snort_filehash')
    source_ip = request.form.get('snort_sourceip')
    source_port = request.form.get('snort_sourceport')
    file_name = request.form.get('snort_filename')
    file_size = request.form.get('snort_filesize')
    file_type = request.form.get('snort_filetype')
    file_path = request.form.get('snort_filePath')

# Parse timestamp
    start_timestamp = parse_timestamp(timestamp_str)
    if not start_timestamp:
        return "Error: Invalid timestamp format.", 400
    
    # Generate iptables logs
    logs = generate_snort_logs(start_timestamp, file_hash, source_ip, source_port, file_name, file_size, file_type, file_path)

    # extract just the log message
    log_messages = [log for _, log in logs]
    # Save logs to a file
    save_snort_logs(log_messages)

    return "Snort Logs generated successfully!"

def generate_snort_logs_quick():
    logs = auto_generate_snort_logs(0.05)
    save_snort_logs(logs)
    return "Random snort logs generated successfuly!" 
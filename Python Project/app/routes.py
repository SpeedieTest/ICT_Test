from flask import render_template, request
from app import app
from datetime import datetime
# Import SSHlogin log creation.
from .log_gen_ssh import generate_single_sshlog, save_ssh_logs, auto_generate_ssh_logs
# iptables Imports
from .log_gen_iptables import generate_iptables_logs, save_logs, generate_random_iptables_logs
# Snort Imports
from .log_gen_snort import generate_snort_logs, save_logs, auto_generate_snort_logs
# Import Kernel log creation
from .log_gen_kernel import generate_single_kernellog, save_kernel_logs, auto_generate_kernel_logs

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/create')
def create():
    return render_template('create.html')

@app.route('/analyse')
def analyse():
    return render_template('analyse.html')

@app.route('/submit', methods=['POST'])
def submit_form():
    log_type = request.form.get('dropdown')

    # Define a dictionary that maps log_type to the respective function calls
    manual_gen_switch = {
        'option1': handle_ssh_logs,
        'option4': handle_iptables_logs,
        'option5': handle_snort_logs,
        'option7': handle_kernel_logs,
    }

    quick_gen_switch = {
        'option1': lambda: handle_quick_gen('option1'),
        'option4': lambda: handle_quick_gen('option4'),
        'option5': lambda: handle_quick_gen('option5'),
        'option7': lambda: handle_quick_gen('option7'),
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
        'option4': generate_iptables_logs_quick,
        'option5': generate_snort_logs_quick,
        'option7': generate_kernel_logs_quick,
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

# Function to handle quick generation of SSH logs
def generate_ssh_logs_quick():
    # Generate daily SSH activity logs 
    # (ip_external_chance_normal, ip_external_chance_bruteforce, bruteforce_chance, spray_attack_chance)
    logs = auto_generate_ssh_logs(0.1,0.8,0.2, 0.6)  
    save_ssh_logs(logs)  # Save the logs
    return "Daily network activity logs generated successfully!"

def handle_iptables_logs (request):
    timestamp_str = request.form.get('iptables_timestamp')
    host_name = request.form.get('iptables_hostName')
    source_ip = request.form.get('iptables_sourceipaddr')
    source_port = request.form.get('iptables_sourceport')
    destination_ip = request.form.get('iptables_destinationipaddr')
    destination_port = request.form.get('iptables_destinationport')
    packet_length= request.form.get('iptables_packetlength')

    # Parse timestamp
    start_timestamp = parse_timestamp(timestamp_str)
    if not start_timestamp:
        return "Error: Invalid timestamp format.", 400

    # Generate iptables logs
    logs = generate_iptables_logs(start_timestamp, host_name, source_ip, source_port, destination_ip, destination_port, packet_length)

    # extract just the log message
    log_messages = [log for _, log in logs]
    # Save logs to a file
    save_logs(log_messages)

    return "iptables Logs generated successfully!"

def generate_iptables_logs_quick():
    logs = generate_random_iptables_logs(0.05)
    save_logs(logs)
    return "Random iptables logs generated successfuly!"


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
    save_logs(log_messages)

    return "Snort Logs generated successfully!"

def generate_snort_logs_quick():
    logs = auto_generate_snort_logs(0.05)
    save_logs(logs)
    return "Random snort logs generated successfuly!"  

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
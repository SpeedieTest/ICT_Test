from flask import render_template, request
from app import app
from datetime import datetime
# Import SSHlogin log creation.
from .sshlogin import generate_single_sshlog, save_ssh_logs, auto_generate_ssh_logs
from .filetransfer import generate_single_ftplog, save_ftp_logs
from .filesystem import generate_single_fslog, save_fs_logs
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
        'option3': handle_ftp_logs,
        'option2': handle_fs_logs,
    }

    quick_gen_switch = {
        'option1': lambda: handle_quick_gen('option1'),
        'option3': lambda: handle_quick_gen('option3'),
        'option2': lambda: handle_quick_gen('option2'),
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
        'option3': generate_ftp_logs_quick,
        'option2': generate_fs_logs_quick,
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

# Function to handle quick generation of SSH logs
def generate_ssh_logs_quick():
    # Generate daily SSH activity logs 
    (ip_external_chance_normal, ip_external_chance_bruteforce, bruteforce_chance, spray_attack_chance)
    logs = auto_generate_ssh_logs(0.1,0.8,0.2, 0.1)  
    save_ssh_logs(logs)  # Save the logs
    return "Daily network activity logs generated successfully!"

# Function to handle quick generation of FTP logs
def generate_ftp_logs_quick():
    # Generate daily FTP activity logs 
    (mass_download_chance, mass_exfiltration_chance)
    logs = auto_generate_ftp_logs(0.1,0.8,0.2, 0.1)  
    save_ftp_logs(logs)  # Save the logs
    return "Daily file transfer logs generated successfully!"

# Function to handle quick generation of File System logs
def generate_fs_logs_quick():
    # Generate daily File System activity logs 
    (chance_of_exfiltration)
    logs = auto_generate_ssh_logs(0.1,0.8,0.2, 0.1)  
    save_fs_logs(logs)  # Save the logs
    return "Daily file system logs generated successfully!"
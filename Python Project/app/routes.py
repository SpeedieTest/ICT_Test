from flask import render_template, request
from app import app
from datetime import datetime
from .sshlogin import generate_synthetic_logs as ssh_gsl
from .sshlogin import save_logs as ssh_sl
from .sshlogin import generate_daily_activity_logs as ssh_dal
from .log_gen_netflow import generate_single_netflowlog, save_netflow_logs, auto_generate_netflow_logs

from .value_generator import generate_random_username, generate_random_hostname, generate_random_source_path

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
        'option6': handle_netflow_logs,
    }

    quick_gen_switch = {
        'option1': lambda: handle_quick_gen('option1'),
        'option6': lambda: handle_quick_gen('option6'),
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
        'option6': generate_netflow_logs_quick,
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
    logs = ssh_gsl(start_timestamp, host_name, source_ip, user_acc, event_outcome, num_logs)
    ssh_sl(logs)

    return "SSH Logs generated successfully!"

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
def generate_ssh_logs_quick():
    logs = ssh_dal()  # Call the function that generates daily SSH activity logs
    ssh_sl(logs)  # Save the logs
    return "Daily network activity logs generated successfully!"

def generate_netflow_logs_quick():
    logs = auto_generate_netflow_logs(0.1,0.05)
    save_netflow_logs(logs)
    return "Daily netflow logs generated successfully!"
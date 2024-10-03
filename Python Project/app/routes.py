from flask import render_template, request
from app import app
from datetime import datetime
from .sshlogin import generate_synthetic_logs as ssh_gsl
from .sshlogin import save_logs as ssh_sl
from .sshlogin import generate_daily_activity_logs as ssh_dal
from .netflow import generate_synthetic_logs as netflow_gsl
from .netflow import save_logs as netflow_sl
from .netflow import generate_daily_activity_logs as netflow_dal

from .value_generator import generate_random_username, generate_random_hostname, generate_random_source_path, generate_random_destination_path

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

def handle_netflow_logs(request):
    timestamp_str = request.form.get('netflow_timestamp')
    source_ip = request.form.get('netflow_sourceip')
    destination_ip = request.form.get('netflow_destinationip')
    source_port = request.form.get('netflow_sourceport')
    destination_port = request.form.get('netflow_destinationport')
    no_connections = request.form.get('netflow_numberofconnections')
    time_period = request.form.get('netflow_timeperiodinminutes')

    #speedie needs to convert from sting to
    #mine should work but no quarantee
    #if not working look at line 86 "validate number of logs"

    # Parse timestamp
    timestamp = parse_timestamp(timestamp_str)
    if not start_timestamp:
        return "Error: Invalid timestamp format.", 400

    # Generate and save SSH logs
    logs = netflow_gsl(timestamp, source_ip, destination_ip, source_port, destination_port, no_connections, time_period)
    netflow_sl(logs)
    return "Netflow Logs generated successfully!"





# Function to handle quick generation of SSH logs
def generate_ssh_logs_quick():
    logs = ssh_dal()  # Call the function that generates daily SSH activity logs
    ssh_sl(logs)  # Save the logs
    return "Daily network activity logs generated successfully!"

def generate_netflow_logs_quick():
    logs = netflow_dal()  # Call the function that generates daily SSH activity logs
    netflow_sl(logs)  # Save the logs
    return "Daily network activity logs generated successfully!"
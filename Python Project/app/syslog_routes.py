from flask import render_template, request
from app import app
from datetime import datetime
from .syslog import generate_synthetic_logs as syslog_gsl
from .syslog import save_logs as syslog_sl
from .value_generator import generate_random_username, generate_random_hostname, generate_random_source_path, generate_random_filename

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
        'option8': handle_syslog_logs,
    }


    # Handle manual generation based on log type
    if 'manualGen' in request.form:
        if log_type in manual_gen_switch:
            return manual_gen_switch[log_type](request)
        return "No valid option selected for manual generation."

    return "No valid option selected!"


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
def handle_syslog_logs(request):
    timestamp_str = request.form.get('syslog_timestamp')
    host_name = request.form.get('syslog_hostName')
    user_name = request.form.get('syslog_userName')
    file_path = request.form.get('syslog_filePath')
    file_name = request.form.get('syslog_fileName')
    bash_id = request.form.get('syslog_bashID')
    num_logs_str = request.form.get('syslog_NumLogs')

    # Validate number of logs
    try:
        num_logs = int(num_logs_str)
    except (TypeError, ValueError):
        return "Error: Invalid number of logs provided.", 400

    # Parse timestamp
    timestamp_ = parse_timestamp(timestamp_str)
    if not timestamp_:
        return "Error: Invalid timestamp format.", 400

    # Generate and save SSH logs
    logs = syslog_gsl(timestamp_, host_name, user_name, file_path, file_name, bash_id, num_logs)
    syslog_sl(logs)

    return "SSH Logs generated successfully!"
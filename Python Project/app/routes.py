from flask import render_template, request
from app import app
from datetime import datetime
from .sshlogin import generate_synthetic_logs as ssh_gsl
from .sshlogin import save_logs as ssh_sl
from .sshlogin import generate_daily_activity_logs as ssh_dal
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
    # Check if the user selected SSH Login (Option 1)
    if 'manualGen' in request.form and request.form.get('dropdown') == 'option1':
        timestamp_str = request.form.get('ssh_timestamp')
        host_name = request.form.get('ssh_hostName')
        source_ip = request.form.get('ssh_sourceIP')
        user_acc = request.form.get('ssh_userAcc')
        event_outcome = request.form.get('ssh_eventOutcome')
        num_logs_str = request.form.get('ssh_NumLogs')

        # Validate num_logs
        if num_logs_str is None or num_logs_str.strip() == '':
            return "Error: Number of logs not provided.", 400

        try:
            num_logs = int(num_logs_str)
        except ValueError:
            return "Error: Invalid number of logs provided.", 400

        # Convert the timestamp
        try:
            start_timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            return "Error: Invalid timestamp format.", 400

        # Generate SSH logs
        logs = ssh_gsl(start_timestamp, host_name, source_ip, user_acc, event_outcome, num_logs)

        # Save logs to a file
        ssh_sl(logs)

        return "SSH Logs generated successfully!"

    # Check if the user clicked on 'Quick Gen' button for SSH logs
    if 'quickGen' in request.form and request.form.get('dropdown') == 'option1':
        # Generate daily activity logs for multiple users with random brute force attacks and off-hours login attempts
        logs = ssh_dal()
        ssh_sl(logs)
        return "Daily network activity logs generated successfully!"

    return "No valid option selected!"

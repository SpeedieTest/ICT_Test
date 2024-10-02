from flask import Blueprint, render_template, request
from app import app
from datetime import datetime
from .sshlogin import generate_synthetic_logs as ssh_gsl
from .sshlogin import save_logs as ssh_sl
from .sshlogin import generate_daily_activity_logs as ssh_dal
from .sshlogin import generate_synthetic_logs as netflow_gsl
from .sshlogin import save_logs as netflow_sl
from .sshlogin import generate_daily_activity_logs as netflow_dal


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

    # Check if the user clicked on 'Quick Gen' button
    if 'quickGen' in request.form and request.form.get('dropdown') == 'option1':
        # Generate daily activity logs for 10 users with random brute force attacks and off-hours login attempts
        logs = ssh_dal()
        ssh_sl(logs)
        return "Daily network activity logs generated successfully!"








    #netflow section
    if 'manualGen' in request.form and request.form.get('dropdown') == 'option6':
        timestamp_str = request.form.get('netflow_timestamp')
        source_ip = request.form.get('netflow_sourceip')
        destination_ip = request.form.get('netflow_destinationip')
        source_port_str = request.form.get('netflow_sourceport')
        destination_port_str = request.form.get('netflow_destinationport')
        no_connections_str = request.form.get('netflow_numberofconnections')
        time_period_str = request.form.get('netflow_timeperiodinminutes')
       
        # Validate source_port
        if source_port_str is None or source_port_str.strip() == '':
            return "Error: Number of logs not provided.", 400
        try:
            source_port = int(source_port_str)
        except ValueError:
            return "Error: Invalid number of logs provided.", 400

        # Validate destination_port
        if destination_port_str is None or destination_port_str.strip() == '':
            return "Error: Number of logs not provided.", 400
        try:
            destination_port = int(destination_port_str)
        except ValueError:
            return "Error: Invalid number of logs provided.", 400

        # Validate destination_port
        if no_connections_str is None or no_connections_str.strip() == '':
            return "Error: Number of logs not provided.", 400
        try:
            no_connections = int(no_connections_str)
        except ValueError:
            return "Error: Invalid number of logs provided.", 400

        # Validate destination_port
        if time_period_str is None or time_period_str.strip() == '':
            return "Error: Number of logs not provided.", 400
        try:
            time_period = int(time_period_str)
        except ValueError:
            return "Error: Invalid number of logs provided.", 400

        # Convert the timestamp
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            return "Error: Invalid timestamp format.", 400

        # Generate SSH logs
        logs = netflow_gsl(timestamp, source_ip, destination_ip, source_port, destination_port, no_connections, time_period)

        # Save logs to a file
        netflow_sl(logs)
        return "Netflow Logs generated successfully!"

    # Check if the user clicked on 'Quick Gen' button
    if 'quickGen' in request.form and request.form.get('dropdown') == 'option6':
        # Generate daily activity logs for 10 users with random brute force attacks and off-hours login attempts
        logs = netflow_dal()
        ssh_sl(logs)
        return "Daily network activity logs generated successfully!"

    return "No valid option selected!"
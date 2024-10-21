from flask import render_template, request
from app import app
from datetime import datetime
from .submit_singleLogGen_form import handle_submit_form
from .submit_quickgen_form import handle_quickgen_form
# Import script to process logs and create alerts
from .run_alerts import process_logs


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/create')
def create():
    return render_template('create.html')

@app.route('/analyse')
def analyse():
    log_folder_path = 'logs'  # Path to your log folder
    alerts, alert_details = process_logs(log_folder_path)  # Get alerts and detailed logs
    return render_template("analyse.html", alerts=alerts, alert_details=alert_details)

@app.route('/submitquick', methods=['POST'])
def submit_quickgen_form():
    return handle_quickgen_form(request)

@app.route('/submit', methods=['POST'])
def submit_form():
    return handle_submit_form(request)
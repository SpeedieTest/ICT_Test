from flask import Flask, render_template, request
from datetime import datetime
from waitress import serve
import sys
from app.submit_singleLogGen_form import handle_submit_form
from app.submit_quickgen_form import handle_quickgen_form
sys.path.insert(0,'ICT_TEST/app')
# Import script to process logs and create alerts
from app.run_alerts import process_logs

app = Flask(__name__)

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

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)
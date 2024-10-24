from dotenv import load_dotenv
import os
import requests
from datetime import datetime
import time
import pycountry  # Import pycountry for ISO country code lookup

# Constants
COMPANY_PUBLIC_IP = '198.26.177.2'
INTERNAL_IP_RANGES = [
    ('10.0.0.0', '10.255.255.255'),       # Private IP range for Class A
    ('172.16.0.0', '172.31.255.255'),     # Private IP range for Class B
    ('192.168.0.0', '192.168.255.255')    # Private IP range for Class C
]

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
AUSTRALIAN_COUNTRY_CODE = 'AU'
RATE_LIMIT_SLEEP_TIME = 60  # 60 seconds between API requests to respect the free rate limit

# Helper function to check if an IP is internal or the company's public IP
def is_internal_or_company_ip(ip):
    # Check if the IP matches the company's public IP
    if ip == COMPANY_PUBLIC_IP:
        return True
    
    # Convert IP to integer for comparison
    ip_int = int(''.join(f'{int(octet):08b}' for octet in ip.split('.')), 2)
    
    # Check if the IP falls within internal IP ranges
    for ip_range in INTERNAL_IP_RANGES:
        range_start = int(''.join(f'{int(octet):08b}' for octet in ip_range[0].split('.')), 2)
        range_end = int(''.join(f'{int(octet):08b}' for octet in ip_range[1].split('.')), 2)
        if range_start <= ip_int <= range_end:
            return True
    
    return False

# Function to check IP with VirusTotal
def check_ip_virustotal(ip):
    params = {'apikey': VIRUSTOTAL_API_KEY, 'ip': ip}
    response = requests.get(VIRUSTOTAL_URL, params=params)
    
    # Handle rate limiting with a 204 response code
    if response.status_code == 204:
        print(f"Rate limit hit. Waiting for {RATE_LIMIT_SLEEP_TIME} seconds before retrying...")
        time.sleep(RATE_LIMIT_SLEEP_TIME)  # Wait before retrying
        return check_ip_virustotal(ip)  # Retry the request after waiting
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"VirusTotal API request failed for IP {ip}: Status Code {response.status_code}")
        return None

# Function to check IP with ipinfo.io if VirusTotal returns no country
def check_ip_ipinfo(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_API_KEY}")
        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown')
        else:
            print(f"IPinfo.io API request failed for IP {ip}: Status Code {response.status_code}")
            return "Unknown"
    except Exception as e:
        return "Unknown"

# Function to get full country name using pycountry
def get_country_name_from_code(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code.upper().strip())
        if country:
            return country.name  # Extract the full country name
        else:
            return "Unknown Country"
    except Exception as e:
        return "Unknown Country"

# Function to analyze logs and detect malicious IPs or non-Australian IPs
def analyse_osint(logs):
    unique_ips = set()  # Store unique IPs
    alerts = []  # Store generated alert messages
    alert_details = []  # Store detailed information about each alert

    # Iterate through logs to collect external unique IPs
    for log in logs:
        ip = log.get('source_ip', None)
        if ip and not is_internal_or_company_ip(ip):
            unique_ips.add(ip)

    # Print how many IP addresses will be searched
    print(f"Searching {len(unique_ips)} unique IP addresses on VirusTotal")

    # Check each unique IP with VirusTotal
    for ip in unique_ips:
        virustotal_data = check_ip_virustotal(ip)
        country_code = None

        if virustotal_data:
            # Check if the IP is malicious
            if virustotal_data.get('detected_urls') or virustotal_data.get('detected_downloaded_samples'):
                alert_message = f"Alert: Malicious IP {ip} detected!"
                detected_timestamp = datetime.now().strftime("%b %d %H:%M:%S")
                columns = ["Timestamp", "Source IP", "Original Log"]
                # Find a single log with the IP
                alert_logs = [log for log in logs if log.get('source_ip') == ip][:1]
                alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'OSINT', 'columns': columns})
                alert_details.append({
                    'alert_message': alert_message,
                    'detected_timestamp': detected_timestamp,
                    'logs': alert_logs
                })
            # Check if the IP is from outside Australia
            country_code = virustotal_data.get('country', None)  # Check if 'country' field exists

        # Use ipinfo.io if VirusTotal does not return a country code
        if not country_code or country_code == "Unknown":
            print(f"Using ipinfo.io to get country code for IP {ip}")
            country_code = check_ip_ipinfo(ip)

        print(f"Country code for IP {ip}: {country_code}")

        if country_code and country_code != 'Unknown':
            country_name = get_country_name_from_code(country_code)
        else:
            country_name = "Unknown Country"

        if country_code and country_code != AUSTRALIAN_COUNTRY_CODE:
            alert_message = f"Alert: Non-Australian IP {ip} detected! IP is from {country_name}."
            detected_timestamp = datetime.now().strftime("%b %d %H:%M:%S")
            columns = ["Timestamp", "Source IP", "Original Log"]
            # Find a single log with the IP
            alert_logs = [log for log in logs if log.get('source_ip') == ip][:1]
            alerts.append({'alert_message': alert_message, 'detected_timestamp': detected_timestamp, 'log_source': 'OSINT', 'columns': columns})
            alert_details.append({
                'alert_message': alert_message,
                'detected_timestamp': detected_timestamp,
                'logs': alert_logs
            })

    # Sort alerts by detected timestamp
    alerts.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))
    alert_details.sort(key=lambda x: datetime.strptime(x['detected_timestamp'], "%b %d %H:%M:%S"))

    # Return the list of alerts and detailed alert information
    return alerts, alert_details
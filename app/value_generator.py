import random
from datetime import datetime, timedelta

# List of usernames for log generation (including potential admin usernames)
usernames = [
    'alice', 'bob', 'charlie', 'dave', 'eve', 'frank', 'grace', 'heidi', 'ivan',
    'judy', 'kate', 'leo', 'mallory', 'nick', 'olivia', 'peggy', 'quinn', 'roger', 
    'steve', 'trudy', 'admin', 'administrator', 'root', 'superuser', 'sysadmin',
    'backup_admin', 'network_admin', 'security_admin', 'dbadmin', 'webadmin',
    'support', 'helpdesk', 'poweruser', 'admin01', 'admin02', 'guest', 'testuser',
    'maintenance', 'readonly', 'audit', 'backup', 'devops', 'itadmin'
]

# List of hostnames
hostnames = [
    'server01', 'server02', 'backup-server', 'web-server', 'db-server', 
    'auth-server', 'file-server', 'mail-server', 'ftp-server', 'proxy-server'
]

# List of base paths for source file paths
base_paths = [
    '/var/www/html/', '/usr/local/share/', '/etc/nginx/', '/home/user/documents/', 
    '/opt/app/config/', '/srv/ftp/', '/mnt/data/', '/media/usb/', '/backup/', '/mnt/drive/',
    '/home/alice/', '/home/bob/', '/var/log/', '/opt/data/', '/usr/share/', '/etc/nginx/', '/srv/ftp/',
    '/mnt/storage/', '/tmp/', '/var/tmp/'
]

file_paths = [
    '/home/user/', '/var/log/', '/etc/init.d/', '/usr/local/bin/', '/usr/bin/',
    '/opt/scripts/', '/home/guest/', '/mnt/shared/', '/srv/scripts/'
]

# List of destination paths for potential exfiltration or normal activity
destination_paths = [
    '/media/usb/', '/external_drive/', '/mnt/backup/', '/media/cdrom/', '/mnt/network_share/'
]

# List of base paths for sensitive file paths (locations where sensitive data might reside)
sensitive_file_paths = [
    '/etc/passwd', '/etc/shadow', '/var/log/auth.log', '/var/log/secure', '/var/www/html/admin/', 
    '/usr/local/share/confidential/', '/home/admin/docs/financials/', '/home/admin/docs/hr/', 
    '/srv/db/backups/', '/srv/ftp/sensitive/', '/opt/secrets/', '/opt/vault/', 
    '/var/lib/mysql/financial_data/', '/var/backups/important/', '/usr/share/nginx/secrets/', 
    '/mnt/secure_drive/encryption_keys/', '/mnt/backup/confidential/', '/var/lib/postgresql/sensitive/', 
    '/home/admin/secret_projects/', '/usr/local/etc/private/'
]

# List of potential temporary file paths on different systems
temp_file_paths = [
    "/tmp/", "/var/tmp/", "C:\\Windows\\Temp\\", "C:\\Users\\username\\AppData\\Local\\Temp\\",
    "/mnt/data/tmp/", "/run/user/1000/", "/private/var/tmp/", "/usr/local/tmp/", "/home/username/tmp/",
]

# List of common script or file names
file_names = [
    'script.sh', 'deploy.py', 'backup.sh', 'cleanup.py', 'monitor.sh', 'start_service.sh',
    'reboot.py', 'update_script.sh', 'maintenance.sh', 'check_status.py'
]

process_names = [
    'ssh', 'apache2', 'nginx', 'docker', 'mysql', 'systemd', 'cron', 'unknown_tool'
]

kernel_log_message = [
    "started network service", "detected USB device", "started file system check", "completed backup operation",
    "terminated process due to memory overflow", "allocated memory for new process", "discovered new hardware device",
    "updated firewall rules", "started SSH service", "established secure connection", "device driver loaded successfully",
    "network interface eth0 brought up", "network interface eth0 brought down", "system call performed",
    "detected possible disk failure", "syncing system time with NTP server", "successfully mounted file system",
    "unmounted file system", "detected CPU overheating warning", "initiating shutdown sequence",
]

external_ips = [
        "50.3.222.157",
        "198.51.100.2",
        "103.18.103.27",
        "203.0.113.4",
        "45.141.148.16",
        "192.0.2.6",
        "130.211.108.73",
        "198.51.100.8",
        "192.0.2.9",
        "203.0.113.10"
    ]



# Function to generate random usernames
def generate_random_username():
    return random.choice(usernames)

# Function to generate random hostnames
def generate_random_hostname():
    return random.choice(hostnames)

# Function to generate random process
def generate_random_processname():
    return random.choice(process_names)

# Function to generate random kernel log message
def generate_random_kernellogmessage():
    return random.choice(kernel_log_message)

# Function to generate a random file path
def generate_random_filepath():
    return random.choice(file_paths)

# Function to generate a random file path
def generate_random_tmpfilepath():
    return random.choice(temp_file_paths)

# Function to generate a random file name
def generate_random_filename():
    return random.choice(file_names)

# Function to generate a random IP address (internal/external based on probability)
def generate_random_ip(external_chance):
    if random.random() < external_chance:
        # Generate an external IP
        return generate_random_external_ip()
    else:
        # Generate an internal IP (e.g., 192.168.x.x or 10.x.x.x)
        return generate_random_internal_ip()
        
def generate_random_internal_ip():
    # Generate an internal IP (e.g., 192.168.x.x or 10.x.x.x)
        internal_prefixes = ['192.168', '10']
        selected_prefix = random.choice(internal_prefixes)
        if selected_prefix == '192.168':
            return f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        else:
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_random_external_ip():
    return random.choice(external_ips)
        
# Function to generate random network interfaces (e.g., eth0, eth1)
def generate_random_interface():
    return random.choice(['eth0', 'eth1', 'wlan0', 'eth2'])

# Function to generate random file paths
def generate_random_file_path():
    return random.choice(base_paths) + f"file{random.randint(1, 100)}.txt"

# Function to generate a random source path
def generate_random_source_path():
    return f"{random.choice(base_paths)}file{random.randint(1, 100)}.txt"

# Function to generate random file paths (sensitive paths)
def generate_random_sensitive_filepath():
    return random.choice(sensitive_file_paths)

# Function to generate random destination path for exfiltration
def generate_random_exfiltration_path():
    return random.choice(destination_paths) + f"file{random.randint(1, 100)}.txt"

# Function to generate random event outcome (success or fail) with 95% chance for success
def generate_random_event_outcome():
    return random.choices(['success', 'fail'], weights=[95, 5], k=1)[0]

# Helper function to generate a random timestamp during business hours or off hours
def generate_random_timestamp(business_hours_chance=0.95):
    BUSINESS_HOURS_START = 9
    BUSINESS_HOURS_END = 18
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

    if random.random() < business_hours_chance:
        random_hours = random.randint(BUSINESS_HOURS_START, BUSINESS_HOURS_END - 1)
    else:
        random_hours = random.randint(0, 23)

    random_minutes = random.randint(0, 59)
    random_seconds = random.randint(0, 59)
    
    return today + timedelta(hours=random_hours, minutes=random_minutes, seconds=random_seconds)

# Function to generate random file hash (SHA256 format)
def generate_random_filehash():
    return ''.join(random.choices('0123456789abcdef', k=64))

# Function to generate random filename
def generate_random_malicious_filename():
    extensions = ['exe', 'pdf', 'txt', 'doc', 'mp4', 'csv', 'zip']
    return f"malicious_file_{random.randint(1, 1000)}.{random.choice(extensions)}"

# Function to generate random host (example of external malicious hosts)
def generate_random_host():
    hosts = [
        'malicious-server.com', 'badactor.org', 'unknown-entity.net', 'evil-host.xyz',
        'suspicious-site.co', 'threatening-site.ru', 'dangerous-domain.biz'
    ]
    return random.choice(hosts)
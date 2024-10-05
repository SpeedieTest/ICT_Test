import random
from datetime import datetime, timedelta

# List of usernames for log generation
usernames = [
    'alice', 'bob', 'charlie', 'dave', 'eve', 'frank', 'grace', 'heidi', 'ivan',
    'judy', 'kate', 'leo', 'mallory', 'nick', 'olivia', 'peggy', 'quinn', 'roger', 
    'steve', 'trudy'
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
    '/home/alice', '/home/bob', '/var/log', '/opt/data', '/usr/share', '/etc/nginx', '/srv/ftp',
    '/mnt/storage', '/tmp', '/var/tmp'
]

# List of destination paths for potential exfiltration or normal activity
destination_paths = [
    '/media/usb/', '/external_drive/', '/mnt/backup/', '/media/cdrom/', '/mnt/network_share/'
]

# Function to generate random usernames
def generate_random_username():
    return random.choice(usernames)

# Function to generate random hostnames
def generate_random_hostname():
    return random.choice(hostnames)

# Function to generate a random IP address (internal/external based on probability)
def generate_random_ip(external_chance=0.1):
    if random.random() < external_chance:
        # Generate an external IP
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    else:
        # Generate an internal IP (e.g., 192.168.x.x or 10.x.x.x)
        internal_prefixes = ['192.168', '10']
        selected_prefix = random.choice(internal_prefixes)
        if selected_prefix == '192.168':
            return f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        else:
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# Function to generate random file paths
def generate_random_file_path():
    return random.choice(base_paths) + f"file{random.randint(1, 100)}.txt"

# Function to generate a random source path
def generate_random_source_path():
    return f"{random.choice(base_paths)}/file{random.randint(1, 100)}.txt"

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

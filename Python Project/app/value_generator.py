import random
from datetime import datetime, timedelta

# Constants for business hours
BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 18

# List of 20 random usernames
usernames = [
    "alice", "bob", "charlie", "dave", "eve", "frank", "grace", "heidi", 
    "ivan", "judy", "karen", "leo", "mallory", "nancy", "oscar", "peggy", 
    "quentin", "rick", "steve", "trudy"
]

# List of 10 base source paths for files
base_paths = [
    "/home/alice/documents", "/home/bob/work", "/var/log", "/usr/local/share", 
    "/opt/data", "/mnt/storage", "/home/shared", "/srv/ftp", 
    "/home/leo/files", "/var/www/html"
]

# List of 5 common destination paths (for normal business activity)
normal_destination_paths = [
    "/home/alice/backup", "/srv/backup", "/mnt/nas", "/home/shared/reports", "/opt/backups"
]

# List of 2 destination paths for potential exfiltration
exfiltration_destination_paths = [
    "/media/usb", "/mnt/external_drive"
]

# Function to generate random username
def generate_random_username():
    return random.choice(usernames)

# Function to generate random file name
def generate_random_filename():
    return f"file_{random.randint(1, 100)}.txt"

# Function to generate random source path
def generate_random_source_path():
    base_path = random.choice(base_paths)
    return f"{base_path}/{generate_random_filename()}"

# Function to generate random destination path (normal activity)
def generate_random_destination_path():
    return random.choice(normal_destination_paths)

# Function to generate random destination path (exfiltration)
def generate_random_exfiltration_path():
    return random.choice(exfiltration_destination_paths)

# Function to generate random hostnames
def generate_random_hostname():
    hostnames = ["server01", "server02", "db01", "web01", "app01", "file01", "backup01"]
    return random.choice(hostnames)

# Function to generate random IP address (internal or external)
def generate_random_ip(external_chance=0.1):
    if random.random() < external_chance:
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    else:
        return f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"

#function to randomly generate cidr ending
def generate_random_cidr():
    key = random.randint(1,4)
    if key == 1:
        return ""
    if key == 2:
        return "/8"
    if key == 3:
        return "/16"
    if key == 4:
        return "/24"

#function that generates a list of random ip addresses
# external = 1 if external
def generate_random_addresses(no_addresses: int, external: int):
    addresses = []
    for _ in range(no_addresses + 1):
        addresses.append(generate_random_ip(external))

    return addresses

#function to generate random avaliable port number
def generate_random_port():
    # List of common standard ports to exclude
    standard_ports = {80, 443, 8080, 21, 22, 25, 110, 143, 3306, 3389, 53, 23}
    
    while True:
        # Generate a random port between 1024 and 65535 (excluding well-known system ports below 1024)
        port = random.randint(1024, 65535)
        
        # Ensure the port is not in the list of standard ports
        if port not in standard_ports:
            return port


# Function to generate random event outcome (success or fail)
def generate_random_event_outcome():
    return random.choice(["success", "fail"])

# Function to generate a random timestamp
def generate_random_timestamp(business_hours_chance=0.95):
    if random.random() < business_hours_chance:
        return generate_random_business_hours_time()
    else:
        return generate_random_off_hours_time()

# Helper function to generate random time during business hours
def generate_random_business_hours_time():
    today = datetime.now().replace(hour=BUSINESS_HOURS_START, minute=0, second=0, microsecond=0)
    random_hours = random.randint(0, BUSINESS_HOURS_END - BUSINESS_HOURS_START)
    random_minutes = random.randint(0, 59)
    random_seconds = random.randint(0, 59)
    return today + timedelta(hours=random_hours, minutes=random_minutes, seconds=random_seconds)

# Helper function to generate random time outside business hours
def generate_random_off_hours_time():
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    if random.random() < 0.5:
        random_hours = random.randint(0, BUSINESS_HOURS_START - 1)
    else:
        random_hours = random.randint(BUSINESS_HOURS_END, 23)
    random_minutes = random.randint(0, 59)
    random_seconds = random.randint(0, 59)
    return today + timedelta(hours=random_hours, minutes=random_minutes, seconds=random_seconds)

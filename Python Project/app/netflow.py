import os
import random

















def save_logs(logs):
    # logs is an array of log objects
    os.makedirs('logs', exist_ok=True)
    log_number = 1
    # Check for existing files and increment log number
    while os.path.exists(f"logs/netflowlogs_{log_number}.txt"):
        log_number += 1
    log_filename = f"logs/netflowlogs_{log_number}.txt"

    # Inspect logs before saving
    print("Logs to be saved:", logs)  # Debug: Print logs to verify structure

    # Write all logs into a single file
    with open(log_filename, 'w') as file:
        for log in logs:
            if isinstance(log, tuple):
                # If it's a tuple (timestamp, log), write the log part
                file.write(log[1] + '\n')
            else:
                # If it's already a string, just write it directly
                file.write(str(log) + '\n')
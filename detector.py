"""
Brute Force Attack Detector

Problem:
    Detect brute-force login attempts by analyzing log files for repeated failed logins from the same IP address.

Tools:
    - Python 3
    - Regular expressions (re)
    - Collections (Counter, defaultdict)
    - datetime for time calculations

Steps:
    1. Read a log file containing authentication attempts.
    2. Parse each line to find failed login attempts and extract the timestamp and IP address.
    3. Count failed attempts from each IP within a rolling time window.
    4. If any IP exceeds the threshold, flag it as suspicious and print a warning.

Results:
    The script prints suspicious IPs with the number of failed attempts and the time window,
    helping you spot possible brute force attacks.

This script is beginner-friendly and well documented.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta

# --- CONFIGURATION ---
LOG_FILE = "example_auth.log"  # Change this to your log file
FAILED_PATTERN = r"(?P<datetime>\w{3} \d{2} \d{2}:\d{2}:\d{2}) .* Failed password .* from (?P<ip>\d+\.\d+\.\d+\.\d+)"
DATETIME_FORMAT = "%b %d %H:%M:%S"
THRESHOLD_ATTEMPTS = 5        # Attempts to trigger alert
TIME_WINDOW_MINUTES = 60      # Time window to count attempts

def parse_log_line(line):
    """
    Parses a log line for failed login attempts.
    Returns (timestamp, ip) if match found, else None.
    """
    match = re.search(FAILED_PATTERN, line)
    if match:
        # Parse datetime (assumes current year)
        now = datetime.now()
        date_str = match.group("datetime")
        # Add the current year to the date string
        date_obj = datetime.strptime(f"{now.year} {date_str}", f"%Y {DATETIME_FORMAT}")
        ip = match.group("ip")
        return date_obj, ip
    return None

def detect_brute_force(log_file):
    """
    Detects brute force attempts in the provided log file.
    """
    attempts = defaultdict(list)  # ip -> list of attempt datetimes

    # Read log file and collect failed attempts
    with open(log_file, "r") as f:
        for line in f:
            result = parse_log_line(line)
            if result:
                date_obj, ip = result
                attempts[ip].append(date_obj)

    print("Analyzing failed login attempts...")
    suspicious_ips = []

    # Check attempts per IP
    for ip, times in attempts.items():
        # Sort times for rolling window
        times.sort()
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(minutes=TIME_WINDOW_MINUTES)
            count = 1
            # Count how many attempts in the window
            for j in range(i + 1, len(times)):
                if times[j] <= window_end:
                    count += 1
                else:
                    break
            if count >= THRESHOLD_ATTEMPTS:
                suspicious_ips.append((ip, count, window_start, window_end))
                break  # Only report once per IP

    # Print results
    if suspicious_ips:
        print("\nPossible brute force attacks detected!")
        for ip, count, start, end in suspicious_ips:
            print(f"IP {ip} had {count} failed attempts between {start} and {end}")
    else:
        print("No brute force attacks detected.")

if __name__ == "__main__":
    detect_brute_force(LOG_FILE)
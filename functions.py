import os
import json
import re
import logging
from datetime import datetime

def save_to_json(filename, data):
    """Save data to a JSON file."""
    try:
        with open(filename, "w") as json_file:
            json.dump(data, json_file, indent=4)
            json_file.write("\n")
    except Exception as e:
        logging.error(f"Error saving data to {filename}: {e}")

def ensure_log_files():
    """Ensure necessary log files exist; create them if not."""
    log_files = {
        "login_history.json": {"timestamp": "", "type": "last_login_history", "entries": []},
        "running_processes.json": {"timestamp": "", "type": "running_processes", "entries": []},
        "system_log.json": {"timestamp": "", "type": "system_log", "entries": []},
        "firewall_logs.json": {"timestamp": "", "type": "firewall_logs", "entries": []},
    }
    for filename, empty_structure in log_files.items():
        if not os.path.exists(filename):
            logging.info(f"Creating missing log file: {filename}")
            save_to_json(filename, empty_structure)

def parse_login_output(output: str) -> dict:
    """Parse output from the 'last' command."""
    logins = output.strip().splitlines()
    parsed_logins = []
    for entry in logins:
        parts = entry.split()
        if len(parts) >= 5:
            parsed_logins.append({
                "user": parts[0],
                "terminal": parts[1],
                "host": parts[2],
                "date_time": " ".join(parts[3:5]),
                "details": " ".join(parts[5:])
            })
    # Limit to last 50 entries
    max_entries = 50
    if len(parsed_logins) > max_entries:
        parsed_logins = parsed_logins[-max_entries:]
    return {
        "timestamp": datetime.now().isoformat(),
        "type": "last_login_history",
        "entries": parsed_logins
    }

def parse_running_processes(output: str) -> dict:
    """Parse output from the 'ps aux' command."""
    processes = output.strip().splitlines()
    if not processes:
        return {"timestamp": datetime.now().isoformat(), "type": "running_processes", "entries": []}
    headers = processes[0].split()
    parsed_processes = []
    for line in processes[1:]:
        parts = line.split(maxsplit=len(headers)-1)
        if len(parts) == len(headers):
            parsed_processes.append(dict(zip(headers, parts)))
    # Limit to last 100 entries
    max_entries = 100
    if len(parsed_processes) > max_entries:
        parsed_processes = parsed_processes[-max_entries:]
    return {
        "timestamp": datetime.now().isoformat(),
        "type": "running_processes",
        "entries": parsed_processes
    }

def parse_system_log(output: str) -> dict:
    """Parse system log file using regex for robust extraction."""
    # Example regex: adjust according to your system log format.
    # This pattern expects logs like: "Feb 21 12:34:56 hostname message..."
    log_pattern = re.compile(r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<message>.+)$')
    lines = output.splitlines()[-20:]
    parsed_logs = []
    for line in lines:
        match = log_pattern.match(line)
        if match:
            parsed_logs.append(match.groupdict())
        else:
            parsed_logs.append({"timestamp": "Unknown", "host": "Unknown", "message": line})
    return {
        "timestamp": datetime.now().isoformat(),
        "type": "system_log",
        "entries": parsed_logs
    }

def parse_firewall_logs(output: str) -> dict:
    """Parse firewall log output."""
    logs = output.strip().splitlines()
    parsed_logs = []
    max_entries = 20
    for line in logs[-max_entries:]:
        parts = line.split(None, 1)
        if len(parts) == 2:
            timestamp, message = parts
        else:
            timestamp, message = "Unknown", line
        parsed_logs.append({"timestamp": timestamp, "message": message})
    return {
        "timestamp": datetime.now().isoformat(),
        "type": "firewall_logs",
        "entries": parsed_logs
    }
def parse_defined_users(output: str) -> dict:
    """
    Parse dscl output, which lists user accounts line by line.
    Return a dict: { "entries": ["user1", "user2", ...] }
    """
    lines = output.strip().splitlines()
    return {
        "timestamp": "dscl-users",
        "type": "defined_users",
        "entries": lines
    }



# Ensure necessary log files exist when the module is imported.
ensure_log_files()

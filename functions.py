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
    """
    Parse the output of the 'last' command into a JSON-friendly dictionary.
    Limits to the last 50 entries.
    """
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
    max_entries = 50
    if len(parsed_logins) > max_entries:
        parsed_logins = parsed_logins[-max_entries:]
    return {
        "timestamp": datetime.now().isoformat(),
        "type": "last_login_history",
        "entries": parsed_logins
    }

def parse_running_processes(output: str) -> dict:
    """
    Parse the output of 'ps aux' command into a dictionary.
    Also clamps any CPU usage values above 100 to 100.
    """
    processes = output.strip().splitlines()
    if not processes:
        return {"timestamp": datetime.now().isoformat(), "type": "running_processes", "entries": []}
    headers = processes[0].split()
    parsed_processes = []
    for line in processes[1:]:
        parts = line.split(maxsplit=len(headers)-1)
        if len(parts) == len(headers):
            # Clamp %CPU to 100 if necessary
            try:
                cpu_val = float(parts[headers.index("%CPU")])
                if cpu_val > 100:
                    parts[headers.index("%CPU")] = "100.0"
            except Exception:
                pass
            parsed_processes.append(dict(zip(headers, parts)))
    return {
        "timestamp": datetime.now().isoformat(),
        "type": "running_processes",
        "entries": parsed_processes
    }

def parse_system_log(output: str) -> dict:
    """
    Parse system log file output using regex.
    Expects lines like: "Feb 21 12:34:56 hostname message..."
    """
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
    """
    Parse firewall log output into a dictionary.
    Limits to the last 20 lines.
    """
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

def parse_network_connections(output: str) -> dict:
    """
    Parse the output of 'netstat -an' to extract external connections.
    Returns a list of dictionaries with keys like: Protocol, Local Address, Foreign Address, State.
    Only includes lines with 'LISTEN' or 'ESTABLISHED'.
    """
    lines = output.strip().splitlines()
    entries = []
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        protocol = parts[0]
        local_address = parts[3]
        foreign_address = parts[4]
        state = parts[5]
        if state in ["LISTEN", "ESTABLISHED"]:
            entries.append({
                "Protocol": protocol,
                "Local Address": local_address,
                "Foreign Address": foreign_address,
                "State": state
            })
    return {"timestamp": datetime.now().isoformat(), "type": "network_connections", "entries": entries}

def parse_network_logs(output: str) -> dict:
    """
    Return the raw netstat -an output as a list of log lines.
    Each line is stored in a dictionary with key 'Line'.
    """
    lines = output.strip().splitlines()
    entries = [{"Line": line} for line in lines]
    return {"timestamp": datetime.now().isoformat(), "type": "network_logs", "entries": entries}
# Ensure log files exist when this module is imported
ensure_log_files()

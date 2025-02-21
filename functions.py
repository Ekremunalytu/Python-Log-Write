import subprocess
import json
import os
from datetime import datetime

def save_to_json(filename, data):
    """ Save data to JSON file safely. """
    try:
        with open(filename, "w") as json_file:
            json.dump(data, json_file, indent=4)
            json_file.write("\n")
    except Exception as e:
        print(f"Error saving data to {filename}: {e}")

def ensure_log_files():
    """ Check and create empty log files if they don’t exist. """
    log_files = {
        "login_history.json": {"timestamp": "", "type": "last_login_history", "entries": []},
        "running_processes.json": {"timestamp": "", "type": "running_processes", "entries": []},
        "system_log.json": {"timestamp": "", "type": "system_log", "entries": []},
        "firewall_rules.json": {"timestamp": "", "type": "firewall_rules", "entries": []},
    }

    for filename, empty_structure in log_files.items():
        if not os.path.exists(filename):
            print(f"Creating missing log file: {filename}")
            save_to_json(filename, empty_structure)

def logininfo():
    """ Fetch last login history. """
    try:
        result = subprocess.run(["last"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            return
        
        logins = result.stdout.strip().splitlines()
        parsed_logins = [{"user": parts[0], "terminal": parts[1], "host": parts[2], "date_time": " ".join(parts[3:5]), "details": " ".join(parts[5:])} for parts in (entry.split() for entry in logins) if len(parts) >= 5]

        log_data = {"timestamp": datetime.now().isoformat(), "type": "last_login_history", "entries": parsed_logins}
        save_to_json("login_history.json", log_data)
    except Exception as e:
        print(f"Error: {e}")

def get_running_processes():
    """ Fetch running processes. """
    try:
        result = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            return

        processes = result.stdout.strip().splitlines()
        headers = processes[0].split()
        parsed_processes = [dict(zip(headers, process.split(maxsplit=len(headers) - 1))) for process in processes[1:] if len(process.split(maxsplit=len(headers) - 1)) == len(headers)]

        log_data = {"timestamp": datetime.now().isoformat(), "type": "running_processes", "entries": parsed_processes}
        save_to_json("running_processes.json", log_data)
    except Exception as e:
        print(f"Error: {e}")

def read_system_log():
    """ Read system log file. """
    log_file_path = "/var/log/system.log"
    try:
        with open(log_file_path, "r") as file:
            logs = file.readlines()
            parsed_logs = [{"timestamp": line.split(None, 1)[0], "message": " ".join(line.split(None, 1)[1:])} for line in logs[-10:]]

        log_data = {"timestamp": datetime.now().isoformat(), "type": "system_log", "entries": parsed_logs}
        save_to_json("system_log.json", log_data)
    except Exception as e:
        print(f"Error: {e}")

def get_firewall_rules(password):
    """ Fetch firewall logs from macOS using sudo password. """
    log_file_path = "/var/log/pf.log"
    try:
        # Sudo ile firewall loglarını oku
        result = subprocess.run(["sudo", "-S", "cat", log_file_path], 
                                input=password + "\n", 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                text=True)
        
        # Eğer komut başarısız olursa hata mesajını göster
        if result.returncode != 0:
            print(f"Error reading firewall logs: {result.stderr}")
            save_to_json("firewall_logs.json", {"timestamp": datetime.now().isoformat(), "type": "firewall_logs", "entries": []})
            return

        logs = result.stdout.strip().splitlines()
        parsed_logs = []
        for line in logs[-20:]:
            parts = line.split(None, 1)
            if len(parts) == 2:
                timestamp, message = parts
            else:
                timestamp, message = "Unknown", line
            parsed_logs.append({"timestamp": timestamp, "message": message})

        log_data = {"timestamp": datetime.now().isoformat(), "type": "firewall_logs", "entries": parsed_logs}
        save_to_json("firewall_logs.json", log_data)

    except FileNotFoundError:
        print(f"Error: {log_file_path} not found. Make sure firewall logging is enabled.")
        save_to_json("firewall_logs.json", {"timestamp": datetime.now().isoformat(), "type": "firewall_logs", "entries": []})

    except PermissionError:
        print(f"Error: Permission denied. Run the app with administrator privileges.")

    except Exception as e:
        print(f"Error: {e}")

# Ensure log files exist when the script is imported
ensure_log_files()

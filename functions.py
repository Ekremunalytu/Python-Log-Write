import subprocess
import json
from datetime import datetime

def save_to_json(filename, data):
    try:
        with open(filename, "w") as json_file:
            json.dump(data, json_file, indent=4)
            json_file.write("\n")
    except Exception as e:
        print(f"Error saving data to {filename}: {e}")

def logininfo():
    try:
        print("Fetching last login history...\n")
        result = subprocess.run(["last"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            print(f"Error executing 'last' command: {result.stderr}")
            return
        
        logins = result.stdout.strip().splitlines()
        parsed_logins = []

        for entry in logins:
            parts = entry.split()
            if len(parts) < 5:
                continue
            parsed_logins.append({
                "user": parts[0],
                "terminal": parts[1],
                "host": parts[2],
                "date_time": " ".join(parts[3:5]),
                "details": " ".join(parts[5:])
            })

        log_data = {
            "timestamp": datetime.now().isoformat(),
            "type": "last_login_history",
            "entries": parsed_logins
        }

        save_to_json("login_history.json", log_data)
        print("Login history saved to login_history.json")
    except Exception as e:
        print(f"Error occurred while fetching login info: {e}")

def get_running_processes():
    try:
        print("Fetching currently running processes...\n")
        result = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            print(f"Error executing 'ps aux' command: {result.stderr}")
            return

        processes = result.stdout.strip().splitlines()
        headers = processes[0].split()
        process_list = processes[1:]

        parsed_processes = []
        for process in process_list:
            parts = process.split(maxsplit=len(headers) - 1)
            if len(parts) != len(headers):
                continue
            process_data = dict(zip(headers, parts))
            parsed_processes.append(process_data)

        log_data = {
            "timestamp": datetime.now().isoformat(),
            "type": "running_processes",
            "total_processes": len(process_list),
            "entries": parsed_processes
        }

        save_to_json("running_processes.json", log_data)
        print("Running processes saved to running_processes.json")
    except Exception as e:
        print(f"Error occurred while fetching running processes: {e}")

def read_system_log():
    log_file_path = "/var/log/system.log"
    try:
        print(f"Reading system log from {log_file_path}...\n")
        
        with open(log_file_path, "r") as file:
            logs = file.readlines()
            
            if not logs:
                print("No logs found.")
                return
            
            parsed_logs = []
            for line in logs[-10:]:
                timestamp, *message = line.strip().split(None, 1)
                parsed_logs.append({
                    "timestamp": timestamp,
                    "message": " ".join(message) if message else ""
                })

            log_data = {
                "timestamp": datetime.now().isoformat(),
                "type": "system_log",
                "entries": parsed_logs
            }

            save_to_json("system_log.json", log_data)
            print("System log saved to system_log.json")
    except FileNotFoundError:
        print(f"Error: {log_file_path} not found.")
    except PermissionError:
        print(f"Error: Permission denied to read {log_file_path}. Please run with sufficient privileges.")
    except Exception as e:
        print(f"Error occurred while reading system log: {e}")

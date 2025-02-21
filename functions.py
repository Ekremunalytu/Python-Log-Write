import os
import json
from datetime import datetime

def save_to_json(filename, data):
    """Veriyi JSON dosyasına kaydeder."""
    try:
        with open(filename, "w") as json_file:
            json.dump(data, json_file, indent=4)
            json_file.write("\n")
    except Exception as e:
        print(f"Error saving data to {filename}: {e}")

def ensure_log_files():
    """Gerekli log dosyalarının var olup olmadığını kontrol eder, yoksa oluşturur."""
    log_files = {
        "login_history.json": {"timestamp": "", "type": "last_login_history", "entries": []},
        "running_processes.json": {"timestamp": "", "type": "running_processes", "entries": []},
        "system_log.json": {"timestamp": "", "type": "system_log", "entries": []},
        "firewall_logs.json": {"timestamp": "", "type": "firewall_logs", "entries": []},
    }
    for filename, empty_structure in log_files.items():
        if not os.path.exists(filename):
            print(f"Creating missing log file: {filename}")
            save_to_json(filename, empty_structure)

def parse_login_output(output: str) -> dict:
    """'last' komutunun çıktısını bir sözlüğe çevirir."""
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
    # Log Boyut Yönetimi: Sadece son 50 giriş
    max_entries = 50
    if len(parsed_logins) > max_entries:
        parsed_logins = parsed_logins[-max_entries:]
    return {
        "timestamp": datetime.now().isoformat(),
        "type": "last_login_history",
        "entries": parsed_logins
    }

def parse_running_processes(output: str) -> dict:
    """'ps aux' çıktısını bir sözlüğe çevirir."""
    processes = output.strip().splitlines()
    if not processes:
        return {"timestamp": datetime.now().isoformat(), "type": "running_processes", "entries": []}
    headers = processes[0].split()
    parsed_processes = []
    for line in processes[1:]:
        parts = line.split(maxsplit=len(headers)-1)
        if len(parts) == len(headers):
            parsed_processes.append(dict(zip(headers, parts)))
    # Son 100 girişle sınırla
    max_entries = 100
    if len(parsed_processes) > max_entries:
        parsed_processes = parsed_processes[-max_entries:]
    return {
        "timestamp": datetime.now().isoformat(),
        "type": "running_processes",
        "entries": parsed_processes
    }

def parse_system_log(output: str) -> dict:
    """Sistem loglarını (örneğin, /var/log/system.log) bir sözlüğe çevirir."""
    lines = output.splitlines()
    # Son 20 satırı kullan
    last_lines = lines[-20:] if len(lines) >= 20 else lines
    parsed_logs = []
    for line in last_lines:
        parts = line.split(None, 1)
        if len(parts) == 2:
            timestamp, message = parts
        else:
            timestamp, message = "Unknown", line
        parsed_logs.append({"timestamp": timestamp, "message": message})
    return {
        "timestamp": datetime.now().isoformat(),
        "type": "system_log",
        "entries": parsed_logs
    }

def parse_firewall_logs(output: str) -> dict:
    """Firewall log çıktısını bir sözlüğe çevirir."""
    logs = output.strip().splitlines()
    parsed_logs = []
    # Son 20 girişle sınırla
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

# Bu modül import edildiğinde gerekli log dosyalarının varlığını kontrol et.
ensure_log_files()

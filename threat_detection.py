def detect_suspicious_activity(log_data: dict) -> list:
    """
    Scan log data for suspicious entries.
    For example, mark entries as suspicious if the user is 'root' without a proper terminal.
    """
    suspicious_entries = []
    for entry in log_data.get("entries", []):
        # Example rule: if user is 'root' and the terminal field does not contain 'tty'
        if entry.get("user") == "root" and "tty" not in entry.get("terminal", ""):
            suspicious_entries.append(entry)
    return suspicious_entries

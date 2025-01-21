import subprocess
import datetime
import time

def logininfo():
    try:
        # "last" komutunu çalıştır
        print("Fetching last login history...\n")
        time.sleep(2)
        result = subprocess.run(["last"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            print(f"Error executing 'last' command: {result.stderr}")
            return
        
        # Çıktıyı ekrana bastır (daha temiz bir formatla)
        print("Last login history:")
        print(result.stdout)
        
        # Sonuçları zaman damgasıyla kaydetmek
        with open("login_history.txt", "a") as log_file:
            log_file.write(f"\n[{datetime.datetime.now()}] Last Login History:\n")
            log_file.write(result.stdout)
            log_file.write("\n")

    except Exception as e:
        print(f"Error occurred while fetching login info: {e}")

def get_running_processes():
    try:
        # 'ps aux' komutunu çalıştır
        print("Fetching currently running processes...\n")
        time.sleep(2)
        result = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            print(f"Error executing 'ps aux' command: {result.stderr}")
            return
        
        # Çıktıyı ekrana bastır
        processes = result.stdout.splitlines()
        print(f"Total running processes: {len(processes) - 1}\n")  # Başlık satırını sayma
        
        # İşlem listesini daha düzenli bir şekilde yazdır
        for process in processes[:10]:  # İlk 10 satır örnek olarak yazdırılacak
            print(process)

        # Tüm çıktıyı kaydetme
        with open("running_processes.txt", "a") as log_file:
            log_file.write(f"\n[{datetime.datetime.now()}] Running Processes:\n")
            log_file.write(result.stdout)
            log_file.write("\n")

    except Exception as e:
        print(f"Error occurred while fetching running processes: {e}")


def read_system_log():
    try:
        time.sleep(2)
        log_file_path = "/var/log/system.log"
        print(f"Reading system log from {log_file_path}...\n")
        
        with open(log_file_path, "r") as file:
            logs = file.readlines()
            
            if not logs:
                print("No logs found.")
                return
            
            # Son 10 satırı yazdırmak
            print("Last 10 system log entries:")
            for line in logs[-10:]:
                print(line.strip())

            # Logları kaydetme
            with open("system_log_output.txt", "a") as log_output_file:
                log_output_file.write(f"\n[{datetime.datetime.now()}] System Log:\n")
                log_output_file.writelines(logs)
                log_output_file.write("\n")

    except FileNotFoundError:
        print(f"Error: {log_file_path} not found.")
    except PermissionError:
        print(f"Error: Permission denied to read {log_file_path}. Please run with sufficient privileges.")
    except Exception as e:
        print(f"Error occurred while reading system log: {e}")

def get_firewall_rules():
    try:
        # "pfctl -sr" komutunu çalıştırarak firewall kurallarını al
        print("Fetching firewall rules...\n")
        result = subprocess.run(["sudo", "pfctl", "-sr"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            print(f"Error executing 'pfctl' command: {result.stderr}")
            return
        
        # Çıktıyı ekrana bastır
        print("Firewall Rules:")
        print(result.stdout)
        
        # Kuralları bir dosyaya kaydet
        with open("firewall_rules.txt", "a") as log_file:
            log_file.write(result.stdout)
            log_file.write("\n")

    except Exception as e:
        print(f"Error occurred while fetching firewall rules: {e}")
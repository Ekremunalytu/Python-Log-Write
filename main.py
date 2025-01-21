import tkinter as tk
from tkinter import scrolledtext, messagebox
import functions

# Fonksiyonları GUI üzerinden çağırmak için yardımcı işlevler
def show_last_log():
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Fetching last log history...\n")
    try:
        functions.logininfo()
        with open("login_history.txt", "r") as file:
            output_text.insert(tk.END, file.read())
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

def show_running_processes():
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Fetching running processes...\n")
    try:
        functions.get_running_processes()
        with open("running_processes.txt", "r") as file:
            output_text.insert(tk.END, file.read())
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

def show_system_logs():
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Reading system logs...\n")
    try:
        functions.read_system_log()
        with open("system_log_output.txt", "r") as file:
            output_text.insert(tk.END, file.read())
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

def show_firewall_rules():
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Fetching firewall rules...\n")
    try:
        functions.get_firewall_rules()
        with open("firewall_rules.txt", "r") as file:
            output_text.insert(tk.END, file.read())
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

def exit_program():
    if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
        root.destroy()

# Ana pencereyi oluştur
root = tk.Tk()
root.title("macOS Log Management App")
root.geometry("800x600")
root.state("zoomed")

# Başlık etiketi
title_label = tk.Label(root, text="macOS Log Management App", font=("Helvetica", 20), bg="blue", fg="white")
title_label.pack(fill=tk.X)

# Butonlar için bir çerçeve oluştur
button_frame = tk.Frame(root)
button_frame.pack(fill=tk.X, pady=10)

# İşlev düğmeleri
tk.Button(button_frame, text="View Last Log History", command=show_last_log, width=25).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="View Running Processes", command=show_running_processes, width=25).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="View System Logs", command=show_system_logs, width=25).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="View Firewall Rules", command=show_firewall_rules, width=25).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Exit", command=exit_program, width=10, bg="red", fg="white").pack(side=tk.RIGHT, padx=5)

# Çıktılar için kaydırılabilir metin alanı
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier", 12))
output_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

# Uygulamayı çalıştır
root.mainloop()

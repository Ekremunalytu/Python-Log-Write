import tkinter as tk
from tkinter import scrolledtext, messagebox
import functions

# Fonksiyonları GUI üzerinden çağırmak için yardımcı işlevler
def show_last_log():
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Fetching last log history...\n")
    try:
        functions.logininfo()
        with open("login_history.json", "r") as file:
            output_text.insert(tk.END, file.read())
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

def show_running_processes():
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Fetching running processes...\n")
    try:
        functions.get_running_processes()
        with open("running_processes.json", "r") as file:
            output_text.insert(tk.END, file.read())
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

def show_system_logs():
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Reading system logs...\n")
    try:
        functions.read_system_log()
        with open("system_log.json", "r") as file:
            output_text.insert(tk.END, file.read())
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

def show_firewall_rules():
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Fetching firewall rules...\n")
    try:
        functions.get_firewall_rules()
        with open("firewall_rules.json", "r") as file:
            output_text.insert(tk.END, file.read())
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

def exit_program():
    if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
        root.destroy()

# Ana pencereyi oluştur
root = tk.Tk()
root.title("macOS Log Management App")
root.geometry("1024x768")  # Tam ekran için başlangıç boyutunu genişlet
root.state("zoomed")
root.configure(bg="#000000")  # Arka plan rengini siyah yap

# Başlık etiketi
title_label = tk.Label(root, text="macOS Log Management App", font=("Helvetica", 24, "bold"), bg="#1E1E1E", fg="white", pady=10)
title_label.pack(fill=tk.X)

# Butonlar için bir çerçeve oluştur
button_frame = tk.Frame(root, bg="#000000")
button_frame.pack(fill=tk.X, pady=10)

# İşlev düğmeleri
def create_button(parent, text, command):
    return tk.Button(
        parent, 
        text=text, 
        command=command, 
        width=30, 
        bg="white", 
        fg="black", 
        activebackground="black", 
        activeforeground="white", 
        font=("Helvetica", 14, "bold"), 
        relief="raised"
    )

create_button(button_frame, "View Last Log History", show_last_log).pack(side=tk.LEFT, padx=10)
create_button(button_frame, "View Running Processes", show_running_processes).pack(side=tk.LEFT, padx=10)
create_button(button_frame, "View System Logs", show_system_logs).pack(side=tk.LEFT, padx=10)
create_button(button_frame, "View Firewall Rules", show_firewall_rules).pack(side=tk.LEFT, padx=10)
tk.Button(
    button_frame, 
    text="Exit", 
    command=exit_program, 
    width=15, 
    bg="white", 
    fg="black", 
    activebackground="black", 
    activeforeground="white", 
    font=("Helvetica", 14, "bold"), 
    relief="raised"
).pack(side=tk.RIGHT, padx=10)

# Çıktılar için kaydırılabilir metin alanı
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier", 14), bg="#1E1E1E", fg="white", insertbackground="white")
output_text.pack(expand=True, fill=tk.BOTH, padx=15, pady=15)

# Uygulamayı çalıştır
root.mainloop()

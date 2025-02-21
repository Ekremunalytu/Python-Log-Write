from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit,
    QLineEdit, QLabel, QHBoxLayout, QComboBox, QInputDialog
)
import json
import functions
from worker import CommandWorker

class LogViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.original_data = None  # Filtrelenmemiş veriyi saklar
        self.workers = []  # Aktif worker nesnelerini saklamak için liste

    def initUI(self):
        self.setWindowTitle("macOS Log Management App")
        self.setGeometry(100, 100, 1024, 768)
        layout = QVBoxLayout()

        # Buton Yerleşimi
        btn_layout = QHBoxLayout()
        self.log_button = QPushButton("View Last Log History")
        self.log_button.clicked.connect(self.fetch_login_info_async)
        self.process_button = QPushButton("View Running Processes")
        self.process_button.clicked.connect(self.fetch_running_processes_async)
        self.system_log_button = QPushButton("View System Logs")
        self.system_log_button.clicked.connect(self.fetch_system_log_async)
        self.firewall_button = QPushButton("View Firewall Rules")
        self.firewall_button.clicked.connect(self.fetch_firewall_logs_async)
        btn_layout.addWidget(self.log_button)
        btn_layout.addWidget(self.process_button)
        btn_layout.addWidget(self.system_log_button)
        btn_layout.addWidget(self.firewall_button)
        layout.addLayout(btn_layout)

        # Çıktı Gösterimi
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)

        # Filtre Bölümü
        filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter filter keyword...")
        self.filter_field = QComboBox()
        self.filter_field.addItem("All Fields")
        self.filter_button = QPushButton("Apply Filter")
        self.filter_button.clicked.connect(self.apply_filter)
        self.clear_filter_button = QPushButton("Clear Filter")
        self.clear_filter_button.clicked.connect(self.clear_filter)
        self.search_label = QLabel("Searching for: ")

        filter_layout.addWidget(QLabel("Filter by:"))
        filter_layout.addWidget(self.filter_field)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.filter_button)
        filter_layout.addWidget(self.clear_filter_button)
        filter_layout.addWidget(self.search_label)
        layout.addLayout(filter_layout)

        self.setLayout(layout)

    # --- Asenkron İşlemler (Worker Referanslarını Yönetiyoruz) ---

    def fetch_login_info_async(self):
        worker = CommandWorker(["last"], functions.parse_login_output)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_login_info(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_login_info(self, log_data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        functions.save_to_json("login_history.json", log_data)
        self.original_data = log_data
        formatted_data = json.dumps(log_data, indent=4)
        self.output_text.setPlainText(formatted_data)
        self.populate_filter_options(log_data)
        self.search_label.setText("Searching for: ")

    def fetch_running_processes_async(self):
        worker = CommandWorker(["ps", "aux"], functions.parse_running_processes)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_running_processes(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_running_processes(self, log_data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        functions.save_to_json("running_processes.json", log_data)
        self.original_data = log_data
        formatted_data = json.dumps(log_data, indent=4)
        self.output_text.setPlainText(formatted_data)
        self.populate_filter_options(log_data)
        self.search_label.setText("Searching for: ")

    def fetch_system_log_async(self):
        worker = CommandWorker(["cat", "/var/log/system.log"], functions.parse_system_log)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_system_log(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_system_log(self, log_data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        functions.save_to_json("system_log.json", log_data)
        self.original_data = log_data
        formatted_data = json.dumps(log_data, indent=4)
        self.output_text.setPlainText(formatted_data)
        self.populate_filter_options(log_data)
        self.search_label.setText("Searching for: ")

    def fetch_firewall_logs_async(self):
        password, ok = QInputDialog.getText(self, "Password", "Enter your sudo password:", QLineEdit.EchoMode.Password)
        if ok and password:
            worker = CommandWorker(
                ["sudo", "-S", "cat", "/var/log/pf.log"],
                functions.parse_firewall_logs,
                input_data=password + "\n"
            )
            self.workers.append(worker)
            worker.finished.connect(lambda data, w=worker: self.handle_firewall_logs(data, w))
            worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
            worker.start()

    def handle_firewall_logs(self, log_data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        functions.save_to_json("firewall_logs.json", log_data)
        self.original_data = log_data
        formatted_data = json.dumps(log_data, indent=4)
        self.output_text.setPlainText(formatted_data)
        self.populate_filter_options(log_data)
        self.search_label.setText("Searching for: ")

    def handle_worker_error(self, error_message: str, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        print(f"Worker error: {error_message}")

    # --- Filtreleme İşlemleri ---

    def populate_filter_options(self, log_data: dict):
        self.filter_field.clear()
        self.filter_field.addItem("All Fields")
        if "entries" in log_data and log_data["entries"]:
            for key in log_data["entries"][0].keys():
                self.filter_field.addItem(key)

    def apply_filter(self):
        if not self.original_data or "entries" not in self.original_data:
            return
        keyword = self.filter_input.text().strip().lower()
        selected_field = self.filter_field.currentText()
        if not keyword:
            return
        self.search_label.setText(f"Searching for: {keyword} in {selected_field}")
        try:
            filtered_data = {"entries": []}
            if selected_field == "All Fields":
                filtered_data["entries"] = [
                    entry for entry in self.original_data["entries"]
                    if keyword in json.dumps(entry).lower()
                ]
            else:
                filtered_data["entries"] = [
                    entry for entry in self.original_data["entries"]
                    if selected_field in entry and keyword in str(entry[selected_field]).lower()
                ]
            self.output_text.setPlainText(json.dumps(filtered_data, indent=4))
        except Exception as e:
            self.output_text.setPlainText(f"Error filtering data: {e}")

    def clear_filter(self):
        if self.original_data:
            self.output_text.setPlainText(json.dumps(self.original_data, indent=4))
            self.search_label.setText("Searching for: ")
            self.filter_input.clear()

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    viewer = LogViewer()
    viewer.show()
    sys.exit(app.exec())

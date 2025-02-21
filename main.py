import sys
import json
import logging
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QLineEdit, QLabel, QComboBox, QInputDialog,
    QToolButton, QMenu, QPushButton, QFrame, QStyle, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QPalette, QColor

import functions
from worker import CommandWorker
from threat_detection import detect_suspicious_activity
from hardware_monitor import HardwareUsageWidget


class NumericTableWidgetItem(QTableWidgetItem):
    """Allows numeric sorting for columns like %CPU or %MEM."""
    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except ValueError:
            return super().__lt__(other)


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("app_debug.log"),
        logging.StreamHandler()
    ]
)
logging.info("Application started")


class LogViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.workers = []
        self.original_data = None
        self.real_time_process = False

        # Timer for real-time process monitoring
        self.process_timer = QTimer(self)
        self.process_timer.timeout.connect(self.fetch_running_processes_async)

        # More detailed hardware widget (collapsible)
        self.hardware_widget = HardwareUsageWidget(self)

        self.initUI()

    def initUI(self):
        self.setWindowTitle("macOS EDR - Enhanced UI")
        self.setGeometry(100, 100, 1200, 800)

        # Reduce margins/spaces for a denser layout
        main_layout = QVBoxLayout()
        main_layout.setSpacing(5)
        main_layout.setContentsMargins(5, 5, 5, 5)
        self.setLayout(main_layout)

        # ===================== TOP BAR (Menu + Filter) =====================
        top_bar = QHBoxLayout()
        top_bar.setSpacing(10)
        top_bar.setContentsMargins(0, 0, 0, 0)

        # Menu button
        self.menu_button = QToolButton()
        self.menu_button.setText("Menu")
        self.create_menu()

        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(6)
        filter_layout.setContentsMargins(0, 0, 0, 0)

        self.filter_label = QLabel("Filter by:")
        self.filter_field = QComboBox()
        self.filter_field.addItem("All Fields")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter filter keyword...")
        self.filter_button = QPushButton("Apply Filter")
        self.filter_button.clicked.connect(self.apply_filter)
        self.clear_filter_button = QPushButton("Clear Filter")
        self.clear_filter_button.clicked.connect(self.clear_filter)

        # We remove the "searching for" text entirely
        # self.search_label = QLabel("Searching for: ")  # REMOVED

        filter_layout.addWidget(self.filter_label)
        filter_layout.addWidget(self.filter_field)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.filter_button)
        filter_layout.addWidget(self.clear_filter_button)

        top_bar.addWidget(self.menu_button, 0, Qt.AlignmentFlag.AlignLeft)
        top_bar.addLayout(filter_layout)

        # A spacer to push the items left or center them
        top_bar.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        main_layout.addLayout(top_bar)

        # ===================== THREAT ALERTS =====================
        self.alert_text = QTextEdit()
        self.alert_text.setReadOnly(True)
        self.alert_text.setPlaceholderText("Threat alerts will appear here...")
        self.alert_text.setMaximumHeight(60)
        main_layout.addWidget(self.alert_text)

        # ===================== MAIN CONTENT (Tabs + Collapsible Hardware) =====================
        content_layout = QHBoxLayout()
        content_layout.setSpacing(5)
        content_layout.setContentsMargins(0, 0, 0, 0)

        # Left: QTabWidget
        self.tab_widget = QTabWidget()
        self.tab_widget.setMinimumWidth(800)

        # --- Logs Tab ---
        self.logs_tab = QWidget()
        self.logs_layout = QVBoxLayout(self.logs_tab)
        self.logs_layout.setSpacing(5)
        self.logs_layout.setContentsMargins(0, 0, 0, 0)

        logs_button_layout = QHBoxLayout()
        self.load_login_button = QPushButton("Load Login History")
        self.load_login_button.clicked.connect(self.fetch_login_info_async)
        self.load_system_button = QPushButton("Load System Logs")
        self.load_system_button.clicked.connect(self.fetch_system_log_async)
        self.load_firewall_button = QPushButton("Load Firewall Logs")
        self.load_firewall_button.clicked.connect(self.fetch_firewall_logs_async)

        logs_button_layout.addWidget(self.load_login_button)
        logs_button_layout.addWidget(self.load_system_button)
        logs_button_layout.addWidget(self.load_firewall_button)

        self.log_text_area = QTextEdit()
        self.log_text_area.setReadOnly(True)

        self.logs_layout.addLayout(logs_button_layout)
        self.logs_layout.addWidget(self.log_text_area)
        self.tab_widget.addTab(self.logs_tab, "Logs")

        # --- Processes Tab ---
        self.process_tab = QWidget()
        self.process_layout = QVBoxLayout(self.process_tab)
        self.process_layout.setSpacing(5)
        self.process_layout.setContentsMargins(0, 0, 0, 0)

        process_button_layout = QHBoxLayout()
        self.load_process_button = QPushButton("Load Processes")
        self.load_process_button.clicked.connect(self.fetch_running_processes_async)
        process_button_layout.addWidget(self.load_process_button)

        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["PID", "USER", "%CPU", "%MEM", "COMMAND"])
        self.process_table.setSortingEnabled(True)

        self.process_layout.addLayout(process_button_layout)
        self.process_layout.addWidget(self.process_table)
        self.tab_widget.addTab(self.process_tab, "Processes")

        # --- Users Tab ---
        self.users_tab = QWidget()
        self.users_layout = QVBoxLayout(self.users_tab)
        self.users_layout.setSpacing(5)
        self.users_layout.setContentsMargins(0, 0, 0, 0)

        users_button_layout = QHBoxLayout()
        self.load_users_button = QPushButton("Load Users & Logins")
        self.load_users_button.clicked.connect(self.fetch_all_users)
        users_button_layout.addWidget(self.load_users_button)

        self.users_table = QTableWidget()
        self.users_table.setColumnCount(3)
        self.users_table.setHorizontalHeaderLabels(["User", "Last Login Info", "Is Defined User?"])
        self.users_table.setSortingEnabled(True)

        self.users_layout.addLayout(users_button_layout)
        self.users_layout.addWidget(self.users_table)
        self.tab_widget.addTab(self.users_tab, "Users")

        content_layout.addWidget(self.tab_widget)

        # Right: collapsible hardware usage
        right_side_layout = QVBoxLayout()
        right_side_layout.setSpacing(5)
        right_side_layout.setContentsMargins(0, 0, 0, 0)

        self.toggle_hw_button = QPushButton("Show/Hide Hardware Usage")
        self.toggle_hw_button.clicked.connect(self.toggle_hardware_widget)
        right_side_layout.addWidget(self.toggle_hw_button)
        right_side_layout.addWidget(self.hardware_widget)

        right_frame = QFrame()
        right_frame.setLayout(right_side_layout)
        content_layout.addWidget(right_frame)

        main_layout.addLayout(content_layout)

    # ===================== MENU =====================
    def create_menu(self):
        menu = QMenu()

        # Toggle Real-time Process Monitoring
        toggle_action = menu.addAction("Real-time Process Monitoring")
        toggle_action.setCheckable(True)
        toggle_action.triggered.connect(self.toggle_process_monitoring)

        # Exit
        menu.addAction("Exit", lambda: QApplication.quit())

        self.menu_button.setMenu(menu)
        self.menu_button.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)

    def toggle_process_monitoring(self, checked: bool):
        self.real_time_process = checked
        if checked:
            logging.info("Real-time process monitoring enabled.")
            self.process_timer.start(5000)
        else:
            logging.info("Real-time process monitoring disabled.")
            self.process_timer.stop()

    def toggle_hardware_widget(self):
        current_state = self.hardware_widget.isVisible()
        self.hardware_widget.setVisible(not current_state)

    # ===================== LOGS =====================
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
        self.log_text_area.setPlainText(json.dumps(log_data, indent=4))

        # Threat detection
        suspicious = detect_suspicious_activity(log_data)
        if suspicious:
            alert_msg = "Suspicious login entries detected:\n" + "\n".join(
                [f"{entry.get('user')} @ {entry.get('terminal')}" for entry in suspicious]
            )
            self.alert_text.setPlainText(alert_msg)
        else:
            self.alert_text.clear()

        self.populate_filter_options(log_data)

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
        self.log_text_area.setPlainText(json.dumps(log_data, indent=4))
        self.alert_text.clear()
        self.populate_filter_options(log_data)

    def fetch_firewall_logs_async(self):
        password, ok = QInputDialog.getText(
            self, "Password", "Enter your sudo password:", QLineEdit.EchoMode.Password
        )
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
        self.log_text_area.setPlainText(json.dumps(log_data, indent=4))
        self.alert_text.clear()
        self.populate_filter_options(log_data)

    # ===================== PROCESSES (sudo ps aux) =====================
    def fetch_running_processes_async(self):
        """
        Use sudo ps aux to capture all processes (similar to Activity Monitor).
        """
        password, ok = QInputDialog.getText(
            self, "Password", "Enter your sudo password:", QLineEdit.EchoMode.Password
        )
        if ok and password:
            worker = CommandWorker(
                ["sudo", "-S", "ps", "aux"],
                functions.parse_running_processes,
                input_data=password + "\n"
            )
            self.workers.append(worker)
            worker.finished.connect(lambda data, w=worker: self.handle_running_processes(data, w))
            worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
            worker.start()

    def handle_running_processes(self, log_data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)

        entries = log_data.get("entries", [])
        self.process_table.setRowCount(len(entries))
        for row, proc in enumerate(entries):
            pid_item = QTableWidgetItem(proc.get("PID", ""))
            user_item = QTableWidgetItem(proc.get("USER", ""))
            cpu_item = NumericTableWidgetItem(proc.get("%CPU", "0"))
            mem_item = NumericTableWidgetItem(proc.get("%MEM", "0"))
            cmd_item = QTableWidgetItem(proc.get("COMMAND", ""))

            self.process_table.setItem(row, 0, pid_item)
            self.process_table.setItem(row, 1, user_item)
            self.process_table.setItem(row, 2, cpu_item)
            self.process_table.setItem(row, 3, mem_item)
            self.process_table.setItem(row, 4, cmd_item)

        self.process_table.resizeColumnsToContents()

    # ===================== USERS =====================
    def fetch_all_users(self):
        worker = CommandWorker(["dscl", ".", "-list", "/Users"], self.parse_defined_users)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_defined_users(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def parse_defined_users(self, output: str) -> dict:
        lines = output.strip().splitlines()
        return {
            "timestamp": "dscl-users",
            "type": "defined_users",
            "entries": lines
        }

    def handle_defined_users(self, user_data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        defined_users = user_data.get("entries", [])

        try:
            with open("login_history.json", "r") as f:
                login_data = json.load(f)
        except:
            login_data = {"entries": []}

        last_logins = {}
        for entry in login_data.get("entries", []):
            user = entry.get("user", "")
            dt = entry.get("date_time", "")
            if user not in last_logins:
                last_logins[user] = dt

        combined_list = []
        # dscl users
        for u in defined_users:
            info = last_logins.get(u, "")
            combined_list.append((u, info, True))

        # any logins not in dscl
        for entry in login_data.get("entries", []):
            user = entry.get("user", "")
            if user not in defined_users:
                dt = entry.get("date_time", "")
                combined_list.append((user, dt, False))

        self.users_table.setRowCount(len(combined_list))
        for row, (username, last_dt, is_defined) in enumerate(combined_list):
            user_item = QTableWidgetItem(username)
            login_item = QTableWidgetItem(last_dt)
            defined_item = QTableWidgetItem("Yes" if is_defined else "No")
            self.users_table.setItem(row, 0, user_item)
            self.users_table.setItem(row, 1, login_item)
            self.users_table.setItem(row, 2, defined_item)

        self.users_table.resizeColumnsToContents()

    # ===================== ERROR HANDLING =====================
    def handle_worker_error(self, error_message: str, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        logging.error(f"Worker error: {error_message}")

    # ===================== FILTERING =====================
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
            self.log_text_area.setPlainText(json.dumps(filtered_data, indent=4))
        except Exception as e:
            self.log_text_area.setPlainText(f"Error filtering data: {e}")

    def clear_filter(self):
        if self.original_data:
            self.log_text_area.setPlainText(json.dumps(self.original_data, indent=4))
            self.filter_input.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Tweaked dark mode palette with more color
    app.setStyle("Fusion")
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.ColorRole.Window, QColor("#2E2E2E"))
    dark_palette.setColor(QPalette.ColorRole.WindowText, QColor("#E8E8E8"))
    dark_palette.setColor(QPalette.ColorRole.Base, QColor("#3B3B3B"))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#4A4A4A"))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#E0E0E0"))
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#FFFFFF"))
    dark_palette.setColor(QPalette.ColorRole.Text, QColor("#E8E8E8"))
    dark_palette.setColor(QPalette.ColorRole.Button, QColor("#525252"))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor("#E8E8E8"))
    dark_palette.setColor(QPalette.ColorRole.BrightText, QColor("#FF0000"))
    dark_palette.setColor(QPalette.ColorRole.Link, QColor("#FF9900"))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor("#5F6A6A"))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#000000"))
    app.setPalette(dark_palette)

    viewer = LogViewer()
    viewer.show()
    sys.exit(app.exec())

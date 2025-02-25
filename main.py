import sys
import json
import logging
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QLineEdit, QLabel, QComboBox, QInputDialog,
    QToolButton, QMenu, QPushButton, QFrame, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QPalette, QColor, QFont

import functions
from worker import CommandWorker
from threat_detection import detect_suspicious_activity
from hardware_monitor import HardwareUsageWidget

# Custom table item for numeric sorting
class NumericTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except ValueError:
            return super().__lt__(other)

# Helper functions for row coloring
def get_log_color(entry, current_log_type):
    # For system logs, use default (white)
    if current_log_type == "system_log":
        return QColor("#ECF0F1")
    text = json.dumps(entry).lower()
    if "fail" in text or "error" in text:
        return QColor("#E74C3C")  # critical: red
    elif "warn" in text:
        return QColor("#F39C12")  # warning: orange
    else:
        return QColor("#2ECC71")  # normal: green

def get_process_color(cpu_usage):
    try:
        cpu = float(cpu_usage)
    except Exception:
        cpu = 0
    if cpu >= 80:
        return QColor("#E74C3C")  # red
    elif cpu >= 50:
        return QColor("#F39C12")  # orange
    else:
        return QColor("#2ECC71")  # green

def get_user_color(user_type):
    if user_type == "System User":
        return QColor("#E74C3C")
    else:
        return QColor("#2ECC71")

def get_user_type(username):
    if username.lower() == "root" or username.startswith("_"):
        return "System User"
    return "Regular User"

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
        # Original data for each tab
        self.original_log_data = None
        self.original_process_data = None
        self.original_network_conn_data = None
        self.original_network_logs_data = None
        self.original_users_data = None

        self.current_log_type = None  # "login", "system_log", or "firewall_logs"
        self.real_time_process = False
        self.sudo_password = None  # Cached sudo password

        self.process_timer = QTimer(self)
        self.process_timer.timeout.connect(self.fetch_running_processes_async)

        # Hardware usage widget (circular gauges)
        self.hardware_widget = HardwareUsageWidget(self)

        self.initUI()

    def initUI(self):
        self.setWindowTitle("macOS EDR - Enhanced UI")
        self.setGeometry(100, 100, 1200, 800)
        self.setFont(QFont("Segoe UI", 12))

        main_layout = QVBoxLayout()
        main_layout.setSpacing(5)
        main_layout.setContentsMargins(10, 10, 10, 10)
        self.setLayout(main_layout)

        # ---------------- TOP ROW: Main Menu | Alert Area | Hardware Gauge ----------------
        top_row = QHBoxLayout()
        top_row.setSpacing(10)
        top_row.setContentsMargins(0, 0, 0, 0)
        # Left: Main Menu button
        self.menu_button = QToolButton()
        self.menu_button.setText("Main Menu")
        self.menu_button.setMinimumWidth(120)
        self.create_menu()
        top_row.addWidget(self.menu_button, 0, Qt.AlignmentFlag.AlignLeft)
        # Center: Alert area (narrower, with adjusted font)
        self.alert_text = QTextEdit()
        self.alert_text.setReadOnly(True)
        self.alert_text.setPlaceholderText("Threat alerts...")
        self.alert_text.setMaximumHeight(40)
        self.alert_text.setFont(QFont("Consolas", 12))
        top_row.addWidget(self.alert_text, 1)
        # Right: Hardware Gauge widget
        top_row.addWidget(self.hardware_widget, 0, Qt.AlignmentFlag.AlignRight)
        main_layout.addLayout(top_row)

        # ---------------- FILTER ROW ----------------
        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)
        filter_row.setContentsMargins(0, 0, 0, 0)
        self.filter_label = QLabel("Filter by:")
        self.filter_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.filter_field = QComboBox()
        self.filter_field.addItem("All Fields")
        self.filter_field.setFont(QFont("Segoe UI", 12))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter filter keyword...")
        self.filter_input.setFont(QFont("Consolas", 12))
        self.filter_button = QPushButton("Apply Filter")
        self.filter_button.setFont(QFont("Segoe UI", 12))
        self.filter_button.clicked.connect(self.apply_filter)
        self.clear_filter_button = QPushButton("Clear Filter")
        self.clear_filter_button.setFont(QFont("Segoe UI", 12))
        self.clear_filter_button.clicked.connect(self.clear_filter)
        filter_row.addWidget(self.filter_label)
        filter_row.addWidget(self.filter_field)
        filter_row.addWidget(self.filter_input)
        filter_row.addWidget(self.filter_button)
        filter_row.addWidget(self.clear_filter_button)
        filter_row.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        main_layout.addLayout(filter_row)

        # ---------------- MAIN CONTENT: Tabs ----------------
        content_layout = QHBoxLayout()
        content_layout.setSpacing(5)
        content_layout.setContentsMargins(0, 0, 0, 0)

        self.tab_widget = QTabWidget()
        self.tab_widget.setMinimumWidth(800)

        # --- Logs Tab ---
        self.logs_tab = QWidget()
        self.logs_layout = QVBoxLayout(self.logs_tab)
        self.logs_layout.setSpacing(5)
        self.logs_layout.setContentsMargins(0, 0, 0, 0)
        logs_button_layout = QHBoxLayout()
        self.load_login_button = QPushButton("Load Login History")
        self.load_login_button.setFont(QFont("Segoe UI", 12))
        self.load_login_button.clicked.connect(self.fetch_login_info_async)
        self.load_system_button = QPushButton("Load System Logs")
        self.load_system_button.setFont(QFont("Segoe UI", 12))
        self.load_system_button.clicked.connect(self.fetch_system_log_async)
        self.load_firewall_button = QPushButton("Load Firewall Logs")
        self.load_firewall_button.setFont(QFont("Segoe UI", 12))
        self.load_firewall_button.clicked.connect(self.fetch_firewall_logs_async)
        logs_button_layout.addWidget(self.load_login_button)
        logs_button_layout.addWidget(self.load_system_button)
        logs_button_layout.addWidget(self.load_firewall_button)
        self.log_table = QTableWidget()
        self.log_table.setSortingEnabled(True)
        self.log_table.setFont(QFont("Consolas", 12))
        self.logs_layout.addLayout(logs_button_layout)
        self.logs_layout.addWidget(self.log_table)
        self.tab_widget.addTab(self.logs_tab, "Logs")

        # --- Processes Tab ---
        self.process_tab = QWidget()
        self.process_layout = QVBoxLayout(self.process_tab)
        self.process_layout.setSpacing(5)
        self.process_layout.setContentsMargins(0, 0, 0, 0)
        process_button_layout = QHBoxLayout()
        self.load_process_button = QPushButton("Load Processes")
        self.load_process_button.setFont(QFont("Segoe UI", 12))
        self.load_process_button.clicked.connect(self.fetch_running_processes_async)
        process_button_layout.addWidget(self.load_process_button)
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["PID", "USER", "%CPU", "%MEM", "COMMAND"])
        self.process_table.setSortingEnabled(True)
        self.process_table.setFont(QFont("Consolas", 12))
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
        self.load_users_button.setFont(QFont("Segoe UI", 12))
        self.load_users_button.clicked.connect(self.fetch_all_users)
        users_button_layout.addWidget(self.load_users_button)
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(3)
        self.users_table.setHorizontalHeaderLabels(["User", "Last Login", "Type"])
        self.users_table.setSortingEnabled(True)
        self.users_table.setFont(QFont("Consolas", 12))
        self.users_layout.addLayout(users_button_layout)
        self.users_layout.addWidget(self.users_table)
        self.tab_widget.addTab(self.users_tab, "Users")

        # --- Network Tab: Inner TabWidget for Connections and Logs ---
        self.network_tab = QWidget()
        network_layout = QVBoxLayout(self.network_tab)
        network_layout.setSpacing(5)
        network_layout.setContentsMargins(0, 0, 0, 0)
        self.network_inner_tab = QTabWidget()

        # Connections sub-tab
        self.connections_tab = QWidget()
        conn_layout = QVBoxLayout(self.connections_tab)
        conn_layout.setSpacing(5)
        conn_layout.setContentsMargins(0, 0, 0, 0)
        conn_filter_layout = QHBoxLayout()
        self.conn_filter_input = QLineEdit()
        self.conn_filter_input.setPlaceholderText("Filter connections...")
        self.conn_filter_input.setFont(QFont("Consolas", 12))
        self.conn_filter_button = QPushButton("Apply Filter")
        self.conn_filter_button.setFont(QFont("Segoe UI", 12))
        self.conn_filter_button.clicked.connect(self.apply_network_connections_filter)
        self.conn_clear_filter_button = QPushButton("Clear Filter")
        self.conn_clear_filter_button.setFont(QFont("Segoe UI", 12))
        self.conn_clear_filter_button.clicked.connect(self.clear_network_connections_filter)
        self.refresh_connections_button = QPushButton("Refresh Connections")
        self.refresh_connections_button.setFont(QFont("Segoe UI", 12))
        self.refresh_connections_button.clicked.connect(self.fetch_network_connections)
        conn_filter_layout.addWidget(QLabel("Filter:"))
        conn_filter_layout.addWidget(self.conn_filter_input)
        conn_filter_layout.addWidget(self.conn_filter_button)
        conn_filter_layout.addWidget(self.conn_clear_filter_button)
        conn_filter_layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        conn_filter_layout.addWidget(self.refresh_connections_button)
        conn_layout.addLayout(conn_filter_layout)
        self.network_conn_table = QTableWidget()
        self.network_conn_table.setSortingEnabled(True)
        self.network_conn_table.setFont(QFont("Consolas", 12))
        conn_layout.addWidget(self.network_conn_table)
        self.network_inner_tab.addTab(self.connections_tab, "Connections")

        # Network Logs sub-tab
        self.netlogs_tab = QWidget()
        netlogs_layout = QVBoxLayout(self.netlogs_tab)
        netlogs_layout.setSpacing(5)
        netlogs_layout.setContentsMargins(0, 0, 0, 0)
        netlogs_filter_layout = QHBoxLayout()
        self.netlogs_filter_input = QLineEdit()
        self.netlogs_filter_input.setPlaceholderText("Filter network logs...")
        self.netlogs_filter_input.setFont(QFont("Consolas", 12))
        self.netlogs_filter_button = QPushButton("Apply Filter")
        self.netlogs_filter_button.setFont(QFont("Segoe UI", 12))
        self.netlogs_filter_button.clicked.connect(self.apply_network_logs_filter)
        self.netlogs_clear_filter_button = QPushButton("Clear Filter")
        self.netlogs_clear_filter_button.setFont(QFont("Segoe UI", 12))
        self.netlogs_clear_filter_button.clicked.connect(self.clear_network_logs_filter)
        self.refresh_netlogs_button = QPushButton("Refresh Logs")
        self.refresh_netlogs_button.setFont(QFont("Segoe UI", 12))
        self.refresh_netlogs_button.clicked.connect(self.fetch_network_logs)
        netlogs_filter_layout.addWidget(QLabel("Filter:"))
        netlogs_filter_layout.addWidget(self.netlogs_filter_input)
        netlogs_filter_layout.addWidget(self.netlogs_filter_button)
        netlogs_filter_layout.addWidget(self.netlogs_clear_filter_button)
        netlogs_filter_layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        netlogs_filter_layout.addWidget(self.refresh_netlogs_button)
        netlogs_layout.addLayout(netlogs_filter_layout)
        self.network_logs_table = QTableWidget()
        self.network_logs_table.setSortingEnabled(True)
        self.network_logs_table.setFont(QFont("Consolas", 12))
        netlogs_layout.addWidget(self.network_logs_table)
        self.network_inner_tab.addTab(self.netlogs_tab, "Logs")

        network_layout.addWidget(self.network_inner_tab)
        self.tab_widget.addTab(self.network_tab, "Network")

        content_layout.addWidget(self.tab_widget)
        main_layout.addLayout(content_layout)
        self.applyStyles()

    def applyStyles(self):
        style = """
            QWidget {
                background-color: #1C1C1C;
                color: #ECF0F1;
            }
            QPushButton {
                background-color: #34495E;
                color: #ECF0F1;
                border: 1px solid #5D6D7E;
                border-radius: 4px;
                padding: 8px 14px;
            }
            QPushButton:hover {
                background-color: #3D566E;
            }
            QPushButton:pressed {
                background-color: #2C3E50;
            }
            QToolButton {
                background-color: #34495E;
                color: #ECF0F1;
                border: none;
                padding: 8px;
            }
            QComboBox, QLineEdit, QTextEdit, QTableWidget {
                background-color: #2C3E50;
                color: #ECF0F1;
                border: 1px solid #5D6D7E;
                border-radius: 4px;
                padding: 6px;
            }
            QTabWidget::pane {
                border: 1px solid #5D6D7E;
            }
            QHeaderView::section {
                background-color: #34495E;
                padding: 6px;
                border: 1px solid #5D6D7E;
            }
        """
        self.setStyleSheet(style)

    def create_menu(self):
        menu = QMenu()
        toggle_action = menu.addAction("Real-time Process Monitoring")
        toggle_action.setCheckable(True)
        toggle_action.triggered.connect(self.toggle_process_monitoring)
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
        self.hardware_widget.setVisible(not self.hardware_widget.isVisible())

    # ---------------- LOGS ----------------
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
        self.current_log_type = "login"
        self.original_log_data = log_data
        for entry in log_data.get("entries", []):
            user = entry.get("user", "")
            entry["Type"] = get_user_type(user)
        self.populate_log_table(log_data)
        self.apply_log_colors()
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
        self.current_log_type = "system_log"
        self.original_log_data = log_data
        self.populate_log_table(log_data)
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
        self.current_log_type = "firewall_logs"
        self.original_log_data = log_data
        self.populate_log_table(log_data)
        self.alert_text.clear()
        self.populate_filter_options(log_data)

    def populate_log_table(self, data: dict):
        entries = data.get("entries", [])
        if not entries:
            self.log_table.setRowCount(0)
            self.log_table.setColumnCount(0)
            return
        columns = list(entries[0].keys())
        if "Type" not in columns:
            columns.append("Type")
        self.log_table.setColumnCount(len(columns))
        self.log_table.setHorizontalHeaderLabels(columns)
        self.log_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for col, key in enumerate(columns):
                item = QTableWidgetItem(str(entry.get(key, "")))
                self.log_table.setItem(row, col, item)
        self.log_table.resizeColumnsToContents()

    def apply_log_colors(self):
        if self.current_log_type == "system_log":
            for row in range(self.log_table.rowCount()):
                for col in range(self.log_table.columnCount()):
                    self.log_table.item(row, col).setForeground(QColor("#ECF0F1"))
            return
        row_count = self.log_table.rowCount()
        col_count = self.log_table.columnCount()
        for row in range(row_count):
            entry = {}
            for col in range(col_count):
                header = self.log_table.horizontalHeaderItem(col).text()
                text = self.log_table.item(row, col).text()
                entry[header] = text
            color = get_log_color(entry, self.current_log_type)
            for col in range(col_count):
                self.log_table.item(row, col).setForeground(color)

    # ---------------- PROCESSES ----------------
    def fetch_running_processes_async(self):
        if self.sudo_password is None:
            pwd, ok = QInputDialog.getText(
                self, "Password", "Enter your sudo password:", QLineEdit.EchoMode.Password
            )
            if ok and pwd:
                self.sudo_password = pwd
            else:
                return
        worker = CommandWorker(
            ["sudo", "-S", "ps", "aux"],
            functions.parse_running_processes,
            input_data=self.sudo_password + "\n"
        )
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_running_processes(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_running_processes(self, data: dict, worker):
        if worker and worker in self.workers:
            self.workers.remove(worker)
        self.original_process_data = data
        entries = data.get("entries", [])
        self.process_table.setRowCount(len(entries))
        for row, proc in enumerate(entries):
            pid_item = QTableWidgetItem(proc.get("PID", ""))
            user_item = QTableWidgetItem(proc.get("USER", ""))
            try:
                cpu_val = float(proc.get("%CPU", "0"))
                if cpu_val > 100:
                    cpu_val = 100.0
            except Exception:
                cpu_val = 0
            cpu_item = NumericTableWidgetItem(str(cpu_val))
            mem_item = NumericTableWidgetItem(proc.get("%MEM", "0"))
            cmd_item = QTableWidgetItem(proc.get("COMMAND", ""))
            color = get_process_color(str(cpu_val))
            pid_item.setForeground(color)
            user_item.setForeground(color)
            cpu_item.setForeground(color)
            mem_item.setForeground(color)
            cmd_item.setForeground(color)
            self.process_table.setItem(row, 0, pid_item)
            self.process_table.setItem(row, 1, user_item)
            self.process_table.setItem(row, 2, cpu_item)
            self.process_table.setItem(row, 3, mem_item)
            self.process_table.setItem(row, 4, cmd_item)
        self.process_table.resizeColumnsToContents()

    # ---------------- NETWORK (Inner TabWidget) ----------------
    def fetch_network_connections(self):
        worker = CommandWorker(["netstat", "-an"], functions.parse_network_connections)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_network_connections(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_network_connections(self, data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        self.original_network_conn_data = data
        self.populate_network_connections_table(data)

    def populate_network_connections_table(self, data: dict):
        entries = data.get("entries", [])
        if not entries:
            self.network_conn_table.setRowCount(0)
            self.network_conn_table.setColumnCount(0)
            return
        columns = list(entries[0].keys())
        self.network_conn_table.setColumnCount(len(columns))
        self.network_conn_table.setHorizontalHeaderLabels(columns)
        self.network_conn_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for col, key in enumerate(columns):
                item = QTableWidgetItem(str(entry.get(key, "")))
                self.network_conn_table.setItem(row, col, item)
        self.network_conn_table.resizeColumnsToContents()

    def apply_network_connections_filter(self):
        keyword = self.conn_filter_input.text().strip().lower()
        if not keyword or not self.original_network_conn_data:
            return
        filtered_entries = []
        for entry in self.original_network_conn_data["entries"]:
            if keyword in " ".join(str(v) for v in entry.values()).lower():
                filtered_entries.append(entry)
        filtered = {"entries": filtered_entries}
        self.populate_network_connections_table(filtered)

    def clear_network_connections_filter(self):
        self.conn_filter_input.clear()
        if self.original_network_conn_data:
            self.populate_network_connections_table(self.original_network_conn_data)

    def fetch_network_logs(self):
        worker = CommandWorker(["netstat", "-an"], functions.parse_network_logs)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_network_logs(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_network_logs(self, data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        self.original_network_logs_data = data
        self.populate_network_logs_table(data)

    def populate_network_logs_table(self, data: dict):
        entries = data.get("entries", [])
        if not entries:
            self.network_logs_table.setRowCount(0)
            self.network_logs_table.setColumnCount(0)
            return
        columns = list(entries[0].keys())
        self.network_logs_table.setColumnCount(len(columns))
        self.network_logs_table.setHorizontalHeaderLabels(columns)
        self.network_logs_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for col, key in enumerate(columns):
                item = QTableWidgetItem(str(entry.get(key, "")))
                self.network_logs_table.setItem(row, col, item)
        self.network_logs_table.resizeColumnsToContents()

    def apply_network_logs_filter(self):
        keyword = self.netlogs_filter_input.text().strip().lower()
        if not keyword or not self.original_network_logs_data:
            return
        filtered_entries = []
        for entry in self.original_network_logs_data["entries"]:
            if keyword in str(entry.get("Line", "")).lower():
                filtered_entries.append(entry)
        filtered = {"entries": filtered_entries}
        self.populate_network_logs_table(filtered)

    def clear_network_logs_filter(self):
        self.netlogs_filter_input.clear()
        if self.original_network_logs_data:
            self.populate_network_logs_table(self.original_network_logs_data)

    # ---------------- USERS ----------------
    def fetch_all_users(self):
        worker = CommandWorker(["dscl", ".", "-list", "/Users"], self.parse_defined_users)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_defined_users(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def parse_defined_users(self, output: str) -> dict:
        lines = output.strip().splitlines()
        return {"timestamp": "dscl-users", "type": "defined_users", "entries": lines}

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
        for u in defined_users:
            info = last_logins.get(u, "")
            combined_list.append((u, info, "System User"))
        for entry in login_data.get("entries", []):
            user = entry.get("user", "")
            if user not in defined_users:
                dt = entry.get("date_time", "")
                combined_list.append((user, dt, "Regular User"))
        self.users_table.setRowCount(len(combined_list))
        for row, (username, last_dt, utype) in enumerate(combined_list):
            user_item = QTableWidgetItem(username)
            login_item = QTableWidgetItem(last_dt)
            type_item = QTableWidgetItem(utype)
            color = get_user_color(utype)
            user_item.setForeground(color)
            login_item.setForeground(color)
            type_item.setForeground(color)
            self.users_table.setItem(row, 0, user_item)
            self.users_table.setItem(row, 1, login_item)
            self.users_table.setItem(row, 2, type_item)
        self.users_table.resizeColumnsToContents()

    # ---------------- ERROR HANDLING ----------------
    def handle_worker_error(self, error_message: str, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        logging.error(f"Worker error: {error_message}")

    # ---------------- FILTERING ----------------
    def populate_filter_options(self, data: dict):
        self.filter_field.clear()
        self.filter_field.addItem("All Fields")
        if data.get("entries"):
            for key in data["entries"][0].keys():
                self.filter_field.addItem(key)

    def apply_filter(self):
        current_index = self.tab_widget.currentIndex()
        keyword = self.filter_input.text().strip().lower()
        selected_field = self.filter_field.currentText()
        if not keyword:
            return

        if current_index == 0:  # Logs tab
            data = self.original_log_data
            if not data:
                return
            try:
                filtered_entries = []
                for entry in data["entries"]:
                    if selected_field == "All Fields":
                        if keyword in json.dumps(entry).lower():
                            filtered_entries.append(entry)
                    else:
                        if keyword in str(entry.get(selected_field, "")).lower():
                            filtered_entries.append(entry)
                filtered = {"entries": filtered_entries}
                self.populate_log_table(filtered)
                self.apply_log_colors()
            except Exception as e:
                logging.error(f"Error filtering log data: {e}")
        elif current_index == 1:  # Processes tab
            data = self.original_process_data
            if not data:
                return
            try:
                filtered_entries = []
                for entry in data["entries"]:
                    if selected_field == "All Fields":
                        entry_str = " ".join(str(v) for v in entry.values()).lower()
                        if keyword in entry_str:
                            filtered_entries.append(entry)
                    else:
                        if keyword in str(entry.get(selected_field, "")).lower():
                            filtered_entries.append(entry)
                filtered = {"entries": filtered_entries}
                self.handle_running_processes(filtered, None)
            except Exception as e:
                logging.error(f"Error filtering process data: {e}")
        # Users tab filtering is not implemented

    def clear_filter(self):
        self.filter_input.clear()
        current_index = self.tab_widget.currentIndex()
        if current_index == 0 and self.original_log_data:
            self.populate_log_table(self.original_log_data)
            if self.current_log_type == "system_log":
                for row in range(self.log_table.rowCount()):
                    for col in range(self.log_table.columnCount()):
                        self.log_table.item(row, col).setForeground(QColor("#ECF0F1"))
            else:
                self.apply_log_colors()
        elif current_index == 1 and self.original_process_data:
            self.handle_running_processes(self.original_process_data, None)

    # ---------------- NETWORK FILTERING ----------------
    def apply_network_connections_filter(self):
        keyword = self.conn_filter_input.text().strip().lower()
        if not keyword or not self.original_network_conn_data:
            return
        filtered_entries = []
        for entry in self.original_network_conn_data["entries"]:
            if keyword in " ".join(str(v) for v in entry.values()).lower():
                filtered_entries.append(entry)
        filtered = {"entries": filtered_entries}
        self.populate_network_connections_table(filtered)

    def clear_network_connections_filter(self):
        self.conn_filter_input.clear()
        if self.original_network_conn_data:
            self.populate_network_connections_table(self.original_network_conn_data)

    def populate_network_connections_table(self, data: dict):
        entries = data.get("entries", [])
        if not entries:
            self.network_conn_table.setRowCount(0)
            self.network_conn_table.setColumnCount(0)
            return
        columns = list(entries[0].keys())
        self.network_conn_table.setColumnCount(len(columns))
        self.network_conn_table.setHorizontalHeaderLabels(columns)
        self.network_conn_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for col, key in enumerate(columns):
                item = QTableWidgetItem(str(entry.get(key, "")))
                self.network_conn_table.setItem(row, col, item)
        self.network_conn_table.resizeColumnsToContents()

    def apply_network_logs_filter(self):
        keyword = self.netlogs_filter_input.text().strip().lower()
        if not keyword or not self.original_network_logs_data:
            return
        filtered_entries = []
        for entry in self.original_network_logs_data["entries"]:
            if keyword in str(entry.get("Line", "")).lower():
                filtered_entries.append(entry)
        filtered = {"entries": filtered_entries}
        self.populate_network_logs_table(filtered)

    def clear_network_logs_filter(self):
        self.netlogs_filter_input.clear()
        if self.original_network_logs_data:
            self.populate_network_logs_table(self.original_network_logs_data)

    def populate_network_logs_table(self, data: dict):
        entries = data.get("entries", [])
        if not entries:
            self.network_logs_table.setRowCount(0)
            self.network_logs_table.setColumnCount(0)
            return
        columns = list(entries[0].keys())
        self.network_logs_table.setColumnCount(len(columns))
        self.network_logs_table.setHorizontalHeaderLabels(columns)
        self.network_logs_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for col, key in enumerate(columns):
                item = QTableWidgetItem(str(entry.get(key, "")))
                self.network_logs_table.setItem(row, col, item)
        self.network_logs_table.resizeColumnsToContents()

    def fetch_network_connections(self):
        worker = CommandWorker(["netstat", "-an"], functions.parse_network_connections)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_network_connections(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_network_connections(self, data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        self.original_network_conn_data = data
        self.populate_network_connections_table(data)

    def fetch_network_logs(self):
        worker = CommandWorker(["netstat", "-an"], functions.parse_network_logs)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_network_logs(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_network_logs(self, data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        self.original_network_logs_data = data
        self.populate_network_logs_table(data)

    # ---------------- USERS ----------------
    def fetch_all_users(self):
        worker = CommandWorker(["dscl", ".", "-list", "/Users"], self.parse_defined_users)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_defined_users(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def parse_defined_users(self, output: str) -> dict:
        lines = output.strip().splitlines()
        return {"timestamp": "dscl-users", "type": "defined_users", "entries": lines}

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
        for u in defined_users:
            info = last_logins.get(u, "")
            combined_list.append((u, info, "System User"))
        for entry in login_data.get("entries", []):
            user = entry.get("user", "")
            if user not in defined_users:
                dt = entry.get("date_time", "")
                combined_list.append((user, dt, "Regular User"))
        self.users_table.setRowCount(len(combined_list))
        for row, (username, last_dt, utype) in enumerate(combined_list):
            user_item = QTableWidgetItem(username)
            login_item = QTableWidgetItem(last_dt)
            type_item = QTableWidgetItem(utype)
            color = get_user_color(utype)
            user_item.setForeground(color)
            login_item.setForeground(color)
            type_item.setForeground(color)
            self.users_table.setItem(row, 0, user_item)
            self.users_table.setItem(row, 1, login_item)
            self.users_table.setItem(row, 2, type_item)
        self.users_table.resizeColumnsToContents()

    # ---------------- ERROR HANDLING ----------------
    def handle_worker_error(self, error_message: str, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        logging.error(f"Worker error: {error_message}")

    # ---------------- FILTERING ----------------
    def populate_filter_options(self, data: dict):
        self.filter_field.clear()
        self.filter_field.addItem("All Fields")
        if data.get("entries"):
            for key in data["entries"][0].keys():
                self.filter_field.addItem(key)

    def apply_filter(self):
        current_index = self.tab_widget.currentIndex()
        keyword = self.filter_input.text().strip().lower()
        selected_field = self.filter_field.currentText()
        if not keyword:
            return

        if current_index == 0:  # Logs tab
            data = self.original_log_data
            if not data:
                return
            try:
                filtered_entries = []
                for entry in data["entries"]:
                    if selected_field == "All Fields":
                        if keyword in json.dumps(entry).lower():
                            filtered_entries.append(entry)
                    else:
                        if keyword in str(entry.get(selected_field, "")).lower():
                            filtered_entries.append(entry)
                filtered = {"entries": filtered_entries}
                self.populate_log_table(filtered)
                self.apply_log_colors()
            except Exception as e:
                logging.error(f"Error filtering log data: {e}")
        elif current_index == 1:  # Processes tab
            data = self.original_process_data
            if not data:
                return
            try:
                filtered_entries = []
                for entry in data["entries"]:
                    if selected_field == "All Fields":
                        entry_str = " ".join(str(v) for v in entry.values()).lower()
                        if keyword in entry_str:
                            filtered_entries.append(entry)
                    else:
                        if keyword in str(entry.get(selected_field, "")).lower():
                            filtered_entries.append(entry)
                filtered = {"entries": filtered_entries}
                self.handle_running_processes(filtered, None)
            except Exception as e:
                logging.error(f"Error filtering process data: {e}")
        # Users tab filtering not implemented

    def clear_filter(self):
        self.filter_input.clear()
        current_index = self.tab_widget.currentIndex()
        if current_index == 0 and self.original_log_data:
            self.populate_log_table(self.original_log_data)
            if self.current_log_type == "system_log":
                for row in range(self.log_table.rowCount()):
                    for col in range(self.log_table.columnCount()):
                        self.log_table.item(row, col).setForeground(QColor("#ECF0F1"))
            else:
                self.apply_log_colors()
        elif current_index == 1 and self.original_process_data:
            self.handle_running_processes(self.original_process_data, None)

    # ---------------- NETWORK ----------------
    def fetch_network_connections(self):
        worker = CommandWorker(["netstat", "-an"], functions.parse_network_connections)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_network_connections(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_network_connections(self, data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        self.original_network_conn_data = data
        self.populate_network_connections_table(data)

    def populate_network_connections_table(self, data: dict):
        entries = data.get("entries", [])
        if not entries:
            self.network_conn_table.setRowCount(0)
            self.network_conn_table.setColumnCount(0)
            return
        columns = list(entries[0].keys())
        self.network_conn_table.setColumnCount(len(columns))
        self.network_conn_table.setHorizontalHeaderLabels(columns)
        self.network_conn_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for col, key in enumerate(columns):
                item = QTableWidgetItem(str(entry.get(key, "")))
                self.network_conn_table.setItem(row, col, item)
        self.network_conn_table.resizeColumnsToContents()

    def apply_network_logs_filter(self):
        keyword = self.netlogs_filter_input.text().strip().lower()
        if not keyword or not self.original_network_logs_data:
            return
        filtered_entries = []
        for entry in self.original_network_logs_data["entries"]:
            if keyword in str(entry.get("Line", "")).lower():
                filtered_entries.append(entry)
        filtered = {"entries": filtered_entries}
        self.populate_network_logs_table(filtered)

    def clear_network_logs_filter(self):
        self.netlogs_filter_input.clear()
        if self.original_network_logs_data:
            self.populate_network_logs_table(self.original_network_logs_data)

    def populate_network_logs_table(self, data: dict):
        entries = data.get("entries", [])
        if not entries:
            self.network_logs_table.setRowCount(0)
            self.network_logs_table.setColumnCount(0)
            return
        columns = list(entries[0].keys())
        self.network_logs_table.setColumnCount(len(columns))
        self.network_logs_table.setHorizontalHeaderLabels(columns)
        self.network_logs_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for col, key in enumerate(columns):
                item = QTableWidgetItem(str(entry.get(key, "")))
                self.network_logs_table.setItem(row, col, item)
        self.network_logs_table.resizeColumnsToContents()

    def fetch_network_logs(self):
        worker = CommandWorker(["netstat", "-an"], functions.parse_network_logs)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_network_logs(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_network_logs(self, data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        self.original_network_logs_data = data
        self.populate_network_logs_table(data)

    # ---------------- USERS ----------------
    def fetch_all_users(self):
        worker = CommandWorker(["dscl", ".", "-list", "/Users"], self.parse_defined_users)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_defined_users(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def parse_defined_users(self, output: str) -> dict:
        lines = output.strip().splitlines()
        return {"timestamp": "dscl-users", "type": "defined_users", "entries": lines}

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
        for u in defined_users:
            info = last_logins.get(u, "")
            combined_list.append((u, info, "System User"))
        for entry in login_data.get("entries", []):
            user = entry.get("user", "")
            if user not in defined_users:
                dt = entry.get("date_time", "")
                combined_list.append((user, dt, "Regular User"))
        self.users_table.setRowCount(len(combined_list))
        for row, (username, last_dt, utype) in enumerate(combined_list):
            user_item = QTableWidgetItem(username)
            login_item = QTableWidgetItem(last_dt)
            type_item = QTableWidgetItem(utype)
            color = get_user_color(utype)
            user_item.setForeground(color)
            login_item.setForeground(color)
            type_item.setForeground(color)
            self.users_table.setItem(row, 0, user_item)
            self.users_table.setItem(row, 1, login_item)
            self.users_table.setItem(row, 2, type_item)
        self.users_table.resizeColumnsToContents()

    # ---------------- ERROR HANDLING ----------------
    def handle_worker_error(self, error_message: str, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        logging.error(f"Worker error: {error_message}")

    # ---------------- FILTERING ----------------
    def populate_filter_options(self, data: dict):
        self.filter_field.clear()
        self.filter_field.addItem("All Fields")
        if data.get("entries"):
            for key in data["entries"][0].keys():
                self.filter_field.addItem(key)

    def apply_filter(self):
        current_index = self.tab_widget.currentIndex()
        keyword = self.filter_input.text().strip().lower()
        selected_field = self.filter_field.currentText()
        if not keyword:
            return

        if current_index == 0:  # Logs tab
            data = self.original_log_data
            if not data:
                return
            try:
                filtered_entries = []
                for entry in data["entries"]:
                    if selected_field == "All Fields":
                        if keyword in json.dumps(entry).lower():
                            filtered_entries.append(entry)
                    else:
                        if keyword in str(entry.get(selected_field, "")).lower():
                            filtered_entries.append(entry)
                filtered = {"entries": filtered_entries}
                self.populate_log_table(filtered)
                self.apply_log_colors()
            except Exception as e:
                logging.error(f"Error filtering log data: {e}")
        elif current_index == 1:  # Processes tab
            data = self.original_process_data
            if not data:
                return
            try:
                filtered_entries = []
                for entry in data["entries"]:
                    if selected_field == "All Fields":
                        entry_str = " ".join(str(v) for v in entry.values()).lower()
                        if keyword in entry_str:
                            filtered_entries.append(entry)
                    else:
                        if keyword in str(entry.get(selected_field, "")).lower():
                            filtered_entries.append(entry)
                filtered = {"entries": filtered_entries}
                self.handle_running_processes(filtered, None)
            except Exception as e:
                logging.error(f"Error filtering process data: {e}")
        # Users tab filtering not implemented

    def clear_filter(self):
        self.filter_input.clear()
        current_index = self.tab_widget.currentIndex()
        if current_index == 0 and self.original_log_data:
            self.populate_log_table(self.original_log_data)
            if self.current_log_type == "system_log":
                for row in range(self.log_table.rowCount()):
                    for col in range(self.log_table.columnCount()):
                        self.log_table.item(row, col).setForeground(QColor("#ECF0F1"))
            else:
                self.apply_log_colors()
        elif current_index == 1 and self.original_process_data:
            self.handle_running_processes(self.original_process_data, None)

    # ---------------- NETWORK FILTERING ----------------
    def fetch_network_connections(self):
        worker = CommandWorker(["netstat", "-an"], functions.parse_network_connections)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_network_connections(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_network_connections(self, data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        self.original_network_conn_data = data
        self.populate_network_connections_table(data)

    def populate_network_connections_table(self, data: dict):
        entries = data.get("entries", [])
        if not entries:
            self.network_conn_table.setRowCount(0)
            self.network_conn_table.setColumnCount(0)
            return
        columns = list(entries[0].keys())
        self.network_conn_table.setColumnCount(len(columns))
        self.network_conn_table.setHorizontalHeaderLabels(columns)
        self.network_conn_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for col, key in enumerate(columns):
                item = QTableWidgetItem(str(entry.get(key, "")))
                self.network_conn_table.setItem(row, col, item)
        self.network_conn_table.resizeColumnsToContents()

    def apply_network_logs_filter(self):
        keyword = self.netlogs_filter_input.text().strip().lower()
        if not keyword or not self.original_network_logs_data:
            return
        filtered_entries = []
        for entry in self.original_network_logs_data["entries"]:
            if keyword in str(entry.get("Line", "")).lower():
                filtered_entries.append(entry)
        filtered = {"entries": filtered_entries}
        self.populate_network_logs_table(filtered)

    def clear_network_logs_filter(self):
        self.netlogs_filter_input.clear()
        if self.original_network_logs_data:
            self.populate_network_logs_table(self.original_network_logs_data)

    def populate_network_logs_table(self, data: dict):
        entries = data.get("entries", [])
        if not entries:
            self.network_logs_table.setRowCount(0)
            self.network_logs_table.setColumnCount(0)
            return
        columns = list(entries[0].keys())
        self.network_logs_table.setColumnCount(len(columns))
        self.network_logs_table.setHorizontalHeaderLabels(columns)
        self.network_logs_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for col, key in enumerate(columns):
                item = QTableWidgetItem(str(entry.get(key, "")))
                self.network_logs_table.setItem(row, col, item)
        self.network_logs_table.resizeColumnsToContents()

    def fetch_network_logs(self):
        worker = CommandWorker(["netstat", "-an"], functions.parse_network_logs)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_network_logs(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def handle_network_logs(self, data: dict, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        self.original_network_logs_data = data
        self.populate_network_logs_table(data)

    # ---------------- USERS ----------------
    def fetch_all_users(self):
        worker = CommandWorker(["dscl", ".", "-list", "/Users"], self.parse_defined_users)
        self.workers.append(worker)
        worker.finished.connect(lambda data, w=worker: self.handle_defined_users(data, w))
        worker.error.connect(lambda err, w=worker: self.handle_worker_error(err, w))
        worker.start()

    def parse_defined_users(self, output: str) -> dict:
        lines = output.strip().splitlines()
        return {"timestamp": "dscl-users", "type": "defined_users", "entries": lines}

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
        for u in defined_users:
            info = last_logins.get(u, "")
            combined_list.append((u, info, "System User"))
        for entry in login_data.get("entries", []):
            user = entry.get("user", "")
            if user not in defined_users:
                dt = entry.get("date_time", "")
                combined_list.append((user, dt, "Regular User"))
        self.users_table.setRowCount(len(combined_list))
        for row, (username, last_dt, utype) in enumerate(combined_list):
            user_item = QTableWidgetItem(username)
            login_item = QTableWidgetItem(last_dt)
            type_item = QTableWidgetItem(utype)
            color = get_user_color(utype)
            user_item.setForeground(color)
            login_item.setForeground(color)
            type_item.setForeground(color)
            self.users_table.setItem(row, 0, user_item)
            self.users_table.setItem(row, 1, login_item)
            self.users_table.setItem(row, 2, type_item)
        self.users_table.resizeColumnsToContents()

    # ---------------- ERROR HANDLING ----------------
    def handle_worker_error(self, error_message: str, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        logging.error(f"Worker error: {error_message}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.ColorRole.Window, QColor("#1C1C1C"))
    dark_palette.setColor(QPalette.ColorRole.WindowText, QColor("#ECF0F1"))
    dark_palette.setColor(QPalette.ColorRole.Base, QColor("#2C3E50"))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#34495E"))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#ECF0F1"))
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#FFFFFF"))
    dark_palette.setColor(QPalette.ColorRole.Text, QColor("#ECF0F1"))
    dark_palette.setColor(QPalette.ColorRole.Button, QColor("#34495E"))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor("#ECF0F1"))
    dark_palette.setColor(QPalette.ColorRole.BrightText, QColor("#FF0000"))
    dark_palette.setColor(QPalette.ColorRole.Link, QColor("#E67E22"))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor("#2980B9"))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
    app.setPalette(dark_palette)

    viewer = LogViewer()
    viewer.show()
    sys.exit(app.exec())

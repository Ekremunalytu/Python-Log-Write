from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QHBoxLayout, QComboBox, QInputDialog
import json
import os
import functions  # Import log functions

class LogViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.original_data = None  # Store unfiltered data

    def initUI(self):
        self.setWindowTitle("macOS Log Management App")
        self.setGeometry(100, 100, 1024, 768)

        layout = QVBoxLayout()
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.log_button = QPushButton("View Last Log History")
        self.log_button.clicked.connect(lambda: self.load_data("login_history.json", functions.logininfo))
        
        self.process_button = QPushButton("View Running Processes")
        self.process_button.clicked.connect(lambda: self.load_data("running_processes.json", functions.get_running_processes))
        
        self.system_log_button = QPushButton("View System Logs")
        self.system_log_button.clicked.connect(lambda: self.load_data("system_log.json", functions.read_system_log))
        
        self.firewall_button = QPushButton("View Firewall Rules")
        self.firewall_button.clicked.connect(self.get_firewall_logs)
        
        btn_layout.addWidget(self.log_button)
        btn_layout.addWidget(self.process_button)
        btn_layout.addWidget(self.system_log_button)
        btn_layout.addWidget(self.firewall_button)
        layout.addLayout(btn_layout)
        
        # Output Display
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)
        
        # Filter Section
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

    def load_data(self, filename, generate_function):
        """ Update log file and load data into UI. """
        generate_function()  # Always refresh log file on button click

        if not os.path.exists(filename):
            print(f"Error: {filename} not found.")
            return

        try:
            with open(filename, "r") as file:
                self.original_data = json.load(file)  # Store unfiltered data
                formatted_data = json.dumps(self.original_data, indent=4)
                self.output_text.setPlainText(formatted_data)
                
                # Reset filter options
                self.filter_field.clear()
                self.filter_field.addItem("All Fields")

                # Populate filter dropdown if there are entries
                if "entries" in self.original_data and len(self.original_data["entries"]) > 0:
                    for key in self.original_data["entries"][0].keys():
                        self.filter_field.addItem(key)

            self.search_label.setText("Searching for: ")
        except Exception as e:
            self.output_text.setPlainText(f"Error: {e}")

    def apply_filter(self):
        """ Apply filtering based on user input. """
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
                filtered_data["entries"] = [entry for entry in self.original_data["entries"] if keyword in json.dumps(entry).lower()]
            else:
                filtered_data["entries"] = [entry for entry in self.original_data["entries"] if selected_field in entry and keyword in str(entry[selected_field]).lower()]

            self.output_text.setPlainText(json.dumps(filtered_data, indent=4))
        except Exception as e:
            self.output_text.setPlainText(f"Error filtering data: {e}")

    def clear_filter(self):
        """ Reset to original data. """
        if self.original_data:
            self.output_text.setPlainText(json.dumps(self.original_data, indent=4))
            self.search_label.setText("Searching for: ")
            self.filter_input.clear()

    def get_firewall_logs(self):
        """ Prompt user for sudo password and fetch firewall logs. """
        password, ok = QInputDialog.getText(self, "Password", "Enter your sudo password:", QLineEdit.EchoMode.Password)
        if ok and password:
            functions.get_firewall_rules(password)
            self.load_data("firewall_logs.json", lambda: None)

if __name__ == "__main__":
    app = QApplication([])
    viewer = LogViewer()
    viewer.show()
    app.exec()

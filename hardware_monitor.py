import time
import psutil
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QWidget, QVBoxLayout
import matplotlib
matplotlib.use('QtAgg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

class HardwareUsageWidget(QWidget):
    """
    A more detailed hardware usage widget showing:
    - Per-core CPU usage (with multiple colored lines)
    - Memory usage on a second Y-axis
    - Data retained for the last 60 seconds
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.num_cores = psutil.cpu_count(logical=True)
        self.core_usage_data = [[] for _ in range(self.num_cores)]
        self.mem_data = []
        self.time_data = []
        self.start_time = time.time()

        self.initUI()

        # Timer to update usage data every second
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_data)
        self.timer.start(1000)  # 1 second

    def initUI(self):
        layout = QVBoxLayout(self)
        self.figure = Figure(figsize=(5, 3))
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        # Primary axis for CPU usage
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title("Hardware Usage")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("CPU Usage (%)")

        # Secondary axis for memory usage
        self.ax2 = self.ax.twinx()
        self.ax2.set_ylabel("Memory Usage (%)")

        # A set of bright colors that still look good on a dark theme
        color_palette = [
            "#FF5733", "#FFC300", "#DAF7A6", "#C70039",
            "#900C3F", "#581845", "#28B463", "#1F618D",
            "#BA4A00", "#6C3483", "#117864", "#5D6D7E"
        ]

        # Lines for each CPU core
        self.cpu_lines = []
        for i in range(self.num_cores):
            color = color_palette[i % len(color_palette)]
            line, = self.ax.plot([], [], color=color, label=f"CPU {i}", linewidth=1.5)
            self.cpu_lines.append(line)

        # Memory usage line (thicker line, different color)
        self.mem_line, = self.ax2.plot([], [], color="#FF00FF", label="Memory", linewidth=2)

        # Create a combined legend
        cpu_labels = [f"CPU {i}" for i in range(self.num_cores)]
        all_lines = self.cpu_lines + [self.mem_line]
        all_labels = cpu_labels + ["Memory"]
        self.ax.legend(all_lines, all_labels, loc="upper right")

        self.canvas.draw()

    def update_data(self):
        current_time = time.time() - self.start_time

        # Per-core CPU usage
        core_usages = psutil.cpu_percent(percpu=True)
        for i, usage in enumerate(core_usages):
            self.core_usage_data[i].append(usage)

        # Memory usage
        mem_usage = psutil.virtual_memory().percent
        self.mem_data.append(mem_usage)

        self.time_data.append(current_time)

        # Keep data for only the last 60 seconds
        while self.time_data and (current_time - self.time_data[0] > 60):
            self.time_data.pop(0)
            for core_data in self.core_usage_data:
                core_data.pop(0)
            self.mem_data.pop(0)

        # Update lines
        for i in range(self.num_cores):
            self.cpu_lines[i].set_data(self.time_data, self.core_usage_data[i])
        self.mem_line.set_data(self.time_data, self.mem_data)

        # Rescale axes
        self.ax.relim()
        self.ax.autoscale_view()
        self.ax2.relim()
        self.ax2.autoscale_view()

        self.canvas.draw()

import time
import psutil
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import QWidget, QHBoxLayout
from PyQt6.QtGui import QPainter, QPen, QFont, QColor

class CircularGauge(QWidget):
    def __init__(self, label, parent=None):
        super().__init__(parent)
        self.value = 0  # percentage (0-100)
        self.label = label
        self.setMinimumSize(150, 150)

    def setValue(self, value):
        self.value = value
        self.update()

    def paintEvent(self, event):
        width = self.width()
        height = self.height()
        side = min(width, height)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        # Center coordinate system
        painter.translate(width/2, height/2)
        scale = side / 200.0
        painter.scale(scale, scale)

        # Draw background circle
        pen = QPen(QColor("#555555"))
        pen.setWidth(10)
        painter.setPen(pen)
        painter.drawArc(-80, -80, 160, 160, 0, 360 * 16)

        # Draw usage arc
        pen = QPen(QColor("#FF5733") if self.label=="CPU Usage" else QColor("#33A1FF"))
        pen.setWidth(10)
        painter.setPen(pen)
        angle = int(360 * (self.value / 100.0))
        # Draw from top (90°) counter-clockwise
        painter.drawArc(-80, -80, 160, 160, 90 * 16, -angle * 16)

        # Draw text (percentage)
        painter.setPen(QColor("#FFFFFF"))
        font = QFont("Segoe UI", 20, QFont.Weight.Bold)
        painter.setFont(font)
        text = f"{self.value:.0f}%"
        fm = painter.fontMetrics()
        text_width = fm.horizontalAdvance(text)
        # Cast x-coordinate to int
        painter.drawText(int(-text_width/2), 10, text)

        # Draw label below
        font = QFont("Segoe UI", 12)
        painter.setFont(font)
        label_width = painter.fontMetrics().horizontalAdvance(self.label)
        painter.drawText(int(-label_width/2), 50, self.label)

class HardwareGaugeWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.cpuGauge = CircularGauge("CPU Usage")
        self.memGauge = CircularGauge("Memory Usage")
        layout = QHBoxLayout()
        layout.addWidget(self.cpuGauge)
        layout.addWidget(self.memGauge)
        self.setLayout(layout)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.updateValues)
        self.timer.start(1000)  # update every second

    def updateValues(self):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        self.cpuGauge.setValue(cpu)
        self.memGauge.setValue(mem)

# Expose the widget as HardwareUsageWidget for compatibility with main.py
HardwareUsageWidget = HardwareGaugeWidget

import sys
import json
import socket
import datetime
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout,
    QTextEdit, QFrame, QStackedWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt

# 📡 Server Thread to Receive Intrusion Alerts from monitor.py
class AlertReceiver(QThread):
    """Listens for alerts from monitor.py and sends them to the UI."""
    new_alert = pyqtSignal(str, str)

    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 5001))  # Must match monitor.py's `send_alert_to_dashboard()`
        server.listen(5)
        print("📡 Listening for alerts on port 5001...")

        while True:
            client, addr = server.accept()
            data = client.recv(1024).decode("utf-8")
            if data:
                alert = json.loads(data)
                ip = alert["ip"]
                action = "Blocked" if alert["intrusion_detected"] else "Allowed"
                self.new_alert.emit(ip, action)  # Send to UI
            client.close()

# 🛡️ Intrusion Detection Dashboard (Integrated with monitor.py)
class IntrusionDashboard(QWidget):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.setWindowTitle("Intrusion Detection Dashboard")
        self.setGeometry(100, 100, 1024, 600)
        self.setStyleSheet("background-color: white; font-family: Arial;")

        # Intrusion Counters
        self.intrusions_count = 0
        self.frozen_count = 0
        self.allowed_count = 0

        # Main Layout: Sidebar + Main Content
        main_layout = QHBoxLayout(self)

        # === Left Sidebar ===
        sidebar = QVBoxLayout()
        self.sidebar_frame = QFrame()
        self.sidebar_frame.setStyleSheet("background-color: #2C3E50; border-radius: 10px;")
        sidebar_layout = QVBoxLayout()

        self.dashboard_button = QPushButton("🏠 Dashboard")
        self.logs_button = QPushButton("📜 Logs")
        self.sidebar_exit_button = QPushButton("❌ Exit")

        for btn in [self.dashboard_button, self.logs_button, self.sidebar_exit_button]:
            btn.setStyleSheet("background: #34495E; color: white; padding: 10px; font-size: 16px; border-radius: 5px;")
            btn.setFixedHeight(40)
            sidebar_layout.addWidget(btn)

        self.sidebar_frame.setLayout(sidebar_layout)
        sidebar.addWidget(self.sidebar_frame)
        main_layout.addLayout(sidebar, 1)

        # === Main Content ===
        self.stacked_widget = QStackedWidget()
        self.dashboard_page = QWidget()
        self.logs_page = QWidget()

        # Dashboard UI
        self.dashboard_page.setLayout(QVBoxLayout())
        self.create_dashboard()
        self.create_logs_page()

        self.stacked_widget.addWidget(self.dashboard_page)
        self.stacked_widget.addWidget(self.logs_page)
        main_layout.addWidget(self.stacked_widget, 4)

        # Connect Buttons
        self.dashboard_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.dashboard_page))
        self.logs_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.logs_page))
        self.sidebar_exit_button.clicked.connect(self.close)

        # 📡 Start Alert Receiver
        self.alert_receiver = AlertReceiver()
        self.alert_receiver.new_alert.connect(self.handle_intrusion_alert)
        self.alert_receiver.start()

    def create_dashboard(self):
        """Create the main dashboard UI."""
        dashboard_layout = self.dashboard_page.layout()

        # === Metrics ===
        metrics_layout = QHBoxLayout()
        self.total_intrusions = self.create_metric_widget("🔴 Total Intrusions", "0", "#E74C3C")
        self.total_frozen = self.create_metric_widget("🛑 Frozen", "0", "#2980B9")
        self.total_allowed = self.create_metric_widget("✅ Allowed", "0", "#27AE60")

        for widget in [self.total_intrusions, self.total_frozen, self.total_allowed]:
            metrics_layout.addWidget(widget)
        dashboard_layout.addLayout(metrics_layout)

        # === Pie Chart ===
        self.figure, self.ax = plt.subplots(figsize=(3.5, 3.5))
        self.pie_canvas = FigureCanvas(self.figure)
        self.update_pie_chart()
        dashboard_layout.addWidget(self.pie_canvas)

        # === Logs ===
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Arial", 12))
        dashboard_layout.addWidget(self.log_display)

    def create_logs_page(self):
        """Create the logs page UI."""
        layout = QVBoxLayout(self.logs_page)
        logs_label = QLabel("📜 Intrusion Logs")
        logs_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        layout.addWidget(logs_label)
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Arial", 12))
        layout.addWidget(self.log_display)

    def create_metric_widget(self, title, value, color):
        """Helper to create metric summary widgets."""
        widget = QFrame()
        widget.setStyleSheet(f"background-color: {color}; color: white; padding: 10px; border-radius: 10px;")
        layout = QVBoxLayout()
        label = QLabel(title)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        widget.value_label = value_label  # Store reference for updates
        layout.addWidget(label)
        layout.addWidget(value_label)
        widget.setLayout(layout)
        return widget

    def update_pie_chart(self):
        """Update the matplotlib pie chart with intrusion data."""
        self.ax.clear()
        labels = ['Frozen', 'Allowed']
        sizes = [self.frozen_count, self.allowed_count]
        colors = ['#2980B9', '#27AE60']
        if sum(sizes) == 0:
            sizes = [1, 1]
        self.ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
        self.ax.set_title("Intrusion Status", fontsize=16)
        self.figure.tight_layout()
        self.pie_canvas.draw()

    def handle_intrusion_alert(self, ip, action):
        """Handle new intrusion alerts and update the UI."""
        self.intrusions_count += 1
        if action == "Blocked":
            self.frozen_count += 1
        else:
            self.allowed_count += 1

        # Update UI
        self.total_intrusions.value_label.setText(str(self.intrusions_count))
        self.total_frozen.value_label.setText(str(self.frozen_count))
        self.total_allowed.value_label.setText(str(self.allowed_count))
        self.update_pie_chart()

        # Log event
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {action} - {ip}"
        self.log_display.append(log_message)


# 🚀 Run Dashboard
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IntrusionDashboard()
    window.show()
    sys.exit(app.exec())
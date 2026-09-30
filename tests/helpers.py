import os
import socket
import subprocess

PROJECT_ROOT: str = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVER_BIN: str = os.path.join(PROJECT_ROOT, "build", "bin", "crypto_server")
CERTS_DIR: str = os.path.join(PROJECT_ROOT, "certs", "trusted")
KEYS_DIR: str = os.path.join(PROJECT_ROOT, "certs", "keys")
SIGN_SCRIPT: str = os.path.join(PROJECT_ROOT, "scripts", "sign_script.sh")

def sign_payload(key_name: str, in_file: str, out_file: str) -> None:
    """Signs a bash script using the specified key."""
    key_path: str = os.path.join(KEYS_DIR, key_name)
    subprocess.run(
        ["bash", SIGN_SCRIPT, key_path, in_file, out_file],
        check=True,
        stdout=subprocess.DEVNULL
    )

def send_to_server(payload_bytes: bytes, uds_path: str) -> str:
    """Connects to the UDS, sends the payload, signals EOF, and returns response."""
    try:
        sock: socket.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(uds_path)
        sock.sendall(payload_bytes)
        sock.shutdown(socket.SHUT_WR)
        
        response: bytes = b""
        while True:
            data: bytes = sock.recv(4096)
            if not data:
                break
            response += data
            
        sock.close()
        return response.decode('utf-8')
    except Exception as e:
        return f"ERROR: {str(e)}"
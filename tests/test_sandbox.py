import pytest
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from helpers import sign_payload, send_to_server, SERVER_BIN, CERTS_DIR

def test_dos_protection_payload_size(server_daemon: str) -> None:
    """Payloads exceeding the MAX_PAYLOAD_SIZE must be dropped/rejected."""
    # Create a 1.5MB payload (Max is 1MB in server.h)
    dos_payload: bytes = b"# SIG: dummy\n" + (b"A" * (int(1.5 * 1024 * 1024)))
    
    response: str = send_to_server(dos_payload, server_daemon)
    assert "STATUS: APPROVED" not in response

def test_concurrent_requests(server_daemon: str, base_script: str, tmp_path: pytest.TempPath) -> None:
    """The daemon must correctly handle multiple concurrent execution requests."""
    signed_script: str = str(tmp_path / "t8_signed.sh")
    sign_payload("valid_codesign.key", base_script, signed_script)
    
    with open(signed_script, "rb") as f:
        payload: bytes = f.read()

    # Fire 5 concurrent requests simultaneously
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(send_to_server, payload, server_daemon) for _ in range(5)]
        
        for future in futures:
            response: str = future.result()
            assert "STATUS: APPROVED" in response
            assert "Hello from the secure sandbox" in response

def test_environment_sanitization(server_daemon: str, tmp_path: pytest.TempPath) -> None:
    """The sandbox must wipe all malicious environment variables and restrict PATH."""
    script_path: str = str(tmp_path / "t10.sh")
    with open(script_path, "w") as f:
        f.write("echo \"PATH IS $PATH\"\n")
        f.write("echo \"SECRET IS $SECRET_VAR\"\n")
        
    signed_script: str = str(tmp_path / "t10_signed.sh")
    sign_payload("valid_codesign.key", script_path, signed_script)
    
    with open(signed_script, "rb") as f:
        payload: bytes = f.read()

    response: str = send_to_server(payload, server_daemon)
    
    assert "STATUS: APPROVED" in response
    assert "PATH IS /usr/bin:/bin" in response
    assert "SECRET IS \n" in response # The variable should be completely empty


def test_cpu_timeout_enforcement(server_daemon: str, tmp_path: pytest.TempPath) -> None:
    """A script attempting an infinite CPU loop must be killed by the kernel via RLIMIT_CPU."""
    script_path: str = str(tmp_path / "cpu_hog.sh")
    with open(script_path, "w") as f:
        # A tight bash loop that instantly spikes CPU to 100%
        f.write("while true; do let 'i++'; done\n")
        
    signed_script: str = str(tmp_path / "cpu_hog_signed.sh")
    sign_payload("valid_codesign.key", script_path, signed_script)
    
    with open(signed_script, "rb") as f:
        payload: bytes = f.read()

    # NOTE: This test will take exactly 10 seconds to complete on the 'dev' profile 
    # because it is waiting for the Linux kernel to send SIGKILL to the process.
    response: str = send_to_server(payload, server_daemon)
    
    assert "STATUS: APPROVED" in response
    # Because the process was killed by a signal (SIGKILL), our C code's 
    # WIFEXITED(status) evaluates to false, which we mapped to -1.
    assert "EXIT CODE: -1" in response

def test_memory_exhaustion_enforcement(server_daemon: str, tmp_path: pytest.TempPath) -> None:
    """A script attempting to allocate massive memory must be killed by RLIMIT_AS."""
    script_path: str = str(tmp_path / "mem_hog.sh")
    with open(script_path, "w") as f:
        # Exponentially doubles a string's size in memory until it hits the limit
        f.write("str=\"A\"\nwhile true; do str=\"$str$str\"; done\n")
        
    signed_script: str = str(tmp_path / "mem_hog_signed.sh")
    sign_payload("valid_codesign.key", script_path, signed_script)
    
    with open(signed_script, "rb") as f:
        payload: bytes = f.read()

    response: str = send_to_server(payload, server_daemon)
    
    assert "STATUS: APPROVED" in response
    # Bash will abort when malloc fails or the kernel kills it
    assert "EXIT CODE: 0" not in response

def test_network_half_open_connection(server_daemon: str) -> None:
    """The server must cleanly tear down the child process if a client drops mid-transmission."""
    # We simulate a malicious client that opens a socket, sends the signature, 
    # but never sends the payload and never closes the connection properly.
    malformed_payload: bytes = b"# SIG: MEUCIQD...\n" 
    
    sock: socket.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(server_daemon)
    
    # Send a tiny bit of data, then violently close the socket without a graceful shutdown
    sock.sendall(malformed_payload)
    sock.close() 
    
    # The true test here isn't a specific string response (since we closed the socket), 
    # but that the server daemon DOES NOT crash. We test this by immediately verifying 
    # the server is still alive and answering new, valid requests.
    
    # Send a quick DoS payload to verify the server is still responsive
    dos_payload: bytes = b"# SIG: dummy\n" + (b"A" * (int(1.5 * 1024 * 1024)))
    response: str = send_to_server(dos_payload, server_daemon)
    
    # Server is alive and correctly enforcing limits
    assert "STATUS: APPROVED" not in response


def test_cli_argument_handling() -> None:
    """The server must reject invalid CLI arguments and print Usage instructions."""
    # 1. Missing arguments
    res1 = subprocess.run([SERVER_BIN], capture_output=True, text=True)
    assert res1.returncode != 0
    assert "Error: Must specify an IPC transport" in res1.stderr

    # 2. Help flag (or invalid flags)
    res2 = subprocess.run([SERVER_BIN, "-h"], capture_output=True, text=True)
    assert res2.returncode != 0
    assert "Usage:" in res2.stderr

def test_tcp_listener_and_missing_newline() -> None:
    """The server must bind via TCP if requested, and reject payloads without newlines."""
    port: str = "8888"
    
    # Start the server in TCP mode instead of Unix Domain Sockets
    server_proc = subprocess.Popen(
        [SERVER_BIN, "-c", CERTS_DIR, "-p", port],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(0.5) # Give it time to bind the TCP port
    
    try:
        # Connect via standard IPv4 TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", int(port)))
        
        # Send a payload that completely lacks a newline character (\n)
        sock.sendall(b"THIS_IS_INVALID_AND_HAS_NO_NEWLINE")
        sock.shutdown(socket.SHUT_WR)
        
        response = sock.recv(4096).decode('utf-8')
        sock.close()
        
        # Assert the server correctly parsed the missing newline via TCP
        assert "STATUS: REJECTED" in response
        assert "Malformed input, no newline" in response
        
    finally:
        # Clean up the background server
        server_proc.terminate()
        server_proc.wait()
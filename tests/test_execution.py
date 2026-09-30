import pytest
from helpers import sign_payload, send_to_server

def test_valid_script_execution(server_daemon: str, base_script: str, tmp_path: pathlib.Path) -> None:
    """A script signed by a valid code-signing cert must be APPROVED and executed."""
    signed_script: str = str(tmp_path / "t1_signed.sh")
    sign_payload("valid_codesign.key", base_script, signed_script)
    
    with open(signed_script, "rb") as f:
        payload: bytes = f.read()
        
    response: str = send_to_server(payload, server_daemon)
    assert "STATUS: APPROVED" in response
    assert "Hello from the secure sandbox" in response
    assert "EXIT CODE: 0" in response

def test_stderr_and_nonzero_exit(server_daemon: str, tmp_path: pathlib.Path) -> None:
    """The sandbox must correctly capture STDERR and return non-zero exit codes."""
    script_path: str = str(tmp_path / "t9.sh")
    with open(script_path, "w") as f:
        f.write(">&2 echo 'Critical failure simulated'\nexit 42\n")
        
    signed_script: str = str(tmp_path / "t9_signed.sh")
    sign_payload("valid_codesign.key", script_path, signed_script)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    assert "STATUS: APPROVED" in response
    assert "Critical failure simulated" in response
    assert "EXIT CODE: 42" in response

def test_empty_payload_handling(server_daemon: str, tmp_path: pathlib.Path) -> None:
    """A script containing ONLY a valid signature and no actual bash code must not crash."""
    script_path: str = str(tmp_path / "t11.sh")
    with open(script_path, "w") as f:
        f.write("") # Completely empty script
        
    signed_script: str = str(tmp_path / "t11_signed.sh")
    sign_payload("valid_codesign.key", script_path, signed_script)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    assert "STATUS: APPROVED" in response
    assert "EXIT CODE: 0" in response

def test_large_output_pipe_deadlock(server_daemon: str, tmp_path: pathlib.Path) -> None:
    """A script generating massive output must not deadlock the IPC pipes."""
    script_path: str = str(tmp_path / "t12.sh")
    with open(script_path, "w") as f:
        # Generate ~100KB of output, exceeding the standard 64KB Linux pipe buffer limit.
        # If the C server doesn't read the pipe asynchronously, this will hang forever.
        f.write("for i in {1..2000}; do echo 'This is a long line of output to test pipe buffer sizes'; done\n")
        
    signed_script: str = str(tmp_path / "t12_signed.sh")
    sign_payload("valid_codesign.key", script_path, signed_script)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    assert "STATUS: APPROVED" in response
    assert "EXIT CODE: 0" in response
    # Verify the output wasn't truncated by counting the expected lines
    assert response.count("This is a long line") == 2000

def test_bash_syntax_error(server_daemon: str, tmp_path: pathlib.Path) -> None:
    """A cryptographically valid script with invalid Bash syntax must fail gracefully."""
    script_path: str = str(tmp_path / "t13.sh")
    with open(script_path, "w") as f:
        # Deliberately missing the 'fi' to close the if statement
        f.write("if [ 1 -eq 1 ]; then\necho 'Missing fi'\n") 
        
    signed_script: str = str(tmp_path / "t13_signed.sh")
    sign_payload("valid_codesign.key", script_path, signed_script)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    assert "STATUS: APPROVED" in response
    assert "syntax error" in response.lower()
    # Bash syntax errors exit with code 2
    assert "EXIT CODE: 2" in response

def test_background_process_reaping(server_daemon: str, tmp_path: pathlib.Path) -> None:
    """A script that spawns a background process must not hang the executor's waitpid()."""
    script_path: str = str(tmp_path / "t14.sh")
    with open(script_path, "w") as f:
        # Spawns a background sleep, but the main script exits immediately
        f.write("sleep 2 &\necho 'Main script done'\n")
        
    signed_script: str = str(tmp_path / "t14_signed.sh")
    sign_payload("valid_codesign.key", script_path, signed_script)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    assert "STATUS: APPROVED" in response
    assert "Main script done" in response
    assert "EXIT CODE: 0" in response
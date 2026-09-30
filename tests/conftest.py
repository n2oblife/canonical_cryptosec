import time
import subprocess
from typing import Generator
import pytest
from helpers import SERVER_BIN, CERTS_DIR

@pytest.fixture(scope="session")
def server_daemon(tmp_path_factory: pytest.TempPathFactory) -> Generator[str, None, None]:
    """Spins up the C server daemon once for the entire test session."""
    run_dir = tmp_path_factory.mktemp("server_run")
    uds_path: str = str(run_dir / "sec_server.sock")
    
    server_proc: subprocess.Popen = subprocess.Popen(
        [SERVER_BIN, "-c", CERTS_DIR, "-u", uds_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(0.5) 
    
    yield uds_path
    
    server_proc.terminate()
    server_proc.wait()

@pytest.fixture
def base_script(tmp_path: pytest.TempPath) -> str:
    """Provides a basic valid bash script for testing in an isolated temp directory."""
    script_path: str = str(tmp_path / "base.sh")
    with open(script_path, "w") as f:
        f.write("echo 'Hello from the secure sandbox'\n")
    return script_path
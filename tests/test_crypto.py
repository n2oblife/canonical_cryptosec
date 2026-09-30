import pytest
import base64
from helpers import sign_payload, send_to_server

def test_tampered_script_rejection(server_daemon: str, base_script: str, tmp_path: pytest.TempPath) -> None:
    """A validly signed script whose payload is subsequently modified must be REJECTED."""
    signed_script: str = str(tmp_path / "t2_signed.sh")
    sign_payload("valid_codesign.key", base_script, signed_script)
    
    # Tamper with the payload after it was signed
    with open(signed_script, "ab") as f:
        f.write(b"echo 'Malicious Payload'\n")
        
    with open(signed_script, "rb") as f:
        payload: bytes = f.read()
        
    response: str = send_to_server(payload, server_daemon)
    assert "STATUS: REJECTED" in response
    assert "Cryptographic signature verification failed" in response

def test_malformed_signature_line(server_daemon: str) -> None:
    """A payload missing the # SIG: prefix must be REJECTED immediately."""
    malformed_payload: bytes = b"INVALID PREFIX: dummy\necho 'Test'"
    response: str = send_to_server(malformed_payload, server_daemon)
    assert "STATUS: REJECTED" in response
    assert "Missing or invalid '# SIG: ' prefix" in response


def test_invalid_base64_signature(server_daemon: str) -> None:
    """A payload with an invalid base64 alphabet in the signature line must be REJECTED."""
    # The signature contains characters that are illegal in base64 (!, @, #, etc.)
    malformed_payload: bytes = b"# SIG: INVALID_B64_!!!@@@\necho 'Test'"
    response: str = send_to_server(malformed_payload, server_daemon)
    
    assert "STATUS: REJECTED" in response
    assert "verification failed" in response

def test_garbage_asn1_signature(server_daemon: str) -> None:
    """A payload with valid base64 but completely invalid ASN.1 ECDSA data must be REJECTED."""
    # Encodes perfectly valid Base64, but the underlying bytes are NOT a valid DER signature.
    # This tests that OpenSSL's EVP_DigestVerifyFinal gracefully rejects garbage bytes without crashing.
    fake_raw_sig: bytes = b"This is definitely not an ECDSA signature"
    fake_b64: str = base64.b64encode(fake_raw_sig).decode('utf-8')
    
    payload: bytes = f"# SIG: {fake_b64}\necho 'Test'".encode('utf-8')
    response: str = send_to_server(payload, server_daemon)
    
    assert "STATUS: REJECTED" in response
    assert "Cryptographic signature verification failed" in response

def test_crlf_line_endings(server_daemon: str, base_script: str, tmp_path: pytest.TempPath) -> None:
    """A script signed on Linux but saved on Windows (CRLF endings) must still verify and be APPROVED."""
    signed_script: str = str(tmp_path / "crlf_signed.sh")
    sign_payload("valid_codesign.key", base_script, signed_script)
    
    with open(signed_script, "rb") as f:
        payload: bytes = f.read()
        
    # Manually inject a Windows Carriage Return '\r' before the first newline
    payload = payload.replace(b"\n", b"\r\n", 1)
        
    response: str = send_to_server(payload, server_daemon)
    
    assert "STATUS: APPROVED" in response
    assert "EXIT CODE: 0" in response

def test_signature_swapping_attack(server_daemon: str, tmp_path: pytest.TempPath) -> None:
    """A valid signature for Script A blindly attached to Script B must be REJECTED."""
    script_a: str = str(tmp_path / "script_a.sh")
    script_b: str = str(tmp_path / "script_b.sh")
    
    with open(script_a, "w") as f: f.write("echo 'I am benign'\n")
    with open(script_b, "w") as f: f.write("echo 'I am malicious'\n")
        
    signed_a: str = str(tmp_path / "script_a_signed.sh")
    sign_payload("valid_codesign.key", script_a, signed_a)
    
    # Read the valid signature line from Script A
    with open(signed_a, "rb") as f:
        valid_sig_line: bytes = f.readline()
        
    # Read the raw, unsigned payload of Script B
    with open(script_b, "rb") as f:
        malicious_payload: bytes = f.read()
        
    # Swap attack: Combine A's valid signature with B's payload
    swapped_attack_payload: bytes = valid_sig_line + malicious_payload
    
    response: str = send_to_server(swapped_attack_payload, server_daemon)
    
    assert "STATUS: REJECTED" in response
    assert "Cryptographic signature verification failed" in response
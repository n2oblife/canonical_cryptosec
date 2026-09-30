import os
import base64
import subprocess
import pytest
import datetime
from helpers import sign_payload, send_to_server

# --- Existing Core PKI Tests ---

def test_missing_eku_rejection(server_daemon: str, base_script: str, tmp_path: pytest.TempPath) -> None:
    """A signature from a trusted CA that lacks the codeSigning EKU must be REJECTED."""
    signed_script: str = str(tmp_path / "t3_signed.sh")
    sign_payload("invalid_no_eku.key", base_script, signed_script)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    assert "STATUS: REJECTED" in response
    assert "verification failed" in response

def test_untrusted_cert_rejection(server_daemon: str, base_script: str, tmp_path: pytest.TempPath) -> None:
    """A signature from a self-signed cert not in the trusted store must be REJECTED."""
    signed_script: str = str(tmp_path / "t4_signed.sh")
    sign_payload("untrusted.key", base_script, signed_script)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    assert "STATUS: REJECTED" in response


# --- Advanced Cryptographic Boundary & Policy Tests ---

def generate_custom_signature(key_type: str, hash_algo: str, script_in: str, script_out: str, tmp_path: pytest.TempPath) -> None:
    """Helper to dynamically generate adversarial keys and signatures on the fly."""
    key_path: str = str(tmp_path / f"temp_{key_type}.key")
    
    # Generate either an RSA or ECDSA key
    if key_type == "rsa":
        subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True, capture_output=True)
    else:
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key_path], check=True, capture_output=True)

    # Sign the payload using the specified hash algorithm (simulating a downgrade attack)
    raw_sig = subprocess.check_output(["openssl", "dgst", f"-{hash_algo}", "-sign", key_path, script_in])
    b64_sig = base64.b64encode(raw_sig).decode('utf-8')
    
    # Write the maliciously signed script
    with open(script_out, "w") as f:
        f.write(f"# SIG: {b64_sig}\n")
        with open(script_in, "r") as orig:
            f.write(orig.read())


def test_unauthorized_but_valid_ecdsa_key(server_daemon: str, base_script: str, tmp_path: pytest.TempPath) -> None:
    """A signature that is mathematically valid ECDSA, but whose key is NOT in the X.509 store, must be REJECTED."""
    signed_script: str = str(tmp_path / "rogue_ecdsa_signed.sh")
    
    # Generate a brand new ECDSA key that the server has never seen
    generate_custom_signature("ecdsa", "sha256", base_script, signed_script, tmp_path)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    assert "STATUS: REJECTED" in response

def test_algorithm_confusion_rsa_signature(server_daemon: str, base_script: str, tmp_path: pytest.TempPath) -> None:
    """An attacker signing with RSA instead of ECDSA must be gracefully REJECTED by OpenSSL EVP."""
    signed_script: str = str(tmp_path / "rsa_signed.sh")
    
    # Generate an RSA key (Algorithm Confusion Attack)
    generate_custom_signature("rsa", "sha256", base_script, signed_script, tmp_path)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    # Proves EVP_DigestVerify doesn't crash when comparing an RSA signature against an ECDSA public key
    assert "STATUS: REJECTED" in response

def test_hash_downgrade_attack_sha1(server_daemon: str, base_script: str, tmp_path: pytest.TempPath) -> None:
    """A FIPS 140-3 system must REJECT deprecated hash algorithms like SHA-1."""
    signed_script: str = str(tmp_path / "sha1_signed.sh")
    
    # Generate a valid ECDSA key, but sign using weak SHA-1 instead of SHA-256
    generate_custom_signature("ecdsa", "sha1", base_script, signed_script, tmp_path)
    
    with open(signed_script, "rb") as f:
        response: str = send_to_server(f.read(), server_daemon)
        
    # Because crypto.c explicitly hardcodes EVP_sha256() in EVP_DigestVerifyInit, 
    # OpenSSL will mathematically reject a SHA-1 signature.
    assert "STATUS: REJECTED" in response


def test_startup_cert_time_validations(tmp_path: pytest.TempPath) -> None:
    """The server must reject expired and not-yet-valid certificates at startup."""
    
    # We use pytest.importorskip to ensure the test fails gracefully if the library is missing
    cryptography = pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

def generate_time_shifted_cert(filename: str, days_offset_start: int, days_offset_end: int) -> None:
    """Forges a code-signing certificate shifted in time."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Time Edge Case Cert")])
    
    now = datetime.datetime.now(datetime.UTC)
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now + datetime.timedelta(days=days_offset_start))\
        .not_valid_after(now + datetime.timedelta(days=days_offset_end))\
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)\
        .sign(private_key, hashes.SHA256())
    
    with open(str(tmp_path / filename), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # 1. Generate an expired cert (Valid from 20 days ago, expired 10 days ago)
    generate_time_shifted_cert("expired.crt", -20, -10)

    # 2. Generate a future cert (Valid starting 10 days from now)
    generate_time_shifted_cert("future.crt", 10, 20)

    # 3. Start the server daemon manually, pointing it ONLY to our temporary directory
    # Note: We import SERVER_BIN locally to avoid circular dependency if you defined it in helpers
    from helpers import SERVER_BIN
    uds_path: str = str(tmp_path / "dummy.sock")

    result = subprocess.run(
        [SERVER_BIN, "-c", str(tmp_path), "-u", uds_path],
        capture_output=True,
        text=True
    )

    # 4. Assert the C daemon successfully caught the FIPS time boundaries and aborted
    assert result.returncode != 0
    assert "Cert is expired" in result.stderr
    assert "Cert is not yet valid" in result.stderr
    assert "No valid code-signing certificates found" in result.stderr


def test_server_startup_invalid_directories(tmp_path: pytest.TempPath) -> None:
    """T15: The server must refuse to start if the cert directory is missing or empty."""
    from helpers import SERVER_BIN
    uds_path: str = str(tmp_path / "dummy.sock")

    # 1. Test opendir() failure (Directory does not exist)
    missing_dir = str(tmp_path / "does_not_exist")
    res1 = subprocess.run([SERVER_BIN, "-c", missing_dir, "-u", uds_path], capture_output=True, text=True)
    assert res1.returncode != 0
    assert "Failed to open certificates directory" in res1.stderr

    # 2. Test sk_X509_num() == 0 (Directory exists, but has no certs)
    empty_dir = str(tmp_path / "empty_certs")
    import os
    os.mkdir(empty_dir)
    
    res2 = subprocess.run([SERVER_BIN, "-c", empty_dir, "-u", uds_path], capture_output=True, text=True)
    assert res2.returncode != 0
    assert "No valid code-signing certificates found" in res2.stderr
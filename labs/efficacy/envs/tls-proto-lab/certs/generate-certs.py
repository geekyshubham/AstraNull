#!/usr/bin/env python3
"""
Generate synthetic self-signed certificates for tls-proto-lab.
Keys are purely synthetic test fixtures for the local isolated lab environment.
"""

import os
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERTS_DIR = os.path.dirname(os.path.abspath(__file__))

def create_cert(cn, not_before, not_after, cert_filename, key_filename):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AstraNull Synthetic Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )

    cert_path = os.path.join(CERTS_DIR, cert_filename)
    key_path = os.path.join(CERTS_DIR, key_filename)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)
    print(f"Generated {cert_filename}: CN={cn}, valid from {not_before.isoformat()} to {not_after.isoformat()}")

if __name__ == "__main__":
    # 1. Expired certificate (expired Jan 1 2026, relative to Oct 17 2026)
    create_cert(
        cn="expired.tls-proto-lab.local",
        not_before=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        not_after=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        cert_filename="expired.crt",
        key_filename="expired.key",
    )

    # 2. Not-yet-valid certificate (valid starting Jan 1 2028, relative to Oct 17 2026)
    create_cert(
        cn="not-yet-valid.tls-proto-lab.local",
        not_before=datetime(2028, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        not_after=datetime(2029, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        cert_filename="not_yet_valid.crt",
        key_filename="not_yet_valid.key",
    )

    # 3. Valid certificate for HTTP/2 listener (valid 2025-2028)
    create_cert(
        cn="h2-unbounded.tls-proto-lab.local",
        not_before=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        not_after=datetime(2028, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        cert_filename="valid_h2.crt",
        key_filename="valid_h2.key",
    )

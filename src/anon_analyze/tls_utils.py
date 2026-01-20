"""TLS utilities for self-signed certificate generation."""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(
    output_dir: str = "/tmp/certs",  # nosec B108 - runs in isolated distroless container
    cert_filename: str = "cert.pem",
    key_filename: str = "key.pem",
) -> tuple[str, str]:
    """Generate a self-signed certificate and private key.

    Args:
        output_dir: Directory to write the certificate and key files.
        cert_filename: Filename for the certificate.
        key_filename: Filename for the private key.

    Returns:
        Tuple of (cert_path, key_path).
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    cert_path = output_path / cert_filename
    key_path = output_path / key_filename

    # Generate 2048-bit RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Build certificate subject and issuer
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    # Build certificate with SANs
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write private key
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Write certificate
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return str(cert_path), str(key_path)

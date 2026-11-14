
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


class FirmwareSecurity:

    def __init__(self, key_directory="keys"):
        self.key_directory = Path(key_directory)
        self.key_directory.mkdir(parents=True, exist_ok=True)

        self.private_key_path = self.key_directory / "private_key.pem"
        self.public_key_path = self.key_directory / "public_key.pem"

    def generate_keys(self):
        """Generate an Ed25519 signing key pair."""

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.private_key_path.write_bytes(private_bytes)
        self.public_key_path.write_bytes(public_bytes)

        return "Ed25519 key pair generated successfully."

    def load_private_key(self):
        return serialization.load_pem_private_key(
            self.private_key_path.read_bytes(),
            password=None
        )

    def load_public_key(self):
        return serialization.load_pem_public_key(
            self.public_key_path.read_bytes()
        )

    def calculate_hash(self, firmware_path):
        """Calculate SHA-256 hash of firmware."""

        firmware_data = Path(firmware_path).read_bytes()

        return hashlib.sha256(firmware_data).hexdigest()

    def sign_firmware(self, firmware_path):
        """Digitally sign firmware using the private key."""

        private_key = self.load_private_key()
        firmware_data = Path(firmware_path).read_bytes()

        signature = private_key.sign(firmware_data)

        signature_path = Path(str(firmware_path) + ".sig")
        signature_path.write_bytes(signature)

        return signature_path

    def verify_firmware(self, firmware_path, signature_path):
        """Verify firmware signature using the trusted public key."""

        public_key = self.load_public_key()
        firmware_data = Path(firmware_path).read_bytes()
        signature = Path(signature_path).read_bytes()

        try:
            public_key.verify(signature, firmware_data)
            return True, "Firmware signature is valid."

        except InvalidSignature:
            return False, "SECURITY ALERT: Firmware signature is invalid."

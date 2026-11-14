
from pathlib import Path
from security.firmware_security import FirmwareSecurity

ROOT = Path(__file__).parent

security = FirmwareSecurity(ROOT / "keys")

firmware = ROOT / "firmware" / "firmware_v1.2.bin"

if not firmware.is_file():
    raise FileNotFoundError(f"Firmware not found: {firmware}")

if not security.private_key_path.is_file():
    raise FileNotFoundError("Private signing key not found.")

signature_path = security.sign_firmware(firmware)

print("=== TRUSTCHARGE FIRMWARE SIGNING ===")
print("Firmware:", firmware.name)
print("SHA-256:", security.calculate_hash(firmware))
print("Signature:", signature_path.name)

valid, message = security.verify_firmware(
    firmware,
    signature_path
)

print("Verification:", message)
print("Signature valid:", valid)

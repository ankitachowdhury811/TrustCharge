
from pathlib import Path

from security.firmware_security import FirmwareSecurity


security = FirmwareSecurity()

firmware = Path("firmware/firmware_v1.1.bin")

print("=== TRUSTCHARGE FIRMWARE SECURITY TEST ===")

# 1. Generate signing keys
print("\n1. Generating cryptographic keys...")
print(security.generate_keys())

# 2. Calculate firmware hash
print("\n2. Calculating SHA-256 hash...")
print("SHA-256:", security.calculate_hash(firmware))

# 3. Sign firmware
print("\n3. Signing firmware...")
signature = security.sign_firmware(firmware)
print("Signature saved:", signature)

# 4. Verify genuine firmware
print("\n4. Verifying genuine firmware...")
valid, message = security.verify_firmware(firmware, signature)
print(message)

# 5. Simulate firmware tampering
print("\n5. Simulating firmware tampering...")

original_data = firmware.read_bytes()

try:
    firmware.write_bytes(original_data + b"\nUNAUTHORIZED MODIFICATION")

    valid, message = security.verify_firmware(firmware, signature)
    print(message)

finally:
    # Restore the original firmware
    firmware.write_bytes(original_data)

print("\n=== TEST COMPLETED ===")

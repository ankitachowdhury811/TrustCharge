
from pathlib import Path

from trustcharge import TrustCharge

root = Path(__file__).parent
tc = TrustCharge(root)

firmware = root / "firmware" / "firmware_v1.1.bin"
signature = root / "firmware" / "firmware_v1.1.bin.sig"

print("=== TRUSTCHARGE FIRMWARE INTEGRATION TEST ===")

print("\n1. Initial firmware state:")
print(tc.firmware_status())

print("\n2. Installing signed firmware:")
result = tc.install_signed_firmware(
    firmware,
    signature,
    "1.1.0"
)
print(result)

print("\n3. Checking installed firmware:")
print(tc.verify_installed_firmware())

print("\n4. Attempting rollback to version 1.0.0:")
rollback = tc.install_signed_firmware(
    firmware,
    signature,
    "1.0.0"
)
print(rollback)

print("\n5. Final firmware state:")
print(tc.firmware_status())

print("\n=== INTEGRATION TEST COMPLETED ===")

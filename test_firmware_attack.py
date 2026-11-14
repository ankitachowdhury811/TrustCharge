
from pathlib import Path
from trustcharge import TrustCharge

root = Path(__file__).parent
tc = TrustCharge(root)

firmware = root / "firmware" / "firmware_v1.1.bin"
signature = root / "firmware" / "firmware_v1.1.bin.sig"

original = firmware.read_bytes()

print("=== MODIFIED FIRMWARE ATTACK TEST ===")

try:
    firmware.write_bytes(
        original + b"\nUNAUTHORIZED MODIFICATION"
    )

    result = tc.install_signed_firmware(
        firmware,
        signature,
        "1.2.0"
    )

    print("Attack result:", result)

finally:
    firmware.write_bytes(original)

print("\nInstalled firmware state:")
print(tc.firmware_status())

print("\n=== ATTACK TEST COMPLETED ===")

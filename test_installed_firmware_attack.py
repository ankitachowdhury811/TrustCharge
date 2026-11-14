
from pathlib import Path
from trustcharge import TrustCharge

root = Path(__file__).parent
tc = TrustCharge(root)

print("=== INSTALLED FIRMWARE TAMPER TEST ===")

state = tc.firmware_status()

if not state.get("installed_file"):
    raise RuntimeError("No installed firmware found.")

firmware = (root / state["installed_file"]).resolve()
original_data = firmware.read_bytes()

print("\n1. Current firmware version:")
print(state["installed_version"])

print("\n2. Checking original firmware:")
print(tc.verify_installed_firmware())

try:
    print("\n3. Simulating unauthorized modification...")

    firmware.write_bytes(
        original_data + b"\nUNAUTHORIZED MODIFICATION"
    )

    print("\n4. Running integrity verification:")
    result = tc.verify_installed_firmware()
    print(result)

    assert result["status"] == "TAMPERED", (
        "Expected firmware tampering to be detected."
    )

    print("\nSUCCESS: Firmware tampering detected.")

finally:
    # Restore the original firmware for subsequent tests.
    firmware.write_bytes(original_data)

print("\n5. Verifying restored firmware:")
print(tc.verify_installed_firmware())

print("\n=== TEST COMPLETED ===")

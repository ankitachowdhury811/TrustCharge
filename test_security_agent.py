
from pathlib import Path

from charger.evse import EVChargingStation
from managed_components.security_agent import SecurityAgent


charger = EVChargingStation()
agent = SecurityAgent(charger)

print("=== TRUSTCHARGE SECURITY AGENT TEST ===")

# Test 1: Create configuration baseline
print("\n1. Creating configuration baseline...")
print(agent.create_configuration_baseline())

# Test 2: Verify unchanged configuration
print("\n2. Checking normal configuration...")
print(agent.verify_configuration())

# Test 3: Simulate unauthorized configuration change
print("\n3. Simulating configuration tampering...")
charger.configuration["max_current"] = 64
print(agent.verify_configuration())

# Restore the configuration for subsequent tests
charger.configuration["max_current"] = 32
charger.security_status = "SECURE"

# Test 4: Verify installed firmware
print("\n4. Checking installed firmware...")

firmware = Path("charger/installed/installed_firmware.bin")

if firmware.exists():
    print(agent.create_firmware_baseline(firmware))
    print(agent.verify_installed_firmware())

    # Simulate firmware modification
    print("\n5. Simulating installed firmware tampering...")

    original_data = firmware.read_bytes()

    try:
        firmware.write_bytes(original_data + b"\nUNAUTHORIZED CHANGE")
        print(agent.verify_installed_firmware())
    finally:
        firmware.write_bytes(original_data)
else:
    print("Firmware not installed yet. Complete the update test first.")

# Test 6: Simulate enclosure opening
print("\n6. Simulating enclosure tampering...")
charger.simulate_enclosure_open()
print(agent.check_enclosure())

print("\n7. Security audit log:")
print(Path("data/audit.json").read_text())

print("\n=== SECURITY AGENT TEST COMPLETED ===")

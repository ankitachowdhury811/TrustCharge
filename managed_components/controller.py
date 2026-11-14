
import shutil
from pathlib import Path

from charger.evse import EVChargingStation
from security.firmware_security import FirmwareSecurity


CONTROLLER_VERSION = "1.2.0"


class FirmwareUpdateController:

    def __init__(self, charger, security):
        self.charger = charger
        self.security = security

        self.installation_directory = Path("charger/installed")
        self.installation_directory.mkdir(
            parents=True, exist_ok=True
        )

    @staticmethod
    def parse_version(version):
        try:
            parts = tuple(int(part) for part in version.split("."))
            if len(parts) != 3 or any(part < 0 for part in parts):
                raise ValueError
            return parts
        except (ValueError, AttributeError):
            raise ValueError("Invalid firmware version format.")

    def install_update(self, firmware_path, signature_path, new_version):

        firmware_path = Path(firmware_path)
        signature_path = Path(signature_path)

        print("\n=== TRUSTCHARGE SECURE UPDATE ===")

        # 1. Check charger security state
        if self.charger.security_status != "SECURE":
            return False, "Update blocked: charger security is not secure."

        if not self.charger.enclosure_closed:
            return False, "Update blocked: charger enclosure is open."

        # 2. Validate firmware version
        try:
            current = self.parse_version(self.charger.firmware_version)
            incoming = self.parse_version(new_version)
        except ValueError as error:
            return False, str(error)

        if incoming <= current:
            return False, "Update rejected: rollback or duplicate version detected."

        # 3. Verify digital signature
        valid, message = self.security.verify_firmware(
            firmware_path, signature_path
        )

        print("Signature verification:", message)

        if not valid:
            return False, "Update rejected: firmware authenticity check failed."

        # 4. Calculate SHA-256 fingerprint
        firmware_hash = self.security.calculate_hash(firmware_path)

        print("SHA-256:", firmware_hash)

        # 5. Simulate firmware installation
        destination = self.installation_directory / "installed_firmware.bin"

        shutil.copy2(firmware_path, destination)

        # 6. Update charger version
        self.charger.firmware_version = ".".join(
            str(part) for part in incoming
        )

        return True, (
            f"Firmware update installed successfully. "
            f"New version: {self.charger.firmware_version}"
        )


if __name__ == "__main__":

    charger = EVChargingStation()
    security = FirmwareSecurity()

    controller = FirmwareUpdateController(charger, security)

    success, message = controller.install_update(
        firmware_path="firmware/firmware_v1.1.bin",
        signature_path="firmware/firmware_v1.1.bin.sig",
        new_version="1.1.0"
    )

    print("\nUpdate result:", message)
    print("Current charger firmware:", charger.firmware_version)


from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class EVChargingStation:
    charger_id: str = "TC-CHARGER-001"
    firmware_version: str = "1.0.0"
    charging_status: str = "IDLE"
    connected_vehicle: str | None = None
    enclosure_closed: bool = True
    security_status: str = "SECURE"

    configuration: dict = field(default_factory=lambda: {
        "max_voltage": 400,
        "max_current": 32,
        "charging_enabled": True
    })

    def connect_vehicle(self, vehicle_id: str):
        if not self.enclosure_closed:
            return "ERROR: Charger enclosure is open."

        self.connected_vehicle = vehicle_id
        self.charging_status = "CONNECTED"

        return f"Vehicle {vehicle_id} connected successfully."

    def start_charging(self):
        if not self.enclosure_closed:
            return "ERROR: Charging blocked. Enclosure tampering detected."

        if self.security_status != "SECURE":
            return "ERROR: Charging blocked. Security verification required."

        if not self.connected_vehicle:
            return "ERROR: No vehicle connected."

        if not self.configuration["charging_enabled"]:
            return "ERROR: Charging is disabled."

        self.charging_status = "CHARGING"
        return f"Charging started for {self.connected_vehicle}."

    def stop_charging(self):
        self.charging_status = "IDLE"
        self.connected_vehicle = None
        return "Charging stopped."

    def simulate_enclosure_open(self):
        self.enclosure_closed = False
        self.security_status = "TAMPER ALERT"
        self.charging_status = "ERROR"

        return "SECURITY ALERT: Charger enclosure opened!"

    def get_status(self):
        return {
            "charger_id": self.charger_id,
            "firmware_version": self.firmware_version,
            "charging_status": self.charging_status,
            "connected_vehicle": self.connected_vehicle,
            "enclosure_closed": self.enclosure_closed,
            "security_status": self.security_status,
            "timestamp": datetime.now().isoformat()
        }


if __name__ == "__main__":
    charger = EVChargingStation()

    print("=== TRUSTCHARGE EVSE SIMULATOR ===")
    print(charger.connect_vehicle("EV-001"))
    print(charger.start_charging())

    print("\nInitial charger status:")
    print(charger.get_status())

    print("\nSimulating physical tampering:")
    print(charger.simulate_enclosure_open())

    print("\nFinal charger status:")
    print(charger.get_status())

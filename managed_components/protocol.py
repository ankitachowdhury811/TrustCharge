
from datetime import datetime, timezone


PROTOCOL_VERSION = "1.2.0"


class ChargingProtocolAdapter:

    def __init__(self, charger):
        self.charger = charger
        self.session_id = None
        self.session_history = []

    def _record(self, event, result):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "charger_id": self.charger.charger_id,
            "session_id": self.session_id,
            "event": event,
            "result": result
        }

        self.session_history.append(record)
        return record

    def connect_vehicle(self, vehicle_id):
        if self.charger.security_status != "SECURE":
            return self._record(
                "CONNECT",
                "REJECTED: Charger security verification required."
            )

        if self.session_id is not None:
            return self._record(
                "CONNECT",
                "REJECTED: Another charging session is active."
            )

        if not self.charger.enclosure_closed:
            return self._record(
                "CONNECT",
                "REJECTED: Charger enclosure is open."
            )

        result = self.charger.connect_vehicle(vehicle_id)

        if result.startswith("Vehicle"):
            self.session_id = (
                f"{self.charger.charger_id}-"
                f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
            )

        return self._record("CONNECT", result)

    def start_charging(self):
        if self.session_id is None:
            return self._record(
                "START_CHARGING",
                "REJECTED: No active charging session."
            )

        result = self.charger.start_charging()

        return self._record("START_CHARGING", result)

    def stop_charging(self):
        if self.session_id is None:
            return self._record(
                "STOP_CHARGING",
                "REJECTED: No active charging session."
        )

        result = self.charger.stop_charging()

        # Preserve the session ID in the event record
        record = self._record("STOP_CHARGING", result)

        self.session_id = None

        return record

    def get_session_history(self):
        return self.session_history


if __name__ == "__main__":

    from charger.evse import EVChargingStation

    charger = EVChargingStation()
    protocol = ChargingProtocolAdapter(charger)

    print("=== TRUSTCHARGE CHARGING PROTOCOL TEST ===")

    print("\n1. Connecting vehicle:")
    print(protocol.connect_vehicle("EV-001"))

    print("\n2. Starting charging:")
    print(protocol.start_charging())

    print("\n3. Stopping charging:")
    print(protocol.stop_charging())

    print("\n4. Session history:")
    for event in protocol.get_session_history():
        print(event)

    print("\n=== PROTOCOL TEST COMPLETED ===")

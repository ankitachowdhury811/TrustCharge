
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path


AGENT_VERSION = "1.2.0"


class SecurityAgent:

    def __init__(
        self,
        charger,
        baseline_path="data/integrity_baseline.json",
        audit_path="data/audit.json"
    ):
        self.charger = charger
        self.baseline_path = Path(baseline_path)
        self.audit_path = Path(audit_path)

        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def calculate_hash(data):
        if isinstance(data, str):
            data = data.encode("utf-8")

        return hashlib.sha256(data).hexdigest()

    def record_event(self, event_type, severity, message):
        """Persist a security event in the audit log."""

        events = []

        if self.audit_path.exists():
            try:
                events = json.loads(self.audit_path.read_text())
                if not isinstance(events, list):
                    events = []
            except (json.JSONDecodeError, OSError):
                events = []

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "charger_id": self.charger.charger_id,
            "event_type": event_type,
            "severity": severity,
            "message": message
        }

        events.append(event)
        self.audit_path.write_text(json.dumps(events, indent=4))

        return event

    def create_configuration_baseline(self):
        """Create a trusted reference for charger configuration."""

        config_hash = self.calculate_hash(
            json.dumps(
                self.charger.configuration,
                sort_keys=True
            )
        )

        baseline = {}

        if self.baseline_path.exists():
            try:
                baseline = json.loads(self.baseline_path.read_text())
            except (json.JSONDecodeError, OSError):
                baseline = {}

        baseline["configuration_sha256"] = config_hash
        baseline["charger_id"] = self.charger.charger_id

        self.baseline_path.write_text(json.dumps(baseline, indent=4))

        self.record_event(
            "CONFIGURATION_BASELINE_CREATED",
            "INFO",
            "Trusted configuration baseline created."
        )

        return config_hash

    def verify_configuration(self):
        """Compare current configuration with the trusted baseline."""

        if not self.baseline_path.exists():
            return False, "Configuration baseline not found."

        try:
            baseline = json.loads(self.baseline_path.read_text())
            trusted_hash = baseline["configuration_sha256"]
        except (json.JSONDecodeError, KeyError, OSError):
            return False, "Configuration baseline is invalid."

        current_hash = self.calculate_hash(
            json.dumps(
                self.charger.configuration,
                sort_keys=True
            )
        )

        if hmac.compare_digest(current_hash, trusted_hash):
            return True, "Configuration integrity verified."

        self.charger.security_status = "TAMPER ALERT"

        self.record_event(
            "CONFIGURATION_TAMPERING",
            "CRITICAL",
            "Unauthorized configuration modification detected."
        )

        return False, "SECURITY ALERT: Configuration tampering detected."

    def create_firmware_baseline(self, firmware_path):
        """Record the hash of an installed firmware image."""

        firmware_path = Path(firmware_path)

        if not firmware_path.is_file():
            return False, "Installed firmware not found."

        firmware_hash = self.calculate_hash(firmware_path.read_bytes())

        baseline = {}

        if self.baseline_path.exists():
            try:
                baseline = json.loads(self.baseline_path.read_text())
            except (json.JSONDecodeError, OSError):
                baseline = {}

        baseline["firmware_sha256"] = firmware_hash
        baseline["firmware_path"] = str(firmware_path)
        baseline["charger_id"] = self.charger.charger_id

        self.baseline_path.write_text(json.dumps(baseline, indent=4))

        self.record_event(
            "FIRMWARE_BASELINE_CREATED",
            "INFO",
            "Installed firmware integrity baseline created."
        )

        return True, firmware_hash

    def verify_installed_firmware(self):
        """Check installed firmware against its trusted hash."""

        if not self.baseline_path.exists():
            return False, "Firmware integrity baseline not found."

        try:
            baseline = json.loads(self.baseline_path.read_text())
            trusted_hash = baseline["firmware_sha256"]
            firmware_path = Path(baseline["firmware_path"])
        except (json.JSONDecodeError, KeyError, OSError):
            return False, "Firmware integrity baseline is invalid."

        if not firmware_path.is_file():
            self.charger.security_status = "TAMPER ALERT"
            return False, "SECURITY ALERT: Installed firmware is missing."

        current_hash = self.calculate_hash(firmware_path.read_bytes())

        if hmac.compare_digest(current_hash, trusted_hash):
            return True, "Installed firmware integrity verified."

        self.charger.security_status = "TAMPER ALERT"

        self.record_event(
            "FIRMWARE_TAMPERING",
            "CRITICAL",
            "Unauthorized modification of installed firmware detected."
        )

        return False, "SECURITY ALERT: Installed firmware was modified."

    def check_enclosure(self):
        """Monitor the simulated enclosure state."""

        if self.charger.enclosure_closed:
            return True, "Enclosure status normal."

        self.charger.security_status = "TAMPER ALERT"

        self.record_event(
            "ENCLOSURE_TAMPERING",
            "CRITICAL",
            "Charger enclosure opening detected."
        )

        return False, "SECURITY ALERT: Charger enclosure is open."

# DEMO_SUSPICIOUS_MARKER: simulated suspicious change

# DEMO_SUSPICIOUS_MARKER: simulated suspicious change

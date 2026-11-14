
from __future__ import annotations
from security.firmware_security import FirmwareSecurity
import hashlib, json, re, shutil
from datetime import datetime, timezone
from pathlib import Path

def now():
    return datetime.now(timezone.utc).isoformat()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

class TrustCharge:
    """Local EVSE lifecycle/security prototype. Managed files are sandbox fixtures, not real device firmware."""
    def __init__(self, root: Path):
        self.root = Path(root)
        self.data = self.root / "data"
        self.components_dir = self.root / "managed_components"
        self.catalog_dir = self.root / "update_catalog"
        self.data.mkdir(exist_ok=True)
        self.components_dir.mkdir(exist_ok=True)
        self.catalog_dir.mkdir(exist_ok=True)
        self.state_path = self.data / "evse_state.json"
        self.versions_path = self.data / "component_versions.json"
        self.baseline_path = self.data / "integrity_baseline.json"
        self.configuration_baseline_path = (
            self.data / "configuration_baseline.json"
        )
        self.audit_path = self.data / "audit.jsonl"
        self._seed_files()
        # Firmware security configuration
        self.firmware_security = FirmwareSecurity(
            self.root / "keys"
        )

        self.firmware_dir = self.root / "firmware"
        self.installed_firmware_dir = self.firmware_dir / "installed"
        self.installed_firmware_dir.mkdir(
            parents=True, exist_ok=True
        )

        self.firmware_state_path = (
            self.data / "firmware_state.json"
        )
        # Initialize simulated physical and configuration security state
        evse_state = self.get_evse()

        evse_state.setdefault("enclosure_closed", True)
        evse_state.setdefault("security_status", "SECURE")

        evse_state.setdefault("configuration", {
            "max_voltage": 400,
            "max_current": 32,
            "charging_enabled": True
        })

        self._save_evse(evse_state)

        if not self.firmware_state_path.exists():
            self._write_json(
                self.firmware_state_path,
                {
                    "installed_version": "1.0.0",
                    "installed_file": None,
                    "sha256": None
                }
            )

    def _write_json(self, path, value):
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _seed_files(self):
        components = {
            "evse_controller": ("controller.py", "# TrustCharge managed demo component: EVSE controller\nCONTROLLER_VERSION = '1.0.0'\n# Simulated contactor and session-state logic.\n"),
            "charging_protocol": ("protocol.py", "# TrustCharge managed demo component: charging protocol adapter\nPROTOCOL_VERSION = '1.2.0'\n# Simulated CCS message-state adapter; no vehicle communication occurs.\n"),
            "security_agent": ("security_agent.py", "# TrustCharge managed demo component: security agent\nAGENT_VERSION = '1.0.0'\n# Simulated integrity and audit agent.\n"),
        }
        self.component_map = {}
        for key, (filename, content) in components.items():
            path = self.components_dir / filename
            if not path.exists():
                path.write_text(content, encoding="utf-8")
            self.component_map[key] = path
        catalogue = {
            "evse_controller": {"version": "1.1.0", "minimum_secure_version": "1.0.0", "notes": "Controller input validation and session-state hardening", "content": "# TrustCharge managed demo component: EVSE controller\nCONTROLLER_VERSION = '1.1.0'\n# Update: stronger simulated session-state validation.\n"},
            "charging_protocol": {"version": "1.2.1", "minimum_secure_version": "1.2.1", "notes": "Fixes a simulated protocol-state validation advisory", "content": "# TrustCharge managed demo component: charging protocol adapter\nPROTOCOL_VERSION = '1.2.1'\n# Update: stricter simulated protocol-state validation.\n"},
            "security_agent": {"version": "1.1.0", "minimum_secure_version": "1.1.0", "notes": "Improves simulated audit-event validation", "content": "# TrustCharge managed demo component: security agent\nAGENT_VERSION = '1.1.0'\n# Update: improved audit-event validation.\n"},
        }
        for key, package in catalogue.items():
            package["content_sha256"] = hashlib.sha256(package["content"].encode("utf-8")).hexdigest()
            self._write_json(self.catalog_dir / f"{key}.json", package)

    def _versions(self):
        return json.loads(self.versions_path.read_text(encoding="utf-8"))

    def _set_version(self, key, version):
        versions = self._versions()
        versions[key] = version
        self._write_json(self.versions_path, versions)

    def _audit(self, action, status, details):
        event = {
            "timestamp_utc": now(),
            "action": action,
            "status": status,
            "details": details
        }
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")

    def create_configuration_baseline(self):
        state = self.get_evse()
        configuration = state.get("configuration", {})
        config_json = json.dumps(configuration, sort_keys=True)
        config_hash = hashlib.sha256(
            config_json.encode("utf-8")
        ).hexdigest()

        self._write_json(
            self.configuration_baseline_path,
            {
                "sha256": config_hash,
                "created_at": now()
            }
        )
        self._audit(
            "create_configuration_baseline",
            "SUCCESS",
            {"sha256": config_hash}
        )
        return config_hash

    def verify_configuration(self):
        if not self.configuration_baseline_path.exists():
            return {"status": "NO_BASELINE"}

        state = self.get_evse()
        configuration = state.get("configuration", {})
        config_json = json.dumps(configuration, sort_keys=True)
        current_hash = hashlib.sha256(
            config_json.encode("utf-8")
        ).hexdigest()

        baseline = json.loads(
            self.configuration_baseline_path.read_text(encoding="utf-8")
        )
        expected_hash = baseline.get("sha256")
        if expected_hash is None:
            return {"status": "INVALID_BASELINE"}

        if current_hash == expected_hash:
            result = {"status": "VERIFIED"}
        else:
            state["security_status"] = "TAMPER ALERT"
            state["charging"] = False
            state["message"] = "Configuration tampering detected."
            self._save_evse(state)
            result = {"status": "TAMPERED"}

        self._audit(
            "verify_configuration",
            result["status"],
            {"expected_sha256": expected_hash, "current_sha256": current_hash}
        )
        return result

    def recover_security(self):
        state = self.get_evse()

        # The enclosure must be closed.
        if not state.get("enclosure_closed", True):
            return {
                "status": "REJECTED",
                "details": "Enclosure is still open."
            }

        # Verify configuration integrity.
        config_result = self.verify_configuration()

        if config_result["status"] != "VERIFIED":
            return {
                "status": "REJECTED",
                "details": "Configuration integrity verification failed."
            }

        # Verify installed firmware integrity.
        firmware_result = self.verify_installed_firmware()

        if firmware_result["status"] != "VERIFIED":
            return {
                "status": "REJECTED",
                "details": "Firmware integrity verification failed."
            }

        # Clear the security alert only after all checks pass.
        state = self.get_evse()
        state["security_status"] = "SECURE"
        state["message"] = "Security verification successful. EVSE is secure."
        self._save_evse(state)

        self._audit(
            "security_recovery",
            "SUCCESS",
            {
                "configuration": "VERIFIED",
                "firmware": "VERIFIED",
                "enclosure_closed": True
            }
        )

        return {
            "status": "RECOVERED",
            "details": "All security checks passed."
        }

    def simulate_enclosure_open(self):
        state = self.get_evse()
        state["enclosure_closed"] = False
        state["security_status"] = "TAMPER ALERT"
        state["charging"] = False
        state["message"] = "SECURITY ALERT: Enclosure opened."
        self._save_evse(state)
        self._audit(
            "enclosure_tampering",
            "DETECTED",
            {"enclosure_closed": False}
        )
        return {"status": "TAMPER DETECTED"}

    def simulate_enclosure_close(self):
        state = self.get_evse()
        state["enclosure_closed"] = True
        state["message"] = "Enclosure closed. Security verification required."
        self._save_evse(state)
        self._audit("enclosure_closed", "RECORDED", {})
        return {"status": "ENCLOSURE CLOSED"}

    def firmware_status(self):
        """Return the currently installed firmware information."""
        return json.loads(
            self.firmware_state_path.read_text(encoding="utf-8")
        )

    def install_signed_firmware(
        self, firmware_path, signature_path, new_version
    ):
        """Verify and install a signed firmware package."""

        firmware_path = Path(firmware_path).resolve()
        signature_path = Path(signature_path).resolve()

        # Restrict package paths to this project.
        try:
            firmware_path.relative_to(self.root.resolve())
            signature_path.relative_to(self.root.resolve())
        except ValueError:
            return {
                "status": "REJECTED",
                "details": "Firmware package must be inside the project."
            }

        if not firmware_path.is_file() or not signature_path.is_file():
            return {
                "status": "REJECTED",
                "details": "Firmware binary or signature file is missing."
            }

        # Validate firmware version.
        try:
            incoming = self._version_tuple(new_version)
            current_state = self.firmware_status()
            installed = self._version_tuple(
                current_state["installed_version"]
            )

            if len(incoming) != 3 or any(x < 0 for x in incoming):
                raise ValueError

        except (ValueError, TypeError, KeyError):
            return {
                "status": "REJECTED",
                "details": "Invalid firmware version."
            }

        if incoming <= installed:
            self._audit(
                "firmware_update",
                "REJECTED",
                {"reason": "Rollback or duplicate version",
                 "requested_version": new_version}
            )
            return {
                "status": "REJECTED",
                "details": "Anti-rollback protection: version is not newer."
            }

        # Verify the digital signature using the trusted public key.
        try:
            valid, message = self.firmware_security.verify_firmware(
                firmware_path, signature_path
            )
        except (OSError, ValueError, TypeError) as error:
            valid, message = False, str(error)

        if not valid:
            self._audit(
                "firmware_update",
                "REJECTED",
                {"reason": message}
            )
            return {
                "status": "REJECTED",
                "details": message
            }

        # Calculate hash and install the verified package.
        firmware_hash = sha256_file(firmware_path)

        destination = (
            self.installed_firmware_dir / "installed_firmware.bin"
        )
        temporary = destination.with_suffix(".tmp")

        try:
            shutil.copyfile(firmware_path, temporary)
            temporary.replace(destination)
        except OSError as error:
            temporary.unlink(missing_ok=True)
            return {
                "status": "ERROR",
                "details": f"Installation failed: {error}"
            }

        # Persist installed version and integrity reference.
        new_state = {
            "installed_version": new_version,
            "installed_file": str(
                destination.relative_to(self.root)
            ),
            "sha256": firmware_hash
        }

        self._write_json(self.firmware_state_path, new_state)

        self._audit(
            "firmware_update",
            "INSTALLED",
            {
                "version": new_version,
                "sha256": firmware_hash
            }
        )

        return {
            "status": "INSTALLED",
            "details": f"Firmware {new_version} installed successfully.",
            "sha256": firmware_hash
        }

    def verify_installed_firmware(self):
        """Compare installed firmware against its stored hash."""

        state = self.firmware_status()
        filename = state.get("installed_file")
        expected = state.get("sha256")

        if not filename or not expected:
            return {
                "status": "NOT_INSTALLED",
                "details": "No installed firmware baseline is available."
            }

        firmware_path = (self.root / filename).resolve()

        try:
            firmware_path.relative_to(
                self.installed_firmware_dir.resolve()
            )
        except ValueError:
            return {
                "status": "ERROR",
                "details": "Invalid installed firmware path."
            }

        if not firmware_path.is_file():
            self._audit(
                "firmware_integrity",
                "MISSING",
                {"file": filename}
            )
            return {
                "status": "TAMPERED",
                "details": "Installed firmware file is missing."
            }

        actual = sha256_file(firmware_path)

        if actual != expected:
            self._audit(
                "firmware_integrity",
                "MISMATCH",
                {"expected": expected, "actual": actual}
            )
            return {
                "status": "TAMPERED",
                "details": "Installed firmware integrity mismatch."
            }

        self._audit(
            "firmware_integrity",
            "PASS",
            {"version": state["installed_version"]}
        )

        return {
            "status": "VERIFIED",
            "details": "Installed firmware integrity verified.",
            "sha256": actual
        }


    def read_audit(self):
        if not self.audit_path.exists():
            return []
        events = []
        for line in self.audit_path.read_text(encoding="utf-8").splitlines():
            try: events.append(json.loads(line))
            except json.JSONDecodeError: pass
        return events[::-1]

    def get_evse(self):
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _save_evse(self, state):
        self._write_json(self.state_path, state)

    def set_vehicle_connected(self, connected):
        state = self.get_evse()
        connected = bool(connected)
        if not connected:
            state["charging"] = False
            state["message"] = "Vehicle disconnected; charging stopped." if state["vehicle_connected"] else "EVSE available; waiting for a vehicle."
        else:
            state["message"] = "Vehicle connected; EVSE ready." if not state["error"] else "Vehicle connected, but charging is blocked by an EVSE fault."
        if connected != state["vehicle_connected"]:
            self._audit("vehicle_connection", "CHANGED", {"connected": connected})
        state["vehicle_connected"] = connected
        self._save_evse(state)

    def start_charging(self):
        state = self.get_evse()

        if (
            not state["vehicle_connected"]
            or state["error"]
            or state.get("security_status") != "SECURE"
            or not state.get("enclosure_closed", True)
        ):
            state["message"] = (
                "Charging blocked: vehicle must be connected, "
                "no fault may be active, and security must be verified."
            )
            self._save_evse(state)
            self._audit(
                "start_charging",
                "REJECTED",
                {
                    "connected": state["vehicle_connected"],
                    "error": state["error"],
                    "security_status": state.get("security_status"),
                    "enclosure_closed": state.get("enclosure_closed")
                }
            )
            return

        state["charging"] = True
        state["energy_kwh"] = round(state["energy_kwh"] + 0.25, 2)
        state["message"] = "Charging session active (simulated). Energy advances on each start action."
        self._save_evse(state)
        self._audit("start_charging", "STARTED", {"energy_kwh": state["energy_kwh"]})

    def stop_charging(self):
        state = self.get_evse()
        state["charging"] = False
        state["message"] = "Charging stopped."
        self._save_evse(state)
        self._audit("stop_charging", "STOPPED", {"energy_kwh": state["energy_kwh"]})

    def inject_fault(self):
        state = self.get_evse()
        state["error"] = True
        state["charging"] = False
        state["message"] = "Simulated EVSE fault: insulation-monitoring alarm."
        self._save_evse(state)
        self._audit("fault_injection", "FAULT", {"fault": "SIMULATED_INSULATION_ALARM"})

    def clear_fault(self):
        state = self.get_evse()
        state["error"] = False
        state["message"] = "Fault cleared; EVSE ready for a new session."
        self._save_evse(state)
        self._audit("clear_fault", "CLEARED", {})

    def component_inventory(self):
        versions = self._versions()
        baseline = json.loads(self.baseline_path.read_text(encoding="utf-8")) if self.baseline_path.exists() else {}
        rows = []
        for key, path in self.component_map.items():
            digest = sha256_file(path)
            expected = baseline.get(key, {}).get("sha256")
            rows.append({"component": key, "installed_version": versions.get(key, "unknown"), "file": path.name, "sha256_current": digest, "baseline_status": "MATCH" if expected == digest else "MISMATCH"})
        return rows

    def enroll_baseline(self, log=True):
        baseline = {}
        for key, path in self.component_map.items():
            baseline[key] = {"file": path.name, "sha256": sha256_file(path), "enrolled_utc": now()}
        self._write_json(self.baseline_path, baseline)
        if log: self._audit("enroll_integrity_baseline", "COMPLETED", {"components": list(baseline)})

    def verify_integrity(self):
        baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        results = []
        for key, path in self.component_map.items():
            actual = sha256_file(path)
            expected = baseline.get(key, {}).get("sha256")
            status = "MATCH" if expected == actual else "MISMATCH"
            results.append({"component": key, "file": path.name, "expected_sha256": expected, "actual_sha256": actual, "status": status})
            if status != "MATCH":
                self._audit("integrity_check", "MISMATCH", {"component": key, "expected": expected, "actual": actual})
        if all(r["status"] == "MATCH" for r in results):
            self._audit("integrity_check", "PASS", {"components_checked": len(results)})
        return results

    def available_updates(self):
        versions = self._versions()
        updates = []
        for key in self.component_map:
            package_path = self.catalog_dir / f"{key}.json"
            package = json.loads(package_path.read_text(encoding="utf-8"))
            installed = versions.get(key, "0.0.0")
            if self._version_tuple(package["version"]) > self._version_tuple(installed):
                updates.append({"component": key, "installed_version": installed, "available_version": package["version"], "package_sha256": hashlib.sha256(package["content"].encode()).hexdigest(), "release_notes": package["notes"]})
        return updates

    def install_update(self, key):
        if key not in self.component_map:
            return [{"component": key, "status": "REJECTED", "details": "Unknown managed component."}]
        path = self.catalog_dir / f"{key}.json"
        package = json.loads(path.read_text(encoding="utf-8"))
        content = package["content"].encode("utf-8")
        actual = hashlib.sha256(content).hexdigest()
        expected = hashlib.sha256(package["content"].encode("utf-8")).hexdigest()
        if actual != expected:
            self._audit("update_install", "REJECTED", {"component": key, "reason": "Package hash mismatch"})
            return [{"component": key, "status": "REJECTED", "details": "Package hash mismatch."}]
        installed = self._versions().get(key, "0.0.0")
        if self._version_tuple(package["version"]) <= self._version_tuple(installed):
            return [{"component": key, "status": "SKIPPED", "details": "Installed version is already current or newer."}]
        self.component_map[key].write_bytes(content)
        self._set_version(key, package["version"])
        baseline = json.loads(self.baseline_path.read_text(encoding="utf-8")) if self.baseline_path.exists() else {}
        baseline[key] = {"file": self.component_map[key].name, "sha256": sha256_file(self.component_map[key]), "enrolled_utc": now()}
        self._write_json(self.baseline_path, baseline)
        self._audit("update_install", "INSTALLED", {"component": key, "from": installed, "to": package["version"], "sha256": actual})
        return [{"component": key, "status": "INSTALLED", "details": f"{installed} → {package['version']}", "sha256": actual}]

    def install_all_updates(self):
        results = []
        for item in self.available_updates():
            results.extend(self.install_update(item["component"]))
        return results

    def tamper_component(self):
        key = "evse_controller"
        with self.component_map[key].open("a", encoding="utf-8") as f:
            f.write("\n# DEMO TAMPERING: unauthorized configuration change\n")
        self._audit("demo_tamper", "INJECTED", {"component": key})

    def inject_suspicious_marker(self):
        key = "security_agent"
        with self.component_map[key].open("a", encoding="utf-8") as f:
            f.write("\n# DEMO_SUSPICIOUS_MARKER: simulated suspicious change\n")
        self._audit("demo_suspicious_marker", "INJECTED", {"component": key})

    def security_findings(self):
        findings = []
        baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        versions = self._versions()
        marker_pattern = re.compile(r"DEMO_TAMPERING|DEMO_SUSPICIOUS_MARKER|TODO_INSECURE", re.IGNORECASE)
        for key, path in self.component_map.items():
            digest = sha256_file(path)
            expected = baseline.get(key, {}).get("sha256")
            if expected != digest:
                findings.append({"severity": "HIGH", "type": "INTEGRITY_MISMATCH", "component": key, "evidence": f"Expected {expected}; found {digest}", "recommendation": "Quarantine the changed component, investigate the source, then restore from a trusted package."})
            content = path.read_text(encoding="utf-8", errors="replace")
            if marker_pattern.search(content):
                findings.append({"severity": "HIGH", "type": "SUSPICIOUS_MARKER", "component": key, "evidence": "Known demo indicator string found in managed component", "recommendation": "Investigate the change; this indicator is a demo heuristic, not malware attribution."})
            package = json.loads((self.catalog_dir / f"{key}.json").read_text(encoding="utf-8"))
            if self._version_tuple(versions.get(key, "0.0.0")) < self._version_tuple(package["minimum_secure_version"]):
                findings.append({"severity": "MEDIUM", "type": "OUTDATED_COMPONENT", "component": key, "evidence": f"Installed {versions.get(key)}; advisory fixed in {package['minimum_secure_version']}", "recommendation": "Review the update and install the fixed version after package validation."})
        self._audit("security_scan", "FINDINGS" if findings else "CLEAN", {"finding_count": len(findings)})
        return findings

    @staticmethod
    def _version_tuple(version):
        try:
            return tuple(int(x) for x in str(version).split("."))
        except ValueError:
            return (0,)

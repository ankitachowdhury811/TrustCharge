from pathlib import Path
import streamlit as st
import pandas as pd
from trustcharge import TrustCharge

ROOT = Path(__file__).parent
tc = TrustCharge(ROOT)

st.set_page_config(page_title="TrustCharge | EVSE Security Operations", page_icon="🔌", layout="wide")
st.title("🔌 TrustCharge")
st.caption("EV charging station operations, component integrity, update management, and security monitoring")
st.warning("Prototype boundary: the EVSE, vehicle connection, and charging session are simulated. The integrity and update tabs use isolated demo component files; the actual project modules are kept separate and are not overwritten by demo updates.")

# Sidebar: operational simulator
st.sidebar.header("EVSE simulator")
connected = st.sidebar.toggle("Vehicle connected", value=tc.get_evse()["vehicle_connected"])
tc.set_vehicle_connected(connected)
evse = tc.get_evse()
st.sidebar.caption(f"Connector: {evse['connector_id']} · Mode: {evse['mode']}")
if connected:
    security_blocked = (
        evse.get("security_status", "SECURE") != "SECURE"
        or not evse.get("enclosure_closed", True)
    )
    if st.sidebar.button(
        "Start charging",
        use_container_width=True,
        disabled=evse["charging"] or evse["error"] or security_blocked
    ):
        tc.start_charging()
        st.rerun()
    if st.sidebar.button("Stop charging", use_container_width=True, disabled=not evse["charging"]):
        tc.stop_charging()
        st.rerun()
else:
    st.sidebar.button("Start charging", use_container_width=True, disabled=True)
if st.sidebar.button("Inject simulated EVSE fault", use_container_width=True):
    tc.inject_fault()
    st.rerun()
if st.sidebar.button("Clear simulated fault", use_container_width=True, disabled=not evse["error"]):
    tc.clear_fault()
    st.rerun()

evse = tc.get_evse()
security_alert = (
    evse.get("security_status", "SECURE") != "SECURE"
    or not evse.get("enclosure_closed", True)
)
status = (
    "SECURITY ALERT" if security_alert
    else "ERROR" if evse["error"]
    else "CHARGING" if evse["charging"]
    else "CONNECTED / READY" if evse["vehicle_connected"]
    else "AVAILABLE"
)
status_color = {
    "SECURITY ALERT": "🔴",
    "ERROR": "🔴",
    "CHARGING": "🟢",
    "CONNECTED / READY": "🔵",
    "AVAILABLE": "⚪"
}[status]
a,b,c,d = st.columns(4)
a.metric("Vehicle", "Connected" if evse["vehicle_connected"] else "Not connected")
b.metric("Charge status", status)
c.metric("Session energy", f"{evse['energy_kwh']:.2f} kWh")
d.metric(
    "EVSE health",
    "Security alert" if security_alert else ("Fault" if evse["error"] else "Normal")
)
st.caption(f"{status_color} {evse['message']}")
if security_alert:
    st.error("Charging is blocked while the EVSE security state is not SECURE.")

st.divider()
st.header("Software integrity and lifecycle")
x,y,z = st.columns(3)
x.metric("Managed components", len(tc.component_inventory()))
y.metric("Components with updates", len(tc.available_updates()))
z.metric("Security findings", len(tc.security_findings()))

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "Component integrity",
    "Updates & packages",
    "Security scan",
    "Audit trail",
    "Firmware Security",
    "EVSE Security"
])

with tab1:
    st.subheader("Verify hashes of managed components")
    st.write("TrustCharge computes SHA-256 from each component file and compares it with the enrolled integrity baseline.")
    if st.button("Verify all component hashes", type="primary"):
        results = tc.verify_integrity()
        st.session_state["integrity_results"] = results
    if st.button("Enroll current files as baseline", help="Use only after confirming the files are trusted. This replaces the stored reference hashes."):
        tc.enroll_baseline()
        st.success("Baseline enrolled from current component files. Only do this when you know the files are trusted.")
    if st.button("Demo: tamper with a component file"):
        tc.tamper_component()
        st.warning("A managed demo component file was modified. Run hash verification and the security scan to observe detection.")
    inventory = tc.component_inventory()
    if inventory:
        st.dataframe(pd.DataFrame(inventory), use_container_width=True, hide_index=True)
    results = st.session_state.get("integrity_results")
    if results:
        st.subheader("Latest hash verification")
        st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)
        if any(r["status"] != "MATCH" for r in results):
            st.error("Integrity mismatch detected. Do not install or trust the altered component.")
        else:
            st.success("All managed component hashes match the enrolled baseline.")

with tab2:
    st.subheader("Check update availability")
    st.write("The local update catalogue contains versioned demo packages. Update installation replaces only TrustCharge's managed sandbox component files.")
    if st.button("Check for updates", type="primary"):
        st.session_state["updates_checked"] = True
        st.session_state["available_updates"] = tc.available_updates()
    updates = tc.available_updates()
    if updates:
        st.dataframe(pd.DataFrame(updates), use_container_width=True, hide_index=True)
        if st.button("Install all verified updates", type="primary"):
            result = tc.install_all_updates()
            st.session_state["update_result"] = result
            st.rerun()
        if st.button("Install selected update"):
            st.info("Use the per-component selector below to install one update.")
        selected = st.selectbox("Component to update", options=[u["component"] for u in updates])
        if st.button(f"Install update for {selected}"):
            st.session_state["update_result"] = tc.install_update(selected)
            st.rerun()
    else:
        st.success("All managed components are at the catalogue's latest version.")
    if "update_result" in st.session_state:
        st.subheader("Update operation result")
        st.dataframe(pd.DataFrame(st.session_state["update_result"]), use_container_width=True, hide_index=True)

with tab3:
    st.subheader("Check for errors, malicious interference, and vulnerable patches")
    st.write("This scan combines file-integrity comparison, version/advisory checks, and simple indicators in the managed demo files. It is not a general-purpose malware scanner or a substitute for CVE/SBOM tooling.")
    if st.button("Run security scan", type="primary"):
        st.session_state["findings"] = tc.security_findings()
    if st.button("Demo: inject a suspicious marker"):
        tc.inject_suspicious_marker()
        st.warning("A harmless demo marker was added to a managed component file. Run the scan to detect it.")
    findings = st.session_state.get("findings", tc.security_findings())
    if findings:
        st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)
        critical = [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")]
        if critical:
            st.error(f"{len(critical)} high/critical finding(s) require investigation.")
        else:
            st.info("Findings are listed above. Review each finding and its evidence.")
    else:
        st.success("No findings detected by the current prototype checks.")

with tab4:
    st.subheader("Audit trail")
    st.write("Actions are appended to a local JSON Lines log with timestamps.")
    events = tc.read_audit()
    if events:
        st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
        st.download_button("Download audit log", data=tc.audit_path.read_text(encoding="utf-8"), file_name="trustcharge_audit.jsonl")
    else:
        st.info("No events recorded yet.")


with tab5:
    st.subheader("EVSE Firmware Security Management")

    st.write(
        "Verify firmware authenticity, monitor installed firmware "
        "integrity, and prevent unauthorized firmware updates."
    )

    firmware_state = tc.firmware_status()

    # Current firmware information
    st.subheader("Installed firmware")

    a, b, c = st.columns(3)

    a.metric(
        "Installed version",
        firmware_state["installed_version"]
    )

    a_path = firmware_state.get("installed_file")
    b.metric(
        "Firmware installed",
        "Yes" if a_path else "No"
    )

    c.metric(
        "SHA-256 reference",
        "Available" if firmware_state.get("sha256") else "Missing"
    )

    st.divider()

    # Installed firmware integrity
    st.subheader("Firmware integrity verification")

    if st.button("Verify installed firmware", key="verify_firmware"):
        result = tc.verify_installed_firmware()

        if result["status"] == "VERIFIED":
            st.success(result["details"])
        else:
            st.error(result["details"])

        st.json(result)

    st.divider()

    # Signed firmware installation
    st.subheader("Secure firmware installation")

    firmware_version = st.text_input(
        "Incoming firmware version",
        value="1.2.0",
        key="incoming_firmware_version"
    )

    firmware_file = (
        ROOT / "firmware" / "firmware_v1.2.bin"
    )

    signature_file = Path(
        str(firmware_file) + ".sig"
    )

    st.caption(
        "The dashboard uses a locally prepared firmware package "
        "and its detached digital signature."
    )

    st.write(
        "Firmware package:",
        firmware_file.name
    )

    if st.button(
        "Install and verify signed firmware",
        type="primary",
        key="install_signed_firmware"
    ):

        if not firmware_file.is_file():
            st.error("Firmware package not found.")

        elif not signature_file.is_file():
            st.error("Firmware signature file not found.")

        else:
            result = tc.install_signed_firmware(
                firmware_file,
                signature_file,
                firmware_version
            )

            if result["status"] == "INSTALLED":
                st.success(result["details"])
            else:
                st.error(result["details"])

            st.session_state["firmware_action_result"] = result
            st.rerun()

    if "firmware_action_result" in st.session_state:
        st.subheader("Latest firmware installation result")
        st.json(st.session_state["firmware_action_result"])

    st.divider()

    # Current firmware status
    st.subheader("Latest firmware security status")

    if st.button(
        "Refresh firmware status",
        key="refresh_firmware_status"
    ):
        st.rerun()

    st.json(tc.firmware_status())

    st.divider()

    st.subheader("Attack Simulation")
    
    # Attack 1: Firmware rollback
    st.markdown("#### 1. Firmware rollback attempt")

    if st.button("Simulate rollback to version 1.1.0"):
        rollback_result = tc.install_signed_firmware(
            ROOT / "firmware" / "firmware_v1.1.bin",
            ROOT / "firmware" / "firmware_v1.1.bin.sig",
            "1.1.0"
        )

        if rollback_result["status"] == "REJECTED":
            st.success("Rollback attack successfully blocked.")
        else:
            st.error("Unexpected rollback result.")

        st.json(rollback_result)

    # Attack 2: Modified firmware package
    st.markdown("#### 2. Modified firmware package")

    if st.button("Simulate malicious firmware modification"):
        package = ROOT / "firmware" / "firmware_v1.2.bin"
        signature = Path(str(package) + ".sig")

        if not package.is_file() or not signature.is_file():
            st.error("Firmware package or signature is missing.")
        else:
            original = package.read_bytes()

            try:
                package.write_bytes(
                    original + b"\nUNAUTHORIZED MODIFICATION"
                )

                result = tc.install_signed_firmware(
                    package,
                    signature,
                    "1.3.0"
                )

                if result["status"] == "REJECTED":
                    st.success("Modified firmware successfully rejected.")
                else:
                    st.error("Unexpected result: inspect installation state.")

                st.json(result)

            finally:
                package.write_bytes(original)

    # Attack 3: Installed firmware tampering
    st.markdown("#### 3. Installed firmware modification")

    if st.button("Simulate installed firmware tampering"):
        state = tc.firmware_status()
        filename = state.get("installed_file")

        if not filename:
            st.error("No installed firmware found.")
        else:
            # State files created on Windows may contain backslash separators.
            relative_name = Path(str(filename).replace("\\\\", "/").replace("\\", "/"))
            expected_directory = (ROOT / "firmware" / "installed").resolve()

            if relative_name.is_absolute() or ".." in relative_name.parts:
                st.error("Unsafe installed firmware path.")
            else:
                installed = (ROOT / relative_name).resolve()
                try:
                    installed.relative_to(expected_directory)
                    path_is_safe = True
                except ValueError:
                    path_is_safe = False

                if not path_is_safe:
                    st.error("Unexpected firmware installation path.")
                elif not installed.is_file():
                    st.error("Installed firmware file is missing.")
                else:
                    original = installed.read_bytes()
                    try:
                        installed.write_bytes(original + b"\\nTAMPERED")
                        result = tc.verify_installed_firmware()
                        if result["status"] == "TAMPERED":
                            st.success("Installed firmware tampering detected.")
                        else:
                            st.error("Unexpected integrity verification result.")
                        st.json(result)
                    finally:
                        installed.write_bytes(original)

                    restored = tc.verify_installed_firmware()
                    st.write("Post-test restoration verification:")
                    st.json(restored)

st.divider()
st.caption("Scope: local EVSE software prototype. It does not communicate with a real charger, vehicle, BMS, CCS controller, or OCPP backend. Do not use it to update production systems.")


with tab6:
    st.subheader("EVSE Configuration & Physical Security")

    st.write(
        "Monitor the simulated charger configuration, detect unauthorized "
        "configuration changes, simulate enclosure tampering, and perform "
        "controlled security recovery."
    )

    current_evse = tc.get_evse()
    security_status = current_evse.get("security_status", "SECURE")
    enclosure_closed = current_evse.get("enclosure_closed", True)

    status_col, enclosure_col, charging_col = st.columns(3)
    status_col.metric("Security status", security_status)
    enclosure_col.metric("Enclosure", "Closed" if enclosure_closed else "Open")
    charging_col.metric("Charging", "Active" if current_evse.get("charging") else "Stopped")

    if security_status == "SECURE" and enclosure_closed:
        st.success("EVSE security checks currently report a secure state.")
    else:
        st.error(
            "Security alert: charging is restricted until the enclosure is closed "
            "and all required integrity checks pass."
        )
    st.rerun()
    st.divider()
    st.subheader("Configuration integrity")

    st.write(
        "Create a SHA-256 baseline for the current simulated EVSE configuration, "
        "then compare the live configuration against that trusted reference."
    )

    baseline_col, verify_col = st.columns(2)

    if baseline_col.button(
        "Create configuration baseline",
        type="primary",
        key="create_config_baseline"
    ):
        baseline_hash = tc.create_configuration_baseline()
        st.session_state["evse_action_result"] = {
            "level": "success",
            "message": "Configuration baseline created.",
            "data": {"sha256": baseline_hash}
        }

    if verify_col.button(
        "Verify configuration",
        key="verify_config_integrity"
    ):
        config_result = tc.verify_configuration()
        if config_result["status"] == "VERIFIED":
            level, message = "success", "Configuration integrity verified."
        elif config_result["status"] == "TAMPERED":
            level, message = "error", "Configuration tampering detected. Charging has been blocked."
        else:
            level, message = "warning", "No configuration baseline exists. Create one first."
        st.session_state["evse_action_result"] = {
            "level": level, "message": message, "data": config_result
        }
    st.rerun()
    st.json(current_evse.get("configuration", {}))

    st.divider()
    st.subheader("Physical tamper simulation")

    st.caption(
        "These controls simulate enclosure state changes in software. "
        "They do not use a physical door sensor."
    )

    open_col, close_col = st.columns(2)

    if open_col.button(
        "Simulate enclosure opening",
        key="simulate_enclosure_open"
    ):
        result = tc.simulate_enclosure_open()
        st.session_state["evse_action_result"] = {
            "level": "error",
            "message": "Enclosure tampering detected. Charging has been stopped.",
            "data": result
        }
    st.rerun()
    if close_col.button(
        "Simulate enclosure closing",
        key="simulate_enclosure_close"
    ):
        result = tc.simulate_enclosure_close()
        st.session_state["evse_action_result"] = {
            "level": "warning",
            "message": "Enclosure closed. Existing security alerts remain active until verification and recovery.",
            "data": result
        }
    st.rerun()
    st.divider()
    st.subheader("Controlled security recovery")

    st.write(
        "Recovery is permitted only when the enclosure is closed, the "
        "configuration matches its baseline, and installed firmware integrity "
        "verification returns VERIFIED."
    )

    if st.button(
        "Run security checks and recover EVSE",
        type="primary",
        key="recover_evse_security"
    ):
        recovery_result = tc.recover_security()

        if recovery_result["status"] == "RECOVERED":
            level, message = "success", "Security recovery successful. EVSE returned to SECURE."
        else:
            level, message = "error", "Security recovery rejected. One or more checks failed."

        st.session_state["evse_action_result"] = {
            "level": level, "message": message, "data": recovery_result
        }
    st.rerun()
    # Render feedback after processing the current button press.
    # No explicit st.rerun() is used here, so the result remains on the page.
    saved_result = st.session_state.get("evse_action_result")
    if saved_result:
        result_level = saved_result.get("level", "info")
        result_message = saved_result.get("message", "Operation completed.")
        if result_level == "success":
            st.success(result_message)
        elif result_level == "warning":
            st.warning(result_message)
        elif result_level == "error":
            st.error(result_message)
        else:
            st.info(result_message)
        if saved_result.get("data") is not None:
            st.json(saved_result["data"])

    st.rerun()
    latest_evse = tc.get_evse()
    st.subheader("Current EVSE security state")
    st.json({
        "security_status": latest_evse.get("security_status"),
        "enclosure_closed": latest_evse.get("enclosure_closed"),
        "charging": latest_evse.get("charging"),
        "vehicle_connected": latest_evse.get("vehicle_connected"),
        "configuration": latest_evse.get("configuration"),
        "message": latest_evse.get("message")
    })

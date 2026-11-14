# TrustCharge v2 — EVSE Security Operations Prototype

## What this prototype demonstrates
- Vehicle connection state and simulated charging session state.
- Start/stop charging controls and simulated EVSE fault handling.
- SHA-256 hashing of real local managed-component files and comparison against an enrolled baseline.
- Local update catalogue with component versions and package content hashes.
- Update availability checks and installation of catalogue payloads into sandbox component files.
- Security findings for integrity mismatches, demo suspicious markers, and components below the catalogue's advisory fixed version.
- Local audit trail export.

## Setup (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## Run
Open the localhost URL Streamlit prints, usually http://localhost:8501.

## Reset demo state
Stop Streamlit, then delete the `data` folder. On next launch, TrustCharge recreates the initial state and hashes the current managed component files. To return component files to their original state, re-extract the project ZIP into a clean folder; deleting `data` alone does not undo component-file changes.

## Important limitations
This is a local educational prototype. The vehicle, EVSE, connector, charging session, and fault are simulated. Integrity checks hash real files within `managed_components`. Updates modify only those demo files, not real charger firmware or system packages. The catalogue is local and is not authenticated by an external vendor signing authority; package hash comparison detects accidental or post-catalogue modification only when the expected digest is independently trusted. The baseline is stored locally and could be modified by an attacker with filesystem access. The security scan uses a small advisory table and demo indicators, not a comprehensive CVE database, SBOM scanner, EDR, or malware-analysis engine. Do not connect this prototype to production charging equipment.

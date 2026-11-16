"""
TrustCharge simulated OEM firmware publisher.
Creates a new simulated firmware image and Ed25519 signature every 5 minutes.
Only firmware/releases/ is published to the separate firmware-releases branch.
"""
from __future__ import annotations
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_DIR = ROOT / "firmware"
RELEASE_DIR = FIRMWARE_DIR / "releases"
STATE_FILE = FIRMWARE_DIR / ".auto_publisher_state.json"
KEY_DIR = ROOT / "keys"
POLL_SECONDS = 300
RELEASE_BRANCH = "firmware-releases"
WORKTREE = ROOT.parent / f"{ROOT.name}_firmware_release_worktree"

sys.path.insert(0, str(ROOT))
from security.firmware_security import FirmwareSecurity


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"last_version": "1.4.0", "sequence": 0}


def next_version(state: dict) -> str:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", state.get("last_version", "1.4.0"))
    if not match:
        raise RuntimeError("Invalid version in firmware/.auto_publisher_state.json")
    major, minor, patch = map(int, match.groups())
    return f"{major}.{minor}.{patch + 1}"


def make_firmware(version: str, sequence: int) -> bytes:
    generated = datetime.now(timezone.utc).isoformat()
    return (
        "TRUSTCHARGE SIMULATED FIRMWARE\n"
        f"VERSION={version}\n"
        "CHARGER=TC-CHARGER-001\n"
        "FEATURE=FIRMWARE_UPDATE\n"
        f"RELEASE_SEQUENCE={sequence}\n"
        f"GENERATED_UTC={generated}\n"
        "NOTE=SIMULATED_OEM_PATCH_NOT_PRODUCTION_FIRMWARE\n"
    ).encode("utf-8")


def run_git(args, cwd: Path, check=True):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=check,
        text=True, capture_output=True
    )


def prepare_release_worktree() -> None:
    # Fetch the remote release branch if it already exists.
    run_git(["fetch", "origin", RELEASE_BRANCH], ROOT, check=False)

    if WORKTREE.exists():
        # Ensure this path is actually a registered Git worktree.
        probe = run_git(["rev-parse", "--is-inside-work-tree"], WORKTREE, check=False)
        if probe.returncode != 0:
            raise RuntimeError(
                f"{WORKTREE} exists but is not a Git worktree. "
                "Rename that folder and rerun."
            )
        run_git(["pull", "--ff-only", "origin", RELEASE_BRANCH], WORKTREE, check=False)
        return

    remote_ref = run_git(
        ["show-ref", "--verify", "--quiet", f"refs/remotes/origin/{RELEASE_BRANCH}"],
        ROOT, check=False
    ).returncode == 0
    local_ref = run_git(
        ["show-ref", "--verify", "--quiet", f"refs/heads/{RELEASE_BRANCH}"],
        ROOT, check=False
    ).returncode == 0

    if remote_ref and local_ref:
        run_git(["worktree", "add", str(WORKTREE), RELEASE_BRANCH], ROOT)
    elif remote_ref:
        run_git(["worktree", "add", "-b", RELEASE_BRANCH, str(WORKTREE),
                 f"origin/{RELEASE_BRANCH}"], ROOT)
    elif local_ref:
        run_git(["worktree", "add", str(WORKTREE), RELEASE_BRANCH], ROOT)
    else:
        run_git(["worktree", "add", "--orphan", "-b", RELEASE_BRANCH,
                 str(WORKTREE)], ROOT)


def publish_release_files(version: str) -> None:
    prepare_release_worktree()
    target = WORKTREE / "firmware" / "releases"
    target.mkdir(parents=True, exist_ok=True)

    # Copy only release artifacts. No app/backend/data/key files are staged.
    for source in RELEASE_DIR.iterdir():
        if source.is_file():
            shutil.copy2(source, target / source.name)

    run_git(["add", "firmware/releases"], WORKTREE)
    staged = run_git(["diff", "--cached", "--quiet"], WORKTREE, check=False)
    if staged.returncode == 0:
        print("No new release artifacts to publish.")
        return

    run_git(["-c", "user.name=TrustCharge Firmware Publisher",
             "-c", "user.email=firmware-publisher@users.noreply.github.com",
             "commit", "-m", f"Publish TrustCharge firmware v{version}"], WORKTREE)
    run_git(["push", "-u", "origin", RELEASE_BRANCH], WORKTREE)


def create_release(state: dict) -> dict:
    for required in (KEY_DIR / "private_key.pem", KEY_DIR / "public_key.pem"):
        if not required.is_file():
            raise RuntimeError(f"Required existing key not found: {required}")

    version = next_version(state)
    sequence = int(state.get("sequence", 0)) + 1
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)

    filename = f"firmware_v{version}.bin"
    package = RELEASE_DIR / filename
    signature_path = Path(str(package) + ".sig")
    metadata_path = Path(str(package) + ".json")

    content = make_firmware(version, sequence)
    package.write_bytes(content)

    security = FirmwareSecurity(KEY_DIR)
    generated_signature = security.sign_firmware(package)
    valid, message = security.verify_firmware(package, generated_signature)
    if not valid:
        raise RuntimeError(f"Ed25519 self-verification failed: {message}")

    metadata = {
        "schema_version": 1,
        "version": version,
        "filename": filename,
        "signature": signature_path.name,
        "signature_algorithm": "Ed25519",
        "sha256": sha256_bytes(content),
        "sequence": sequence,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "simulated": True
    }
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    # Publish first. Advance state only after the Git push succeeds.
    publish_release_files(version)

    state["last_version"] = version
    state["sequence"] = sequence
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print(f"[SUCCESS] Published firmware v{version}")
    print(f"  Binary:    {package}")
    print(f"  Signature: {signature_path}")
    print(f"  Metadata:  {metadata_path}")
    print(f"  SHA-256:   {metadata['sha256']}")
    return metadata


def main():
    once = "--once" in sys.argv[1:]
    print(f"TrustCharge firmware publisher; interval={POLL_SECONDS}s")
    while True:
        try:
            create_release(read_state())
        except Exception as exc:
            print(f"[ERROR] Release was not confirmed as published: {exc}", file=sys.stderr)
        if once:
            break
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()

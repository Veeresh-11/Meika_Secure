"""
TRACK D — Hardened External Verification CLI
"""

from __future__ import annotations

import sys
import json
import argparse
from pathlib import Path

from app.security.track_d.storage.sqlite_backend import SQLiteBackend
from app.security.track_d.signing.threshold_verifier import ThresholdVerifier
from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.governance.governance_registry import GovernanceRegistry
from app.security.track_d.audit.verification_ledger import VerificationLedger
from app.security.track_d.transparency.transparency_log import TransparencyLog


# ---------------------------------------------------------
# Constants
# ---------------------------------------------------------

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

EXIT_PASS = 0
EXIT_SIGNATURE_FAIL = 10
EXIT_GOVERNANCE_FAIL = 20
EXIT_TRANSPARENCY_FAIL = 30
EXIT_LEDGER_FAIL = 40
EXIT_DB_FAIL = 50
EXIT_INPUT_FAIL = 60
EXIT_UNKNOWN = 99


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _load_json_file(path_str: str):

    path = Path(path_str)

    if not path.exists() or not path.is_file():
        raise ValueError("Invalid file path")

    if path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("File too large")

    data = json.loads(path.read_text())

    if not isinstance(data, dict):
        raise ValueError("JSON root must be object")

    return data


def _validate_utc(ts: str):
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError("Invalid UTC timestamp")


# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="Meika External Verification CLI"
    )

    parser.add_argument("--payload", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--now", required=True)

    args = parser.parse_args()

    # ---------------------------------------------------------
    # Input Validation
    # ---------------------------------------------------------

    try:
        payload = _load_json_file(args.payload)
        signature = _load_json_file(args.signature)
        _validate_utc(args.now)
    except Exception as e:
        print(json.dumps({
            "status": "ERROR",
            "reason": str(e)
        }))
        sys.exit(EXIT_INPUT_FAIL)

    # ---------------------------------------------------------
    # Database Initialization
    # ---------------------------------------------------------

    try:
        backend = SQLiteBackend(args.db)
    except Exception:
        print(json.dumps({
            "status": "ERROR",
            "reason": "Database integrity failure"
        }))
        sys.exit(EXIT_DB_FAIL)

    # ---------------------------------------------------------
    # In-Memory Objects
    # ---------------------------------------------------------

    trust_store = TrustStore()
    governance_registry = GovernanceRegistry()
    ledger = VerificationLedger()
    transparency = TransparencyLog()

    verifier = ThresholdVerifier(
        trust_store=trust_store,
        governance_registry=governance_registry,
        transparency_log=transparency,
        ledger=ledger,
    )

    # ---------------------------------------------------------
    # Verification
    # ---------------------------------------------------------

    try:
        verifier.verify(
            payload=payload,
            signature_object=signature,
            now_utc=args.now,
        )

    except Exception as e:

        message = str(e)

        if "Governance" in message:
            code = EXIT_GOVERNANCE_FAIL
        elif "Ledger" in message:
            code = EXIT_LEDGER_FAIL
        elif "Transparency" in message:
            code = EXIT_TRANSPARENCY_FAIL
        else:
            code = EXIT_SIGNATURE_FAIL

        print(json.dumps({
            "status": "FAIL",
            "reason": message
        }))

        sys.exit(code)

    # ---------------------------------------------------------
    # Chain Validation
    # ---------------------------------------------------------

    try:
        if not ledger.validate_chain():
            raise RuntimeError("Ledger chain invalid")

        transparency.validate_chain()

    except Exception as e:
        print(json.dumps({
            "status": "FAIL",
            "reason": str(e)
        }))
        sys.exit(EXIT_LEDGER_FAIL)

    # ---------------------------------------------------------
    # PASS
    # ---------------------------------------------------------

    print(json.dumps({
        "status": "PASS",
        "payload_hash": signature.get("payload_hash"),
        "policy_family": signature.get("policy_family"),
        "policy_version": signature.get("policy_version"),
        "ledger_valid": True,
        "transparency_valid": True
    }))

    sys.exit(EXIT_PASS)


if __name__ == "__main__":
    main()


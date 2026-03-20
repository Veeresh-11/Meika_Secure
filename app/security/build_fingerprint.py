# app/security/build_fingerprint.py

import hashlib
import importlib.util
from pathlib import Path


# Modules that define the constitutional law surface
CRITICAL_MODULES = [
    "app.security.canonical",
    "app.security.decision",
    "app.security.results",
    "app.security.policy.adapter",
]


def _module_file(module_name: str) -> Path:
    spec = importlib.util.find_spec(module_name)
    if spec is None or spec.origin is None:
        raise RuntimeError(f"Cannot resolve module: {module_name}")
    return Path(spec.origin)


def compute_build_hash() -> str:
    sha = hashlib.sha256()

    for module_name in CRITICAL_MODULES:
        path = _module_file(module_name)

        with open(path, "rb") as f:
            sha.update(f.read())

    return sha.hexdigest()

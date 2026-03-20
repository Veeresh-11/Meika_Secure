# app/security/policy/loader.py

import yaml
from app.security.policy.models import PolicyDocument, PolicyRule


class PolicyLoadError(Exception):
    pass


def load_policy(path: str) -> PolicyDocument:
    try:
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
    except Exception as e:
        raise PolicyLoadError(f"Failed to load policy file: {path}") from e

    if "version" not in raw or "rules" not in raw:
        raise PolicyLoadError("Invalid policy format")

    rules = []
    for rule in raw["rules"]:
        rules.append(
            PolicyRule(
                name=rule["name"],
                when=rule.get("when", {}),
                effect=rule["effect"],
                reason=rule["reason"],
            )
        )

    return PolicyDocument(
        version=raw["version"],
        rules=rules,
    )

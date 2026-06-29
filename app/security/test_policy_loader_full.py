import pytest

from app.security.policy.loader import (
    load_policy,
    PolicyLoadError,
)
from app.security.policy.models import PolicyEffect


def test_load_policy_success(tmp_path):

    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
version: TEST-1

rules:
  - name: allow_authenticated
    effect: allow
    when:
      authenticated: true
    reason: Authenticated user
"""
    )

    document = load_policy(
        str(policy_file)
    )

    assert document.version == "TEST-1"

    assert len(document.rules) == 1

    rule = document.rules[0]

    assert rule.name == "allow_authenticated"
    assert rule.effect == PolicyEffect.ALLOW
    assert rule.when == {
        "authenticated": True
    }
    assert rule.reason == "Authenticated user"


def test_load_policy_file_failure():

    with pytest.raises(PolicyLoadError):
        load_policy(
            "/does/not/exist.yaml"
        )


def test_load_policy_invalid_format():

    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".yaml",
        delete=False,
    ) as f:

        f.write(
            """
invalid: true
"""
        )

        path = f.name

    with pytest.raises(PolicyLoadError):
        load_policy(path)
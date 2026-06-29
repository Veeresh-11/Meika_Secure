from types import SimpleNamespace
from datetime import datetime

from app.security.policy.engine import PolicyEngine


def ctx():
    return SimpleNamespace(
        principal_id="alice",
        authenticated=True,
        intent="read",
        request_time=datetime.utcnow(),
        metadata={"resource": "file1"},
        device=None,
    )


def policy(rule=None):
    return SimpleNamespace(
        version="1.0",
        rules=[] if rule is None else [rule],
    )


def test_clone_confirmed_denied():
    c = ctx()

    c.device = SimpleNamespace(
        clone_confirmed=True,
        compromised=False,
    )

    result = PolicyEngine(policy()).evaluate(c)

    assert result.reason == "Device cloning detected"


def test_compromised_device_denied():
    c = ctx()

    c.device = SimpleNamespace(
        clone_confirmed=False,
        compromised=True,
    )

    result = PolicyEngine(policy()).evaluate(c)

    assert result.reason == "Device compromised"


def test_graph_authorization_denied():
    c = ctx()

    graph = SimpleNamespace(
        check=lambda s, a, r: False
    )

    result = PolicyEngine(
        policy(),
        graph=graph,
    ).evaluate(c)

    assert result.reason == "Graph authorization denied"


def test_matching_rule_returns_effect():
    c = ctx()

    rule = SimpleNamespace(
        effect="allow",
        reason="matched",
        when={},
    )

    result = PolicyEngine(
        policy(rule)
    ).evaluate(c)

    assert result.reason == "matched"


def test_no_matching_rule_denied():
    c = ctx()

    rule = SimpleNamespace(
        effect="allow",
        reason="matched",
        when={
            "conditions": [
                {
                    "type": "user",
                    "value": "bob",
                }
            ]
        },
    )

    result = PolicyEngine(
        policy(rule)
    ).evaluate(c)

    assert result.reason == "No matching policy rule"
    

def test_compromised_false_continues():
    ctx = SimpleNamespace(
        principal_id="alice",
        authenticated=True,
        intent="read",
        request_time=datetime.utcnow(),
        metadata={},
        device=SimpleNamespace(
            clone_confirmed=False,
            compromised=False,
        ),
    )

    rule = SimpleNamespace(
        effect="allow",
        reason="ok",
        when={},
    )

    result = PolicyEngine(
        SimpleNamespace(
            version="1.0",
            rules=[rule],
        )
    ).evaluate(ctx)

    assert result.reason == "ok"


def test_graph_present_without_resource():
    ctx = SimpleNamespace(
        principal_id="alice",
        authenticated=True,
        intent="read",
        request_time=datetime.utcnow(),
        metadata={},      # no resource
        device=None,
    )

    graph = SimpleNamespace(
        check=lambda *args: False
    )

    rule = SimpleNamespace(
        effect="allow",
        reason="ok",
        when={},
    )

    result = PolicyEngine(
        SimpleNamespace(
            version="1.0",
            rules=[rule],
        ),
        graph=graph,
    ).evaluate(ctx)

    assert result.reason == "ok"


def test_graph_allows():
    ctx = SimpleNamespace(
        principal_id="alice",
        authenticated=True,
        intent="read",
        request_time=datetime.utcnow(),
        metadata={
            "resource": "file1",
        },
        device=None,
    )

    graph = SimpleNamespace(
        check=lambda *args: True
    )

    rule = SimpleNamespace(
        effect="allow",
        reason="ok",
        when={},
    )

    result = PolicyEngine(
        SimpleNamespace(
            version="1.0",
            rules=[rule],
        ),
        graph=graph,
    ).evaluate(ctx)

    assert result.reason == "ok"
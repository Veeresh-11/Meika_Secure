from datetime import datetime
from types import SimpleNamespace

from app.security.policy.evaluators.graph import (
    GraphPolicyEvaluator,
)
from app.security.decision import DecisionOutcome


def make_ctx(resource=None):
    return SimpleNamespace(
        principal_id="alice",
        intent="read",
        metadata={"resource": resource},
        request_time=datetime.utcnow(),
    )


def test_missing_resource_denied():
    graph = SimpleNamespace()

    evaluator = GraphPolicyEvaluator(graph)

    result = evaluator.evaluate(
        make_ctx(None)
    )

    assert result.outcome == DecisionOutcome.DENY
    assert result.reason == "missing_resource"


def test_graph_denied():
    graph = SimpleNamespace(
        check=lambda *args: False
    )

    evaluator = GraphPolicyEvaluator(graph)

    result = evaluator.evaluate(
        make_ctx("file1")
    )

    assert result.outcome == DecisionOutcome.DENY
    assert result.reason == "graph_access_denied"


def test_graph_allowed():
    graph = SimpleNamespace(
        check=lambda *args: True
    )

    evaluator = GraphPolicyEvaluator(graph)

    result = evaluator.evaluate(
        make_ctx("file1")
    )

    assert result.outcome == DecisionOutcome.ALLOW
    assert result.reason == "graph_access_allowed"
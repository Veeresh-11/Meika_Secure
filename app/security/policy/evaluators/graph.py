from app.security.results import PolicyResult, ResultKind
from app.security.decision import DecisionOutcome


class GraphPolicyEvaluator:
    """
    Graph-based authorization evaluator.
    """

    POLICY_VERSION = "graph-auth-v1"

    def __init__(self, graph):
        self.graph = graph

    def evaluate(self, context):

        subject = context.principal_id
        action = context.intent
        resource = context.metadata.get("resource")

        if resource is None:
            return PolicyResult(
                outcome=DecisionOutcome.DENY,
                reason="missing_resource",
                policy_version=self.POLICY_VERSION,
                evaluated_at=context.request_time,
                kind=ResultKind.POLICY,
            )

        allowed = self.graph.check(subject, action, resource)

        if not allowed:
            return PolicyResult(
                outcome=DecisionOutcome.DENY,
                reason="graph_access_denied",
                policy_version=self.POLICY_VERSION,
                evaluated_at=context.request_time,
                kind=ResultKind.POLICY,
            )

        return PolicyResult(
            outcome=DecisionOutcome.ALLOW,
            reason="graph_access_allowed",
            policy_version=self.POLICY_VERSION,
            evaluated_at=context.request_time,
            kind=ResultKind.POLICY,
        )

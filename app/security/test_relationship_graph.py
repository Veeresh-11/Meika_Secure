# app/security/test_relationship_graph.py

from app.security.graph.relationship_graph import (
    RelationshipGraph,
)


class FakeStore:

    def __init__(self):
        self.relations = set()
        self.parents = {}

    def has(
        self,
        subject,
        relation,
        obj,
    ):
        return (
            subject,
            relation,
            obj,
        ) in self.relations

    def find_objects(
        self,
        obj,
        relation,
    ):
        return self.parents.get(
            obj,
            [],
        )


def test_direct_relationship():
    store = FakeStore()

    store.relations.add(
        ("alice", "viewer", "doc")
    )

    graph = RelationshipGraph(store)

    assert graph.check(
        "alice",
        "viewer",
        "doc",
    )


def test_parent_traversal():
    store = FakeStore()

    store.relations.add(
        ("alice", "viewer", "parent")
    )

    store.parents["doc"] = ["parent"]

    graph = RelationshipGraph(store)

    assert graph.check(
        "alice",
        "viewer",
        "doc",
    )


def test_missing_relationship():
    store = FakeStore()

    graph = RelationshipGraph(store)

    assert (
        graph.check(
            "alice",
            "viewer",
            "doc",
        )
        is False
    )


def test_cycle_protection():
    store = FakeStore()

    store.parents["a"] = ["b"]
    store.parents["b"] = ["a"]

    graph = RelationshipGraph(store)

    assert (
        graph.check(
            "alice",
            "viewer",
            "a",
        )
        is False
    )


def test_depth_limit():
    store = FakeStore()

    current = "root"

    for i in range(20):
        nxt = f"n{i}"
        store.parents[current] = [nxt]
        current = nxt

    graph = RelationshipGraph(store)

    assert (
        graph.check(
            "alice",
            "viewer",
            "root",
        )
        is False
    )


def test_budget_limit():
    store = FakeStore()

    graph = RelationshipGraph(store)

    budget = {"remaining": 0}

    assert (
        graph.check(
            "alice",
            "viewer",
            "doc",
            budget=budget,
        )
        is False
    )
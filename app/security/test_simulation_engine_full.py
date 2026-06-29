# app/security/test_simulation_engine_full.py

from app.security.simulation.engine import SimulationEngine


def test_evaluate_returns_empty_list():
    engine = SimulationEngine()

    result = engine.evaluate(
        context=object(),
        decision=object(),
    )

    assert result == []
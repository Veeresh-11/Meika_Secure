from app.security.simulation.emitter import SimulationEmitter


def test_emit_accepts_empty_list():

    emitter = SimulationEmitter()

    assert emitter.emit([]) is None


def test_emit_accepts_results():

    emitter = SimulationEmitter()

    assert emitter.emit([object()]) is None
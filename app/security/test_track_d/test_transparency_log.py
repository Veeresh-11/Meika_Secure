from app.security.track_d.audit.transparency_log import TransparencyLog


def test_append_and_root_changes():
    log = TransparencyLog()

    root1 = log.append({"event": "A"})
    root2 = log.append({"event": "B"})

    assert root1 != root2


def test_inclusion_proof_generation():
    log = TransparencyLog()

    log.append({"event": "A"})
    log.append({"event": "B"})
    log.append({"event": "C"})

    proof = log.get_inclusion_proof(1)

    assert isinstance(proof, list)
    assert len(proof) > 0


def test_tamper_detection():
    log = TransparencyLog()

    log.append({"event": "A"})
    log.append({"event": "B"})

    # Tamper with entry
    log._entries[0]["event"] = "HACKED"

    assert not log.validate()

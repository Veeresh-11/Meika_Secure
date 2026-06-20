from app.security.webauthn.challenge import generate_challenge


def test_generate_challenge_returns_string():
    challenge = generate_challenge()

    assert isinstance(challenge, str)
    assert len(challenge) > 20


def test_generate_challenges_are_unique():
    a = generate_challenge()
    b = generate_challenge()

    assert a != b
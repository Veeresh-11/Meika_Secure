import pytest

pytestmark = pytest.mark.track_a

import inspect
from app.security.pipeline import SecurityPipeline

def test_no_magic_deny_strings():
    src = inspect.getsource(SecurityPipeline)
    assert "Device cloning detected" not in src

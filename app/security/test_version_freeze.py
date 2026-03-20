from app.security.version import KERNEL_VERSION, SCHEMA_VERSION


def test_kernel_version_frozen():
    assert KERNEL_VERSION == "1.0.0"


def test_schema_version_frozen():
    assert SCHEMA_VERSION == "1.0.0"

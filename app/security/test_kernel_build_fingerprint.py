from app.security.version import KERNEL_BUILD_HASH


def test_kernel_build_hash_is_stable():
    from app.security.build_fingerprint import compute_build_hash
    assert compute_build_hash() == KERNEL_BUILD_HASH

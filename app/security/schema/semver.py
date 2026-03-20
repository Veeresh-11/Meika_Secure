from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class SemanticVersion:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, version_str: str):
        try:
            parts = version_str.split(".")
            if len(parts) != 3:
                raise ValueError
            major, minor, patch = map(int, parts)
            return cls(major, minor, patch)
        except Exception:
            raise ValueError("INVALID_SEMANTIC_VERSION")

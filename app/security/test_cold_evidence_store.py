from app.security.evidence.memory.cold import ColdEvidenceStore


class FakeReader:

    def get(self, record_hash):
        return {"hash": record_hash}

    def range(self, start, end):
        return ["a", "b", "c"]


def test_get_delegates_to_reader():

    store = ColdEvidenceStore(FakeReader())

    result = store.get("hash123")

    assert result == {
        "hash": "hash123",
    }


def test_range_delegates_to_reader():

    store = ColdEvidenceStore(FakeReader())

    result = store.range(1, 10)

    assert result == [
        "a",
        "b",
        "c",
    ]


def test_reader_saved_in_constructor():

    reader = FakeReader()

    store = ColdEvidenceStore(reader)

    assert store._reader is reader
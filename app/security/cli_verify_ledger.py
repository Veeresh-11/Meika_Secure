import sys
import os

from app.security.evidence.postgres_store import PostgresEvidenceStore
from app.security.evidence.verify import verify_chain


def main():
    dsn = os.getenv("EVIDENCE_DSN")

    if not dsn:
        print("EVIDENCE_DSN not set")
        sys.exit(1)

    store = PostgresEvidenceStore(dsn)
    records = store.get_all()

    try:
        verify_chain(records)
        print("Ledger integrity: VALID")
        sys.exit(0)
    except Exception as e:
        print("Ledger integrity: INVALID")
        print(str(e))
        sys.exit(2)


if __name__ == "__main__":
    main()

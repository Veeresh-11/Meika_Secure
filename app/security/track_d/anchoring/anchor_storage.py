from __future__ import annotations

import sqlite3
from typing import Optional, List

from .anchor_receipt import AnchorReceipt


class AnchorStorage:

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        cursor = self.conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS anchor_receipts (
                transaction_id TEXT PRIMARY KEY,
                root_hash TEXT NOT NULL,
                network TEXT NOT NULL,
                block_number INTEGER NOT NULL,
                anchored_at TEXT NOT NULL,
                receipt_hash TEXT NOT NULL
            )
            """
        )

        self.conn.commit()

    # ---------------------------------------------------------
    # Insert (Immutable)
    # ---------------------------------------------------------

    def store(self, receipt: AnchorReceipt) -> None:
        cursor = self.conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO anchor_receipts (
                    transaction_id,
                    root_hash,
                    network,
                    block_number,
                    anchored_at,
                    receipt_hash
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.transaction_id,
                    receipt.root_hash,
                    receipt.network,
                    receipt.block_number,
                    receipt.anchored_at,
                    receipt.receipt_hash,
                ),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError("Anchor receipt already stored")

    # ---------------------------------------------------------
    # Lookup
    # ---------------------------------------------------------

    def get_by_transaction(self, transaction_id: str) -> Optional[AnchorReceipt]:
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT root_hash, network, transaction_id, block_number,
                   anchored_at, receipt_hash
            FROM anchor_receipts
            WHERE transaction_id = ?
            """,
            (transaction_id,),
        )

        row = cursor.fetchone()
        if not row:
            return None

        receipt = AnchorReceipt(
            root_hash=row[0],
            network=row[1],
            transaction_id=row[2],
            block_number=row[3],
            anchored_at=row[4],
            receipt_hash=row[5],
        )

        # integrity check
        receipt.verify_integrity()

        return receipt

    def get_by_root(self, root_hash: str) -> Optional[AnchorReceipt]:
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT root_hash, network, transaction_id, block_number,
                   anchored_at, receipt_hash
            FROM anchor_receipts
            WHERE root_hash = ?
            """,
            (root_hash,),
        )

        row = cursor.fetchone()
        if not row:
            return None

        receipt = AnchorReceipt(
            root_hash=row[0],
            network=row[1],
            transaction_id=row[2],
            block_number=row[3],
            anchored_at=row[4],
            receipt_hash=row[5],
        )

        receipt.verify_integrity()
        return receipt

    # ---------------------------------------------------------
    # List Ordered
    # ---------------------------------------------------------

    def list_all(self) -> List[AnchorReceipt]:
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT root_hash, network, transaction_id, block_number,
                   anchored_at, receipt_hash
            FROM anchor_receipts
            ORDER BY block_number ASC
            """
        )

        rows = cursor.fetchall()
        receipts = []

        for row in rows:
            receipt = AnchorReceipt(
                root_hash=row[0],
                network=row[1],
                transaction_id=row[2],
                block_number=row[3],
                anchored_at=row[4],
                receipt_hash=row[5],
            )
            receipt.verify_integrity()
            receipts.append(receipt)

        return receipts

    # ---------------------------------------------------------
    # Count
    # ---------------------------------------------------------

    def size(self) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM anchor_receipts")
        return cursor.fetchone()[0]

from unittest.mock import patch

from app.security.cli_verify_ledger import main


def test_missing_dsn_exits_1():

    with patch.dict("os.environ", {}, clear=True):
        try:
            main()
        except SystemExit as e:
            assert e.code == 1


def test_valid_ledger_exits_0():

    fake_store = type(
        "Store",
        (),
        {
            "get_all": lambda self: []
        },
    )

    with patch.dict(
        "os.environ",
        {"EVIDENCE_DSN": "postgres://test"},
        clear=True,
    ):
        with patch(
            "app.security.cli_verify_ledger.PostgresEvidenceStore",
            return_value=fake_store(),
        ):
            with patch(
                "app.security.cli_verify_ledger.verify_chain"
            ):
                try:
                    main()
                except SystemExit as e:
                    assert e.code == 0


def test_invalid_ledger_exits_2():

    fake_store = type(
        "Store",
        (),
        {
            "get_all": lambda self: []
        },
    )

    with patch.dict(
        "os.environ",
        {"EVIDENCE_DSN": "postgres://test"},
        clear=True,
    ):
        with patch(
            "app.security.cli_verify_ledger.PostgresEvidenceStore",
            return_value=fake_store(),
        ):
            with patch(
                "app.security.cli_verify_ledger.verify_chain",
                side_effect=RuntimeError("broken"),
            ):
                try:
                    main()
                except SystemExit as e:
                    assert e.code == 2
"""`vhir --case X backup DEST` backs up case X: the backup command's own
--case must not reset the root one when it is not given."""

from vhir_cli import main


def _case(argv):
    return main.build_parser().parse_args(argv).case


def test_root_case_reaches_backup():
    assert _case(["--case", "A", "backup", "dest"]) == "A"


def test_backup_case_option():
    assert _case(["backup", "--case", "B", "dest"]) == "B"


def test_backup_case_option_wins_over_root():
    assert _case(["--case", "A", "backup", "--case", "B", "dest"]) == "B"


def test_no_case_given_is_none():
    assert _case(["backup", "dest"]) is None


def test_other_commands_keep_root_case():
    assert _case(["--case", "A", "todo"]) == "A"

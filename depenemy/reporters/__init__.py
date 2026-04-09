"""Output reporters."""

from depenemy.reporters.json_reporter import generate_json, write_json
from depenemy.reporters.sarif import generate_sarif, write_sarif

__all__ = ["generate_sarif", "write_sarif", "generate_json", "write_json", "print_table"]


def print_table(result, console=None):  # type: ignore[no-untyped-def]
    from depenemy.reporters.table import print_table as _print_table
    return _print_table(result, console=console)

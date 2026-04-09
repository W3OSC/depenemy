"""Ecosystem parsers."""

from depenemy.parsers.npm import NpmParser
from depenemy.parsers.python import PythonParser
from depenemy.parsers.rust import RustParser
from depenemy.parsers.solidity import SolidityParser

__all__ = ["NpmParser", "PythonParser", "RustParser", "SolidityParser"]

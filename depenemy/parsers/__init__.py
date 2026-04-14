"""Ecosystem parsers."""

from depenemy.parsers.npm import NpmParser
from depenemy.parsers.python import PythonParser
from depenemy.parsers.rust import RustParser

__all__ = ["NpmParser", "PythonParser", "RustParser"]

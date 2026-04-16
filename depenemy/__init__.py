"""depenemy - dependency scanner that finds your enemies in the supply chain."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("depenemy")
except PackageNotFoundError:
    __version__ = "0.0.0"

__author__ = "W3OSC"

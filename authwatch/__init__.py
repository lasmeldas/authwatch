"""authwatch: detect SSH brute-force attacks in auth logs."""

from .detector import Alert, detect, summarize
from .parser import Event, parse_line, parse_lines

__all__ = ["Alert", "Event", "detect", "summarize", "parse_line", "parse_lines"]
__version__ = "0.1.0"

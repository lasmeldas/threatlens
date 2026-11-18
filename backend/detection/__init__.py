"""Rule-based detection for SSH auth logs.

The parser and rules come from authwatch (github.com/lasmeldas/authwatch), the same author's
command-line tool. tests/test_detection_parity.py checks that this copy and authwatch give the
same alerts on 28 logs.
"""

from .detector import Alert, detect, exclude_ips, summarize
from .parser import Event, parse_line, parse_lines

__all__ = ["Alert", "Event", "detect", "exclude_ips", "parse_line", "parse_lines", "summarize"]

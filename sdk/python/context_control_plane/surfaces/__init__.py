"""Interface surface package for CLI, MCP, UI, and future northbound transports."""

from .cli import DISCOVERY_COMMANDS, build_parser, main, run

__all__ = [
    "DISCOVERY_COMMANDS",
    "build_parser",
    "main",
    "run",
]

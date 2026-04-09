from __future__ import annotations

from .surfaces.cli import build_parser, main as surface_main, run

__all__ = [
    "build_parser",
    "main",
    "run",
]


def main(argv: list[str] | None = None) -> int:
    try:
        return surface_main(argv)
    except SystemExit as exc:
        return int(exc.code or 0)


if __name__ == "__main__":
    raise SystemExit(main())

"""Repo-root import shim for the control-plane SDK.

This lets `python -m unittest` and other repo-root entrypoints import
`context_control_plane` without requiring callers to add `sdk/python` to
`PYTHONPATH` manually.
"""

from pathlib import Path


_IMPL_DIR = Path(__file__).resolve().parent.parent / "sdk" / "python" / "context_control_plane"
_IMPL_INIT = _IMPL_DIR / "__init__.py"

if not _IMPL_INIT.exists():
    raise ImportError(f"control-plane SDK package not found at {_IMPL_INIT}")

__path__ = [str(_IMPL_DIR)]
__file__ = str(_IMPL_INIT)

exec(compile(_IMPL_INIT.read_text(encoding="utf-8"), __file__, "exec"), globals(), globals())

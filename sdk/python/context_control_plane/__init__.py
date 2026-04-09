from __future__ import annotations

from .kernel import CORE_PACKAGE_NAME, build_version_payload, resolve_package_version

__all__ = [
    "CORE_PACKAGE_NAME",
    "__version__",
    "build_version_payload",
    "resolve_package_version",
]

__version__ = resolve_package_version()

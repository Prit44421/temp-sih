"""Utilities for detecting host operating system metadata."""
from __future__ import annotations

import logging
import platform
from functools import lru_cache
from typing import Dict

try:  # pragma: no cover - optional dependency on non-Linux hosts
    import distro  # type: ignore
except ImportError:  # pragma: no cover
    distro = None


logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_os_info() -> Dict[str, str | None]:
    """Return a dictionary describing the current operating system.

    The result is cached because this information is static for the lifetime of the
    process. Missing fields are set to ``None`` rather than omitted so that the
    structure is predictable for consumers such as the API layer.
    """

    system = platform.system()
    os_info: Dict[str, str | None] = {
        "system": system,
        "release": platform.release(),
        "version": platform.version(),
        "distro_name": None,
        "distro_version": None,
        "distro_id": None,
    }

    if system == "Linux" and distro is not None:
        try:
            os_info["distro_name"] = distro.name(pretty=True) or None
            os_info["distro_version"] = distro.version(best=True) or None
            os_info["distro_id"] = distro.id() or None
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to gather distro information: %s", exc)
    elif system == "Windows":
        # Additional Windows specific metadata can be queried lazily by callers.
        logger.debug("Detected Windows platform")

    return os_info


__all__ = ["get_os_info"]

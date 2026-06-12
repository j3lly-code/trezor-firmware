"""
KeetaGetVersion handler.

Returns firmware Keeta version information to the host.
The host uses this to discover protocol version compatibility.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import KeetaGetVersion, KeetaVersion


async def get_version(msg: KeetaGetVersion) -> KeetaVersion:
    from trezor.messages import KeetaVersion

    from .constants import (
        KEETA_VERSION_FLAGS,
        KEETA_VERSION_MAJOR,
        KEETA_VERSION_MINOR,
        KEETA_VERSION_PATCH,
    )

    return KeetaVersion(
        flags=KEETA_VERSION_FLAGS,
        major=KEETA_VERSION_MAJOR,
        minor=KEETA_VERSION_MINOR,
        patch=KEETA_VERSION_PATCH,
    )

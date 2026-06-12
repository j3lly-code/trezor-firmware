# This file is part of the Trezor project.
#
# Copyright (C) SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

"""Trezorlib Keeta Network helpers.

Provides ergonomic wrappers around Keeta protobuf message types for
getting public keys, authenticated addresses, and signing blocks.
"""

from typing import TYPE_CHECKING, List

from . import messages
from .tools import workflow

if TYPE_CHECKING:
    from .client import Session


@workflow(capability=messages.Capability.Keeta)
def get_public_key(
    session: "Session",
    address_n: List[int],
    show_display: bool = False,
    algorithm: messages.KeetaAlgorithm = messages.KeetaAlgorithm.SECP256K1,
) -> messages.KeetaPublicKey:
    """Get the Keeta public key and address for a BIP-32 path.

    Returns the full KeetaPublicKey message containing the raw public key
    bytes and the human-readable keeta_ address string.
    """
    return session.call(
        messages.KeetaGetPublicKey(
            address_n=address_n,
            show_display=show_display,
            algorithm=algorithm,
        ),
        expect=messages.KeetaPublicKey,
    )


@workflow(capability=messages.Capability.Keeta)
def get_authenticated_address(
    session: "Session",
    address_n: List[int],
    show_display: bool = False,
    chunkify: bool = False,
    algorithm: messages.KeetaAlgorithm = messages.KeetaAlgorithm.SECP256K1,
) -> messages.KeetaAddress:
    """Get the authenticated Keeta address with HMAC-SHA3-256 MAC.

    Returns the full KeetaAddress message containing the address string
    and a 32-byte MAC for host-side verification.
    """
    return session.call(
        messages.KeetaGetAddress(
            address_n=address_n,
            show_display=show_display,
            chunkify=chunkify,
            algorithm=algorithm,
        ),
        expect=messages.KeetaAddress,
    )


def get_address(
    session: "Session",
    address_n: List[int],
    show_display: bool = False,
    chunkify: bool = False,
    algorithm: messages.KeetaAlgorithm = messages.KeetaAlgorithm.SECP256K1,
) -> str:
    """Get a Keeta address string for a BIP-32 path.

    Convenience wrapper around get_authenticated_address() that returns
    only the address string.
    """
    resp = get_authenticated_address(
        session,
        address_n,
        show_display=show_display,
        chunkify=chunkify,
        algorithm=algorithm,
    )
    return resp.address


@workflow(capability=messages.Capability.Keeta)
def sign_block(
    session: "Session",
    address_n: List[int],
    block_bytes: bytes,
    algorithm: messages.KeetaAlgorithm = messages.KeetaAlgorithm.SECP256K1,
    network_id: int = 0x54455354,  # TEST network
    chunk_size: int = 896,
) -> bytes:
    """Sign a DER-encoded Keeta block using the streaming protocol.

    Splits the block bytes into chunks and sends them to the device
    in FIRST / ADD / LAST phases. The handler processes chunks
    incrementally, validates the block structure, displays
    confirmation screens, and returns the signature.

    Parameters
    ----------
    session: connected device session
    address_n: BIP-32 derivation path
    block_bytes: complete DER-encoded block (V1 or V2 format)
    algorithm: signing algorithm (default SECP256K1)
    network_id: network identifier (default 0x54455354 = TEST)
    chunk_size: max bytes per chunk (default 896, fits USB packet)

    Returns
    -------
    64-byte signature (ECDSA or EdDSA)
    """
    if not block_bytes:
        raise ValueError("Empty block")

    # Split block into chunks
    chunks: list[bytes] = []
    for i in range(0, len(block_bytes), chunk_size):
        chunks.append(block_bytes[i : i + chunk_size])

    # FIRST chunk carries address_n, algorithm, and network_id
    session.write(
        messages.KeetaSignBlock(
            address_n=address_n,
            algorithm=algorithm,
            network_id=network_id,
            chunk_phase=messages.KeetaChunkPhase.FIRST,
            chunk_index=0,
            chunk_data=chunks[0],
        )
    )

    # ADD chunks for the middle (if more than 2 total)
    for i, chunk in enumerate(chunks[1:-1], start=1):
        session.write(
            messages.KeetaSignBlock(
                chunk_phase=messages.KeetaChunkPhase.ADD,
                chunk_index=i,
                chunk_data=chunk,
            )
        )

    # LAST chunk — call() blocks until the device returns the signature
    if len(chunks) == 1:
        # Single chunk: FIRST had the data, LAST is empty
        response = session.call(
            messages.KeetaSignBlock(
                chunk_phase=messages.KeetaChunkPhase.LAST,
                chunk_index=1,
                chunk_data=b"",
            ),
            expect=messages.KeetaBlockSignature,
        )
    else:
        last_idx = len(chunks) - 1
        response = session.call(
            messages.KeetaSignBlock(
                chunk_phase=messages.KeetaChunkPhase.LAST,
                chunk_index=last_idx,
                chunk_data=chunks[-1],
            ),
            expect=messages.KeetaBlockSignature,
        )

    return response.signature

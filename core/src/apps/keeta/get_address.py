"""
KeetaGetAddress handler.

Returns the Keeta address for a given BIP-32 path and algorithm.
Uses custom key derivation (not the standard ``with_slip44_keychain`` pattern).
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import KeetaAddress, KeetaGetAddress


async def get_address(msg: KeetaGetAddress) -> KeetaAddress:
    from trezor import wire
    from trezor.messages import KeetaAddress
    from trezor.ui.layouts import show_address

    from apps.common.paths import (
        PathSchema,
        address_n_to_str,
        unharden,
    )

    from . import PATTERNS, SLIP44_ID
    from . import address as address_module
    from .constants import ALGO_ED25519, ALGO_MULTISIG, ALGO_SECP256K1, ALGO_SECP256R1
    from .keychain import derive_keeta_key, hmac_sha3_256

    # 1. Extract algorithm (default to ALGO_SECP256K1)
    algorithm = msg.algorithm if msg.algorithm is not None else ALGO_SECP256K1

    # Reject MULTISIG — not supported for address generation
    if algorithm == ALGO_MULTISIG:
        raise wire.DataError("MULTISIG is not supported for address generation")

    # 2. Validate BIP-32 path against PATTERNS
    schemas = [PathSchema.parse(p, SLIP44_ID) for p in PATTERNS]
    path_valid = any(s.match(msg.address_n) for s in schemas)
    if not path_valid:
        raise wire.DataError("Forbidden key path")

    # 3. Extract account_index (last element of path)
    account_index = unharden(msg.address_n[-1])

    # 4. Derive Keeta key (async)
    try:
        private_key = await derive_keeta_key(msg.address_n, account_index, algorithm)
    except Exception as e:
        raise wire.DataError(f"Key derivation failed: {e}")

    # 5. Derive public key from private key based on algorithm
    try:
        if algorithm == ALGO_SECP256K1:
            from trezorcrypto import secp256k1

            pubkey = secp256k1.publickey(private_key, True)  # 33 bytes

        elif algorithm == ALGO_SECP256R1:
            from trezorcrypto import nist256p1

            pubkey = nist256p1.publickey(private_key, True)  # 33 bytes

        elif algorithm == ALGO_ED25519:
            from trezorcrypto import ed25519

            pubkey = ed25519.publickey_ext(private_key)  # 32 bytes

        else:
            raise wire.DataError(f"Unsupported algorithm: 0x{algorithm:02x}")

    except Exception as e:
        raise wire.DataError(f"Public key derivation failed: {e}")

    # 6. Encode address via Keeta address encoding
    addr_str = address_module.encode_address(pubkey, algorithm)

    # 7. Compute MAC using HMAC-SHA3-256 with the derived key
    mac = hmac_sha3_256(private_key, addr_str.encode())

    # 8. Show address on the device display if requested
    if msg.show_display:
        path_str = address_n_to_str(msg.address_n)
        await show_address(
            addr_str,
            subtitle="Keeta",
            path=path_str,
            chunkify=bool(msg.chunkify),
        )

    # 9. Return response
    return KeetaAddress(address=addr_str, mac=mac)

"""
KeetaGetPublicKey handler.

Returns the public key and Keeta address for a given BIP-32 path and algorithm.
Uses the custom Keeta key derivation (NOT the standard with_slip44_keychain pattern).

Flow:
    1. Extract and validate algorithm from message
    2. Validate BIP-32 path against Keeta path patterns
    3. Derive Keeta private key via keychain.derive_keeta_key()
    4. Derive public key from private key (curve-dependent)
    5. Encode Keeta address
    6. Optionally display on device screen
    7. Return KeetaPublicKey with public_key bytes and address string
"""

from typing import TYPE_CHECKING

from apps.common.paths import PathSchema, address_n_to_str, validate_path

from . import PATTERNS, SLIP44_ID
from .address import encode_address
from .constants import (
    ALGO_ED25519,
    ALGO_MULTISIG,
    ALGO_SECP256K1,
    ALGO_SECP256R1,
)
from .keychain import derive_keeta_key

if TYPE_CHECKING:
    from trezor.messages import KeetaGetPublicKey, KeetaPublicKey

# Algorithms that support public key derivation from private key.
# NETWORK (0x02), TOKEN (0x03), STORAGE (0x04) are generated accounts
# without private keys. MULTISIG (0x07) is explicitly rejected.
_SUPPORTED_PUBKEY_ALGORITHMS = (ALGO_SECP256K1, ALGO_ED25519, ALGO_SECP256R1)

# Pre-parsed BIP-32 path schemas for validation (derived from PATTERNS).
_SCHEMAS = [PathSchema.parse(p, SLIP44_ID) for p in PATTERNS]


class _KeetaPathChecker:
    """Minimal path checker implementing the KeychainValidatorType protocol.

    Validates that a BIP-32 path matches at least one of the Keeta path patterns.
    """

    def verify_path(self, path: list[int]) -> None:
        if not self.is_in_keychain(path):
            from trezor import wire

            raise wire.DataError("Forbidden key path")

    @staticmethod
    def is_in_keychain(path: list[int]) -> bool:
        return any(s.match(path) for s in _SCHEMAS)


async def get_public_key(msg: KeetaGetPublicKey) -> KeetaPublicKey:
    from trezor import wire
    from trezor.messages import KeetaPublicKey
    from trezor.ui.layouts import show_pubkey

    # Step 1: Extract algorithm (default to secp256k1)
    algorithm = msg.algorithm if msg.algorithm is not None else ALGO_SECP256K1

    # Reject unsupported algorithms before any key derivation
    if algorithm == ALGO_MULTISIG:
        raise wire.DataError("MULTISIG addresses not supported")
    if algorithm not in _SUPPORTED_PUBKEY_ALGORITHMS:
        raise wire.DataError("Algorithm not supported for public key derivation")

    # Step 2: Validate BIP-32 path against Keeta patterns
    await validate_path(_KeetaPathChecker(), msg.address_n)

    # Step 3: Extract account index (last path element)
    account_index = msg.address_n[-1]

    # Step 4: Derive Keeta private key (async — incorporates passphrase)
    private_key = await derive_keeta_key(msg.address_n, account_index, algorithm)

    # Step 5: Derive public key from private key based on algorithm
    if algorithm == ALGO_SECP256K1:
        from trezorcrypto import secp256k1

        pubkey = secp256k1.publickey(private_key, compressed=True)  # 33 bytes
    elif algorithm == ALGO_SECP256R1:
        from trezorcrypto import nist256p1

        pubkey = nist256p1.publickey(private_key, compressed=True)  # 33 bytes
    elif algorithm == ALGO_ED25519:
        from trezorcrypto import ed25519

        pubkey = ed25519.publickey_ext(private_key)  # 32 bytes raw
    else:
        raise wire.DataError("Algorithm not supported for public key derivation")

    # Step 6: Encode Keeta address
    address = encode_address(pubkey, algorithm)

    # Step 7: Display on device screen if requested
    if msg.show_display:
        path_str = address_n_to_str(msg.address_n)
        await show_pubkey(address, path=path_str)

    # Step 8: Return response
    return KeetaPublicKey(public_key=pubkey, address=address)

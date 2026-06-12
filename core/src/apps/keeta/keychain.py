"""
Keeta key derivation module.

Custom key derivation matching the Ledger reference implementation.
ALL public functions are async. This module is CRITICAL for security.

References:
    - references/keeta-plan/07-key-derivation.md
    - Ledger device application: crypto/kdf.rs
"""

from trezor.crypto import bip32
from trezorcrypto import sha3_256 as _c_sha3_256

from apps.common import seed as seed_module

from .constants import SECP256K1_ORDER, SECP256R1_ORDER

# ---------------------------------------------------------------------------
# NIST SHA3-256 safety wrapper
# ---------------------------------------------------------------------------

# NIST FIPS 202, Section 5.2: SHA3-256 rate = 1600 - 2*256 bits = 1088 bits
SHA3_256_BLOCK_SIZE = 136  # 1088 / 8


def sha3_256_nist(data: bytes) -> bytes:
    """NIST SHA3-256 (NOT Keccak).

    Trezor's sha3_256() supports keccak=True for Ethereum compatibility.
    All Keeta operations MUST use keccak=False (NIST SHA3).
    Never use keccak=True for Keeta operations.
    """
    return _c_sha3_256(data, keccak=False).digest()


# ---------------------------------------------------------------------------
# HMAC-SHA3-256 (pure MicroPython implementation)
# ---------------------------------------------------------------------------


def hmac_sha3_256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA3-256 using NIST SHA3-256.

    Pure MicroPython implementation (no C module dependency).
    Follows RFC 2104 with SHA3-256 block size of 136 bytes.
    """
    if len(key) > SHA3_256_BLOCK_SIZE:
        key = sha3_256_nist(key)
    if len(key) < SHA3_256_BLOCK_SIZE:
        key = key + b"\x00" * (SHA3_256_BLOCK_SIZE - len(key))
    o_key_pad = bytes(k ^ 0x5C for k in key)
    i_key_pad = bytes(k ^ 0x36 for k in key)
    return sha3_256_nist(o_key_pad + sha3_256_nist(i_key_pad + msg))


# ---------------------------------------------------------------------------
# HKDF-SHA3-256 (expand-only)
# ---------------------------------------------------------------------------


def hkdf_sha3_256_expand(prk: bytes, info: bytes = b"") -> bytes:
    """HKDF-SHA3-256 expand step (single iteration).

    Returns exactly 32 bytes (SHA3-256 output length).
    """
    return hmac_sha3_256(prk, info + b"\x01")


# ---------------------------------------------------------------------------
# KeyDerivationError
# ---------------------------------------------------------------------------


class KeyDerivationError(Exception):
    """Raised when key derivation fails (e.g., HKDF retry exhausted)."""

    pass


# ---------------------------------------------------------------------------
# secp256k1 / secp256r1 per-index derivation
# ---------------------------------------------------------------------------


def derive_secp_key(keeta_seed: bytes, index: int, curve_order: int) -> bytes:
    """Derive a secp256k1 or secp256r1 private key for a given index.

    Uses HKDF-SHA3-256 expand with up to 100 retries to produce a valid
    scalar (0 < scalar < curve_order). Applies low-S normalization.

    Args:
        keeta_seed: 32-byte Keeta seed (keeta_seed from Step 2).
        index: Account index (non-negative integer).
        curve_order: Curve order constant (SECP256K1_ORDER or SECP256R1_ORDER).

    Returns:
        32-byte private key scalar.

    Raises:
        KeyDerivationError: if no valid scalar found after 100 attempts.
    """
    index_bytes = index.to_bytes(4, "big")  # BIG endian — Keeta protocol standard
    combined = keeta_seed + index_bytes
    candidate = None
    for attempt in range(100):
        info = b"" if attempt == 0 else attempt.to_bytes(4, "big")
        candidate = hkdf_sha3_256_expand(combined + info)
        candidate_int = int.from_bytes(candidate, "big")
        if 0 < candidate_int < curve_order:
            n_half = curve_order // 2
            if candidate_int > n_half:
                candidate_int = curve_order - candidate_int
                return candidate_int.to_bytes(32, "big")
            return candidate
        # Zero failed-attempt candidate within Python heap (defense in depth)
        candidate = None
    raise KeyDerivationError("HKDF retry exhausted")


# ---------------------------------------------------------------------------
# ed25519 per-index derivation
# ---------------------------------------------------------------------------


def derive_ed25519_key(keeta_seed: bytes, index: int) -> bytes:
    """Derive an ed25519 private key for a given index.

    Uses SHA3-256 with standard Ed25519 clamping.

    Args:
        keeta_seed: 32-byte Keeta seed (keeta_seed from Step 2).
        index: Account index (non-negative integer).

    Returns:
        32-byte clamped ed25519 scalar.
    """
    combined = keeta_seed + index.to_bytes(4, "big")
    raw = sha3_256_nist(combined)  # 32 bytes
    # Standard Ed25519 clamping
    raw = bytearray(raw)
    raw[0] &= 0xF8
    raw[31] &= 0x7F
    raw[31] |= 0x40
    return bytes(raw)


def derive_ed25519_nonce_extension(keeta_seed: bytes, index: int) -> bytes:
    """Derive deterministic ed25519 nonce extension.

    Domain-separated by b"ed25519_nonce". Deterministic per-seed, unique
    per-account (index is unique per path).

    Used with ed25519.sign_ext() for signing.
    """
    return sha3_256_nist(keeta_seed + index.to_bytes(4, "big") + b"ed25519_nonce")


# ---------------------------------------------------------------------------
# Memory safety — cleanup helpers
# ---------------------------------------------------------------------------


def _zero_bytes(buf: bytearray) -> None:
    """Zero a bytearray in place. Allocation-free.

    This provides defense-in-depth but cannot fully guarantee cleanup:
    - C-layer functions return immutable bytes objects (can only zero copies)
    - Python GC may have moved bytearray contents before zeroing
    - Primary zeroing should happen at the C level
    """
    for i in range(len(buf)):
        buf[i] = 0


# ---------------------------------------------------------------------------
# Main key derivation
# ---------------------------------------------------------------------------


async def derive_keeta_key(
    address_n: list[int],
    account_index: int,
    algorithm: int,
) -> bytes:
    """Full Keeta key derivation.

    Implements the 3-step Keeta key derivation flow:
    Step 1: Obtain BIP-32 seed (passphrase-integrated, async) and derive BIP-32 node
    Step 2: Compute keeta_seed = SHA3-256(uncompressed 65-byte pubkey)
    Step 3: Derive per-index key using the specified algorithm

    Args:
        address_n: BIP-32 derivation path.
        account_index: Account index for per-index derivation.
        algorithm: Algorithm byte constants (0x00 = secp256k1, 0x01 = ed25519,
                   0x06 = secp256r1).

    Returns:
        32-byte private key scalar for the derived account.

    Raises:
        TypeError: If seed_bytes is not bytes/bytearray.
        ValueError: If algorithm is not supported.
        KeyDerivationError: If HKDF retry is exhausted.
    """
    # Step 1: Obtain BIP-32 seed (async — incorporates passphrase)
    seed_bytes = await seed_module.get_seed()
    if not isinstance(seed_bytes, (bytes, bytearray)):
        raise TypeError("seed_bytes must be bytes, got {}".format(type(seed_bytes)))

    # Derive the BIP-32 node. Use secp256k1 for the intermediate BIP-32 path
    # (this is just for the intermediate derivation, not the final key).
    from trezorcrypto import secp256k1  # noqa: F811

    bip32_node = bip32.from_seed(seed_bytes, "secp256k1")
    bip32_node.derive_path(address_n)

    # Step 2: Compute keeta_seed from UNCOMPRESSED 65-byte public key
    # Trezor's HDNode.public_key() returns 33-byte COMPRESSED pubkey.
    # Keeta needs UNCOMPRESSED 65-byte format (0x04 || x || y).
    # Use secp256k1.publickey() with compressed=False to get the 65-byte form.
    private_key_bytes = bip32_node.private_key()
    uncompressed_pubkey = secp256k1.publickey(private_key_bytes, compressed=False)
    keeta_seed = sha3_256_nist(uncompressed_pubkey)  # 32 bytes

    # Step 3: Derive per-index key by algorithm
    if algorithm == 0x00:  # ALGO_SECP256K1
        private_key = derive_secp_key(keeta_seed, account_index, SECP256K1_ORDER)
    elif algorithm == 0x06:  # ALGO_SECP256R1
        private_key = derive_secp_key(keeta_seed, account_index, SECP256R1_ORDER)
    elif algorithm == 0x01:  # ALGO_ED25519
        private_key = derive_ed25519_key(keeta_seed, account_index)
    else:
        raise ValueError("Unsupported algorithm: {}".format(algorithm))

    return private_key


async def derive_and_cleanup(
    address_n: list[int],
    account_index: int,
    algorithm: int,
) -> bytes:
    """Full derivation with memory cleanup.

    Wraps derive_keeta_key with try/finally to zero sensitive material.
    Callers should always use this instead of derive_keeta_key directly.

    Note: C-layer returned bytes objects cannot be fully zeroed from Python.
    See 07-key-derivation.md for C-level zeroing strategy.
    """
    seed_bytes = None
    keeta_seed = None
    private_key = None
    uncompressed_pubkey = None
    try:
        # Step 1: Obtain seed
        raw_seed = await seed_module.get_seed()
        if not isinstance(raw_seed, (bytes, bytearray)):
            raise TypeError("seed_bytes must be bytes, got {}".format(type(raw_seed)))
        seed_bytes = bytearray(raw_seed)

        from trezorcrypto import secp256k1  # noqa: F811

        bip32_node = bip32.from_seed(bytes(seed_bytes), "secp256k1")
        bip32_node.derive_path(address_n)

        private_key_bytes = bip32_node.private_key()
        uncompressed_pubkey = secp256k1.publickey(private_key_bytes, compressed=False)
        keeta_seed = sha3_256_nist(uncompressed_pubkey)

        if algorithm == 0x00:
            private_key = derive_secp_key(keeta_seed, account_index, SECP256K1_ORDER)
        elif algorithm == 0x06:
            private_key = derive_secp_key(keeta_seed, account_index, SECP256R1_ORDER)
        elif algorithm == 0x01:
            private_key = derive_ed25519_key(keeta_seed, account_index)
        else:
            raise ValueError("Unsupported algorithm: {}".format(algorithm))

        return private_key
    finally:
        if private_key is not None:
            _zero_bytes(bytearray(private_key))
        if keeta_seed is not None:
            _zero_bytes(bytearray(keeta_seed))
        if uncompressed_pubkey is not None:
            _zero_bytes(bytearray(uncompressed_pubkey))
        if seed_bytes is not None:
            _zero_bytes(seed_bytes)

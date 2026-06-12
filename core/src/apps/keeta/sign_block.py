"""
Keeta streaming block signing handler.

Implements the ctx.read() loop pattern for receiving chunks of a DER-encoded
Keeta block, parsing them, displaying operations, and producing a signature.

Flow:
  1. FIRST chunk: initialize session, derive key, process FIRST chunk data
  2. Loop: ctx.read() for ADD/LAST chunks, hash + parse each
  3. LAST: break from loop, finalize hash, validate, display confirmation, sign
  4. Cleanup: always executed via finally block

References:
    - references/keeta-plan/08-block-signing.md
    - Keeta SDK / Ledger reference for block format and signing
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import KeetaBlockSignature, KeetaSignBlock

    from .der_parser import DerParser

# ---------------------------------------------------------------------------
# Module-level state (session-scoped across chunk messages)
# ---------------------------------------------------------------------------
_active: bool = False
_parser: "DerParser | None" = None  # DerParser instance
_hasher = None  # SHA3-256 hasher
_private_key: bytearray | None = None  # derived signing key as mutable bytearray
_keeta_seed: bytearray | None = None
_address_n: list[int] | None = None
_algorithm: int | None = None
_network_id: int | None = None
_expected_index: int = 0
_first_chunk_time: int = 0  # utime.ticks_ms() of FIRST chunk
_blind_signing_enabled: bool = True  # default to enabled for now
# Accumulator for completed operations returned by parser.feed()
_completed_ops: list[tuple[int, bytes]] = []


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_ALGO_SECP256K1 = 0x00
_ALGO_ED25519 = 0x01
_ALGO_SECP256R1 = 0x06
_ALGO_MULTISIG = 0x07

_ALGO_NAMES = {
    _ALGO_SECP256K1: "secp256k1",
    _ALGO_ED25519: "ed25519",
    _ALGO_SECP256R1: "secp256r1",
}

_NETWORK_NAMES = {
    0x54455354: "Testnet",  # "TEST" as u32
    0x5382: "Mainnet",
}


# ---------------------------------------------------------------------------
# Low-S enforcement
# ---------------------------------------------------------------------------
def _enforce_low_s(signature: bytes, curve_order: int) -> bytes:
    """Ensure s <= n/2 per Bitcoin/Keeta convention.

    Takes a 64-byte signature (r||s). Returns a 64-byte signature with
    s normalized to the low-S form if necessary.
    """
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    n_half = curve_order // 2
    if s > n_half:
        s = curve_order - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Public key derivation
# ---------------------------------------------------------------------------
def _derive_public_key(private_key: bytes, algorithm: int) -> bytes:
    """Derive the compressed public key from a private key scalar."""
    if algorithm == _ALGO_SECP256K1:
        from trezorcrypto import secp256k1

        return secp256k1.publickey(private_key, compressed=True)
    elif algorithm == _ALGO_SECP256R1:
        from trezorcrypto import nist256p1

        return nist256p1.publickey(private_key, compressed=True)
    elif algorithm == _ALGO_ED25519:
        from trezorcrypto import ed25519

        return ed25519.publickey_ext(private_key)
    else:
        from trezor import wire

        raise wire.DataError("Unsupported algorithm for public key derivation")


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
def _cleanup() -> None:
    """Safely reset all module-level state and zero sensitive material.

    Must be called in ALL exit paths (success, error, cancellation).
    Allocation-free zeroing of bytearrays, then drops references.
    """
    global _active, _parser, _hasher, _private_key
    global _keeta_seed, _address_n, _algorithm, _network_id
    global _expected_index, _first_chunk_time, _completed_ops

    # 1. Zero private key and keeta_seed (mutable bytearrays -- allocation-free)
    if _private_key is not None:
        for i in range(len(_private_key)):
            _private_key[i] = 0
    if _keeta_seed is not None:
        for i in range(len(_keeta_seed)):
            _keeta_seed[i] = 0

    # 2. Reset all state
    _active = False
    _parser = None
    _hasher = None
    _private_key = None
    _keeta_seed = None
    _address_n = None
    _algorithm = None
    _network_id = None
    _expected_index = 0
    _first_chunk_time = 0
    _completed_ops = []

    # 3. Unlock token cache
    from .token_cache import unlock

    unlock()

    # 4. Garbage collect twice to clear any residual copies
    import gc

    gc.collect()
    gc.collect()


# ---------------------------------------------------------------------------
# Path validation helper
# ---------------------------------------------------------------------------
def _validate_keeta_path(address_n: list[int]) -> None:
    """Validate the BIP-32 path against Keeta path patterns.

    Uses PathSchema from apps.common.paths to match against PATTERNS.
    Raises wire.DataError if the path is not valid.
    """
    from trezor import wire

    from apps.common.paths import PathSchema

    from . import PATTERNS, SLIP44_ID

    for pattern in PATTERNS:
        schema = PathSchema.parse(pattern, SLIP44_ID)
        if schema.match(address_n):
            return

    raise wire.DataError("Invalid path for Keeta")


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------
def _sign_block_hash(
    block_hash: bytes,
    private_key: bytes,
    algorithm: int,
    keeta_seed: bytes | bytearray | None = None,
    account_index: int = 0,
) -> bytes:
    """Sign the block hash using the specified algorithm.

    The signing digest is SHA3-256(block_hash) -- a double-hash construction.

    For secp256k1/secp256r1: strips the recovery byte, returns 64 bytes.
    For ed25519: uses sign_ext with nonce extension derived from keeta_seed.

    Applies low-S normalization for secp curves.
    """
    from trezorcrypto import sha3_256 as _c_sha3_256

    from .constants import SECP256K1_ORDER, SECP256R1_ORDER

    # Double-hash: signing digest = SHA3-256(block_hash)
    digest = _c_sha3_256(block_hash, keccak=False).digest()

    if algorithm == _ALGO_SECP256K1:
        from trezorcrypto import secp256k1

        raw_sig = secp256k1.sign(private_key, digest)  # 65 bytes
        signature = raw_sig[1:65]  # strip recovery byte
        return _enforce_low_s(signature, SECP256K1_ORDER)

    elif algorithm == _ALGO_SECP256R1:
        from trezorcrypto import nist256p1

        raw_sig = nist256p1.sign(private_key, digest)  # 65 bytes
        signature = raw_sig[1:65]  # strip recovery byte
        return _enforce_low_s(signature, SECP256R1_ORDER)

    elif algorithm == _ALGO_ED25519:
        from trezorcrypto import ed25519

        if keeta_seed is None:
            from trezor import wire

            raise wire.DataError("Missing keeta_seed for ed25519 signing")

        from .keychain import derive_ed25519_nonce_extension

        nonce_ext = derive_ed25519_nonce_extension(bytes(keeta_seed), account_index)
        return ed25519.sign_ext(private_key, nonce_ext, digest)  # 64 bytes

    else:
        from trezor import wire

        raise wire.DataError("Unsupported signing algorithm")


# ---------------------------------------------------------------------------
# Display confirmation helpers
# ---------------------------------------------------------------------------
async def _confirm_signing(address: str, network_name: str) -> None:
    """Display the signing account and block header confirmation."""
    algo_name = _ALGO_NAMES.get(_algorithm if _algorithm is not None else 0, "unknown")

    from .layout import confirm_block_header, confirm_signing_account

    await confirm_signing_account(address, algo_name)
    await confirm_block_header(address, None, "", network_name)


async def _confirm_operations(completed_ops: list[tuple[int, bytes]]) -> None:
    """Walk completed operations and display confirmation for each.

    If >5 operations, shows a summary. Handles oversized and blind ops.
    Per-operation confirmation functions are imported from layout and
    operations modules.
    """
    if not completed_ops:
        return

    from .constants import OP_BUF_SIZE
    from .layout import (
        confirm_blind_signing_warning,
        confirm_operation_summary,
        confirm_oversized_operation_warning,
    )

    op_count = len(completed_ops)
    has_oversized = False
    has_blind = False
    first_oversized_index = 0

    # Build summary displays and detect blind/oversized ops
    op_displays: list[dict] = []

    for index, (tag, tlv_bytes) in enumerate(completed_ops):
        from .operations import decode_operation

        op = decode_operation(tag, tlv_bytes)

        if op.is_blind:
            has_blind = True
        if not has_oversized and len(tlv_bytes) > OP_BUF_SIZE:
            has_oversized = True
            first_oversized_index = index

        # Build summary dict for confirm_operation_summary
        op_displays.append(
            {
                "type": op.name,
                "is_blind": op.is_blind,
                "index": index,
                "byte_count": len(tlv_bytes),
                "hash_prefix": op.fields.get("hash_preview", ""),
            }
        )

    if has_oversized:
        await confirm_oversized_operation_warning(first_oversized_index)
    if has_blind:
        await confirm_blind_signing_warning()

    # If >5 ops, show summary
    if op_count > 5:
        await confirm_operation_summary(op_displays)


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------
async def sign_block(msg: "KeetaSignBlock") -> "KeetaBlockSignature":
    """Streaming block signing handler.

    Receives chunks of a DER-encoded Keeta block, parses them incrementally,
    displays operation details for user confirmation, and produces a
    KeetaBlockSignature with a 64-byte ECDSA/EdDSA signature.

    Uses a session-scoped state machine that persists across chunk messages.
    """
    import utime

    from trezor import wire
    from trezor.crypto.hashlib import sha3_256
    from trezor.enums import KeetaChunkPhase, MessageType
    from trezor.messages import KeetaBlockSignature
    from trezor.wire.context import get_context

    from .constants import SESSION_TIMEOUT_MS
    from .der_parser import DerParser
    from .keychain import derive_keeta_key_with_seed
    from .token_cache import lock as _lock_token_cache

    # References to mutable globals
    global _active, _parser, _hasher, _private_key
    global _keeta_seed, _address_n, _algorithm, _network_id
    global _expected_index, _first_chunk_time, _completed_ops

    # ======================================================================
    # Entry validation (no mutable state modified here)
    # ======================================================================
    if msg.chunk_phase == KeetaChunkPhase.UNKNOWN:
        raise wire.DataError("Unknown chunk phase")

    # Session restart: if FIRST arrives while _active, clean up and restart
    if msg.chunk_phase == KeetaChunkPhase.FIRST and _active:
        _cleanup()

    # ======================================================================
    # Main body: initialization, streaming, finalization
    # Wrapped in try/finally to guarantee cleanup on ALL paths
    # ======================================================================
    try:
        if msg.chunk_phase == KeetaChunkPhase.FIRST:
            # -- FIRST chunk: validate and initialize ------------------------
            if msg.chunk_index != 0:
                raise wire.DataError("First chunk must have chunk_index 0")
            if msg.address_n is None:
                raise wire.DataError("Missing address_n")
            if msg.network_id is None:
                raise wire.DataError("Missing network_id")

            # Store session parameters
            _address_n = list(msg.address_n)
            _algorithm = msg.algorithm if msg.algorithm is not None else 0
            _network_id = msg.network_id

            if _algorithm == _ALGO_MULTISIG:
                raise wire.DataError("MULTISIG algorithm not supported")

            # Validate BIP-32 path
            _validate_keeta_path(_address_n)

            # Extract account_index from address_n (last path element)
            account_index = _address_n[-1] & 0x7FFFFFFF if _address_n else 0

            # Derive signing key and keeta_seed
            derived_key, keeta_seed = await derive_keeta_key_with_seed(
                _address_n, account_index, _algorithm
            )
            _private_key = bytearray(derived_key)
            _keeta_seed = bytearray(keeta_seed)

            # Initialize incremental parser and SHA3-256 hasher
            _parser = DerParser()
            _hasher = sha3_256(keccak=False)

            # Lock token cache for session duration
            _lock_token_cache()

            # Record session start
            _first_chunk_time = utime.ticks_ms()
            _active = True
            _expected_index = 0
            _completed_ops = []

            # Process FIRST chunk data: HASHER BEFORE PARSER
            chunk_data = bytes(msg.chunk_data) if msg.chunk_data is not None else b""
            if len(chunk_data) > 0:
                _hasher.update(chunk_data)
                ops = _parser.feed(chunk_data)
                _completed_ops.extend(ops)

            _expected_index += 1  # next expected chunk index

        # ==================================================================
        # ADD or LAST without FIRST -- error
        # ==================================================================
        elif not _active:
            raise wire.DataError("No active signing session")

        # ==================================================================
        # Streaming loop: reads ADD/LAST chunks from the wire
        # ==================================================================
        assert _parser is not None  # guaranteed by FIRST branch
        assert _hasher is not None  # guaranteed by FIRST branch
        while True:
            # Read the next chunk from the wire
            ctx = get_context()
            msg = await ctx.read({MessageType.KeetaSignBlock}, KeetaSignBlock)

            # -- Per-chunk validation ---------------------------------------
            if msg.chunk_phase == KeetaChunkPhase.UNKNOWN:
                raise wire.DataError("Unknown chunk phase")

            if msg.chunk_index != _expected_index:
                raise wire.DataError("Chunk sequence error")

            # Check session timeout (120s from FIRST)
            if (
                utime.ticks_diff(utime.ticks_ms(), _first_chunk_time)
                > SESSION_TIMEOUT_MS
            ):
                raise wire.DataError("Session timeout")

            # -- Process chunk data (HASHER BEFORE PARSER) ------------------
            chunk_data = bytes(msg.chunk_data) if msg.chunk_data is not None else b""
            if len(chunk_data) > 0:
                _hasher.update(chunk_data)
                ops = _parser.feed(chunk_data)
                _completed_ops.extend(ops)

            # -- Check for LAST ---------------------------------------------
            if msg.chunk_phase == KeetaChunkPhase.LAST:
                break

            # ADD chunk: advance expected index and continue
            _expected_index += 1

        # ==================================================================
        # Post-processing (after LAST chunk consumed)
        # ==================================================================
        assert _parser is not None  # guaranteed by FIRST branch
        assert _hasher is not None
        assert _private_key is not None

        # Assert parser terminal state
        if _parser.is_failed():
            error_msg = _parser.error_message or "Parser failed"
            raise wire.DataError(f"Block parse failed: {error_msg}")
        if not _parser.is_complete():
            raise wire.DataError("Block parsing incomplete")

        # Extract block header fields
        if _parser.version is None:
            raise wire.DataError("Missing block version")
        if _parser.network_id is None:
            raise wire.DataError("Missing network ID in block header")
        if _parser.account is None:
            raise wire.DataError("Missing account in block header")

        # Validate network_id against known constants
        from .constants import MAINNET_NETWORK_ID, TESTNET_NETWORK_ID

        network_id_bytes = bytes(_parser.network_id)
        if not network_id_bytes:
            raise wire.DataError("Empty network ID in block header")
        parsed_network_id = int.from_bytes(network_id_bytes, "big")
        if parsed_network_id not in (MAINNET_NETWORK_ID, TESTNET_NETWORK_ID):
            raise wire.DataError(f"Unknown network: 0x{parsed_network_id:x}")

        # Derive the expected public key from the derived private key
        assert _algorithm is not None  # guaranteed by FIRST branch
        derived_pubkey = _derive_public_key(bytes(_private_key), _algorithm)

        # Compare with block account from parser
        # block.account is raw OCTET STRING: algo_byte(1) || pubkey(32 or 33)
        account_bytes = bytes(_parser.account)
        if len(account_bytes) < 1:
            raise wire.DataError("Account field too short")
        block_pubkey = account_bytes[1:]

        if derived_pubkey != block_pubkey:
            raise wire.DataError("Account mismatch")

        # Encode the signing account address for display
        from .address import encode_address

        address = encode_address(derived_pubkey, _algorithm)

        # -- Display confirmation flow ------------------------------------
        network_name = _NETWORK_NAMES.get(
            parsed_network_id, f"Network 0x{parsed_network_id:x}"
        )
        await _confirm_signing(address, network_name)
        await _confirm_operations(_completed_ops)

        # -- Sign the block hash ------------------------------------------
        block_hash = _hasher.digest()
        account_index = _address_n[-1] & 0x7FFFFFFF if _address_n else 0

        signature = _sign_block_hash(
            block_hash,
            bytes(_private_key),
            _algorithm,
            _keeta_seed,
            account_index,
        )

        # Post-signing integrity check
        assert _parser.total_bytes > 0, "Parser consumed no bytes"

        return KeetaBlockSignature(signature=signature)

    except Exception:
        # Re-raise after finally ensures cleanup
        raise
    finally:
        # ALWAYS execute cleanup -- success, error, or cancellation
        _cleanup()

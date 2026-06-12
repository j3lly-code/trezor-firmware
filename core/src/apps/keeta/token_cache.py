"""
Keeta token metadata cache.

Session-scoped cache for token metadata (symbol, decimals, chain_id)
with signature verification and immutability guarantees.

Host sends KeetaProvideToken messages before signing transactions
to provide token metadata. The device caches verified token info
for use during transaction parsing and display.

Signature format: DER-encoded SignedTokenInfo SEQUENCE
  SEQUENCE {
    TokenData SEQUENCE {
      symbol      UTF8String,
      address     OCTET STRING,
      decimals    INTEGER,
      chainId     INTEGER
    },
    signature     OCTET STRING  -- DER-encoded ECDSA signature
  }
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import KeetaProvideToken, Success

from trezor.crypto import der
from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha3_256

from .constants import TOKEN_CACHE_MAX_ENTRIES, TRUSTED_TOKEN_KEY

# Session-scoped storage
_cache: dict[bytes, dict] = {}  # {token_address: {symbol, decimals, chain_id}}
_active_signing: bool = False


async def token_cache(msg: "KeetaProvideToken") -> "Success":
    """Handler for KeetaProvideToken messages.

    Validates the token metadata signature against a trusted key,
    then caches the token info for use during transaction parsing.
    """
    from trezor import wire
    from trezor.messages import Success

    # 1. Validate token_address length (33 bytes = compressed secp256k1 pubkey)
    if len(msg.token_address) != 33:
        raise wire.DataError("Invalid token address length")

    # 2. Check active signing lock — reject during active signing
    if _active_signing:
        raise wire.ProcessError("Token provisioning not allowed during active signing")

    # 3. Check cache capacity — FIFO eviction if full
    if len(_cache) >= TOKEN_CACHE_MAX_ENTRIES and msg.token_address not in _cache:
        first_key = next(iter(_cache))
        del _cache[first_key]

    # 4. Verify immutability — reject overwrite of existing cached token
    if msg.token_address in _cache:
        raise wire.DataError("Token already cached -- immutable for session")

    # 5. Verify signature if provided
    if msg.signature:
        _verify_token_signature(msg, TRUSTED_TOKEN_KEY)

    # 6. Cache the token info
    _cache[bytes(msg.token_address)] = {
        "symbol": msg.symbol if msg.symbol else "",
        "decimals": msg.decimals if msg.decimals else 0,
        "chain_id": msg.chain_id if msg.chain_id else 0,
    }

    return Success(message="Token cached")


# ---------------------------------------------------------------------------
# Lookup functions
# ---------------------------------------------------------------------------


def get_token_symbol(address: bytes) -> str | None:
    """Look up token symbol. Returns None if not cached."""
    entry = _cache.get(address)
    if entry is None:
        return None
    return entry["symbol"]


def get_token_decimals(address: bytes) -> int | None:
    """Look up token decimals. Returns None if not cached."""
    entry = _cache.get(address)
    if entry is None:
        return None
    return entry["decimals"]


def get_token_info(address: bytes) -> dict | None:
    """Look up full token info. Returns None if not cached."""
    return _cache.get(address)


# ---------------------------------------------------------------------------
# Lifecycle: active-signing lock
# ---------------------------------------------------------------------------


def lock() -> None:
    """Lock the token cache during active signing."""
    global _active_signing
    _active_signing = True


def unlock() -> None:
    """Unlock the token cache. Idempotent — safe to call multiple times."""
    global _active_signing
    _active_signing = False


def is_locked() -> bool:
    """Check if the token cache is locked."""
    return _active_signing


def clear() -> None:
    """Clear all cached tokens.

    Called on device lock, Initialize, or new session.
    """
    global _active_signing
    _cache.clear()
    _active_signing = False


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def _verify_token_signature(
    msg: "KeetaProvideToken",
    trusted_key: bytes,
) -> None:
    """Verify the SignedTokenInfo signature against the trusted key.

    Parses DER-encoded SignedTokenInfo, computes SHA3-256 over TokenData,
    converts DER signature to raw 64-byte format, and verifies against
    the trusted secp256k1 public key.

    Raises wire.DataError on any validation failure.
    """
    from trezor import wire

    if not msg.signature:
        raise wire.DataError("Token signature required")

    try:
        # Parse SignedTokenInfo DER to extract TokenData and DER signature
        token_data_bytes, der_signature = _parse_signed_token_info(bytes(msg.signature))
    except Exception as e:
        raise wire.DataError("Invalid SignedTokenInfo format") from e

    # Compute SHA3-256 over TokenData bytes (NIST, not Keccak)
    digest = sha3_256(token_data_bytes, keccak=False).digest()

    # Convert DER signature to raw 64-byte (r||s) format
    raw_sig = der.decode_signature(der_signature)

    # Verify ECDSA signature against trusted public key
    # trusted_key is 65-byte uncompressed secp256k1 public key
    if not secp256k1.verify(trusted_key, bytes(raw_sig), digest):
        raise wire.DataError("Invalid token signature")


def _parse_signed_token_info(data: bytes) -> tuple[bytes, bytes]:
    """Parse DER-encoded SignedTokenInfo.

    Expects:
      SEQUENCE {
        TokenData SEQUENCE {
          symbol      UTF8String,
          address     OCTET STRING,
          decimals    INTEGER,
          chainId     INTEGER
        },
        signature     OCTET STRING
      }

    Returns (token_data_bytes, signature_bytes) where:
    - token_data_bytes: the raw DER bytes of the inner TokenData SEQUENCE
      (tag + length + content)
    - signature_bytes: the raw DER-encoded ECDSA signature bytes
      (content of the OCTET STRING, itself a DER SEQUENCE of INTEGERs)
    """
    pos = 0

    # Outer SEQUENCE tag
    if pos >= len(data) or data[pos] != 0x30:
        raise ValueError("Expected SEQUENCE for SignedTokenInfo")
    pos += 1

    # Outer SEQUENCE length
    outer_len = data[pos]
    pos += 1
    if outer_len >= 0x80:
        num_bytes = outer_len & 0x7F
        if num_bytes == 0 or num_bytes > 4:
            raise ValueError("Invalid outer length encoding")
        outer_len = int.from_bytes(data[pos : pos + num_bytes], "big")
        pos += num_bytes

    outer_end = pos + outer_len
    if outer_end > len(data):
        raise ValueError("Data truncated in outer SEQUENCE")

    # First child: TokenData SEQUENCE (0x30)
    if pos >= outer_end or data[pos] != 0x30:
        raise ValueError("Expected TokenData SEQUENCE")
    token_data_start = pos  # Save position of TokenData tag byte
    pos += 1

    # TokenData SEQUENCE length
    td_len = data[pos]
    pos += 1
    if td_len >= 0x80:
        num_bytes = td_len & 0x7F
        if num_bytes == 0 or num_bytes > 4:
            raise ValueError("Invalid TokenData length encoding")
        td_len = int.from_bytes(data[pos : pos + num_bytes], "big")
        pos += num_bytes

    td_content_end = pos + td_len
    if td_content_end > outer_end:
        raise ValueError("TokenData exceeds outer SEQUENCE boundary")

    # Capture full TokenData TLV (tag + length + content)
    token_data_bytes = data[token_data_start:td_content_end]

    pos = td_content_end

    # Second child: signature OCTET STRING (0x04)
    if pos >= outer_end or data[pos] != 0x04:
        raise ValueError("Expected OCTET STRING for signature")
    pos += 1

    sig_outer_len = data[pos]
    pos += 1
    if sig_outer_len >= 0x80:
        num_bytes = sig_outer_len & 0x7F
        if num_bytes == 0 or num_bytes > 4:
            raise ValueError("Invalid signature length encoding")
        sig_outer_len = int.from_bytes(data[pos : pos + num_bytes], "big")
        pos += num_bytes

    # The OCTET STRING content is a DER-encoded ECDSA signature
    signature_bytes = data[pos : pos + sig_outer_len]
    if len(signature_bytes) != sig_outer_len:
        raise ValueError("Signature data truncated")

    return token_data_bytes, signature_bytes

"""
Keeta address encoding/decoding.

Format: keeta_ + base32(lowercase, unpadded)[algorithm_byte || pubkey || checksum(5)]

Checksum: SHA3-256(NIST, not Keccak)[0:5]
"""

from trezor.crypto import base32
from trezor.crypto.hashlib import sha3_256

# Algorithm byte values
_ALGO_SECP256K1 = 0x00
_ALGO_ED25519 = 0x01
_ALGO_NETWORK = 0x02
_ALGO_TOKEN = 0x03
_ALGO_STORAGE = 0x04
_ALGO_SECP256R1 = 0x06
_ALGO_MULTISIG = 0x07

# Pubkey sizes per algorithm (bytes)
_ALGO_PUBKEY_SIZE = {
    _ALGO_SECP256K1: 33,  # compressed: 0x02/0x03 || x (32 bytes)
    _ALGO_ED25519: 32,  # raw 32-byte public key
    _ALGO_NETWORK: 32,  # 32-byte hash (generated account)
    _ALGO_TOKEN: 32,  # 32-byte hash (generated account)
    _ALGO_STORAGE: 32,  # 32-byte hash (generated account)
    _ALGO_SECP256R1: 33,  # compressed: 0x02/0x03 || x (32 bytes)
}

_CHECKSUM_LEN = 5
_ALGO_BYTE_LEN = 1
_ADDRESS_PREFIX = "keeta_"
_ADDRESS_PREFIX_LEN = len(_ADDRESS_PREFIX)


def _sha3_256_nist(data: bytes) -> bytes:
    """Compute NIST SHA3-256 (NOT Keccak).

    trezorcrypto.sha3_256 with keccak=False (default) produces NIST SHA3-256.
    """
    return sha3_256(data, keccak=False).digest()


def _base32_encode_unpadded(data: bytes) -> str:
    """Base32 encode (RFC 4648 uppercase with padding) then strip padding and lowercase."""
    encoded = base32.encode(data)  # returns uppercase with '=' padding
    return encoded.rstrip("=").lower()


def _base32_decode_unpadded(s: str) -> bytes:
    """Restore padding, uppercase, then Base32 decode."""
    padded = s.upper() + "=" * ((8 - len(s) % 8) % 8)
    return base32.decode(padded)


def encode_address(pubkey_bytes: bytes, algorithm: int) -> str:
    """Encode a public key into a Keeta address string.

    Args:
        pubkey_bytes: The public key bytes.
            - secp256k1 (0x00): compressed 33-byte (0x02/0x03 || x)
            - ed25519 (0x01): raw 32-byte public key
            - NETWORK/TOKEN/STORAGE (0x02-0x04): 32-byte hash
            - secp256r1 (0x06): compressed 33-byte (0x02/0x03 || x)
        algorithm: The algorithm byte value.

    Returns:
        A Keeta address string starting with 'keeta_'.

    Raises:
        ValueError: If algorithm is unknown, MULTISIG, or pubkey length is wrong.
    """
    # Validate algorithm
    expected_size = _ALGO_PUBKEY_SIZE.get(algorithm)
    if expected_size is None:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    if algorithm == _ALGO_MULTISIG:
        raise ValueError("MULTISIG addresses cannot be encoded")
    if len(pubkey_bytes) != expected_size:
        raise ValueError(
            f"Invalid pubkey length for algorithm 0x{algorithm:02x}: "
            f"expected {expected_size}, got {len(pubkey_bytes)}"
        )

    # Build payload: algorithm_byte || pubkey_bytes
    algo_byte = bytes([algorithm])
    payload = algo_byte + pubkey_bytes

    # Compute checksum: SHA3-256(payload)[0:5]
    checksum = _sha3_256_nist(payload)[:_CHECKSUM_LEN]

    # Encode: base32(algo_byte || pubkey_bytes || checksum)
    raw = algo_byte + pubkey_bytes + checksum
    encoded = _base32_encode_unpadded(raw)

    return _ADDRESS_PREFIX + encoded


def decode_address(address: str) -> tuple[bytes, int]:
    """Decode a Keeta address string into (pubkey_bytes, algorithm).

    Args:
        address: A Keeta address string starting with 'keeta_'.

    Returns:
        A tuple of (pubkey_bytes, algorithm_byte).

    Raises:
        ValueError: If the address is invalid, checksum mismatches,
                    or algorithm is MULTISIG (0x07).
    """
    # Verify prefix
    if not address.startswith(_ADDRESS_PREFIX):
        raise ValueError(f"Address must start with '{_ADDRESS_PREFIX}'")

    # Strip prefix
    encoded_part = address[_ADDRESS_PREFIX_LEN:]

    # Base32 decode
    decoded = _base32_decode_unpadded(encoded_part)

    # Minimum: algo(1) + pubkey(min 32) + checksum(5) = 38 bytes
    if len(decoded) < _ALGO_BYTE_LEN + min(_ALGO_PUBKEY_SIZE.values()) + _CHECKSUM_LEN:
        raise ValueError("Address too short")

    # Split: algo_byte(1) || pubkey(32/33) || checksum(5)
    algo_byte = decoded[0]
    checksum_stored = decoded[-_CHECKSUM_LEN:]
    payload_candidate = decoded[:-_CHECKSUM_LEN]

    # Determine pubkey size from algorithm
    expected_size = _ALGO_PUBKEY_SIZE.get(algo_byte)
    if expected_size is None:
        raise ValueError(f"Unknown algorithm: 0x{algo_byte:02x}")

    # Verify total length: 1 + pubkey_size + 5
    expected_total = _ALGO_BYTE_LEN + expected_size + _CHECKSUM_LEN
    if len(decoded) != expected_total:
        raise ValueError(
            f"Invalid address length for algorithm 0x{algo_byte:02x}: "
            f"expected {expected_total}, got {len(decoded)}"
        )

    # Reject MULTISIG
    if algo_byte == _ALGO_MULTISIG:
        raise ValueError("MULTISIG addresses not supported")

    # Extract pubkey
    pubkey = decoded[_ALGO_BYTE_LEN : _ALGO_BYTE_LEN + expected_size]

    # Verify checksum (constant-time comparison via direct bytes equality)
    expected_checksum = _sha3_256_nist(payload_candidate)[:_CHECKSUM_LEN]
    if checksum_stored != expected_checksum:
        raise ValueError(
            f"Checksum mismatch: expected {expected_checksum.hex()}, "
            f"got {checksum_stored.hex()}"
        )

    return (pubkey, algo_byte)


def validate_address(address: str) -> bool:
    """Validate a Keeta address string.

    Args:
        address: A Keeta address string.

    Returns:
        True if the address is valid, False otherwise.
    """
    try:
        decode_address(address)
        return True
    except ValueError:
        return False

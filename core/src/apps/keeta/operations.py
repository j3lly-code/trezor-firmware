"""
Keeta operations parser module.

Parses DER-encoded operation TLVs into typed display objects.
ALL display fields are parsed from DER bytes -- NEVER trust host-provided metadata.

Operation TLVs are context-specific constructed tags (0xA0-0xA8) containing
sub-TLVs for each field. Each sub-TLV uses a context-specific primitive tag
(0x80+) where content is the raw field value. Field interpretation depends
on the operation type and field tag number.

9 operation types:
  0xA0 SEND                       -- from, to, amount, token, memo
  0xA1 SET_REP                    -- account, representative
  0xA2 SET_INFO                   -- account, name, description, permissions, metadata
  0xA3 MODIFY_PERMISSIONS         -- account, principal, action, permissions, target
  0xA4 CREATE_IDENTIFIER          -- Multisig/Swap/Bare variants
  0xA5 TOKEN_ADMIN_SUPPLY         -- account, action, amount
  0xA6 TOKEN_ADMIN_MODIFY_BALANCE  -- account, token, action, amount
  0xA7 RECEIVE                    -- account, from, amount, token, exact_match, forward_to
  0xA8 MANAGE_CERTIFICATE         -- opaque (blind-sign only)
  Tags 0xA9-0xAA MUST be REJECTED (unassigned)
"""

from trezor import wire
from trezor.crypto.hashlib import sha3_256

from apps.keeta.address import encode_address
from apps.keeta.constants import (
    OP_BUF_SIZE,
    OP_CREATE_IDENTIFIER,
    OP_MANAGE_CERTIFICATE,
    OP_MODIFY_PERMISSIONS,
    OP_NAMES,
    OP_RECEIVE,
    OP_SEND,
    OP_SET_INFO,
    OP_SET_REP,
    OP_TOKEN_ADMIN_MODIFY_BALANCE,
    OP_TOKEN_ADMIN_SUPPLY,
    REJECTED_OP_TAGS,
)
from apps.keeta.token_cache import get_token_symbol

try:
    from ubinascii import a2b_base64
except ImportError:
    from binascii import a2b_base64

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum amount size in bytes (16 bytes = u128 max)
_MAX_AMOUNT_BYTES = 16

# Permission action values
_PERM_ACTION_ADD = 0
_PERM_ACTION_SUBTRACT = 1
_PERM_ACTION_SET = 2

_PERM_ACTION_NAMES = {0: "Add", 1: "Subtract", 2: "Set"}

# Supply action values
_SUPPLY_ACTION_MINT = 0
_SUPPLY_ACTION_BURN = 1
_SUPPLY_ACTION_SET = 2

_SUPPLY_ACTION_NAMES = {0: "Mint", 1: "Burn", 2: "Set"}

# Modify balance action values
_BALANCE_ACTION_ADD = 0
_BALANCE_ACTION_SUBTRACT = 1
_BALANCE_ACTION_SET = 2

_BALANCE_ACTION_NAMES = {0: "Add", 1: "Subtract", 2: "Set"}

# CREATE_IDENTIFIER types
_IDENTIFIER_TYPE_MULTISIG = 1
_IDENTIFIER_TYPE_SWAP = 2
_IDENTIFIER_TYPE_BARE = 3

_IDENTIFIER_TYPE_NAMES = {1: "Multisig", 2: "Swap", 3: "Bare"}

# SET_INFO metadata decode states
_METADATA_EMPTY = 0
_METADATA_DECODED = 1
_METADATA_UNKNOWN = 2
_METADATA_INVALID = 3

_METADATA_STATE_NAMES = {0: "Empty", 1: "Decoded", 2: "Unknown", 3: "Invalid"}

# Whitelist: valid permission bit positions (from Keeta SDK permission defs)
# Bits 0-15 are defined; bits 16+ are reserved and must be rejected
_VALID_PERMISSION_BITS = frozenset(range(16))

_PERMISSION_BIT_NAMES = {
    0: "ACCESS",
    1: "ADMIN",
    2: "SEND",
    3: "RECEIVE",
    4: "MODIFY_PERMISSIONS",
    5: "SET_INFO",
    6: "DELEGATE",
    7: "REPRESENT",
    8: "CREATE_IDENTIFIER",
    9: "TOKEN_ADMIN",
    10: "CERTIFICATE",
    11: "VOTE",
}

# UTF-8 string sanitization: whitelist ranges
_MIN_PRINTABLE_ASCII = 0x20
_MAX_PRINTABLE_ASCII = 0x7E
_MIN_LATIN1_SUPPLEMENT = 0xA0
_MAX_LATIN1_SUPPLEMENT = 0xFF


# ---------------------------------------------------------------------------
# OperationDisplay
# ---------------------------------------------------------------------------


class OperationDisplay:
    """Typed display object for a decoded operation.

    Attributes:
        tag: Operation tag (0xA0-0xA8).
        name: Human-readable operation type name.
        fields: Dict of field_name -> parsed value.
        is_blind: True if blind-signed (opaque/oversized).
        warnings: List of warning strings for display.
    """

    def __init__(
        self,
        tag: int,
        name: str,
        fields: dict | None = None,
        is_blind: bool = False,
        warnings: list | None = None,
    ):
        self.tag = tag
        self.name = name
        self.fields = fields if fields is not None else {}
        self.is_blind = is_blind
        self.warnings = warnings if warnings is not None else []


# ---------------------------------------------------------------------------
# TLV header / sub-TLV reading helpers
# ---------------------------------------------------------------------------


def _read_tlv_header(data: bytes, pos: int) -> tuple[int, int, int]:
    """Read a DER TLV header starting at pos.

    Returns (tag, length, new_pos).
    Raises wire.DataError on invalid encoding.
    """
    if pos >= len(data):
        raise wire.DataError("Unexpected end of data in TLV header")

    tag = data[pos]
    pos += 1

    if pos >= len(data):
        raise wire.DataError("Unexpected end of data in length field")

    first_len = data[pos]
    pos += 1

    if first_len < 0x80:
        length = first_len
    elif first_len == 0x80:
        raise wire.DataError("Indefinite DER length not supported")
    else:
        num_len_bytes = first_len & 0x7F
        if num_len_bytes == 0 or num_len_bytes > 4:
            raise wire.DataError("Invalid DER long-form length encoding")
        if pos + num_len_bytes > len(data):
            raise wire.DataError("Truncated DER long-form length")
        length = 0
        for _ in range(num_len_bytes):
            length = (length << 8) | data[pos]
            pos += 1
        if num_len_bytes > 1 and length < 0x80:
            raise wire.DataError("Non-minimal DER length encoding")

    return tag, length, pos


def _read_subtlv(data: bytes, pos: int) -> tuple[int | None, bytes | None, int]:
    """Read one sub-TLV from operation content bytes.

    Each field within an operation is a context-specific primitive TLV
    where the content bytes are the raw field value (interpretation
    depends on the field definition).

    Returns (field_tag, content_bytes, new_pos).
    When pos reaches end of data, returns (None, None, pos).
    """
    if pos >= len(data):
        return None, None, pos

    tag, length, pos = _read_tlv_header(data, pos)

    if tag < 0x80 or tag > 0xBF:
        raise wire.DataError(f"Invalid context-specific field tag: 0x{tag:02x}")

    if pos + length > len(data):
        raise wire.DataError("Field content exceeds operation boundary")

    content = data[pos : pos + length]
    pos += length

    return tag, content, pos


def _extract_tlv_content(tlv_bytes: bytes) -> bytes:
    """Extract the content bytes from a DER TLV (strip tag and length)."""
    tag, length, pos = _read_tlv_header(tlv_bytes, 0)
    if pos + length > len(tlv_bytes):
        raise wire.DataError("Truncated TLV content")
    return tlv_bytes[pos : pos + length]


# ---------------------------------------------------------------------------
# Field value parsers (ALL parse from DER bytes)
# ---------------------------------------------------------------------------


def _parse_amount_bytes(data: bytes) -> int:
    """Parse DER INTEGER content bytes into a signed integer.

    Rejects amounts exceeding 16 bytes at parse time (u128 max).
    Detects negative values via MSB of first content byte.
    Returns the integer value (may be negative).
    """
    if not data:
        raise wire.DataError("Empty amount field")

    if len(data) > _MAX_AMOUNT_BYTES:
        raise wire.DataError(
            f"Amount exceeds maximum size ({len(data)} > {_MAX_AMOUNT_BYTES})"
        )

    # Non-minimal encoding check: leading 0x00 when next byte's MSB is 0
    if len(data) > 1 and data[0] == 0x00 and not (data[1] & 0x80):
        raise wire.DataError("Non-minimal DER INTEGER encoding in amount")

    # Valid padding byte: 0x00 prefix when the actual value's MSB is set
    # The value is positive
    if data[0] == 0x00:
        return int.from_bytes(data[1:], "big")

    # No padding: MSB set means negative (two's complement)
    if data[0] & 0x80:
        value = int.from_bytes(data, "big")
        value -= 1 << (len(data) * 8)
        return value

    # Positive value without padding
    return int.from_bytes(data, "big")


def _parse_unsigned_amount(data: bytes) -> int:
    """Parse DER INTEGER content bytes into a non-negative integer.

    Rejects negative values. Used for fields like action codes,
    quorum counts, and other unsigned numerical values.
    """
    if not data:
        raise wire.DataError("Empty unsigned integer field")

    if len(data) > _MAX_AMOUNT_BYTES:
        raise wire.DataError(
            f"Unsigned integer exceeds maximum size ({len(data)} > {_MAX_AMOUNT_BYTES})"
        )

    # Non-minimal encoding check
    if len(data) > 1 and data[0] == 0x00 and not (data[1] & 0x80):
        raise wire.DataError("Non-minimal DER INTEGER encoding in unsigned field")

    # Strip leading 0x00 padding if present (valid when value's MSB would be set)
    if data[0] == 0x00:
        data = data[1:]

    return int.from_bytes(data, "big")


def _format_address(data: bytes) -> str:
    """Convert raw address bytes (algo_byte || pubkey) to Keeta address string."""
    if len(data) < 33:
        raise wire.DataError(f"Address data too short: {len(data)} bytes")

    algo_byte = data[0]
    pubkey = data[1:]

    try:
        return encode_address(pubkey, algo_byte)
    except ValueError as e:
        raise wire.DataError(str(e)) from e


def _sanitize_utf8(data: bytes) -> str:
    """Sanitize and decode UTF-8 bytes using a whitelist approach.

    Only printable ASCII (0x20-0x7E) and Latin-1 Supplement (0xA0-0xFF)
    are allowed. Rejects control characters, zero-width characters,
    bidi overrides, math alphanumerics, and variation selectors.
    """
    sanitized = bytearray()
    for byte in data:
        if _MIN_PRINTABLE_ASCII <= byte <= _MAX_PRINTABLE_ASCII:
            sanitized.append(byte)
        elif _MIN_LATIN1_SUPPLEMENT <= byte <= _MAX_LATIN1_SUPPLEMENT:
            sanitized.append(byte)
        elif byte in (0x09, 0x0A, 0x0D):  # Tab, LF, CR
            sanitized.append(0x20)  # Replace with space
        else:
            raise wire.DataError(f"Invalid UTF-8 character code: 0x{byte:02x}")

    return sanitized.decode("utf-8")


# ---------------------------------------------------------------------------
# Field cardinality tracker
# ---------------------------------------------------------------------------


class _Cardinality:
    """Tracks field occurrence counts for duplicate detection.

    Strict expected cardinality per field:
      REQUIRED = exactly 1
      OPTIONAL = 0 or 1
      REPEATABLE = 0 or more
    """

    REQUIRED = 1
    OPTIONAL = 2
    REPEATABLE = 3

    def __init__(self) -> None:
        self._seen: dict[int, list[int]] = {}

    def check(self, tag: int, expected: int, field_name: str) -> None:
        """Record a field occurrence and validate against expected cardinality.

        Raises wire.DataError on duplicate REQUIRED or OPTIONAL fields.
        """
        if tag not in self._seen:
            self._seen[tag] = []
        occurrences = self._seen[tag]
        occurrences.append(len(occurrences) + 1)  # 1-based occurrence index

        count = len(occurrences)
        if expected == self.REQUIRED and count > 1:
            raise wire.DataError(
                f"Duplicate required field '{field_name}' (tag 0x{tag:02x})"
            )
        if expected == self.OPTIONAL and count > 1:
            raise wire.DataError(
                f"Duplicate optional field '{field_name}' (tag 0x{tag:02x})"
            )

    def assert_seen(self, tag: int, field_name: str) -> None:
        """Assert that a required field was present in the input."""
        if tag not in self._seen:
            raise wire.DataError(
                f"Missing required field '{field_name}' (tag 0x{tag:02x})"
            )


# ---------------------------------------------------------------------------
# Permission bitmask formatting
# ---------------------------------------------------------------------------


def _format_permissions(mask: int, warnings: list) -> str:
    """Format a 64-bit permission bitmask into human-readable names.

    If ANY bit outside the valid whitelist (bits 0-15) is set,
    the operation is rejected. Returns a comma-separated string
    of permission names.
    """
    # Check for undefined bits outside the 0-15 whitelist
    if mask >> 15:
        raise wire.DataError(
            f"Permission bitmask contains undefined bits: 0x{mask:016x}"
        )

    # Extract valid permission names
    names = []
    for bit in sorted(_VALID_PERMISSION_BITS):
        if mask & (1 << bit):
            name = _PERMISSION_BIT_NAMES.get(bit, f"BIT{bit}")
            names.append(name)

    if not names:
        return "None"
    return ", ".join(names)


# ---------------------------------------------------------------------------
# Blind operation display
# ---------------------------------------------------------------------------


def _make_blind_display(tag: int, tlv_bytes: bytes) -> OperationDisplay:
    """Create a display object for blind-signed operations.

    For oversized ops (>512B) or MANAGE_CERTIFICATE, show the operation
    index, byte count, and first 8 hex chars of SHA3-256 hash.
    """
    digest = sha3_256(tlv_bytes, keccak=False).digest()
    hash_preview = digest[:4].hex()  # First 8 hex chars = 4 bytes

    warnings = []
    if tag == OP_MANAGE_CERTIFICATE:
        warnings.append("Certificate operation -- blind signed")
    else:
        warnings.append(
            f"Operation too large for display ({len(tlv_bytes)} bytes) -- blind signed"
        )

    fields = {
        "byte_count": len(tlv_bytes),
        "hash_preview": hash_preview,
    }

    name = OP_NAMES.get(tag, f"Operation 0x{tag:02x}")
    return OperationDisplay(tag, name, fields, is_blind=True, warnings=warnings)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def decode_operation(tag: int, tlv_bytes: bytes) -> OperationDisplay:
    """Parse a DER-encoded operation TLV into a typed display object.

    Args:
        tag: Operation tag (0xA0-0xA8).
        tlv_bytes: Full DER TLV bytes including tag and length.

    Returns:
        An OperationDisplay object with parsed fields and warnings.

    Raises:
        wire.DataError: If the operation data is invalid or rejected.
    """
    # Reject unassigned tags
    if tag in REJECTED_OP_TAGS:
        raise wire.DataError(f"Rejected operation tag: 0x{tag:02x}")

    # Validate tag is known
    if tag not in OP_NAMES:
        raise wire.DataError(f"Unknown operation tag: 0x{tag:02x}")

    # Blind-sign for MANAGE_CERTIFICATE or oversized ops
    if tag == OP_MANAGE_CERTIFICATE or len(tlv_bytes) > OP_BUF_SIZE:
        return _make_blind_display(tag, tlv_bytes)

    # Extract operation content (strip outer TLV header)
    content = _extract_tlv_content(tlv_bytes)

    # Dispatch to appropriate sub-parser
    if tag == OP_SEND:
        return _decode_send(content)
    elif tag == OP_SET_REP:
        return _decode_set_rep(content)
    elif tag == OP_SET_INFO:
        return _decode_set_info(content)
    elif tag == OP_MODIFY_PERMISSIONS:
        return _decode_modify_permissions(content)
    elif tag == OP_CREATE_IDENTIFIER:
        return _decode_create_identifier(content)
    elif tag == OP_TOKEN_ADMIN_SUPPLY:
        return _decode_token_admin_supply(content)
    elif tag == OP_TOKEN_ADMIN_MODIFY_BALANCE:
        return _decode_token_admin_modify_balance(content)
    elif tag == OP_RECEIVE:
        return _decode_receive(content)
    else:
        raise wire.DataError(f"Unhandled operation tag: 0x{tag:02x}")


# ---------------------------------------------------------------------------
# Operation-specific sub-parsers
# ---------------------------------------------------------------------------


def _decode_send(content: bytes) -> OperationDisplay:
    """Parse SEND (0xA0) operation.

    Fields:
      0x80 from     (address, REQUIRED)
      0x81 to       (address, REQUIRED)
      0x82 amount   (integer, REQUIRED) -- 16-byte limit, negative detection
      0x83 token    (address, OPTIONAL)
      0x84 memo     (UTF8String, OPTIONAL)
    """
    card = _Cardinality()
    fields: dict = {}
    pos = 0
    warnings: list[str] = []

    while pos < len(content):
        tag, value, pos = _read_subtlv(content, pos)
        if tag is None:
            break
        assert value is not None  # guaranteed by _read_subtlv when tag is not None

        if tag == 0x80:  # from
            card.check(tag, _Cardinality.REQUIRED, "from")
            fields["from"] = _format_address(value)

        elif tag == 0x81:  # to
            card.check(tag, _Cardinality.REQUIRED, "to")
            fields["to"] = _format_address(value)

        elif tag == 0x82:  # amount
            card.check(tag, _Cardinality.REQUIRED, "amount")
            amount = _parse_amount_bytes(value)
            if amount < 0:
                warnings.append("WARNING: Amount is NEGATIVE")
            fields["amount"] = amount

        elif tag == 0x83:  # token
            card.check(tag, _Cardinality.OPTIONAL, "token")
            token_addr = _format_address(value)
            symbol = get_token_symbol(value)
            if symbol:
                token_addr = f"{token_addr} ({symbol})"
            fields["token"] = token_addr

        elif tag == 0x84:  # memo
            card.check(tag, _Cardinality.OPTIONAL, "memo")
            fields["memo"] = _sanitize_utf8(value)

        else:
            raise wire.DataError(f"Unknown SEND field tag: 0x{tag:02x}")

    card.assert_seen(0x80, "from")
    card.assert_seen(0x81, "to")
    card.assert_seen(0x82, "amount")

    return OperationDisplay(OP_SEND, OP_NAMES[OP_SEND], fields, warnings=warnings)


def _decode_set_rep(content: bytes) -> OperationDisplay:
    """Parse SET_REP (0xA1) operation.

    Fields:
      0x80 account        (address, REQUIRED)
      0x81 representative (address, REQUIRED)

    WARNING: delegating to zero-address/null representative is rejected.
    """
    card = _Cardinality()
    fields: dict = {}
    pos = 0
    warnings: list[str] = []

    while pos < len(content):
        tag, value, pos = _read_subtlv(content, pos)
        if tag is None:
            break
        assert value is not None  # guaranteed by _read_subtlv when tag is not None

        if tag == 0x80:  # account
            card.check(tag, _Cardinality.REQUIRED, "account")
            fields["account"] = _format_address(value)

        elif tag == 0x81:  # representative
            card.check(tag, _Cardinality.REQUIRED, "representative")
            rep_addr = _format_address(value)
            # Check for null/zero representative (all-zero bytes after algo byte)
            # A zero address means delegating voting power to no one
            raw_pubkey = value[1:]  # Strip algorithm byte
            if all(b == 0 for b in raw_pubkey):
                raise wire.DataError(
                    "Null representative address rejected -- would delegate "
                    "voting power to no one"
                )
            fields["representative"] = rep_addr

        else:
            raise wire.DataError(f"Unknown SET_REP field tag: 0x{tag:02x}")

    card.assert_seen(0x80, "account")
    card.assert_seen(0x81, "representative")

    return OperationDisplay(OP_SET_REP, OP_NAMES[OP_SET_REP], fields, warnings=warnings)


def _decode_set_info(content: bytes) -> OperationDisplay:
    """Parse SET_INFO (0xA2) operation.

    Fields:
      0x80 account           (address, REQUIRED)
      0x81 name              (UTF8String, REQUIRED)
      0x82 description       (UTF8String, OPTIONAL)
      0x83 defaultPermission (integer bitmask, REQUIRED)
      0x84 externalPerms     (integer bitmask, OPTIONAL)
      0x85 metadata          (UTF8String base64, OPTIONAL)

    Metadata: base64 decode -> JSON; 4-state display:
      Empty (no metadata), Decoded (show Symbol/Asset ID/Authority),
      Unknown (blind-sign), Invalid (reject).
    """
    card = _Cardinality()
    fields: dict = {}
    pos = 0
    warnings: list[str] = []

    while pos < len(content):
        tag, value, pos = _read_subtlv(content, pos)
        if tag is None:
            break
        assert value is not None  # guaranteed by _read_subtlv when tag is not None

        if tag == 0x80:  # account
            card.check(tag, _Cardinality.REQUIRED, "account")
            fields["account"] = _format_address(value)

        elif tag == 0x81:  # name
            card.check(tag, _Cardinality.REQUIRED, "name")
            fields["name"] = _sanitize_utf8(value)

        elif tag == 0x82:  # description
            card.check(tag, _Cardinality.OPTIONAL, "description")
            fields["description"] = _sanitize_utf8(value)

        elif tag == 0x83:  # defaultPermission
            card.check(tag, _Cardinality.REQUIRED, "defaultPermission")
            perm_value = _parse_amount_bytes(value)
            fields["defaultPermission"] = _format_permissions(perm_value, warnings)

        elif tag == 0x84:  # externalPerms
            card.check(tag, _Cardinality.OPTIONAL, "externalPerms")
            perm_value = _parse_amount_bytes(value)
            fields["externalPerms"] = _format_permissions(perm_value, warnings)

        elif tag == 0x85:  # metadata (base64)
            card.check(tag, _Cardinality.OPTIONAL, "metadata")
            metadata_result = _decode_set_info_metadata(value, warnings)
            fields["metadata"] = metadata_result

        else:
            raise wire.DataError(f"Unknown SET_INFO field tag: 0x{tag:02x}")

    card.assert_seen(0x80, "account")
    card.assert_seen(0x81, "name")
    card.assert_seen(0x83, "defaultPermission")

    return OperationDisplay(
        OP_SET_INFO, OP_NAMES[OP_SET_INFO], fields, warnings=warnings
    )


def _decode_set_info_metadata(data: bytes, warnings: list) -> str:
    """Decode SET_INFO metadata field with 4-state result.

    Returns a display string describing the metadata state.
    Adds to warnings list for Unknown/Invalid states.
    """
    if not data:
        return "Empty"

    # Try base64 decode
    try:
        decoded = a2b_base64(data)
    except Exception:
        raise wire.DataError("SET_INFO metadata: invalid base64 encoding")

    # Try UTF-8 decode
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        warnings.append("SET_INFO metadata: decoded but not valid UTF-8 (blind signed)")
        return "Unknown"

    # Try to extract structured fields from the decoded text
    # Expected format: JSON or structured text with Symbol, Asset ID, Authority
    display_parts = []
    found_fields = False

    for line in text.replace("{", "").replace("}", "").split("\n"):
        line = line.strip()
        for field_prefix in ("Symbol", "Asset ID", "Authority"):
            if line.startswith(field_prefix) or f'"{field_prefix}"' in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key = parts[0].strip().strip('"').strip("'")
                    val = parts[1].strip().strip('"').strip("'").strip(",")
                    if val:
                        display_parts.append(f"{key}: {val}")
                        found_fields = True

    if found_fields:
        return "Decoded: " + " | ".join(display_parts)

    # Decoded but no recognized fields -- blind sign
    warnings.append(
        "SET_INFO metadata: decoded but no recognized fields (blind signed)"
    )
    return "Unknown"


def _decode_modify_permissions(content: bytes) -> OperationDisplay:
    """Parse MODIFY_PERMISSIONS (0xA3) operation.

    Fields:
      0x80 account     (address, REQUIRED)
      0x81 principal   (address, REQUIRED)
      0x82 action      (integer, REQUIRED) -- 0=add, 1=subtract, 2=set
      0x83 permissions (64-bit integer bitmask, REQUIRED)
      0x84 target      (address, OPTIONAL)
    """
    card = _Cardinality()
    fields: dict = {}
    pos = 0
    warnings: list[str] = []

    while pos < len(content):
        tag, value, pos = _read_subtlv(content, pos)
        if tag is None:
            break
        assert value is not None  # guaranteed by _read_subtlv when tag is not None

        if tag == 0x80:  # account
            card.check(tag, _Cardinality.REQUIRED, "account")
            fields["account"] = _format_address(value)

        elif tag == 0x81:  # principal
            card.check(tag, _Cardinality.REQUIRED, "principal")
            fields["principal"] = _format_address(value)

        elif tag == 0x82:  # action
            card.check(tag, _Cardinality.REQUIRED, "action")
            action_val = _parse_unsigned_amount(value)
            action_name = _PERM_ACTION_NAMES.get(action_val)
            if action_name is None:
                raise wire.DataError(f"Invalid permission action value: {action_val}")
            fields["action"] = action_name

        elif tag == 0x83:  # permissions
            card.check(tag, _Cardinality.REQUIRED, "permissions")
            perm_value = _parse_amount_bytes(value)
            if perm_value < 0:
                raise wire.DataError("Negative permission bitmask not allowed")
            fields["permissions"] = _format_permissions(perm_value, warnings)

        elif tag == 0x84:  # target
            card.check(tag, _Cardinality.OPTIONAL, "target")
            fields["target"] = _format_address(value)

        else:
            raise wire.DataError(f"Unknown MODIFY_PERMISSIONS field tag: 0x{tag:02x}")

    card.assert_seen(0x80, "account")
    card.assert_seen(0x81, "principal")
    card.assert_seen(0x82, "action")
    card.assert_seen(0x83, "permissions")

    return OperationDisplay(
        OP_MODIFY_PERMISSIONS,
        OP_NAMES[OP_MODIFY_PERMISSIONS],
        fields,
        warnings=warnings,
    )


def _decode_create_identifier(content: bytes) -> OperationDisplay:
    """Parse CREATE_IDENTIFIER (0xA4) operation.

    Three variants determined by the type field (tag 0x82):
      Type 1 (Multisig): Account, Identifier, Quorum, Signer 1-3
      Type 2 (Swap):     Account, Identifier, Sell Token, Sell Rate,
                         Buy Token, Buy Rate, Quantity
      Type 3 (Bare):     Account, Identifier

    Common fields:
      0x80 account    (address, REQUIRED)
      0x81 identifier (UTF8String, REQUIRED)
      0x82 type       (integer, REQUIRED) -- 1=Multisig, 2=Swap, 3=Bare
    """
    card = _Cardinality()
    fields: dict = {}
    pos = 0
    warnings: list[str] = []

    # Pass 1: parse common fields to determine type
    type_value = None
    raw_subtlvs: list[tuple[int, bytes]] = []

    while pos < len(content):
        tag, value, pos = _read_subtlv(content, pos)
        if tag is None:
            break
        assert value is not None

        raw_subtlvs.append((tag, value))

        if tag == 0x80:  # account
            card.check(tag, _Cardinality.REQUIRED, "account")
            fields["account"] = _format_address(value)

        elif tag == 0x81:  # identifier
            card.check(tag, _Cardinality.REQUIRED, "identifier")
            fields["identifier"] = _sanitize_utf8(value)

        elif tag == 0x82:  # type
            card.check(tag, _Cardinality.REQUIRED, "type")
            type_value = _parse_unsigned_amount(value)
            type_name = _IDENTIFIER_TYPE_NAMES.get(type_value)
            if type_name is None:
                raise wire.DataError(f"Invalid CREATE_IDENTIFIER type: {type_value}")
            fields["type"] = type_name

    card.assert_seen(0x80, "account")
    card.assert_seen(0x81, "identifier")
    card.assert_seen(0x82, "type")

    # Pass 2: parse variant-specific fields
    if type_value == _IDENTIFIER_TYPE_MULTISIG:
        _parse_identifier_multisig(raw_subtlvs, fields, warnings)
    elif type_value == _IDENTIFIER_TYPE_SWAP:
        _parse_identifier_swap(raw_subtlvs, fields, warnings)
    # Type 3 (Bare) has no additional fields

    return OperationDisplay(
        OP_CREATE_IDENTIFIER,
        OP_NAMES[OP_CREATE_IDENTIFIER],
        fields,
        warnings=warnings,
    )


def _parse_identifier_multisig(
    raw_subtlvs: list[tuple[int, bytes]], fields: dict, warnings: list
) -> None:
    """Parse Multisig-specific fields (tags 0x83-0x86).

    Tags:
      0x83 quorum  (integer, REQUIRED)
      0x84 signer1 (address, REQUIRED)
      0x85 signer2 (address, OPTIONAL)
      0x86 signer3 (address, OPTIONAL)

    Quorum validation: reject if quorum > signer_count or quorum == 0.
    """
    card = _Cardinality()
    signers: list[str] = []
    quorum = None

    for tag, value in raw_subtlvs:
        if tag == 0x80 or tag == 0x81 or tag == 0x82:
            continue  # Already parsed

        if tag == 0x83:  # quorum
            card.check(tag, _Cardinality.REQUIRED, "quorum")
            quorum = _parse_unsigned_amount(value)
            fields["quorum"] = quorum

        elif tag == 0x84:  # signer1
            card.check(tag, _Cardinality.REQUIRED, "signer1")
            signers.append(_format_address(value))

        elif tag == 0x85:  # signer2
            card.check(tag, _Cardinality.OPTIONAL, "signer2")
            signers.append(_format_address(value))

        elif tag == 0x86:  # signer3
            card.check(tag, _Cardinality.OPTIONAL, "signer3")
            signers.append(_format_address(value))

    card.assert_seen(0x83, "quorum")
    card.assert_seen(0x84, "signer1")

    # Quorum validation
    if quorum is not None:
        if quorum == 0:
            raise wire.DataError("Multisig quorum must be > 0")
        if quorum > len(signers):
            raise wire.DataError(
                f"Multisig quorum ({quorum}) exceeds signer count ({len(signers)})"
            )

    for i, signer in enumerate(signers):
        fields[f"signer{i + 1}"] = signer


def _parse_identifier_swap(
    raw_subtlvs: list[tuple[int, bytes]], fields: dict, warnings: list
) -> None:
    """Parse Swap-specific fields (tags 0x83-0x87).

    Tags:
      0x83 sell_token  (address, REQUIRED)
      0x84 sell_rate   (integer, REQUIRED)
      0x85 buy_token   (address, REQUIRED)
      0x86 buy_rate    (integer, REQUIRED)
      0x87 quantity    (integer, REQUIRED)
    """
    card = _Cardinality()

    for tag, value in raw_subtlvs:
        if tag == 0x80 or tag == 0x81 or tag == 0x82:
            continue  # Already parsed

        if tag == 0x83:  # sell_token
            card.check(tag, _Cardinality.REQUIRED, "sell_token")
            addr = _format_address(value)
            symbol = get_token_symbol(value)
            if symbol:
                addr = f"{addr} ({symbol})"
            fields["sell_token"] = addr

        elif tag == 0x84:  # sell_rate
            card.check(tag, _Cardinality.REQUIRED, "sell_rate")
            rate = _parse_amount_bytes(value)
            if rate < 0:
                warnings.append("WARNING: sell_rate is NEGATIVE")
            fields["sell_rate"] = rate

        elif tag == 0x85:  # buy_token
            card.check(tag, _Cardinality.REQUIRED, "buy_token")
            addr = _format_address(value)
            symbol = get_token_symbol(value)
            if symbol:
                addr = f"{addr} ({symbol})"
            fields["buy_token"] = addr

        elif tag == 0x86:  # buy_rate
            card.check(tag, _Cardinality.REQUIRED, "buy_rate")
            rate = _parse_amount_bytes(value)
            if rate < 0:
                warnings.append("WARNING: buy_rate is NEGATIVE")
            fields["buy_rate"] = rate

        elif tag == 0x87:  # quantity
            card.check(tag, _Cardinality.REQUIRED, "quantity")
            quantity = _parse_amount_bytes(value)
            if quantity < 0:
                warnings.append("WARNING: quantity is NEGATIVE")
            fields["quantity"] = quantity

    card.assert_seen(0x83, "sell_token")
    card.assert_seen(0x84, "sell_rate")
    card.assert_seen(0x85, "buy_token")
    card.assert_seen(0x86, "buy_rate")
    card.assert_seen(0x87, "quantity")


def _decode_token_admin_supply(content: bytes) -> OperationDisplay:
    """Parse TOKEN_ADMIN_SUPPLY (0xA5) operation.

    Fields:
      0x80 account (address, REQUIRED) -- must equal block signing account
      0x81 action  (integer, REQUIRED) -- 0=mint, 1=burn, 2=set
      0x82 amount  (integer, REQUIRED)

    Authorization: block_account must equal token_account (enforced by signer).
    """
    card = _Cardinality()
    fields: dict = {}
    pos = 0
    warnings: list[str] = []

    while pos < len(content):
        tag, value, pos = _read_subtlv(content, pos)
        if tag is None:
            break
        assert value is not None  # guaranteed by _read_subtlv when tag is not None

        if tag == 0x80:  # account
            card.check(tag, _Cardinality.REQUIRED, "account")
            fields["account"] = _format_address(value)

        elif tag == 0x81:  # action
            card.check(tag, _Cardinality.REQUIRED, "action")
            action_val = _parse_unsigned_amount(value)
            action_name = _SUPPLY_ACTION_NAMES.get(action_val)
            if action_name is None:
                raise wire.DataError(f"Invalid supply action value: {action_val}")
            fields["action"] = action_name

        elif tag == 0x82:  # amount
            card.check(tag, _Cardinality.REQUIRED, "amount")
            amount = _parse_amount_bytes(value)
            if amount < 0:
                warnings.append("WARNING: supply amount is NEGATIVE")
            fields["amount"] = amount

        else:
            raise wire.DataError(f"Unknown TOKEN_ADMIN_SUPPLY field tag: 0x{tag:02x}")

    card.assert_seen(0x80, "account")
    card.assert_seen(0x81, "action")
    card.assert_seen(0x82, "amount")

    return OperationDisplay(
        OP_TOKEN_ADMIN_SUPPLY,
        OP_NAMES[OP_TOKEN_ADMIN_SUPPLY],
        fields,
        warnings=warnings,
    )


def _decode_token_admin_modify_balance(content: bytes) -> OperationDisplay:
    """Parse TOKEN_ADMIN_MODIFY_BALANCE (0xA6) operation.

    Fields:
      0x80 account (address, REQUIRED)
      0x81 token   (address, REQUIRED)
      0x82 action  (integer, REQUIRED) -- 0=add, 1=subtract, 2=set
      0x83 amount  (integer, REQUIRED)

    Prominent warning when Set action with zero amount (balance wipe).
    """
    card = _Cardinality()
    fields: dict = {}
    pos = 0
    warnings: list[str] = []
    action_val = None
    amount = None

    while pos < len(content):
        tag, value, pos = _read_subtlv(content, pos)
        if tag is None:
            break
        assert value is not None  # guaranteed by _read_subtlv when tag is not None

        if tag == 0x80:  # account
            card.check(tag, _Cardinality.REQUIRED, "account")
            fields["account"] = _format_address(value)

        elif tag == 0x81:  # token
            card.check(tag, _Cardinality.REQUIRED, "token")
            token_addr = _format_address(value)
            symbol = get_token_symbol(value)
            if symbol:
                token_addr = f"{token_addr} ({symbol})"
            fields["token"] = token_addr

        elif tag == 0x82:  # action
            card.check(tag, _Cardinality.REQUIRED, "action")
            action_val = _parse_unsigned_amount(value)
            action_name = _BALANCE_ACTION_NAMES.get(action_val)
            if action_name is None:
                raise wire.DataError(
                    f"Invalid modify balance action value: {action_val}"
                )
            fields["action"] = action_name

        elif tag == 0x83:  # amount
            card.check(tag, _Cardinality.REQUIRED, "amount")
            amount = _parse_amount_bytes(value)
            if amount < 0:
                warnings.append("WARNING: balance amount is NEGATIVE")
            fields["amount"] = amount

        else:
            raise wire.DataError(
                f"Unknown TOKEN_ADMIN_MODIFY_BALANCE field tag: 0x{tag:02x}"
            )

    card.assert_seen(0x80, "account")
    card.assert_seen(0x81, "token")
    card.assert_seen(0x82, "action")
    card.assert_seen(0x83, "amount")

    # Warning for Set action with zero amount (balance wipe)
    if action_val == _BALANCE_ACTION_SET and amount == 0:
        warnings.append(
            "PROMINENT WARNING: Setting balance to ZERO will wipe the token balance"
        )

    return OperationDisplay(
        OP_TOKEN_ADMIN_MODIFY_BALANCE,
        OP_NAMES[OP_TOKEN_ADMIN_MODIFY_BALANCE],
        fields,
        warnings=warnings,
    )


def _decode_receive(content: bytes) -> OperationDisplay:
    """Parse RECEIVE (0xA7) operation.

    Fields:
      0x80 account     (address, REQUIRED)
      0x81 from        (address, REQUIRED)
      0x82 amount      (integer, REQUIRED)
      0x83 token       (address, OPTIONAL)
      0x84 exact_match (integer boolean, OPTIONAL) -- 0=false, 1=true
      0x85 forward_to  (address, OPTIONAL)
    """
    card = _Cardinality()
    fields: dict = {}
    pos = 0
    warnings: list[str] = []

    while pos < len(content):
        tag, value, pos = _read_subtlv(content, pos)
        if tag is None:
            break
        assert value is not None  # guaranteed by _read_subtlv when tag is not None

        if tag == 0x80:  # account
            card.check(tag, _Cardinality.REQUIRED, "account")
            fields["account"] = _format_address(value)

        elif tag == 0x81:  # from
            card.check(tag, _Cardinality.REQUIRED, "from")
            fields["from"] = _format_address(value)

        elif tag == 0x82:  # amount
            card.check(tag, _Cardinality.REQUIRED, "amount")
            amount = _parse_amount_bytes(value)
            if amount < 0:
                warnings.append("WARNING: receive amount is NEGATIVE")
            fields["amount"] = amount

        elif tag == 0x83:  # token
            card.check(tag, _Cardinality.OPTIONAL, "token")
            token_addr = _format_address(value)
            symbol = get_token_symbol(value)
            if symbol:
                token_addr = f"{token_addr} ({symbol})"
            fields["token"] = token_addr

        elif tag == 0x84:  # exact_match
            card.check(tag, _Cardinality.OPTIONAL, "exact_match")
            exact_val = _parse_unsigned_amount(value)
            fields["exact_match"] = bool(exact_val)

        elif tag == 0x85:  # forward_to
            card.check(tag, _Cardinality.OPTIONAL, "forward_to")
            fields["forward_to"] = _format_address(value)

        else:
            raise wire.DataError(f"Unknown RECEIVE field tag: 0x{tag:02x}")

    card.assert_seen(0x80, "account")
    card.assert_seen(0x81, "from")
    card.assert_seen(0x82, "amount")

    return OperationDisplay(OP_RECEIVE, OP_NAMES[OP_RECEIVE], fields, warnings=warnings)

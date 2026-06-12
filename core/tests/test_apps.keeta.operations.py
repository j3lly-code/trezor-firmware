# flake8: noqa: F403,F405
"""Tests for Keeta operation parsers.

Covers all 9 operation types (0xA0-0xA8), rejected tags (0xA9-0xAA),
helper functions (_read_tlv_header, _parse_amount_bytes, etc.),
and edge cases (empty body, truncated, duplicate fields, max values).
"""

from common import *  # isort:skip

if not utils.BITCOIN_ONLY:
    from trezor import wire

    from apps.keeta import token_cache as _test_token_cache
    from apps.keeta.constants import (
        OP_BUF_SIZE,
        OP_CREATE_IDENTIFIER,
        OP_MANAGE_CERTIFICATE,
        OP_MODIFY_PERMISSIONS,
        OP_RECEIVE,
        OP_SEND,
        OP_SET_INFO,
        OP_SET_REP,
        OP_TOKEN_ADMIN_MODIFY_BALANCE,
        OP_TOKEN_ADMIN_SUPPLY,
        REJECTED_OP_TAGS,
    )
    from apps.keeta.operations import (
        OperationDisplay,
        _decode_create_identifier,
        _decode_modify_permissions,
        _decode_receive,
        _decode_send,
        _decode_set_info,
        _decode_set_info_metadata,
        _decode_set_rep,
        _decode_token_admin_modify_balance,
        _decode_token_admin_supply,
        _extract_tlv_content,
        _format_address,
        _format_permissions,
        _make_blind_display,
        _parse_amount_bytes,
        _parse_unsigned_amount,
        _read_subtlv,
        _read_tlv_header,
        _sanitize_utf8,
        decode_operation,
    )


# ---------------------------------------------------------------------------
# Test data builders
# ---------------------------------------------------------------------------


def _bit_length(n: int) -> int:
    """Return the number of bits needed to represent integer n.
    Equivalent to n.bit_length() in CPython."""
    if n < 0:
        n = -n
    bits = 0
    while n:
        n >>= 1
        bits += 1
    return bits


def _make_address(algo: int = 0x00, fill: int = 0x01) -> bytes:
    """Create raw address bytes: algo_byte || pubkey.

    algo 0x00 (secp256k1): 1 + 33 = 34 bytes, first pubkey byte 0x02
    algo 0x02 (network):   1 + 32 = 33 bytes
    algo 0x03 (token):     1 + 32 = 33 bytes
    algo 0x06 (secp256r1): 1 + 33 = 34 bytes, first pubkey byte 0x02
    """
    if algo in (0x00, 0x06):
        # Compressed pubkey: 0x02/0x03 || x (32 bytes)
        return bytes([algo, 0x02]) + bytes([fill] * 32)
    else:
        # Network/token addresses: 32-byte hash
        return bytes([algo]) + bytes([fill] * 32)


def _make_subtlv(tag: int, content: bytes) -> bytes:
    """Encode a sub-TLV: tag byte, short length, content bytes."""
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    # Long form for longer content
    length_bytes = _encode_var_length(len(content))
    return bytes([tag]) + length_bytes + content


def _encode_var_length(length: int) -> bytes:
    """Encode a DER length in long form (if length >= 0x80)."""
    if length < 0x80:
        return bytes([length])
    # Convert length to big-endian bytes
    len_bytes = length.to_bytes((_bit_length(length) + 7) // 8, "big")
    return bytes([0x80 | len(len_bytes)]) + len_bytes


def _make_op_tlv(tag: int, fields: list[tuple[int, bytes]]) -> bytes:
    """Build a full operation TLV: outer tag + length + sub-TLVs.

    Args:
        tag: Operation tag (0xA0-0xA8).
        fields: List of (subtag, content_bytes) pairs.

    Returns:
        Full DER TLV bytes (tag + length + content).
    """
    inner = b"".join(_make_subtlv(st, ct) for st, ct in fields)
    return bytes([tag]) + _encode_var_length(len(inner)) + inner


def _make_amount_bytes(value: int) -> bytes:
    """Encode an integer as DER INTEGER content bytes.

    Returns big-endian bytes with minimal encoding.
    Positive values: plain big-endian (with leading 0x00 if MSB set).
    Negative values: two's complement big-endian.
    """
    if value == 0:
        return b"\x00"
    if value > 0:
        result = value.to_bytes((_bit_length(value) + 7) // 8, "big")
        # If MSB is set, add leading 0x00 to make it positive
        if result[0] & 0x80:
            result = b"\x00" + result
        return result
    else:
        # Negative: two's complement
        result = value.to_bytes(((value.bit_length() + 8) // 8) + 1, "big", signed=True)
        return result


# ---------------------------------------------------------------------------
# Tests for helper functions
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationHelpers(unittest.TestCase):
    """Tests for low-level operation helper functions."""

    # -- _read_tlv_header ---------------------------------------------------

    def test_read_tlv_header_short_form(self):
        """Read a simple short-form TLV header."""
        data = bytes([0x80, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])
        tag, length, pos = _read_tlv_header(data, 0)
        self.assertEqual(tag, 0x80)
        self.assertEqual(length, 5)
        self.assertEqual(pos, 2)

    def test_read_tlv_header_long_form(self):
        """Read a long-form TLV header (length > 127)."""
        content = b"\x01" * 0x80  # 128 bytes of content
        data = bytes([0x80, 0x81, 0x80]) + content
        tag, length, pos = _read_tlv_header(data, 0)
        self.assertEqual(tag, 0x80)
        self.assertEqual(length, 0x80)
        self.assertEqual(pos, 3)

    def test_read_tlv_header_long_form_2byte(self):
        """Read a long-form TLV with 2-byte length (0x82 xx xx)."""
        content = b"\x02" * 0x100
        data = bytes([0x80, 0x82, 0x01, 0x00]) + content
        tag, length, pos = _read_tlv_header(data, 0)
        self.assertEqual(tag, 0x80)
        self.assertEqual(length, 0x100)
        self.assertEqual(pos, 4)

    def test_read_tlv_header_empty_data(self):
        """Reject TLV header with empty data."""
        with self.assertRaises(wire.DataError):
            _read_tlv_header(b"", 0)

    def test_read_tlv_header_truncated_length(self):
        """Reject TLV header when pos overshoots data."""
        with self.assertRaises(wire.DataError):
            _read_tlv_header(b"\x80", 0)

    def test_read_tlv_header_truncated_long_form(self):
        """Reject TLV header with truncated long-form length bytes."""
        with self.assertRaises(wire.DataError):
            _read_tlv_header(b"\x80\x82\x01", 0)

    def test_read_tlv_header_indefinite_length(self):
        """Reject indefinite length encoding (0x80)."""
        with self.assertRaises(wire.DataError):
            _read_tlv_header(b"\x80\x80", 0)

    def test_read_tlv_header_invalid_num_len_bytes(self):
        """Reject with num_len_bytes == 0 (long form with 0 length bytes)."""
        with self.assertRaises(wire.DataError):
            _read_tlv_header(b"\x80\x80\x00", 0)

    def test_read_tlv_header_non_minimal_length(self):
        """Reject non-minimal DER length encoding (0x81 0x03 when 0x03 suffices)."""
        with self.assertRaises(wire.DataError):
            _read_tlv_header(b"\x80\x81\x03\x00\x00\x00", 0)

    # -- _read_subtlv ------------------------------------------------------

    def test_read_subtlv_basic(self):
        """Read a single sub-TLV from content bytes."""
        data = _make_subtlv(0x80, b"\x01\x02\x03")
        field_tag, content, new_pos = _read_subtlv(data, 0)
        self.assertEqual(field_tag, 0x80)
        self.assertEqual(content, b"\x01\x02\x03")
        self.assertEqual(new_pos, len(data))

    def test_read_subtlv_at_end(self):
        """Return (None, None, pos) when pos is at end of data."""
        tag, content, new_pos = _read_subtlv(b"", 0)
        self.assertIsNone(tag)
        self.assertIsNone(content)
        self.assertEqual(new_pos, 0)

    def test_read_subtlv_invalid_field_tag_low(self):
        """Reject field tag below 0x80."""
        data = _make_subtlv(0x01, b"data")
        with self.assertRaises(wire.DataError):
            _read_subtlv(data, 0)

    def test_read_subtlv_invalid_field_tag_high(self):
        """Reject field tag above 0xBF."""
        data = _make_subtlv(0xC0, b"data")
        with self.assertRaises(wire.DataError):
            _read_subtlv(data, 0)

    def test_read_subtlv_content_exceeds_boundary(self):
        """Reject when field content exceeds operation boundary."""
        data = bytes([0x80, 0x05, 0x01, 0x02])  # Claims length 5 but only 2 bytes
        with self.assertRaises(wire.DataError):
            _read_subtlv(data, 0)

    # -- _extract_tlv_content ----------------------------------------------

    def test_extract_tlv_content_basic(self):
        """Extract content bytes from a full TLV."""
        content = _make_subtlv(0x80, b"test")
        full_tlv = _make_op_tlv(0xA0, [(0x80, b"test")])
        # full_tlv is: 0xA0 <len> 0x80 0x04 "test"
        extracted = _extract_tlv_content(full_tlv)
        self.assertEqual(extracted, _make_subtlv(0x80, b"test"))

    def test_extract_tlv_content_truncated(self):
        """Reject truncated TLV content."""
        with self.assertRaises(wire.DataError):
            _extract_tlv_content(
                b"\x30\x05\x01\x02"
            )  # Claims length 5 but only 4 bytes

    # -- _parse_amount_bytes ------------------------------------------------

    def test_parse_amount_bytes_zero(self):
        """Parse zero amount."""
        result = _parse_amount_bytes(b"\x00")
        self.assertEqual(result, 0)

    def test_parse_amount_bytes_positive(self):
        """Parse positive amount."""
        result = _parse_amount_bytes(b"\x01\x00")
        self.assertEqual(result, 256)

    def test_parse_amount_bytes_positive_padded(self):
        """Parse positive amount with leading 0x00 padding (MSB guard)."""
        # 0x80 = 128, but MSB is set, so encoded as 0x00 0x80
        result = _parse_amount_bytes(b"\x00\x80")
        self.assertEqual(result, 128)

    def test_parse_amount_bytes_max_16(self):
        """Parse the maximum 16-byte amount (15 significant bytes + leading 0x00)."""
        data = b"\x00" + b"\xff" * 15  # 16 bytes with leading 0x00 for positivity
        result = _parse_amount_bytes(data)
        expected = (1 << 120) - 1  # 15 significant bytes of 0xFF
        self.assertEqual(result, expected)

    def test_parse_amount_bytes_exceeds_16(self):
        """Reject amount exceeding 16 bytes."""
        data = b"\x00" + b"\xff" * 16  # 17 bytes
        with self.assertRaises(wire.DataError):
            _parse_amount_bytes(data)

    def test_parse_amount_bytes_negative(self):
        """Parse negative amount (MSB set, two's complement)."""
        # 0xFF = -1 in one byte
        result = _parse_amount_bytes(b"\xff")
        self.assertEqual(result, -1)

    def test_parse_amount_bytes_negative_large(self):
        """Parse a larger negative amount."""
        # 0xFE = -2 in one byte
        result = _parse_amount_bytes(b"\xfe")
        self.assertEqual(result, -2)

    def test_parse_amount_bytes_non_minimal(self):
        """Reject non-minimal DER INTEGER encoding."""
        with self.assertRaises(wire.DataError):
            _parse_amount_bytes(b"\x00\x01")  # Should be just b"\x01"

    def test_parse_amount_bytes_empty(self):
        """Reject empty amount field."""
        with self.assertRaises(wire.DataError):
            _parse_amount_bytes(b"")

    def test_parse_amount_bytes_non_minimal_zero(self):
        """Reject non-minimal zero: 0x00 0x00."""
        with self.assertRaises(wire.DataError):
            _parse_amount_bytes(b"\x00\x00")

    # -- _parse_unsigned_amount ---------------------------------------------

    def test_parse_unsigned_amount_zero(self):
        """Parse unsigned zero."""
        result = _parse_unsigned_amount(b"\x00")
        self.assertEqual(result, 0)

    def test_parse_unsigned_amount_positive(self):
        """Parse unsigned positive value."""
        result = _parse_unsigned_amount(b"\x2a")
        self.assertEqual(result, 42)

    def test_parse_unsigned_amount_with_padding(self):
        """Parse unsigned with leading 0x00 padding."""
        result = _parse_unsigned_amount(b"\x00\x80")  # MSB set, needs padding
        self.assertEqual(result, 128)

    def test_parse_unsigned_amount_non_minimal(self):
        """Reject non-minimal unsigned integer."""
        with self.assertRaises(wire.DataError):
            _parse_unsigned_amount(b"\x00\x01")

    def test_parse_unsigned_amount_empty(self):
        """Reject empty unsigned field."""
        with self.assertRaises(wire.DataError):
            _parse_unsigned_amount(b"")

    # -- _sanitize_utf8 -----------------------------------------------------

    def test_sanitize_utf8_ascii(self):
        """Sanitize normal ASCII text."""
        result = _sanitize_utf8(b"Hello, World!")
        self.assertEqual(result, "Hello, World!")

    def test_sanitize_utf8_latin1(self):
        """Sanitize Latin-1 Supplement characters."""
        result = _sanitize_utf8(b"\xa9\xae")  # Copyright and Registered
        self.assertEqual(result, "\xa9\xae")

    def test_sanitize_utf8_tab_replaced(self):
        """Replace tab with space."""
        result = _sanitize_utf8(b"a\tb")
        self.assertEqual(result, "a b")

    def test_sanitize_utf8_newline_replaced(self):
        """Replace LF with space."""
        result = _sanitize_utf8(b"a\nb")
        self.assertEqual(result, "a b")

    def test_sanitize_utf8_carriage_return_replaced(self):
        """Replace CR with space."""
        result = _sanitize_utf8(b"a\rb")
        self.assertEqual(result, "a b")

    def test_sanitize_utf8_rejects_control(self):
        """Reject control characters (below 0x20, not tab/lf/cr)."""
        with self.assertRaises(wire.DataError):
            _sanitize_utf8(b"\x01")

    def test_sanitize_utf8_rejects_del(self):
        """Reject DEL character (0x7F)."""
        with self.assertRaises(wire.DataError):
            _sanitize_utf8(b"\x7f")

    def test_sanitize_utf8_empty(self):
        """Empty bytes produce empty string."""
        result = _sanitize_utf8(b"")
        self.assertEqual(result, "")

    # -- _format_address ---------------------------------------------------

    def test_format_address_secp256k1(self):
        """Format a valid secp256k1 address."""
        addr_bytes = _make_address(0x00)
        result = _format_address(addr_bytes)
        self.assertTrue(result.startswith("keeta_"))

    def test_format_address_network(self):
        """Format a NETWORK algorithm address."""
        addr_bytes = _make_address(0x02)
        result = _format_address(addr_bytes)
        self.assertTrue(result.startswith("keeta_"))

    def test_format_address_too_short(self):
        """Reject address data that is too short."""
        with self.assertRaises(wire.DataError):
            _format_address(b"\x00\x02")  # Only 2 bytes, needs 33+

    def test_format_address_unknown_algo(self):
        """Reject address with unknown algorithm byte."""
        with self.assertRaises(wire.DataError):
            _format_address(
                bytes([0x05]) + b"\x02" + bytes([0x01] * 32)
            )  # algo 0x05 unknown

    # -- _format_permissions ------------------------------------------------

    def test_format_permissions_none(self):
        """Format zero permissions as 'None'."""
        result = _format_permissions(0, [])
        self.assertEqual(result, "None")

    def test_format_permissions_access(self):
        """Format ACCESS permission bit."""
        result = _format_permissions(1 << 0, [])
        self.assertEqual(result, "ACCESS")

    def test_format_permissions_multiple(self):
        """Format multiple permission bits."""
        result = _format_permissions((1 << 0) | (1 << 2), [])
        self.assertEqual(result, "ACCESS, SEND")

    def test_format_permissions_all_defined(self):
        """Format all defined permission bits (0-11)."""
        all_bits = sum(1 << b for b in range(12))
        result = _format_permissions(all_bits, [])
        self.assertIn("ACCESS", result)
        self.assertIn("ADMIN", result)
        self.assertIn("VOTE", result)

    def test_format_permissions_rejects_undefined_bits(self):
        """Reject permission bitmask with bits outside 0-15 range."""
        with self.assertRaises(wire.DataError):
            _format_permissions(1 << 16, [])

    def test_format_permissions_rejects_high_bits(self):
        """Reject permission bitmask with high bits set."""
        with self.assertRaises(wire.DataError):
            _format_permissions(1 << 31, [])


# ---------------------------------------------------------------------------
# Tests for SEND operation (0xA0)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationSend(unittest.TestCase):
    """Tests for SEND (0xA0) operation parser."""

    def setUp(self):
        self.from_addr = _make_address(0x00, 0x11)
        self.to_addr = _make_address(0x00, 0x22)
        self.token_addr = _make_address(0x03, 0x33)

    def test_send_valid_minimal(self):
        """Parse a valid minimal SEND operation (from, to, amount)."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x81, self.to_addr),
                (0x82, _make_amount_bytes(1000)),
            ],
        )
        result = decode_operation(OP_SEND, tlv)
        self.assertEqual(result.tag, OP_SEND)
        self.assertEqual(result.name, "Send")
        self.assertIn("from", result.fields)
        self.assertIn("to", result.fields)
        self.assertEqual(result.fields["amount"], 1000)

    def test_send_with_token(self):
        """Parse SEND with token field."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x81, self.to_addr),
                (0x82, _make_amount_bytes(500)),
                (0x83, self.token_addr),
            ],
        )
        result = decode_operation(OP_SEND, tlv)
        self.assertIn("token", result.fields)
        self.assertIn("keeta_", result.fields["token"])

    def test_send_with_memo(self):
        """Parse SEND with memo field."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x81, self.to_addr),
                (0x82, _make_amount_bytes(500)),
                (0x84, b"Test memo"),
            ],
        )
        result = decode_operation(OP_SEND, tlv)
        self.assertEqual(result.fields["memo"], "Test memo")

    def test_send_with_all_fields(self):
        """Parse SEND with all optional fields."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x81, self.to_addr),
                (0x82, _make_amount_bytes(999)),
                (0x83, self.token_addr),
                (0x84, b"Payment for services"),
            ],
        )
        result = decode_operation(OP_SEND, tlv)
        self.assertEqual(result.fields["amount"], 999)
        self.assertIn("token", result.fields)
        self.assertEqual(result.fields["memo"], "Payment for services")

    def test_send_negative_amount(self):
        """Parse SEND with negative amount produces a warning."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x81, self.to_addr),
                (0x82, b"\xff"),  # -1
            ],
        )
        result = decode_operation(OP_SEND, tlv)
        self.assertEqual(result.fields["amount"], -1)
        self.assertTrue(any("NEGATIVE" in w for w in result.warnings))

    def test_send_missing_from(self):
        """Reject SEND without 'from' field."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x81, self.to_addr),
                (0x82, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_send_missing_to(self):
        """Reject SEND without 'to' field."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x82, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_send_missing_amount(self):
        """Reject SEND without 'amount' field."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x81, self.to_addr),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_send_duplicate_from(self):
        """Reject SEND with duplicate 'from' field."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x80, self.from_addr),
                (0x81, self.to_addr),
                (0x82, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_send_amount_exceeds_16_bytes(self):
        """Reject SEND with amount over 16 bytes."""
        oversize = b"\x00" + b"\xff" * 16  # 17 bytes
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x81, self.to_addr),
                (0x82, oversize),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_send_unknown_field_tag(self):
        """Reject SEND with unknown field tag."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x81, self.to_addr),
                (0x82, _make_amount_bytes(100)),
                (0x85, b"unknown"),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_send_empty_body(self):
        """Reject SEND with empty body (no fields at all)."""
        tlv = bytes([OP_SEND, 0x00])  # Tag 0xA0, length 0
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_send_memo_with_invalid_chars(self):
        """Reject SEND with memo containing invalid UTF-8 characters."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.from_addr),
                (0x81, self.to_addr),
                (0x82, _make_amount_bytes(100)),
                (0x84, b"\x01test"),  # control character
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)


# ---------------------------------------------------------------------------
# Tests for SET_REP operation (0xA1)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationSetRep(unittest.TestCase):
    """Tests for SET_REP (0xA1) operation parser."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)
        self.rep = _make_address(0x00, 0x22)

    def test_set_rep_valid(self):
        """Parse a valid SET_REP operation."""
        tlv = _make_op_tlv(
            OP_SET_REP,
            [
                (0x80, self.account),
                (0x81, self.rep),
            ],
        )
        result = decode_operation(OP_SET_REP, tlv)
        self.assertEqual(result.tag, OP_SET_REP)
        self.assertEqual(result.name, "Set Representative")
        self.assertIn("account", result.fields)
        self.assertIn("representative", result.fields)

    def test_set_rep_missing_account(self):
        """Reject SET_REP without account field."""
        tlv = _make_op_tlv(
            OP_SET_REP,
            [
                (0x81, self.rep),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_REP, tlv)

    def test_set_rep_missing_representative(self):
        """Reject SET_REP without representative field."""
        tlv = _make_op_tlv(
            OP_SET_REP,
            [
                (0x80, self.account),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_REP, tlv)

    def test_set_rep_null_representative(self):
        """Reject SET_REP with all-zero pubkey (null representative)."""
        # Use algo 0x02 (NETWORK, 32-byte hash) so all-zero is reachable.
        # secp256k1 (algo 0x00) addresses always have a compressed prefix byte
        # 0x02/0x03 as the first pubkey byte, making them structurally non-zero.
        null_rep = bytes([0x02]) + bytes([0x00] * 32)
        tlv = _make_op_tlv(
            OP_SET_REP,
            [
                (0x80, self.account),
                (0x81, null_rep),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_REP, tlv)

    def test_set_rep_unknown_field(self):
        """Reject SET_REP with unknown field tag."""
        tlv = _make_op_tlv(
            OP_SET_REP,
            [
                (0x80, self.account),
                (0x81, self.rep),
                (0x82, b"\x01"),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_REP, tlv)

    def test_set_rep_duplicate_account(self):
        """Reject SET_REP with duplicate account field."""
        tlv = _make_op_tlv(
            OP_SET_REP,
            [
                (0x80, self.account),
                (0x80, self.account),
                (0x81, self.rep),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_REP, tlv)


# ---------------------------------------------------------------------------
# Tests for SET_INFO operation (0xA2)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationSetInfo(unittest.TestCase):
    """Tests for SET_INFO (0xA2) operation parser."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)

    def test_set_info_valid_minimal(self):
        """Parse minimal valid SET_INFO (account, name, defaultPermission)."""
        tlv = _make_op_tlv(
            OP_SET_INFO,
            [
                (0x80, self.account),
                (0x81, b"My Account"),
                (0x83, _make_amount_bytes(1)),  # ACCESS
            ],
        )
        result = decode_operation(OP_SET_INFO, tlv)
        self.assertEqual(result.tag, OP_SET_INFO)
        self.assertEqual(result.name, "Set Info")
        self.assertEqual(result.fields["name"], "My Account")

    def test_set_info_with_description(self):
        """Parse SET_INFO with optional description."""
        tlv = _make_op_tlv(
            OP_SET_INFO,
            [
                (0x80, self.account),
                (0x81, b"Test"),
                (0x82, b"A description"),
                (0x83, _make_amount_bytes(1)),
            ],
        )
        result = decode_operation(OP_SET_INFO, tlv)
        self.assertEqual(result.fields["description"], "A description")

    def test_set_info_with_external_perms(self):
        """Parse SET_INFO with optional externalPerms."""
        tlv = _make_op_tlv(
            OP_SET_INFO,
            [
                (0x80, self.account),
                (0x81, b"Test"),
                (0x83, _make_amount_bytes(3)),  # ACCESS | ADMIN
                (0x84, _make_amount_bytes(1)),  # ACCESS
            ],
        )
        result = decode_operation(OP_SET_INFO, tlv)
        self.assertIn("defaultPermission", result.fields)
        self.assertIn("externalPerms", result.fields)

    def test_set_info_with_metadata_decoded(self):
        """Parse SET_INFO with valid metadata (base64 encoded JSON)."""
        # Pre-computed base64 of: {"Symbol": "TKN", "Authority": "keeta_test"}
        b64_data = b"eyJTeW1ib2wiOiAiVEtOIiwgIkF1dGhvcml0eSI6ICJrZWV0YV90ZXN0In0="
        tlv = _make_op_tlv(
            OP_SET_INFO,
            [
                (0x80, self.account),
                (0x81, b"Test"),
                (0x83, _make_amount_bytes(1)),
                (0x85, b64_data),
            ],
        )
        result = decode_operation(OP_SET_INFO, tlv)
        self.assertIn("metadata", result.fields)
        meta = result.fields["metadata"]
        self.assertTrue(meta.startswith("Decoded:"), f"Expected Decoded, got: {meta}")

    def test_set_info_metadata_empty(self):
        """Empty metadata field returns 'Empty'."""
        result = _decode_set_info_metadata(b"", [])
        self.assertEqual(result, "Empty")

    def test_set_info_metadata_invalid_base64(self):
        """Reject SET_INFO metadata with invalid base64."""
        with self.assertRaises(wire.DataError):
            _decode_set_info_metadata(b"!!!invalid base64!!!", [])

    def test_set_info_metadata_blob_not_utf8(self):
        """Metadata that decodes to non-UTF-8 returns 'Unknown' with warning."""
        warnings = []
        # Pre-computed base64 of bytes 0x80-0x8F (not valid UTF-8)
        b64_data = b"gIGCg4SFhoeIiYqLjI2Ojw=="
        result = _decode_set_info_metadata(b64_data, warnings)
        self.assertEqual(result, "Unknown")
        self.assertTrue(len(warnings) > 0)

    def test_set_info_missing_name(self):
        """Reject SET_INFO without name field."""
        tlv = _make_op_tlv(
            OP_SET_INFO,
            [
                (0x80, self.account),
                (0x83, _make_amount_bytes(1)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_INFO, tlv)

    def test_set_info_missing_default_permission(self):
        """Reject SET_INFO without defaultPermission field."""
        tlv = _make_op_tlv(
            OP_SET_INFO,
            [
                (0x80, self.account),
                (0x81, b"Test"),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_INFO, tlv)

    def test_set_info_unknown_field(self):
        """Reject SET_INFO with unknown field tag."""
        tlv = _make_op_tlv(
            OP_SET_INFO,
            [
                (0x80, self.account),
                (0x81, b"Test"),
                (0x83, _make_amount_bytes(1)),
                (0x86, b"\x01"),  # Unknown tag
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_INFO, tlv)

    def test_set_info_duplicate_name(self):
        """Reject SET_INFO with duplicate name field."""
        tlv = _make_op_tlv(
            OP_SET_INFO,
            [
                (0x80, self.account),
                (0x81, b"Name1"),
                (0x81, b"Name2"),
                (0x83, _make_amount_bytes(1)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_INFO, tlv)

    def test_set_info_rejects_metadata_bits_16(self):
        """Reject permission bitmask with bits outside 0-15 in SET_INFO."""
        tlv = _make_op_tlv(
            OP_SET_INFO,
            [
                (0x80, self.account),
                (0x81, b"Test"),
                (0x83, _make_amount_bytes(1 << 16)),  # Invalid bit
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SET_INFO, tlv)


# ---------------------------------------------------------------------------
# Tests for MODIFY_PERMISSIONS operation (0xA3)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationModifyPermissions(unittest.TestCase):
    """Tests for MODIFY_PERMISSIONS (0xA3) operation parser."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)
        self.principal = _make_address(0x00, 0x22)

    def test_modify_permissions_add(self):
        """Parse MODIFY_PERMISSIONS with Add action."""
        tlv = _make_op_tlv(
            OP_MODIFY_PERMISSIONS,
            [
                (0x80, self.account),
                (0x81, self.principal),
                (0x82, _make_amount_bytes(0)),  # Add
                (0x83, _make_amount_bytes(0x05)),  # ACCESS | SEND
            ],
        )
        result = decode_operation(OP_MODIFY_PERMISSIONS, tlv)
        self.assertEqual(result.fields["action"], "Add")
        self.assertIn("ACCESS", result.fields["permissions"])
        self.assertIn("SEND", result.fields["permissions"])

    def test_modify_permissions_subtract(self):
        """Parse MODIFY_PERMISSIONS with Subtract action."""
        tlv = _make_op_tlv(
            OP_MODIFY_PERMISSIONS,
            [
                (0x80, self.account),
                (0x81, self.principal),
                (0x82, _make_amount_bytes(1)),  # Subtract
                (0x83, _make_amount_bytes(0x01)),  # ACCESS
            ],
        )
        result = decode_operation(OP_MODIFY_PERMISSIONS, tlv)
        self.assertEqual(result.fields["action"], "Subtract")

    def test_modify_permissions_set(self):
        """Parse MODIFY_PERMISSIONS with Set action."""
        tlv = _make_op_tlv(
            OP_MODIFY_PERMISSIONS,
            [
                (0x80, self.account),
                (0x81, self.principal),
                (0x82, _make_amount_bytes(2)),  # Set
                (0x83, _make_amount_bytes(0x03)),  # ACCESS | ADMIN
            ],
        )
        result = decode_operation(OP_MODIFY_PERMISSIONS, tlv)
        self.assertEqual(result.fields["action"], "Set")

    def test_modify_permissions_with_target(self):
        """Parse MODIFY_PERMISSIONS with optional target field."""
        target = _make_address(0x00, 0x33)
        tlv = _make_op_tlv(
            OP_MODIFY_PERMISSIONS,
            [
                (0x80, self.account),
                (0x81, self.principal),
                (0x82, _make_amount_bytes(0)),
                (0x83, _make_amount_bytes(0x01)),
                (0x84, target),
            ],
        )
        result = decode_operation(OP_MODIFY_PERMISSIONS, tlv)
        self.assertIn("target", result.fields)

    def test_modify_permissions_invalid_action(self):
        """Reject MODIFY_PERMISSIONS with invalid action value."""
        tlv = _make_op_tlv(
            OP_MODIFY_PERMISSIONS,
            [
                (0x80, self.account),
                (0x81, self.principal),
                (0x82, _make_amount_bytes(99)),  # Invalid
                (0x83, _make_amount_bytes(0x01)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_MODIFY_PERMISSIONS, tlv)

    def test_modify_permissions_negative_bitmask(self):
        """Reject MODIFY_PERMISSIONS with negative permission bitmask."""
        tlv = _make_op_tlv(
            OP_MODIFY_PERMISSIONS,
            [
                (0x80, self.account),
                (0x81, self.principal),
                (0x82, _make_amount_bytes(0)),
                (0x83, b"\xff"),  # -1 (negative)
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_MODIFY_PERMISSIONS, tlv)

    def test_modify_permissions_missing_principal(self):
        """Reject MODIFY_PERMISSIONS missing principal."""
        tlv = _make_op_tlv(
            OP_MODIFY_PERMISSIONS,
            [
                (0x80, self.account),
                (0x82, _make_amount_bytes(0)),
                (0x83, _make_amount_bytes(0x01)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_MODIFY_PERMISSIONS, tlv)

    def test_modify_permissions_missing_action(self):
        """Reject MODIFY_PERMISSIONS missing action."""
        tlv = _make_op_tlv(
            OP_MODIFY_PERMISSIONS,
            [
                (0x80, self.account),
                (0x81, self.principal),
                (0x83, _make_amount_bytes(0x01)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_MODIFY_PERMISSIONS, tlv)

    def test_modify_permissions_missing_permissions(self):
        """Reject MODIFY_PERMISSIONS missing permissions."""
        tlv = _make_op_tlv(
            OP_MODIFY_PERMISSIONS,
            [
                (0x80, self.account),
                (0x81, self.principal),
                (0x82, _make_amount_bytes(0)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_MODIFY_PERMISSIONS, tlv)


# ---------------------------------------------------------------------------
# Tests for CREATE_IDENTIFIER operation (0xA4)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationCreateIdentifier(unittest.TestCase):
    """Tests for CREATE_IDENTIFIER (0xA4) operation parser."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)

    def test_create_identifier_multisig(self):
        """Parse CREATE_IDENTIFIER Multisig variant."""
        signer1 = _make_address(0x00, 0x22)
        signer2 = _make_address(0x00, 0x33)
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x81, b"ident-1"),
                (0x82, _make_amount_bytes(1)),  # Multisig
                (0x83, _make_amount_bytes(2)),  # Quorum = 2
                (0x84, signer1),
                (0x85, signer2),
            ],
        )
        result = decode_operation(OP_CREATE_IDENTIFIER, tlv)
        self.assertEqual(result.fields["type"], "Multisig")
        self.assertEqual(result.fields["quorum"], 2)
        self.assertIn("signer1", result.fields)
        self.assertIn("signer2", result.fields)

    def test_create_identifier_multisig_full(self):
        """Parse CREATE_IDENTIFIER Multisig with all 3 signers."""
        s1 = _make_address(0x00, 0x11)
        s2 = _make_address(0x00, 0x22)
        s3 = _make_address(0x00, 0x33)
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x81, b"multisig-full"),
                (0x82, _make_amount_bytes(1)),  # Multisig
                (0x83, _make_amount_bytes(3)),  # Quorum = 3
                (0x84, s1),
                (0x85, s2),
                (0x86, s3),
            ],
        )
        result = decode_operation(OP_CREATE_IDENTIFIER, tlv)
        self.assertEqual(result.fields["quorum"], 3)
        self.assertIn("signer1", result.fields)
        self.assertIn("signer2", result.fields)
        self.assertIn("signer3", result.fields)

    def test_create_identifier_swap(self):
        """Parse CREATE_IDENTIFIER Swap variant."""
        sell_token = _make_address(0x03, 0x44)
        buy_token = _make_address(0x03, 0x55)
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x81, b"swap-1"),
                (0x82, _make_amount_bytes(2)),  # Swap
                (0x83, sell_token),
                (0x84, _make_amount_bytes(100)),
                (0x85, buy_token),
                (0x86, _make_amount_bytes(200)),
                (0x87, _make_amount_bytes(50)),
            ],
        )
        result = decode_operation(OP_CREATE_IDENTIFIER, tlv)
        self.assertEqual(result.fields["type"], "Swap")
        self.assertEqual(result.fields["sell_rate"], 100)
        self.assertEqual(result.fields["buy_rate"], 200)
        self.assertEqual(result.fields["quantity"], 50)
        self.assertIn("sell_token", result.fields)
        self.assertIn("buy_token", result.fields)

    def test_create_identifier_bare(self):
        """Parse CREATE_IDENTIFIER Bare variant (no extra fields)."""
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x81, b"bare-1"),
                (0x82, _make_amount_bytes(3)),  # Bare
            ],
        )
        result = decode_operation(OP_CREATE_IDENTIFIER, tlv)
        self.assertEqual(result.fields["type"], "Bare")
        # Only account, identifier, type should be present
        self.assertIn("account", result.fields)
        self.assertIn("identifier", result.fields)
        self.assertTrue("quorum" not in result.fields)

    def test_create_identifier_invalid_type(self):
        """Reject CREATE_IDENTIFIER with invalid type."""
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x81, b"test"),
                (0x82, _make_amount_bytes(99)),  # Invalid type
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_CREATE_IDENTIFIER, tlv)

    def test_create_identifier_multisig_quorum_zero(self):
        """Reject CREATE_IDENTIFIER Multisig with quorum == 0."""
        s1 = _make_address(0x00, 0x22)
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x81, b"test"),
                (0x82, _make_amount_bytes(1)),  # Multisig
                (0x83, _make_amount_bytes(0)),  # Quorum = 0
                (0x84, s1),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_CREATE_IDENTIFIER, tlv)

    def test_create_identifier_multisig_quorum_exceeds_signers(self):
        """Reject CREATE_IDENTIFIER Multisig where quorum > signer count."""
        s1 = _make_address(0x00, 0x22)
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x81, b"test"),
                (0x82, _make_amount_bytes(1)),  # Multisig
                (0x83, _make_amount_bytes(5)),  # Quorum = 5, but only 1 signer
                (0x84, s1),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_CREATE_IDENTIFIER, tlv)

    def test_create_identifier_missing_account(self):
        """Reject CREATE_IDENTIFIER without account."""
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x81, b"test"),
                (0x82, _make_amount_bytes(3)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_CREATE_IDENTIFIER, tlv)

    def test_create_identifier_missing_identifier(self):
        """Reject CREATE_IDENTIFIER without identifier field."""
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x82, _make_amount_bytes(3)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_CREATE_IDENTIFIER, tlv)

    def test_create_identifier_missing_type(self):
        """Reject CREATE_IDENTIFIER without type field."""
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x81, b"test"),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_CREATE_IDENTIFIER, tlv)

    def test_create_identifier_swap_negative_rate(self):
        """Parse CREATE_IDENTIFIER Swap with negative sell_rate produces warning."""
        sell_token = _make_address(0x03, 0x44)
        buy_token = _make_address(0x03, 0x55)
        tlv = _make_op_tlv(
            OP_CREATE_IDENTIFIER,
            [
                (0x80, self.account),
                (0x81, b"swap-neg"),
                (0x82, _make_amount_bytes(2)),  # Swap
                (0x83, sell_token),
                (0x84, b"\xff"),  # sell_rate = -1
                (0x85, buy_token),
                (0x86, _make_amount_bytes(200)),
                (0x87, _make_amount_bytes(50)),
            ],
        )
        result = decode_operation(OP_CREATE_IDENTIFIER, tlv)
        self.assertEqual(result.fields["sell_rate"], -1)
        self.assertTrue(any("NEGATIVE" in w for w in result.warnings))


# ---------------------------------------------------------------------------
# Tests for TOKEN_ADMIN_SUPPLY operation (0xA5)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationTokenAdminSupply(unittest.TestCase):
    """Tests for TOKEN_ADMIN_SUPPLY (0xA5) operation parser."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)

    def test_supply_mint(self):
        """Parse TOKEN_ADMIN_SUPPLY with Mint action."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_SUPPLY,
            [
                (0x80, self.account),
                (0x81, _make_amount_bytes(0)),  # Mint
                (0x82, _make_amount_bytes(1000000)),
            ],
        )
        result = decode_operation(OP_TOKEN_ADMIN_SUPPLY, tlv)
        self.assertEqual(result.fields["action"], "Mint")
        self.assertEqual(result.fields["amount"], 1000000)

    def test_supply_burn(self):
        """Parse TOKEN_ADMIN_SUPPLY with Burn action."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_SUPPLY,
            [
                (0x80, self.account),
                (0x81, _make_amount_bytes(1)),  # Burn
                (0x82, _make_amount_bytes(500)),
            ],
        )
        result = decode_operation(OP_TOKEN_ADMIN_SUPPLY, tlv)
        self.assertEqual(result.fields["action"], "Burn")

    def test_supply_set(self):
        """Parse TOKEN_ADMIN_SUPPLY with Set action."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_SUPPLY,
            [
                (0x80, self.account),
                (0x81, _make_amount_bytes(2)),  # Set
                (0x82, _make_amount_bytes(10000000)),
            ],
        )
        result = decode_operation(OP_TOKEN_ADMIN_SUPPLY, tlv)
        self.assertEqual(result.fields["action"], "Set")

    def test_supply_invalid_action(self):
        """Reject TOKEN_ADMIN_SUPPLY with invalid action value."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_SUPPLY,
            [
                (0x80, self.account),
                (0x81, _make_amount_bytes(99)),
                (0x82, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_TOKEN_ADMIN_SUPPLY, tlv)

    def test_supply_negative_amount(self):
        """Parse TOKEN_ADMIN_SUPPLY with negative amount produces warning."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_SUPPLY,
            [
                (0x80, self.account),
                (0x81, _make_amount_bytes(0)),
                (0x82, b"\xff"),  # -1
            ],
        )
        result = decode_operation(OP_TOKEN_ADMIN_SUPPLY, tlv)
        self.assertEqual(result.fields["amount"], -1)
        self.assertTrue(any("NEGATIVE" in w for w in result.warnings))

    def test_supply_missing_account(self):
        """Reject TOKEN_ADMIN_SUPPLY without account."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_SUPPLY,
            [
                (0x81, _make_amount_bytes(0)),
                (0x82, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_TOKEN_ADMIN_SUPPLY, tlv)

    def test_supply_missing_action(self):
        """Reject TOKEN_ADMIN_SUPPLY without action."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_SUPPLY,
            [
                (0x80, self.account),
                (0x82, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_TOKEN_ADMIN_SUPPLY, tlv)

    def test_supply_missing_amount(self):
        """Reject TOKEN_ADMIN_SUPPLY without amount."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_SUPPLY,
            [
                (0x80, self.account),
                (0x81, _make_amount_bytes(0)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_TOKEN_ADMIN_SUPPLY, tlv)


# ---------------------------------------------------------------------------
# Tests for TOKEN_ADMIN_MODIFY_BALANCE operation (0xA6)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationModifyBalance(unittest.TestCase):
    """Tests for TOKEN_ADMIN_MODIFY_BALANCE (0xA6) operation parser."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)
        self.token = _make_address(0x03, 0x22)

    def test_modify_balance_add(self):
        """Parse TOKEN_ADMIN_MODIFY_BALANCE with Add action."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x81, self.token),
                (0x82, _make_amount_bytes(0)),  # Add
                (0x83, _make_amount_bytes(500)),
            ],
        )
        result = decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)
        self.assertEqual(result.fields["action"], "Add")
        self.assertEqual(result.fields["amount"], 500)

    def test_modify_balance_subtract(self):
        """Parse TOKEN_ADMIN_MODIFY_BALANCE with Subtract action."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x81, self.token),
                (0x82, _make_amount_bytes(1)),  # Subtract
                (0x83, _make_amount_bytes(100)),
            ],
        )
        result = decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)
        self.assertEqual(result.fields["action"], "Subtract")

    def test_modify_balance_set(self):
        """Parse TOKEN_ADMIN_MODIFY_BALANCE with Set action."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x81, self.token),
                (0x82, _make_amount_bytes(2)),  # Set
                (0x83, _make_amount_bytes(1000)),
            ],
        )
        result = decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)
        self.assertEqual(result.fields["action"], "Set")

    def test_modify_balance_set_zero_warning(self):
        """Parse TOKEN_ADMIN_MODIFY_BALANCE Set with zero amount produces prominent warning."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x81, self.token),
                (0x82, _make_amount_bytes(2)),  # Set
                (0x83, _make_amount_bytes(0)),  # Zero
            ],
        )
        result = decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)
        self.assertTrue(any("PROMINENT" in w for w in result.warnings))

    def test_modify_balance_invalid_action(self):
        """Reject TOKEN_ADMIN_MODIFY_BALANCE with invalid action."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x81, self.token),
                (0x82, _make_amount_bytes(99)),
                (0x83, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)

    def test_modify_balance_negative_amount(self):
        """Parse TOKEN_ADMIN_MODIFY_BALANCE with negative amount produces warning."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x81, self.token),
                (0x82, _make_amount_bytes(0)),
                (0x83, b"\xfe"),  # -2
            ],
        )
        result = decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)
        self.assertEqual(result.fields["amount"], -2)
        self.assertTrue(any("NEGATIVE" in w for w in result.warnings))

    def test_modify_balance_missing_account(self):
        """Reject TOKEN_ADMIN_MODIFY_BALANCE without account."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x81, self.token),
                (0x82, _make_amount_bytes(0)),
                (0x83, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)

    def test_modify_balance_missing_token(self):
        """Reject TOKEN_ADMIN_MODIFY_BALANCE without token."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x82, _make_amount_bytes(0)),
                (0x83, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)

    def test_modify_balance_missing_action(self):
        """Reject TOKEN_ADMIN_MODIFY_BALANCE without action."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x81, self.token),
                (0x83, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)

    def test_modify_balance_missing_amount(self):
        """Reject TOKEN_ADMIN_MODIFY_BALANCE without amount."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x81, self.token),
                (0x82, _make_amount_bytes(0)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)

    def test_modify_balance_token_with_symbol(self):
        """Parse TOKEN_ADMIN_MODIFY_BALANCE where token address has cached symbol."""
        tlv = _make_op_tlv(
            OP_TOKEN_ADMIN_MODIFY_BALANCE,
            [
                (0x80, self.account),
                (0x81, self.token),
                (0x82, _make_amount_bytes(0)),
                (0x83, _make_amount_bytes(100)),
            ],
        )
        # Set up token cache
        _test_token_cache._cache[self.token] = {
            "symbol": "TKN",
            "decimals": 8,
            "chain_id": 1413829460,
        }
        try:
            result = decode_operation(OP_TOKEN_ADMIN_MODIFY_BALANCE, tlv)
            self.assertIn("TKN", result.fields["token"])
        finally:
            _test_token_cache._cache.pop(self.token, None)


# ---------------------------------------------------------------------------
# Tests for RECEIVE operation (0xA7)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationReceive(unittest.TestCase):
    """Tests for RECEIVE (0xA7) operation parser."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)
        self.from_addr = _make_address(0x00, 0x22)

    def test_receive_valid_minimal(self):
        """Parse valid minimal RECEIVE (account, from, amount)."""
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x81, self.from_addr),
                (0x82, _make_amount_bytes(1000)),
            ],
        )
        result = decode_operation(OP_RECEIVE, tlv)
        self.assertEqual(result.tag, OP_RECEIVE)
        self.assertEqual(result.name, "Receive")
        self.assertEqual(result.fields["amount"], 1000)

    def test_receive_with_token(self):
        """Parse RECEIVE with token field."""
        token = _make_address(0x03, 0x33)
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x81, self.from_addr),
                (0x82, _make_amount_bytes(500)),
                (0x83, token),
            ],
        )
        result = decode_operation(OP_RECEIVE, tlv)
        self.assertIn("token", result.fields)

    def test_receive_exact_match_true(self):
        """Parse RECEIVE with exact_match = true."""
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x81, self.from_addr),
                (0x82, _make_amount_bytes(500)),
                (0x84, _make_amount_bytes(1)),  # exact_match = true
            ],
        )
        result = decode_operation(OP_RECEIVE, tlv)
        self.assertTrue(result.fields["exact_match"])

    def test_receive_exact_match_false(self):
        """Parse RECEIVE with exact_match = false."""
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x81, self.from_addr),
                (0x82, _make_amount_bytes(500)),
                (0x84, _make_amount_bytes(0)),  # exact_match = false
            ],
        )
        result = decode_operation(OP_RECEIVE, tlv)
        self.assertFalse(result.fields["exact_match"])

    def test_receive_with_forward_to(self):
        """Parse RECEIVE with forward_to field."""
        forward = _make_address(0x00, 0x44)
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x81, self.from_addr),
                (0x82, _make_amount_bytes(500)),
                (0x85, forward),
            ],
        )
        result = decode_operation(OP_RECEIVE, tlv)
        self.assertIn("forward_to", result.fields)

    def test_receive_all_fields(self):
        """Parse RECEIVE with all fields."""
        token = _make_address(0x03, 0x33)
        forward = _make_address(0x00, 0x44)
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x81, self.from_addr),
                (0x82, _make_amount_bytes(100)),
                (0x83, token),
                (0x84, _make_amount_bytes(1)),
                (0x85, forward),
            ],
        )
        result = decode_operation(OP_RECEIVE, tlv)
        self.assertIn("token", result.fields)
        self.assertTrue(result.fields["exact_match"])
        self.assertIn("forward_to", result.fields)

    def test_receive_negative_amount(self):
        """Parse RECEIVE with negative amount produces warning."""
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x81, self.from_addr),
                (0x82, b"\xff"),  # -1
            ],
        )
        result = decode_operation(OP_RECEIVE, tlv)
        self.assertEqual(result.fields["amount"], -1)
        self.assertTrue(any("NEGATIVE" in w for w in result.warnings))

    def test_receive_missing_from(self):
        """Reject RECEIVE without from field."""
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x82, _make_amount_bytes(100)),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_RECEIVE, tlv)

    def test_receive_missing_amount(self):
        """Reject RECEIVE without amount."""
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x81, self.from_addr),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_RECEIVE, tlv)

    def test_receive_unknown_field(self):
        """Reject RECEIVE with unknown field tag."""
        tlv = _make_op_tlv(
            OP_RECEIVE,
            [
                (0x80, self.account),
                (0x81, self.from_addr),
                (0x82, _make_amount_bytes(100)),
                (0x86, b"\x01"),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_RECEIVE, tlv)


# ---------------------------------------------------------------------------
# Tests for MANAGE_CERTIFICATE operation (0xA8)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationManageCertificate(unittest.TestCase):
    """Tests for MANAGE_CERTIFICATE (0xA8) operation parser.

    MANAGE_CERTIFICATE is always blind-signed (opaque blob).
    """

    def test_manage_certificate_small(self):
        """Parse a small MANAGE_CERTIFICATE (always blind-signed)."""
        cert_data = b"\x01\x02\x03\x04" * 10  # 40 bytes
        tlv = _make_op_tlv(OP_MANAGE_CERTIFICATE, [(0x80, cert_data)])
        result = decode_operation(OP_MANAGE_CERTIFICATE, tlv)
        self.assertTrue(result.is_blind)
        self.assertIn("byte_count", result.fields)
        self.assertIn("hash_preview", result.fields)
        self.assertTrue(any("blind" in w.lower() for w in result.warnings))

    def test_manage_certificate_empty(self):
        """Parse MANAGE_CERTIFICATE with minimal body."""
        tlv = bytes(
            [OP_MANAGE_CERTIFICATE, 0x02, 0x80, 0x00]
        )  # tag 0xA8, len 2, subtag 0x80 len 0
        result = decode_operation(OP_MANAGE_CERTIFICATE, tlv)
        self.assertTrue(result.is_blind)

    def test_manage_certificate_large(self):
        """Parse MANAGE_CERTIFICATE with large blob."""
        cert_data = bytes(range(256))
        tlv = _make_op_tlv(OP_MANAGE_CERTIFICATE, [(0x80, cert_data)])
        result = decode_operation(OP_MANAGE_CERTIFICATE, tlv)
        self.assertTrue(result.is_blind)
        self.assertEqual(result.fields["byte_count"], len(tlv))


# ---------------------------------------------------------------------------
# Tests for oversized operations (blind signing)
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationOversized(unittest.TestCase):
    """Tests for oversized operations that exceed OP_BUF_SIZE."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)
        self.to = _make_address(0x00, 0x22)

    def test_send_oversized(self):
        """Parse an oversized SEND operation (blind-signed)."""
        # Create a SEND with a very long memo field that exceeds OP_BUF_SIZE
        memo = b"X" * (OP_BUF_SIZE + 50)  # Exceeds 512 bytes
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.account),
                (0x81, self.to),
                (0x82, _make_amount_bytes(100)),
                (0x84, memo),
            ],
        )
        result = decode_operation(OP_SEND, tlv)
        self.assertTrue(result.is_blind)
        self.assertIn("byte_count", result.fields)
        self.assertIn("hash_preview", result.fields)

    def test_oversized_op_has_valid_hash_preview(self):
        """Oversized blind display has 8-char hash preview."""
        memo = b"Y" * (OP_BUF_SIZE + 10)
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.account),
                (0x81, self.to),
                (0x82, _make_amount_bytes(100)),
                (0x84, memo),
            ],
        )
        result = decode_operation(OP_SEND, tlv)
        self.assertEqual(len(result.fields["hash_preview"]), 8)


# ---------------------------------------------------------------------------
# Tests for _make_blind_display helper
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaBlindDisplay(unittest.TestCase):
    """Tests for _make_blind_display helper function."""

    def test_blind_display_basic(self):
        """Create a blind display with expected fields."""
        result = _make_blind_display(0xA0, bytes([0xA0, 0x03, 0x01, 0x02, 0x03]))
        self.assertTrue(result.is_blind)
        self.assertEqual(result.fields["byte_count"], 5)
        self.assertEqual(len(result.fields["hash_preview"]), 8)

    def test_blind_display_certificate_warning(self):
        """Certificate operations show appropriate warning."""
        result = _make_blind_display(0xA8, bytes([0xA8, 0x00]))
        self.assertIn("Certificate", str(result.warnings))

    def test_blind_display_oversized_warning(self):
        """Non-certificate oversized ops show size warning."""
        result = _make_blind_display(
            0xA0, bytes([0xA0] + [0x82, 0x02, 0x01, 0x00] + [0x00] * 256)
        )
        self.assertIn("too large", str(result.warnings).lower())

    def test_blind_display_unknown_tag_name(self):
        """Blind display uses fallback name for unknown tags."""
        result = _make_blind_display(0xFF, bytes([0xFF, 0x00]))
        self.assertIn("Operation 0xff", result.name)


# ---------------------------------------------------------------------------
# Tests for rejected operation tags
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationRejectedTags(unittest.TestCase):
    """Tests that unassigned operation tags are rejected."""

    def test_reject_tag_a9(self):
        """Reject operation tag 0xA9."""
        with self.assertRaises(wire.DataError):
            decode_operation(0xA9, bytes([0xA9, 0x00]))

    def test_reject_tag_aa(self):
        """Reject operation tag 0xAA."""
        with self.assertRaises(wire.DataError):
            decode_operation(0xAA, bytes([0xAA, 0x00]))

    def test_reject_unknown_tag(self):
        """Reject completely unknown operation tag."""
        with self.assertRaises(wire.DataError):
            decode_operation(0x00, bytes([0x00, 0x00]))

    def test_reject_tag_ab(self):
        """Reject operation tag 0xAB (outside known and rejected ranges)."""
        with self.assertRaises(wire.DataError):
            decode_operation(0xAB, bytes([0xAB, 0x00]))

    def test_rejected_ops_constant(self):
        """Verify REJECTED_OP_TAGS contains expected tags."""
        self.assertIn(0xA9, REJECTED_OP_TAGS)
        self.assertIn(0xAA, REJECTED_OP_TAGS)
        self.assertEqual(len(REJECTED_OP_TAGS), 2)


# ---------------------------------------------------------------------------
# Tests for decode_operation main entry point
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaDecodeOperation(unittest.TestCase):
    """Tests for the main decode_operation entry point."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)

    def test_decode_operation_returns_operation_display(self):
        """decode_operation returns OperationDisplay for valid ops."""
        tlv = _make_op_tlv(
            OP_SET_REP,
            [
                (0x80, self.account),
                (0x81, _make_address(0x00, 0x22)),
            ],
        )
        result = decode_operation(OP_SET_REP, tlv)
        self.assertIsInstance(result, OperationDisplay)

    def test_decode_operation_all_op_types_smoke(self):
        """Smoke test: all 9 operation types can be routed through decode_operation."""
        valid_tlvs = {
            OP_SEND: (
                0x80,
                self.account,
                0x81,
                _make_address(0x00, 0x22),
                0x82,
                _make_amount_bytes(1),
            ),
            OP_SET_REP: (0x80, self.account, 0x81, _make_address(0x00, 0x22)),
            OP_SET_INFO: (0x80, self.account, 0x81, b"n", 0x83, _make_amount_bytes(1)),
            OP_MODIFY_PERMISSIONS: (
                0x80,
                self.account,
                0x81,
                _make_address(0x00, 0x22),
                0x82,
                _make_amount_bytes(0),
                0x83,
                _make_amount_bytes(1),
            ),
            OP_CREATE_IDENTIFIER: (
                0x80,
                self.account,
                0x81,
                b"id",
                0x82,
                _make_amount_bytes(3),
            ),
            OP_TOKEN_ADMIN_SUPPLY: (
                0x80,
                self.account,
                0x81,
                _make_amount_bytes(0),
                0x82,
                _make_amount_bytes(1),
            ),
            OP_TOKEN_ADMIN_MODIFY_BALANCE: (
                0x80,
                self.account,
                0x81,
                _make_address(0x03, 0x22),
                0x82,
                _make_amount_bytes(0),
                0x83,
                _make_amount_bytes(1),
            ),
            OP_RECEIVE: (
                0x80,
                self.account,
                0x81,
                _make_address(0x00, 0x22),
                0x82,
                _make_amount_bytes(1),
            ),
            OP_MANAGE_CERTIFICATE: (0x80, bytes([0x01, 0x02, 0x03])),
        }
        for tag in valid_tlvs:
            fields_data = valid_tlvs[tag]
            # Build field list from flat tuple (tag, content, tag, content, ...)
            if isinstance(fields_data, tuple):
                field_list = [
                    (fields_data[i], fields_data[i + 1])
                    for i in range(0, len(fields_data), 2)
                ]
            else:
                field_list = fields_data
            tlv = _make_op_tlv(tag, field_list)
            result = decode_operation(tag, tlv)
            self.assertIsInstance(result, OperationDisplay)

    def test_decode_operation_rejects_invalid_body(self):
        """decode_operation raises DataError for invalid body."""
        tlv = bytes([OP_SEND, 0x02, 0x80, 0x01, 0xFF])  # Truncated content
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_decode_operation_empty_send_body(self):
        """decode_operation raises DataError for empty SEND body."""
        tlv = bytes([OP_SEND, 0x00])
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_decode_operation_blind_sign_oversized(self):
        """Operations > OP_BUF_SIZE are blind-signed even if tag is well-known."""
        # Build a SEND with a body > OP_BUF_SIZE
        large_memo = b"A" * (OP_BUF_SIZE - 5)  # Make it slightly too big overall
        # We need total operation TLV > OP_BUF_SIZE
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.account),
                (0x81, _make_address(0x00, 0x22)),
                (0x82, _make_amount_bytes(100)),
                (0x84, large_memo),
            ],
        )
        # If still not oversized, add more data
        if len(tlv) <= OP_BUF_SIZE:
            tlv = _make_op_tlv(
                OP_SEND,
                [
                    (0x80, self.account),
                    (0x81, _make_address(0x00, 0x22)),
                    (0x82, _make_amount_bytes(100)),
                    (0x84, b"A" * OP_BUF_SIZE),  # Force oversized
                ],
            )
        self.assertTrue(len(tlv) > OP_BUF_SIZE)
        result = decode_operation(OP_SEND, tlv)
        self.assertTrue(result.is_blind)


# ---------------------------------------------------------------------------
# Tests for edge cases
# ---------------------------------------------------------------------------


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaOperationEdgeCases(unittest.TestCase):
    """Tests for edge cases and boundary conditions."""

    def setUp(self):
        self.account = _make_address(0x00, 0x11)

    def test_max_amount_value(self):
        """Parse the maximum amount value that fits in 16 DER INTEGER bytes."""
        # Max value with 15 significant bytes + leading 0x00 = (2^120) - 1
        max_val = (1 << 120) - 1
        amount_bytes = b"\x00" + b"\xff" * 15  # 16 bytes with leading 0x00
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.account),
                (0x81, _make_address(0x00, 0x22)),
                (0x82, amount_bytes),
            ],
        )
        result = decode_operation(OP_SEND, tlv)
        self.assertEqual(result.fields["amount"], max_val)

    def test_empty_operation_tag_only(self):
        """Tag-only operation with zero-length body."""
        tlv = bytes([OP_SEND, 0x00])
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_non_minimal_amount_encoding_rejected(self):
        """Reject non-minimal DER encoding of amount fields."""
        # 0x00 0x01 when 0x01 would suffice
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.account),
                (0x81, _make_address(0x00, 0x22)),
                (0x82, b"\x00\x01"),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_duplicate_optional_field(self):
        """Reject duplicate optional field (e.g., two memo fields)."""
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, self.account),
                (0x81, _make_address(0x00, 0x22)),
                (0x82, _make_amount_bytes(100)),
                (0x84, b"memo1"),
                (0x84, b"memo2"),
            ],
        )
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_zero_address_bytes(self):
        """Parse a SEND with all-zero address bytes still works (different from null rep)."""
        # For SEND, we just encode addresses -- all-zero addresses are valid
        zero_addr = bytes([0x00, 0x02]) + bytes(
            [0x01] * 31
        )  # valid compressed key, all 0x01 in x
        # Zero-ish: make it valid but with some zeros
        almost_zero = bytes([0x00, 0x02]) + bytes([0x00] * 32)
        tlv = _make_op_tlv(
            OP_SEND,
            [
                (0x80, almost_zero),
                (0x81, _make_address(0x00, 0x22)),
                (0x82, _make_amount_bytes(1)),
            ],
        )
        result = decode_operation(OP_SEND, tlv)
        self.assertIn("keeta_", result.fields["from"])

    def test_body_with_extra_trailing_bytes(self):
        """Reject operation with extra bytes after sub-TLVs (caught by TLV structure)."""
        # Body: valid sub-TLV followed by stray byte
        body = _make_subtlv(0x80, self.account) + b"\xff"
        tlv = bytes([OP_SEND]) + _encode_var_length(len(body)) + body
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)

    def test_amount_16_bytes_not_padded(self):
        """16-byte amount with MSB=0 does not need padding."""
        # Construct 16-byte value where first byte's MSB is 0
        value = 1 << 120  # Large but MSB of first byte = 0
        data = value.to_bytes(16, "big")
        self.assertEqual(len(data), 16)
        result = _parse_amount_bytes(data)
        self.assertEqual(result, value)

    def test_empty_body_for_oversized(self):
        """An empty operation TLV is not oversized but still gets rejected for missing fields."""
        tlv = bytes([OP_SEND, 0x00])
        with self.assertRaises(wire.DataError):
            decode_operation(OP_SEND, tlv)


if __name__ == "__main__":
    unittest.main()

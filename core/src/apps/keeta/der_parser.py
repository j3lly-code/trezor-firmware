"""
Incremental ASN.1 DER parser state machine for Keeta block signing.

Receives chunks of DER-encoded block bytes via feed() and returns
completed operation TLVs. Maintains internal state across chunk
boundaries so that any DER position (mid-tag, mid-length, mid-content)
is handled correctly.

9-phase state machine:
  DetectVersion -> WalkHeaderFields -> ReadOpsHeader -> BufferOp
  -> CompleteOp -> (back to BufferOp) ... -> Trailing -> CompleteBlock
  SkipOversizedOp (for ops > 512 bytes)
  Failed (terminal error)

V1 format (tag 0x30 outer SEQUENCE):
  30 <len>             -- outer SEQUENCE
    02 <len> <version>  -- INTEGER
    04 <len> <network>  -- OCTET STRING
    04 <len> <account>  -- OCTET STRING
    18 <len> <date>     -- GeneralizedTime
    0C <len> <purpose>  -- UTF8String (optional)
    04 <len> <prev_hash>
    30 <len>            -- operations SEQUENCE
      A0 <len> ...      -- operation TLVs
    03 <len> <sig>      -- BIT STRING signature

V2 format (tag 0xA1 wrapper):
  A1 <len>             -- context [1] wrapper
    30 <len>           -- inner SEQUENCE
      04 <len> <account>
      04 <len> <signer>
      02 <len> <network>
      18 <len> <date>
      0C <len> <purpose>
      30 <len>         -- operations SEQUENCE
        A0 <len> ...
    30 <len>           -- signatures SEQUENCE
      03 <len> <sig>
"""

from apps.keeta.constants import (
    MAX_BLOCK_SIZE,
    MAX_CHUNKS,
    MAX_DER_DEPTH,
    MAX_HEADER_SIZE,
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
    TAG_BIT_STRING,
    TAG_GENERALIZED_TIME,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_SEQUENCE,
    TAG_UTF8_STRING,
)

# Context tag for V2 wrapper [1]
TAG_CONTEXT_1 = 0xA1

# Constructed tag variants (constructed bit = 0x20)
TAG_CONSTRUCTED_OCTET_STRING = 0x24
TAG_CONSTRUCTED_UTF8_STRING = 0x2C

# Operation tags set for fast lookup
OP_TAGS = frozenset(
    {
        OP_SEND,
        OP_SET_REP,
        OP_SET_INFO,
        OP_MODIFY_PERMISSIONS,
        OP_CREATE_IDENTIFIER,
        OP_TOKEN_ADMIN_SUPPLY,
        OP_TOKEN_ADMIN_MODIFY_BALANCE,
        OP_RECEIVE,
        OP_MANAGE_CERTIFICATE,
    }
)

# Tags allowed in trailing phase (signatures, extra data)
TRAILING_ALLOWED_TAGS = frozenset(
    {
        TAG_BIT_STRING,  # V1 signature
        TAG_SEQUENCE,  # V2 signatures container
        TAG_OCTET_STRING,  # allowed trailing data
        TAG_UTF8_STRING,  # allowed trailing data
    }
)


class _Phase:
    """Phase constants (plain ints for MicroPython compatibility)."""

    DetectVersion = 1
    WalkHeaderFields = 2
    ReadOpsHeader = 3
    BufferOp = 4
    SkipOversizedOp = 5
    Trailing = 6
    Failed = 7
    CompleteOp = 8
    CompleteBlock = 9


class DerParserError(Exception):
    """Raised when DER parsing encounters a fatal error."""

    pass


class DerParser:
    """Incremental ASN.1 DER parser state machine.

    Usage:
        parser = DerParser()
        for chunk in chunks:
            ops = parser.feed(chunk)
            for tag, op_tlv in ops:
                # decode and display operation
        # Block is complete
    """

    def __init__(self) -> None:
        self.phase = _Phase.DetectVersion

        # Block metadata captured during header walk
        self.version = None  # int: 1 or 2
        self.network_id = None  # bytes or None
        self.account = None  # bytes or None

        # Container tracking (stack for nested SEQUENCE containers)
        self.container_remaining = 0
        self._container_stack = []  # list of parent remaining_bytes

        # Header accumulation (shared across phases)
        self.header_buf = bytearray(MAX_HEADER_SIZE)
        self.header_len = 0
        self.header_size = 0
        self.content_length = 0

        # Field content accumulation (WalkHeaderFields, Trailing)
        self.field_buf = bytearray()
        self.field_content_remaining = 0
        self.field_tag = None

        # Operation accumulation (BufferOp)
        self.op_buf = bytearray()
        self.op_total = 0
        self.expected_op_len = 0
        self.current_op_tag = None

        # DER nesting depth
        self.depth = 0

        # Limits
        self.total_bytes = 0
        self.chunk_count = 0

        # Final state
        self.block_complete = False
        self.error_message = None

        # WalkHeaderFields tracking
        self._walk_seq_count = 0  # SEQUENCE counter for V2

    # ----------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        """Process a chunk of DER bytes.

        Returns a list of completed operations as (tag, tlv_bytes) tuples.
        Each tlv_bytes includes the operation's DER tag + length + content.
        """
        completed_ops: list[tuple[int, bytes]] = []

        if self.phase in (_Phase.Failed,):
            raise DerParserError(self.error_message or "Parser in failed state")
        if self.phase in (_Phase.CompleteBlock,) or self.block_complete:
            raise DerParserError("Block already complete")

        self.chunk_count += 1
        reparse: bool = False
        reparse_byte: int = 0

        data_iter = iter(data)
        while True:
            if reparse:
                byte = reparse_byte
                reparse = False
            else:
                try:
                    byte = next(data_iter)
                except StopIteration:
                    break

            self.total_bytes += 1

            if self.total_bytes > MAX_BLOCK_SIZE:
                self._set_error("Block exceeds maximum size")
                break
            if self.chunk_count > MAX_CHUNKS:
                self._set_error("Block exceeds maximum chunks")
                break
            if self.phase == _Phase.Failed:
                break
            if self.phase == _Phase.CompleteBlock:
                break

            # --- Phase dispatch ---
            if self.phase == _Phase.DetectVersion:
                self._handle_detect_version(byte)

            elif self.phase == _Phase.WalkHeaderFields:
                if self._walk_header_byte(byte):
                    self._walk_header_dispatch()

            elif self.phase == _Phase.ReadOpsHeader:
                self._handle_read_ops_header(byte)
                if self.phase == _Phase.BufferOp:
                    reparse = True
                    reparse_byte = byte

            elif self.phase == _Phase.BufferOp:
                if self._buffer_op_byte(byte):
                    op_bytes = bytes(self.op_buf)
                    assert self.current_op_tag is not None  # set during ReadOpsHeader
                    completed_ops.append((self.current_op_tag, op_bytes))
                    self.phase = _Phase.CompleteOp
                    self._complete_op()

            elif self.phase == _Phase.CompleteOp:
                pass  # _complete_op transitions away immediately

            elif self.phase == _Phase.SkipOversizedOp:
                self._handle_skip_oversized(byte)

            elif self.phase == _Phase.Trailing:
                self._handle_trailing(byte)

        # Empty chunk handling (LAST chunk with zero data bytes)
        if len(data) == 0 and self.phase not in (_Phase.Failed, _Phase.CompleteBlock):
            self._handle_empty_chunk()

        return completed_ops

    def process_chunk(self, data: bytes) -> list[tuple[int, bytes]]:
        """Process a chunk with pre-condition checks."""
        if self.phase == _Phase.Failed:
            raise DerParserError(self.error_message or "Parser in failed state")
        if self.phase == _Phase.CompleteBlock:
            raise DerParserError("Block already complete")
        return self.feed(data)

    def is_complete(self) -> bool:
        return self.phase == _Phase.CompleteBlock

    def is_failed(self) -> bool:
        return self.phase == _Phase.Failed

    # ----------------------------------------------------------------
    # Container stack management
    # ----------------------------------------------------------------

    def _enter_sequence(self, header_size: int, content_length: int) -> bool:
        """Enter a SEQUENCE container. Pushes current level, sets new.

        Pushes the parent container's remaining bytes AFTER this
        SEQUENCE's total TLV (header + content), then sets
        container_remaining to the SEQUENCE's content length so child
        TLV processing tracks consumption correctly.

        Returns True on success, False on error.
        """
        self._container_stack.append(
            self.container_remaining - header_size - content_length
        )
        self.container_remaining = content_length
        self.depth += 1
        if self.depth > MAX_DER_DEPTH:
            self._set_error("DER depth exceeds maximum")
            return False
        return True

    def _container_exhausted(self) -> None:
        """Called when current container_remaining reaches 0.

        Pops container stack and transitions to the appropriate phase
        for the parent container's remaining bytes.
        """
        self.depth -= 1

        if self._container_stack:
            self.container_remaining = self._container_stack.pop()
        else:
            self.container_remaining = 0

        if self.container_remaining > 0:
            # Data remains in parent container
            if self.phase in (
                _Phase.BufferOp,
                _Phase.CompleteOp,
                _Phase.SkipOversizedOp,
                _Phase.ReadOpsHeader,
            ):
                # After ops done, remaining data is trailing
                self.phase = _Phase.Trailing
            elif self.phase == _Phase.Trailing:
                pass  # Continue in trailing
            elif self.phase == _Phase.WalkHeaderFields:
                pass  # Continue walking fields
        else:
            # Parent container also exhausted
            if self._container_stack:
                # Recursively pop more levels
                self._container_exhausted()
            else:
                # All containers exhausted
                if self.phase in (
                    _Phase.Trailing,
                    _Phase.WalkHeaderFields,
                    _Phase.BufferOp,
                    _Phase.CompleteOp,
                    _Phase.SkipOversizedOp,
                    _Phase.ReadOpsHeader,
                ):
                    self.phase = _Phase.CompleteBlock

    # ----------------------------------------------------------------
    # Header accumulation (shared)
    # ----------------------------------------------------------------

    def _start_header(self, byte: int) -> None:
        """Start accumulating a new DER TLV header."""
        self.header_buf[0] = byte
        self.header_len = 1
        self.header_size = 0
        self.content_length = 0

    def _accumulate_header(self, byte: int) -> bool:
        """Accumulate one header byte. Returns True when complete.

        Sets self.header_size and self.content_length on completion.
        """
        self.header_buf[self.header_len] = byte
        self.header_len += 1

        if self.header_len >= 2:
            first_len = self.header_buf[1]
            if first_len < 0x80:
                # Short form
                self.content_length = first_len
                self.header_size = 2
                return True
            elif first_len == 0x80:
                self._set_error("Indefinite length encoding not supported")
                return False
            else:
                # Long form
                num_len_bytes = first_len & 0x7F
                if num_len_bytes == 0 or num_len_bytes > 4:
                    self._set_error("Invalid length encoding")
                    return False
                if self.header_len >= 2 + num_len_bytes:
                    length_bytes = bytes(self.header_buf[2 : 2 + num_len_bytes])
                    self.content_length = int.from_bytes(length_bytes, "big")
                    self.header_size = 2 + num_len_bytes
                    # Non-minimal length check
                    if num_len_bytes == 1 and self.content_length < 0x80:
                        self._set_error("Non-minimal length encoding")
                        return False
                    return True
        return False

    def _reset_header(self) -> None:
        """Clear the header accumulator."""
        self.header_len = 0
        self.header_size = 0
        self.content_length = 0

    # ----------------------------------------------------------------
    # DetectVersion (Phase 1)
    # ----------------------------------------------------------------

    def _handle_detect_version(self, byte: int) -> None:
        """Phase 1: Read first tag + outer container length."""
        if self.header_len == 0:
            # First byte — outer container tag
            if byte == TAG_SEQUENCE:
                self.version = 1
            elif byte == TAG_CONTEXT_1:
                self.version = 2
            else:
                self._set_error(f"Unexpected leading tag: 0x{byte:02x}")
                return
            self._start_header(byte)
            return

        # Accumulate outer container header bytes
        if self._accumulate_header(byte):
            self.container_remaining = self.content_length
            self.depth += 1  # Entered outer container
            self.phase = _Phase.WalkHeaderFields
            self._reset_header()

    # ----------------------------------------------------------------
    # WalkHeaderFields (Phase 2)
    # ----------------------------------------------------------------

    def _walk_header_byte(self, byte: int) -> bool:
        """Process one byte during WalkHeaderFields.

        Returns True when a complete TLV is ready for dispatch.
        """
        # If accumulating primitive field content
        if self.field_content_remaining > 0:
            self.field_buf.append(byte)
            self.field_content_remaining -= 1
            if self.field_content_remaining == 0:
                self.container_remaining -= self._last_walk_tlv_total
                if self.container_remaining == 0:
                    self._container_exhausted()
                return True
            return False

        # If no header started, begin a new TLV
        if self.header_len == 0:
            tag = byte
            if tag == 0x00:
                self._set_error("Unexpected EOC tag (0x00)")
                return False
            if (tag & 0x1F) == 0x1F:
                self._set_error("Long-form tags not supported")
                return False
            if tag == TAG_CONSTRUCTED_OCTET_STRING:
                self._set_error("Constructed OCTET STRING not allowed")
                return False
            if tag == TAG_CONSTRUCTED_UTF8_STRING:
                self._set_error("Constructed UTF8String not allowed")
                return False
            self._start_header(byte)
            return False

        # Accumulating header bytes
        if self.header_size == 0:
            if not self._accumulate_header(byte):
                return False

            # Header is now complete
            tag = self.header_buf[0]
            tlv_total = self.header_size + self.content_length

            if tlv_total > self.container_remaining:
                self._set_error("Container underflow")
                return False

            self._last_walk_tlv_total = tlv_total
            self.field_tag = tag

            if tag == TAG_SEQUENCE:
                # SEQUENCE container — enter it
                if not self._enter_sequence(self.header_size, self.content_length):
                    return False

                self._walk_seq_count += 1

                if self.version == 1:
                    # V1: this SEQUENCE is the ops SEQUENCE
                    # (outer SEQUENCE was consumed in DetectVersion)
                    self._reset_header()
                    self.phase = _Phase.ReadOpsHeader
                    return False
                else:
                    # V2
                    if self._walk_seq_count == 1:
                        # Inner SEQUENCE — enter and continue walking
                        self._reset_header()
                        return False  # Not a dispatchable field
                    else:
                        # Second SEQUENCE = ops SEQUENCE
                        self._reset_header()
                        self.phase = _Phase.ReadOpsHeader
                        return False
            else:
                # Primitive field — accumulate content
                self.field_buf = bytearray()
                self.field_content_remaining = self.content_length
                if self.content_length == 0:
                    # Zero-length primitive
                    self.container_remaining -= self.header_size
                    if self.container_remaining == 0:
                        self._container_exhausted()
                    return True
                return False

        return False

    def _walk_header_dispatch(self) -> None:
        """Dispatch a completed primitive header field by tag."""
        tag = self.field_tag
        content = bytes(self.field_buf)

        if tag == TAG_INTEGER:
            self._handle_int_field(content)

        elif tag == TAG_OCTET_STRING:
            self._handle_octet_field(content)

        elif tag == TAG_GENERALIZED_TIME:
            if not self._validate_generalized_time(content):
                return  # Error already set

        elif tag == TAG_UTF8_STRING:
            pass  # Purpose/metadata — optional, skip

        elif tag in OP_TAGS or tag in REJECTED_OP_TAGS:
            self._set_error(f"Operation tag 0x{tag:02x} outside ops SEQUENCE")
            return
        else:
            pass  # Unknown tag — skip (optional field)

        self._reset_field_state()

    def _handle_int_field(self, content: bytes) -> None:
        """Process an INTEGER header field."""
        value = self._parse_integer_value(content)
        if value is None:
            return  # Error set

        if self.version == 1:
            # V1: first INTEGER encountered = version
            if self.network_id is None and self.account is None:
                self.version = int.from_bytes(content, "big")
        else:
            # V2: INTEGER = network ID
            self.network_id = content

    def _handle_octet_field(self, content: bytes) -> None:
        """Process an OCTET STRING header field."""
        if self.version == 1:
            # V1: first 04 = network, second 04 = account
            if self.network_id is None:
                self.network_id = content
            elif self.account is None:
                self.account = content
            # Subsequent 04 (prev_hash) are skipped
        else:
            # V2: first 04 = account, second 04 = signer (skip)
            if self.account is None:
                self.account = content

    def _reset_field_state(self) -> None:
        """Clear field accumulation state after dispatch."""
        self.field_buf = bytearray()
        self.field_content_remaining = 0
        self.field_tag = None
        self._reset_header()

    # ----------------------------------------------------------------
    # ReadOpsHeader (Phase 3)
    # ----------------------------------------------------------------

    def _handle_read_ops_header(self, byte: int) -> None:
        """Phase 3: Validate required fields then start operation parsing.

        This is a pass-through phase: it validates and immediately
        transitions to BufferOp. The byte that triggered this is
        re-processed in BufferOp.
        """
        # Validate required header fields
        if self.version is None:
            self._set_error("Missing version in block header")
            return
        if self.network_id is None:
            self._set_error("Missing network ID in block header")
            return
        if self.account is None:
            self._set_error("Missing account in block header")
            return

        self.phase = _Phase.BufferOp

    # ----------------------------------------------------------------
    # BufferOp (Phase 4)
    # ----------------------------------------------------------------

    def _buffer_op_byte(self, byte: int) -> bool:
        """Accumulate one byte of an operation TLV.

        Returns True when a complete operation TLV is buffered.
        """
        if self.header_len == 0:
            # First byte of new operation = tag byte
            tag = byte
            if tag in REJECTED_OP_TAGS:
                self._set_error(f"Rejected operation tag: 0x{tag:02x}")
                return False
            if tag not in OP_TAGS:
                self._set_error(f"Unknown operation tag: 0x{tag:02x}")
                return False

            self.current_op_tag = tag
            self._start_header(byte)
            self.op_buf = bytearray()
            self.op_buf.append(byte)
            self.op_total = 1
            return False

        # Accumulate byte into operation buffer
        self.op_buf.append(byte)
        self.op_total += 1

        if self.header_size == 0:
            # Still accumulating header bytes
            was_complete = self._accumulate_header(byte)
            if self.phase == _Phase.Failed:
                return False
            if not was_complete:
                return False

            # Header complete — determine expected TLV size
            self.expected_op_len = self.header_size + self.content_length
            if self.expected_op_len > OP_BUF_SIZE:
                # Operation too large — blind sign mode
                self.phase = _Phase.SkipOversizedOp
                return False

            if self.content_length == 0:
                # Zero-length operation (edge case)
                self.container_remaining -= self.expected_op_len
                if self.container_remaining == 0:
                    self._container_exhausted()
                return True

            return False

        # Accumulating content bytes
        if self.op_total >= self.expected_op_len:
            self.container_remaining -= self.expected_op_len
            return True

        return False

    def _complete_op(self) -> None:
        """Phase 8: Clean up after completing an operation."""
        self.op_buf = bytearray()
        self.op_total = 0
        self.expected_op_len = 0
        self.current_op_tag = None
        self._reset_header()

        if self.container_remaining == 0:
            self._container_exhausted()
        else:
            self.phase = _Phase.BufferOp

    # ----------------------------------------------------------------
    # SkipOversizedOp (Phase 5)
    # ----------------------------------------------------------------

    def _handle_skip_oversized(self, byte: int) -> None:
        """Phase 5: Skip oversized operation content bytes."""
        self.op_total += 1

        if self.op_total >= self.expected_op_len:
            # Finished skipping this oversized op
            self.container_remaining -= self.expected_op_len
            self.op_buf = bytearray()
            self.op_total = 0
            self.expected_op_len = 0
            self.current_op_tag = None
            self._reset_header()

            if self.container_remaining == 0:
                self._container_exhausted()
            else:
                self.phase = _Phase.BufferOp

    # ----------------------------------------------------------------
    # Trailing (Phase 6)
    # ----------------------------------------------------------------

    def _handle_trailing(self, byte: int) -> None:
        """Phase 6: Verify trailing data against allowlist.

        Accumulates TLV headers and validates tags against the allowed
        set. Content bytes are skipped (trailing data is already hashed
        by the caller).
        """
        # Field content accumulation in progress
        if self.field_content_remaining > 0:
            self.field_content_remaining -= 1
            if self.field_content_remaining == 0:
                self.container_remaining -= self._last_trail_tlv_total
                self._reset_field_state()
                if self.container_remaining == 0:
                    self._container_exhausted()
            return

        # Header accumulation in progress
        if self.header_len == 0:
            # Start new trailing TLV
            tag = byte
            if tag not in TRAILING_ALLOWED_TAGS:
                self._set_error(f"Unexpected trailing tag: 0x{tag:02x}")
                return
            self._start_header(byte)
            return

        if self.header_size == 0:
            if not self._accumulate_header(byte):
                return

            # Header complete
            tag = self.header_buf[0]
            if tag not in TRAILING_ALLOWED_TAGS:
                self._set_error(f"Unexpected trailing tag: 0x{tag:02x}")
                return

            tlv_total = self.header_size + self.content_length
            if tlv_total > self.container_remaining:
                self._set_error("Container underflow")
                return

            self._last_trail_tlv_total = tlv_total
            self.field_content_remaining = self.content_length
            self.field_tag = tag
            self._reset_header()

            if self.content_length == 0:
                # Zero-length trailing TLV
                self.container_remaining -= tlv_total
                if self.container_remaining == 0:
                    self._container_exhausted()

    # ----------------------------------------------------------------
    # Empty / LAST chunk
    # ----------------------------------------------------------------

    def _handle_empty_chunk(self) -> None:
        """Handle an empty LAST chunk (zero data bytes).

        Validates that no partial data is pending and transitions
        to CompleteBlock if appropriate.
        """
        if self.header_len != 0:
            self._set_error("Incomplete block")
            return
        if self.op_total != 0:
            self._set_error("Incomplete block")
            return
        if self.field_content_remaining != 0:
            self._set_error("Incomplete block")
            return

        if self.phase in (
            _Phase.DetectVersion,
            _Phase.WalkHeaderFields,
            _Phase.ReadOpsHeader,
            _Phase.BufferOp,
            _Phase.CompleteOp,
            _Phase.SkipOversizedOp,
        ):
            self._set_error("Incomplete block")
        elif self.phase == _Phase.Trailing:
            self.phase = _Phase.CompleteBlock

    # ----------------------------------------------------------------
    # Validation helpers
    # ----------------------------------------------------------------

    def _parse_integer_value(self, data: bytes) -> int | None:
        """Parse a DER INTEGER value from raw content bytes.

        Returns the integer value, or None if invalid (error set).
        Rejects negative values (MSB set without 0x00 padding).
        Rejects non-minimal encoding.
        """
        if not data:
            self._set_error("Empty INTEGER content")
            return None

        # Non-minimal encoding: leading 0x00 when MSB of next byte < 0x80
        if len(data) > 1 and data[0] == 0x00 and (data[1] & 0x80) == 0:
            self._set_error("Non-minimal INTEGER encoding")
            return None

        # Valid 0x00 padding when MSB of next byte IS set
        if data[0] == 0x00:
            return int.from_bytes(data[1:], "big")

        # Negative value (MSB set, no padding)
        if data[0] & 0x80:
            self._set_error("Negative INTEGER value (unsigned field)")
            return None

        return int.from_bytes(data, "big")

    def _validate_generalized_time(self, data: bytes) -> bool:
        """Validate GeneralizedTime format.

        Conditions:
        - Length must be 15 (no fraction) or 17+ (with fraction)
        - Must end with 'Z' (0x5A)
        - All chars before '.' or 'Z' are ASCII digits (0x30-0x39)
        - Year (first 4 chars) in range 2020-2150
        """
        if len(data) < 15:
            self._set_error("Invalid GeneralizedTime: too short")
            return False

        if data[-1] != 0x5A:  # 'Z'
            self._set_error("Invalid GeneralizedTime: must end with Z")
            return False

        # Validate digit characters
        for i, b in enumerate(data[:-1]):
            if b == 0x2E:  # '.' — fractional seconds separator
                break
            if b < 0x30 or b > 0x39:
                self._set_error("Invalid GeneralizedTime: non-digit character")
                return False

        # Validate year
        if len(data) >= 4:
            for b in data[:4]:
                if b < 0x30 or b > 0x39:
                    self._set_error("Invalid GeneralizedTime: non-digit year")
                    return False
            year = (
                (data[0] - 0x30) * 1000
                + (data[1] - 0x30) * 100
                + (data[2] - 0x30) * 10
                + (data[3] - 0x30)
            )
            if year < 2020 or year > 2150:
                self._set_error(f"Invalid GeneralizedTime year: {year}")
                return False

        return True

    def _set_error(self, msg: str) -> None:
        """Transition to Failed phase with an error message."""
        self.phase = _Phase.Failed
        self.error_message = msg

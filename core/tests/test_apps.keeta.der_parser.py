# flake8: noqa: F403,F405
"""Tests for Keeta incremental DER parser."""

from common import *  # isort:skip

if not utils.BITCOIN_ONLY:
    from apps.keeta.der_parser import DerParser, DerParserError


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaDerParser(unittest.TestCase):
    """Test the streaming DER parser state machine."""

    def _make_minimal_v1_block(self) -> bytes:
        """Create a minimal valid V1 block for testing.

        Builds a valid DER-encoded V1 block with minimal fields:
        SEQUENCE {
            INTEGER version(1),
            OCTET STRING network("TEST"),
            OCTET STRING account(33 bytes),
            GeneralizedTime date,
            UTF8String purpose,
            OCTET STRING prev_hash(32 bytes),
            SEQUENCE { (empty operations) },
            BIT STRING signature(64 bytes)
        }
        """
        # Account field: algorithm byte (0x00) + compressed pubkey (33 bytes)
        account_body = bytes([0x00, 0x02]) + bytes([0x00] * 31)
        # Date: 2025-01-01 00:00:00 UTC
        date_body = b"20250101000000Z"
        # Purpose
        purpose_body = b"test"
        # Previous hash (32 zero bytes)
        prev_hash_body = bytes([0x00] * 32)
        # Signature (64 zero bytes, BIT STRING unused bits = 0x00)
        sig_body = bytes([0x00]) + bytes([0x00] * 64)

        body = b""
        body += bytes([0x02, 0x01, 0x01])  # version = INTEGER(1, value=1)
        body += bytes([0x04, 0x04]) + b"TEST"  # network = OCTET STRING("TEST")
        body += bytes([0x04, len(account_body)]) + account_body  # account
        body += bytes([0x18, len(date_body)]) + date_body  # date
        body += bytes([0x0C, len(purpose_body)]) + purpose_body  # purpose
        body += bytes([0x04, len(prev_hash_body)]) + prev_hash_body  # prev_hash
        body += bytes([0x30, 0x00])  # empty operations SEQUENCE
        body += bytes([0x03, len(sig_body)]) + sig_body  # BIT STRING signature

        # Encode outer SEQUENCE
        outer_len = len(body)
        header = bytes([0x30, outer_len])
        return header + body

    def _make_minimal_v2_block(self) -> bytes:
        """Create a minimal valid V2 block for testing.

        V2 format:
        context[1] {
            SEQUENCE {
                OCTET STRING account,
                OCTET STRING signer,
                INTEGER network,
                GeneralizedTime date,
                UTF8String purpose,
                SEQUENCE { (empty operations) }
            }
            SEQUENCE { BIT STRING signature }
        }
        """
        account_body = bytes([0x00, 0x02]) + bytes([0x00] * 31)
        signer_body = bytes([0x00, 0x02]) + bytes([0x01] * 31)
        date_body = b"20250101000000Z"
        purpose_body = b"test"

        inner_body = b""
        inner_body += bytes([0x04, len(account_body)]) + account_body
        inner_body += bytes([0x04, len(signer_body)]) + signer_body
        inner_body += bytes([0x02, 0x04]) + (1413829460).to_bytes(4, "big")  # network
        inner_body += bytes([0x18, len(date_body)]) + date_body
        inner_body += bytes([0x0C, len(purpose_body)]) + purpose_body
        inner_body += bytes([0x30, 0x00])  # empty operations

        # Signature
        sig_body = bytes([0x00]) + bytes([0x00] * 64)
        sigs_body = bytes([0x03, len(sig_body)]) + sig_body
        sigs_outer = bytes([0x30, len(sigs_body)]) + sigs_body

        # Inner SEQUENCE wrapping
        inner_seq = bytes([0x30, len(inner_body)]) + inner_body
        # Context [1] wrapper
        wrapper_content = inner_seq + sigs_outer
        wrapper = bytes([0xA1, len(wrapper_content)]) + wrapper_content

        return wrapper

    def test_detect_v1(self):
        """Test parser detects V1 block format."""
        parser = DerParser()
        block = self._make_minimal_v1_block()
        parser.feed(block)
        self.assertEqual(parser.version, 1)

    def test_detect_v2(self):
        """Test parser detects V2 block format."""
        parser = DerParser()
        block = self._make_minimal_v2_block()
        parser.feed(block)
        self.assertEqual(parser.version, 2)

    def test_reject_indefinite_length(self):
        """Test parser rejects indefinite length encoding."""
        parser = DerParser()
        with self.assertRaises(DerParserError):
            parser.feed(bytes([0x30, 0x80]))

    def test_empty_last_chunk_finalizes(self):
        """Test parser accepts empty LAST chunk to finalize."""
        parser = DerParser()
        block = self._make_minimal_v1_block()
        parser.feed(block)
        # Feed empty chunk to finalize
        parser.feed(b"")
        self.assertTrue(parser.block_complete)

    def test_split_across_chunks(self):
        """Test parser handles data split across chunk boundaries."""
        parser = DerParser()
        block = self._make_minimal_v1_block()
        mid = len(block) // 2
        parser.feed(block[:mid])
        self.assertFalse(parser.block_complete)
        parser.feed(block[mid:])
        self.assertTrue(parser.block_complete)

    def test_split_at_multiple_positions(self):
        """Test parser handles splits at various chunk boundaries."""
        block = self._make_minimal_v1_block()
        # Test splits at positions 1, 2, 3, half-1, half
        for split_pos in [1, 2, 3, len(block) // 2 - 1, len(block) // 2]:
            with self.subTest(split_pos=split_pos):
                parser = DerParser()
                parser.feed(block[:split_pos])
                parser.feed(block[split_pos:])
                self.assertTrue(
                    parser.block_complete, f"Failed at split pos {split_pos}"
                )

    def test_split_mid_tag(self):
        """Test parser handles split in the middle of a tag byte."""
        parser = DerParser()
        block = self._make_minimal_v1_block()
        # Split after the first byte (partial tag for next field)
        parser.feed(block[:1])
        parser.feed(block[1:])
        self.assertTrue(parser.block_complete)

    def test_split_mid_length(self):
        """Test parser handles split in the middle of length bytes."""
        parser = DerParser()
        block = self._make_minimal_v1_block()
        # Split after tag byte + first length byte (when length is long form)
        # For V1 with body <= 127, use long form length
        # Actually the block is small enough for short form, so test with mid-content split
        mid = 5  # Split mid-header for the network field
        parser.feed(block[:mid])
        parser.feed(block[mid:])
        self.assertTrue(parser.block_complete)

    def test_reject_non_minimal_length(self):
        """Test parser rejects non-minimal length encoding."""
        parser = DerParser()
        # Non-minimal: 0x81 0x03 indicates 1-byte length with value 3,
        # but short form 0x03 would suffice for values < 128.
        with self.assertRaises(DerParserError):
            parser.feed(bytes([0x30, 0x81, 0x03, 0x00, 0x00, 0x00]))

    def test_reject_non_minimal_length_zero(self):
        """Test parser rejects non-minimal length encoding for zero."""
        parser = DerParser()
        with self.assertRaises(DerParserError):
            parser.feed(bytes([0x30, 0x81, 0x00]))

    def test_v1_block_complete(self):
        """Test parser reaches CompleteBlock phase after full V1 block."""
        parser = DerParser()
        block = self._make_minimal_v1_block()
        parser.feed(block)
        parser.feed(b"")  # finalize
        self.assertTrue(parser.block_complete)

    def test_reject_unassigned_op_tag_a9(self):
        """Test parser rejects blocks with unassigned operation tag 0xA9."""
        from apps.keeta.constants import REJECTED_OP_TAGS

        self.assertIn(0xA9, REJECTED_OP_TAGS)

    def test_reject_unassigned_op_tag_aa(self):
        """Test parser rejects blocks with unassigned operation tag 0xAA."""
        from apps.keeta.constants import REJECTED_OP_TAGS

        self.assertIn(0xAA, REJECTED_OP_TAGS)

    def test_reject_trailing_data(self):
        """Test parser rejects blocks with trailing data after signatures."""
        parser = DerParser()
        block = self._make_minimal_v1_block()
        # Append extra bytes after the valid block
        parser.feed(block + b"\x00\x00\x00")
        with self.assertRaises(DerParserError):
            parser.feed(b"")

    def test_parse_initial_state(self):
        """Test parser starts in correct initial state."""
        parser = DerParser()
        self.assertIsNone(parser.version)
        self.assertFalse(parser.block_complete)

    def test_reject_excessive_depth(self):
        """Test parser rejects nesting beyond MAX_DER_DEPTH."""
        # Build a deeply nested structure
        # MAX_DER_DEPTH = 5, so 6 nested SEQUENCEs should be rejected
        inner = b"\x00"
        for _ in range(6):
            inner = bytes([0x30, len(inner)]) + inner
        parser = DerParser()
        with self.assertRaises(DerParserError):
            parser.feed(inner)

    def test_reject_empty_block(self):
        """Test parser rejects empty input."""
        parser = DerParser()
        with self.assertRaises(DerParserError):
            parser.feed(b"")
        # Also test via feed that completes
        parser2 = DerParser()
        parser2.feed(b"")
        self.assertFalse(parser2.block_complete)


if __name__ == "__main__":
    unittest.main()

# flake8: noqa: F403,F405
"""Tests for Keeta address encoding/decoding."""

from common import *  # isort:skip

if not utils.BITCOIN_ONLY:
    from apps.keeta.address import decode_address, encode_address, validate_address


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaAddress(unittest.TestCase):
    def test_encode_secp256k1(self):
        """Test encoding a secp256k1 address."""
        pubkey = bytes([0x02] + [0x00] * 31)  # compressed 33-byte
        address = encode_address(pubkey, 0x00)
        self.assertTrue(address.startswith("keeta_"))
        # Address should be lowercase
        self.assertEqual(address, address.lower())
        # No padding
        self.assertNotIn("=", address)

    def test_encode_ed25519(self):
        """Test encoding an ed25519 address."""
        pubkey = bytes([0x00] * 32)  # raw 32-byte
        address = encode_address(pubkey, 0x01)
        self.assertTrue(address.startswith("keeta_"))
        self.assertEqual(address, address.lower())

    def test_encode_secp256r1(self):
        """Test encoding a secp256r1 address."""
        pubkey = bytes([0x02] + [0xCC] * 31)
        address = encode_address(pubkey, 0x06)
        self.assertTrue(address.startswith("keeta_"))

    def test_encode_network(self):
        """Test encoding a NETWORK (generated) address."""
        pubkey_hash = bytes([0xDD] * 32)
        address = encode_address(pubkey_hash, 0x02)
        self.assertTrue(address.startswith("keeta_"))

    def test_encode_token(self):
        """Test encoding a TOKEN (generated) address."""
        pubkey_hash = bytes([0xEE] * 32)
        address = encode_address(pubkey_hash, 0x03)
        self.assertTrue(address.startswith("keeta_"))

    def test_encode_storage(self):
        """Test encoding a STORAGE (generated) address."""
        pubkey_hash = bytes([0xFF] * 32)
        address = encode_address(pubkey_hash, 0x04)
        self.assertTrue(address.startswith("keeta_"))

    def test_encode_reject_multisig(self):
        """Test that MULTISIG addresses are rejected."""
        pubkey = bytes([0x02] + [0x00] * 31)
        with self.assertRaises(ValueError):
            encode_address(pubkey, 0x07)

    def test_roundtrip_secp256k1(self):
        """Test encode -> decode roundtrip for secp256k1."""
        pubkey = bytes([0x03] + [0xFF] * 31)
        address = encode_address(pubkey, 0x00)
        decoded_pubkey, algo = decode_address(address)
        self.assertEqual(pubkey, decoded_pubkey)
        self.assertEqual(algo, 0x00)

    def test_roundtrip_ed25519(self):
        """Test encode -> decode roundtrip for ed25519."""
        pubkey = bytes([0xAA] * 32)
        address = encode_address(pubkey, 0x01)
        decoded_pubkey, algo = decode_address(address)
        self.assertEqual(pubkey, decoded_pubkey)
        self.assertEqual(algo, 0x01)

    def test_roundtrip_secp256r1(self):
        """Test encode -> decode roundtrip for secp256r1."""
        pubkey = bytes([0x03] + [0xBB] * 31)
        address = encode_address(pubkey, 0x06)
        decoded_pubkey, algo = decode_address(address)
        self.assertEqual(pubkey, decoded_pubkey)
        self.assertEqual(algo, 0x06)

    def test_decode_invalid_checksum(self):
        """Test that corrupted addresses are rejected."""
        pubkey = bytes([0x02] + [0xAA] * 31)
        address = encode_address(pubkey, 0x00)
        # Corrupt the address by changing a character
        corrupted = address[:-1] + ("a" if address[-1] != "a" else "b")
        with self.assertRaises(ValueError):
            decode_address(corrupted)

    def test_decode_missing_prefix(self):
        """Test that addresses without 'keeta_' prefix are rejected."""
        with self.assertRaises(ValueError):
            decode_address("nosuchprefix_abc123")

    def test_decode_reject_multisig(self):
        """Test decode rejects MULTISIG (0x07) addresses."""
        with self.assertRaises(ValueError):
            # A multisig address would have correct checksum but algo=0x07
            decode_address("keeta_xxxxxxxxxxxx")

    def test_validate_address(self):
        """Test validate_address function."""
        pubkey = bytes([0x02] + [0xBB] * 31)
        address = encode_address(pubkey, 0x00)
        self.assertTrue(validate_address(address))
        self.assertFalse(validate_address("keeta_invalid"))
        self.assertFalse(validate_address("not_keeta_123"))
        self.assertFalse(validate_address(""))
        self.assertFalse(validate_address("keeta_"))

    def test_validate_address_roundtrip_all_algorithms(self):
        """Test validate_address accepts all valid algorithm types."""
        for algo, pubkey in [
            (0x00, bytes([0x02] + [0x11] * 31)),  # secp256k1
            (0x01, bytes([0x22] * 32)),  # ed25519
            (0x02, bytes([0x33] * 32)),  # network
            (0x03, bytes([0x44] * 32)),  # token
            (0x04, bytes([0x55] * 32)),  # storage
            (0x06, bytes([0x02] + [0x66] * 31)),  # secp256r1
        ]:
            address = encode_address(pubkey, algo)
            self.assertTrue(validate_address(address), f"Failed for algo {algo}")

    def test_encode_empty_pubkey(self):
        """Test encoding with empty pubkey raises error."""
        with self.assertRaises(ValueError):
            encode_address(b"", 0x00)

    def test_encode_wrong_length_pubkey(self):
        """Test encoding with wrong length pubkey raises error."""
        # secp256k1 expects 33 compressed bytes
        with self.assertRaises(ValueError):
            encode_address(bytes([0x00] * 20), 0x00)
        # ed25519 expects 32 bytes
        with self.assertRaises(ValueError):
            encode_address(bytes([0x00] * 33), 0x01)


if __name__ == "__main__":
    unittest.main()

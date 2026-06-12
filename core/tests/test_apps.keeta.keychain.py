# flake8: noqa: F403,F405
"""Tests for Keeta key derivation."""

from common import *  # isort:skip

if not utils.BITCOIN_ONLY:
    from apps.keeta.keychain import (
        KeyDerivationError,
        derive_keeta_key,
        derive_secp_key,
        hkdf_sha3_256_expand,
        hmac_sha3_256,
        sha3_256_nist,
    )


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaSha3_256(unittest.TestCase):
    """Tests for NIST SHA3-256 safety wrapper."""

    def test_sha3_256_nist_empty(self):
        """Test NIST SHA3-256 produces expected output for empty input."""
        result = sha3_256_nist(b"")
        expected = bytes.fromhex(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )
        self.assertEqual(result, expected)

    def test_sha3_256_nist_abc(self):
        """Test NIST SHA3-256 with 'abc' input."""
        result = sha3_256_nist(b"abc")
        expected = bytes.fromhex(
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        )
        self.assertEqual(result, expected)

    def test_sha3_256_nist_256bit(self):
        """Test NIST SHA3-256 with longer input."""
        result = sha3_256_nist(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )
        expected = bytes.fromhex(
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a765e9f120c0f3e2c0e3a3a"
        )
        self.assertEqual(result, expected)

    def test_sha3_256_not_keccak(self):
        """Test that NIST SHA3-256 is NOT Keccak (different padding)."""
        # NIST SHA3-256 on empty input
        nist_result = sha3_256_nist(b"")
        # Keccak-256 on empty input (without NIST padding) is different
        from trezor.crypto import sha3_256

        keccak_result = sha3_256(b"", keccak=True).digest()
        self.assertNotEqual(nist_result, keccak_result)


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaHmacSha3_256(unittest.TestCase):
    """Tests for HMAC-SHA3-256 implementation."""

    def test_hmac_basic(self):
        """Test HMAC-SHA3-256 with RFC 4231 test vector case 1 (adapted)."""
        key = b"\x0b" * 32
        msg = b"Hi There"
        result = hmac_sha3_256(key, msg)
        self.assertEqual(len(result), 32)

    def test_hmac_key_longer_than_block(self):
        """Test HMAC-SHA3-256 with key longer than block size (136 bytes)."""
        key = b"\xaa" * 200  # longer than 136 bytes
        msg = b"Test message"
        result = hmac_sha3_256(key, msg)
        self.assertEqual(len(result), 32)

    def test_hmac_deterministic(self):
        """Test HMAC-SHA3-256 produces deterministic output."""
        key = b"\x01\x02\x03\x04" * 8
        msg = b"Deterministic test"
        r1 = hmac_sha3_256(key, msg)
        r2 = hmac_sha3_256(key, msg)
        self.assertEqual(r1, r2)

    def test_hmac_different_keys(self):
        """Test different keys produce different outputs."""
        msg = b"Same message"
        r1 = hmac_sha3_256(b"\xaa" * 32, msg)
        r2 = hmac_sha3_256(b"\xbb" * 32, msg)
        self.assertNotEqual(r1, r2)

    def test_hmac_empty_key(self):
        """Test HMAC-SHA3-256 with empty key."""
        result = hmac_sha3_256(b"", b"test")
        self.assertEqual(len(result), 32)

    def test_hmac_empty_message(self):
        """Test HMAC-SHA3-256 with empty message."""
        result = hmac_sha3_256(b"\x01" * 32, b"")
        self.assertEqual(len(result), 32)


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaHkdfSha3_256(unittest.TestCase):
    """Tests for HKDF-SHA3-256 expand step."""

    def test_hkdf_expand_basic(self):
        """Test HKDF-SHA3-256 expand produces 32-byte output."""
        prk = bytes([0x01] * 32)
        result = hkdf_sha3_256_expand(prk)
        self.assertEqual(len(result), 32)

    def test_hkdf_expand_deterministic(self):
        """Test HKDF expand is deterministic for same input."""
        prk = bytes([0x01] * 32)
        result1 = hkdf_sha3_256_expand(prk)
        result2 = hkdf_sha3_256_expand(prk)
        self.assertEqual(result1, result2)

    def test_hkdf_expand_different_inputs(self):
        """Test HKDF expand produces different outputs for different PRKs."""
        prk1 = bytes([0x01] * 32)
        prk2 = bytes([0x02] * 32)
        r1 = hkdf_sha3_256_expand(prk1)
        r2 = hkdf_sha3_256_expand(prk2)
        self.assertNotEqual(r1, r2)

    def test_hkdf_expand_with_info(self):
        """Test HKDF expand with non-empty info parameter."""
        prk = bytes([0x03] * 32)
        info = b"test_info"
        result = hkdf_sha3_256_expand(prk, info)
        self.assertEqual(len(result), 32)

    def test_hkdf_expand_different_info(self):
        """Test different info parameters produce different outputs."""
        prk = bytes([0x04] * 32)
        r1 = hkdf_sha3_256_expand(prk, b"info1")
        r2 = hkdf_sha3_256_expand(prk, b"info2")
        self.assertNotEqual(r1, r2)


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaDeriveSecpKey(unittest.TestCase):
    """Tests for secp256k1/r1 key derivation with retry loop."""

    def test_derive_secp_key_basic(self):
        """Test derive_secp_key produces valid key."""
        from apps.keeta.constants import SECP256K1_ORDER

        keeta_seed = bytes([0x05] * 32)
        key = derive_secp_key(keeta_seed, 0, SECP256K1_ORDER)
        self.assertEqual(len(key), 32)
        # Key must be in valid range for curve
        key_int = int.from_bytes(key, "big")
        self.assertGreater(key_int, 0)
        self.assertLess(key_int, SECP256K1_ORDER)

    def test_derive_secp_key_low_s_normalized(self):
        """Test low-S normalization produces valid signature-compatible keys."""
        from apps.keeta.constants import SECP256K1_ORDER

        keeta_seed = bytes([0x06] * 32)
        key = derive_secp_key(keeta_seed, 0, SECP256K1_ORDER)
        key_int = int.from_bytes(key, "big")
        n_half = SECP256K1_ORDER // 2
        self.assertLessEqual(key_int, n_half)

    def test_derive_secp_key_deterministic(self):
        """Test secp key derivation is deterministic."""
        from apps.keeta.constants import SECP256K1_ORDER

        keeta_seed = bytes([0x07] * 32)
        k1 = derive_secp_key(keeta_seed, 1, SECP256K1_ORDER)
        k2 = derive_secp_key(keeta_seed, 1, SECP256K1_ORDER)
        self.assertEqual(k1, k2)

    def test_derive_secp_key_different_index(self):
        """Test different indices produce different keys."""
        from apps.keeta.constants import SECP256K1_ORDER

        keeta_seed = bytes([0x08] * 32)
        k0 = derive_secp_key(keeta_seed, 0, SECP256K1_ORDER)
        k1 = derive_secp_key(keeta_seed, 1, SECP256K1_ORDER)
        self.assertNotEqual(k0, k1)

    def test_derive_secp_key_secp256r1(self):
        """Test derivation works for secp256r1 curve."""
        from apps.keeta.constants import SECP256R1_ORDER

        keeta_seed = bytes([0x09] * 32)
        key = derive_secp_key(keeta_seed, 0, SECP256R1_ORDER)
        self.assertEqual(len(key), 32)
        key_int = int.from_bytes(key, "big")
        self.assertLess(key_int, SECP256R1_ORDER)


if __name__ == "__main__":
    unittest.main()

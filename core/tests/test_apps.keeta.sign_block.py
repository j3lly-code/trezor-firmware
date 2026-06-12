# flake8: noqa: F403,F405
"""Tests for Keeta streaming block signing handler."""

from common import *  # isort:skip

if not utils.BITCOIN_ONLY:
    from apps.keeta.constants import SECP256K1_ORDER, SECP256R1_ORDER
    from apps.keeta.sign_block import (
        _ALGO_ED25519,
        _ALGO_MULTISIG,
        _ALGO_SECP256K1,
        _ALGO_SECP256R1,
        _NETWORK_NAMES,
        _active,
        _address_n,
        _algorithm,
        _cleanup,
        _completed_ops,
        _derive_public_key,
        _enforce_low_s,
        _expected_index,
        _first_chunk_time,
        _hasher,
        _keeta_seed,
        _network_id,
        _parser,
        _private_key,
    )


# ==============================================================================
# Low-S enforcement tests
# ==============================================================================


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaLowSEnforcementSecp256k1(unittest.TestCase):
    """Test _enforce_low_s with secp256k1 curve order."""

    N = SECP256K1_ORDER
    N_HALF = N // 2

    def test_s_low_unchanged(self):
        """s value below n/2 is returned unchanged."""
        r = bytes([0x01] * 32)
        s = (self.N_HALF - 1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result, sig)

    def test_s_exactly_half_unchanged(self):
        """s value equal to n/2 is returned unchanged."""
        r = bytes([0xAA] * 32)
        s = self.N_HALF.to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result, sig)

    def test_s_high_is_negated(self):
        """s value above n/2 is negated (n - s)."""
        r = bytes([0xBB] * 32)
        s = (self.N_HALF + 1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        expected_s = self.N - (self.N_HALF + 1)
        expected = r + expected_s.to_bytes(32, "big")
        self.assertEqual(result, expected)

    def test_s_max_negated(self):
        """s = n-1 is negated to 1."""
        r = bytes([0xCC] * 32)
        s = (self.N - 1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        expected = r + (1).to_bytes(32, "big")
        self.assertEqual(result, expected)

    def test_s_zero(self):
        """s = 0 is returned unchanged (below n/2)."""
        r = bytes([0xDD] * 32)
        s = (0).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result, sig)

    def test_s_one_low(self):
        """s = 1 is returned unchanged (below n/2)."""
        r = bytes([0xEE] * 32)
        s = (1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result, sig)

    def test_r_preserved_when_s_changes(self):
        """r portion is preserved even when s is negated."""
        r = bytes([0xFF] * 32)
        s = (self.N - 100).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result[:32], r)
        # s should be negated
        expected_s = self.N - (self.N - 100)
        self.assertEqual(result[32:], expected_s.to_bytes(32, "big"))

    def test_output_length(self):
        """Result is always exactly 64 bytes."""
        r = bytes([0x11] * 32)
        s = (42).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(len(result), 64)

    def test_deterministic(self):
        """Same input produces same output."""
        r = bytes([0x22] * 32)
        s = (self.N - 5000).to_bytes(32, "big")
        sig = r + s
        r1 = _enforce_low_s(sig, self.N)
        r2 = _enforce_low_s(sig, self.N)
        self.assertEqual(r1, r2)


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaLowSEnforcementSecp256r1(unittest.TestCase):
    """Test _enforce_low_s with secp256r1 curve order."""

    N = SECP256R1_ORDER
    N_HALF = N // 2

    def test_s_low_unchanged(self):
        """s value below n/2 is returned unchanged."""
        r = bytes([0x11] * 32)
        s = (self.N_HALF - 1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result, sig)

    def test_s_exactly_half_unchanged(self):
        """s value equal to n/2 is returned unchanged."""
        r = bytes([0x22] * 32)
        s = self.N_HALF.to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result, sig)

    def test_s_high_is_negated(self):
        """s value above n/2 is negated (n - s)."""
        r = bytes([0x33] * 32)
        s = (self.N_HALF + 1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        expected_s = self.N - (self.N_HALF + 1)
        expected = r + expected_s.to_bytes(32, "big")
        self.assertEqual(result, expected)

    def test_s_max_negated(self):
        """s = n-1 is negated to 1."""
        r = bytes([0x44] * 32)
        s = (self.N - 1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        expected = r + (1).to_bytes(32, "big")
        self.assertEqual(result, expected)

    def test_s_zero(self):
        """s = 0 is returned unchanged."""
        r = bytes([0x55] * 32)
        s = (0).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result, sig)

    def test_s_one_low(self):
        """s = 1 is returned unchanged."""
        r = bytes([0x66] * 32)
        s = (1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result, sig)

    def test_output_length(self):
        """Result is always exactly 64 bytes."""
        r = bytes([0x77] * 32)
        s = (999).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(len(result), 64)


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaLowSEnforcementEd25519(unittest.TestCase):
    """Test _enforce_low_s with ed25519 curve order.

    While ed25519 itself handles signature malleability differently,
    the function should still work generically with any curve order.
    """

    N = 2**252 + 27742317777372353535851937790883648493
    N_HALF = N // 2

    def test_s_low_ed25519(self):
        """s below n/2 unchanged for ed25519 curve order."""
        r = bytes([0x11] * 32)
        s = (self.N_HALF - 1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        self.assertEqual(result, sig)

    def test_s_high_ed25519(self):
        """s above n/2 negated for ed25519 curve order."""
        r = bytes([0x22] * 32)
        s = (self.N_HALF + 1).to_bytes(32, "big")
        sig = r + s
        result = _enforce_low_s(sig, self.N)
        expected_s = self.N - (self.N_HALF + 1)
        expected = r + expected_s.to_bytes(32, "big")
        self.assertEqual(result, expected)


# ==============================================================================
# Public key derivation tests
# ==============================================================================


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaDerivePublicKeySecp256k1(unittest.TestCase):
    """Test _derive_public_key for secp256k1."""

    def test_derives_compressed_public_key(self):
        """secp256k1 private key produces 33-byte compressed public key."""
        private_key = bytes([0x01] * 32)
        pubkey = _derive_public_key(private_key, _ALGO_SECP256K1)
        self.assertIsInstance(pubkey, bytes)
        self.assertEqual(len(pubkey), 33)

    def test_different_private_key_different_pubkey(self):
        """Different private keys produce different public keys."""
        pk1 = _derive_public_key(bytes([0x01] * 32), _ALGO_SECP256K1)
        pk2 = _derive_public_key(bytes([0x02] * 32), _ALGO_SECP256K1)
        self.assertNotEqual(pk1, pk2)

    def test_deterministic(self):
        """Same private key always produces same public key."""
        pk1 = _derive_public_key(bytes([0xAA] * 32), _ALGO_SECP256K1)
        pk2 = _derive_public_key(bytes([0xAA] * 32), _ALGO_SECP256K1)
        self.assertEqual(pk1, pk2)

    def test_compressed_prefix_02_or_03(self):
        """Compressed secp256k1 public key starts with 0x02 or 0x03."""
        pubkey = _derive_public_key(bytes([0x01] * 32), _ALGO_SECP256K1)
        self.assertIn(pubkey[0], (0x02, 0x03))


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaDerivePublicKeySecp256r1(unittest.TestCase):
    """Test _derive_public_key for secp256r1."""

    def test_derives_compressed_public_key(self):
        """secp256r1 private key produces 33-byte compressed public key."""
        private_key = bytes([0x11] * 32)
        pubkey = _derive_public_key(private_key, _ALGO_SECP256R1)
        self.assertIsInstance(pubkey, bytes)
        self.assertEqual(len(pubkey), 33)

    def test_different_private_key_different_pubkey(self):
        """Different private keys produce different public keys."""
        pk1 = _derive_public_key(bytes([0x11] * 32), _ALGO_SECP256R1)
        pk2 = _derive_public_key(bytes([0x22] * 32), _ALGO_SECP256R1)
        self.assertNotEqual(pk1, pk2)

    def test_deterministic(self):
        """Same private key always produces same public key."""
        pk1 = _derive_public_key(bytes([0xBB] * 32), _ALGO_SECP256R1)
        pk2 = _derive_public_key(bytes([0xBB] * 32), _ALGO_SECP256R1)
        self.assertEqual(pk1, pk2)

    def test_compressed_prefix(self):
        """Compressed secp256r1 public key starts with 0x02 or 0x03."""
        pubkey = _derive_public_key(bytes([0x11] * 32), _ALGO_SECP256R1)
        self.assertIn(pubkey[0], (0x02, 0x03))


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaDerivePublicKeyEd25519(unittest.TestCase):
    """Test _derive_public_key for ed25519."""

    def test_derives_public_key(self):
        """ed25519 private key produces 32-byte raw public key."""
        private_key = bytes([0x21] * 32)
        pubkey = _derive_public_key(private_key, _ALGO_ED25519)
        self.assertIsInstance(pubkey, bytes)
        self.assertEqual(len(pubkey), 32)

    def test_different_private_key_different_pubkey(self):
        """Different private keys produce different public keys."""
        pk1 = _derive_public_key(bytes([0x21] * 32), _ALGO_ED25519)
        pk2 = _derive_public_key(bytes([0x22] * 32), _ALGO_ED25519)
        self.assertNotEqual(pk1, pk2)

    def test_deterministic(self):
        """Same private key always produces same public key."""
        pk1 = _derive_public_key(bytes([0xCC] * 32), _ALGO_ED25519)
        pk2 = _derive_public_key(bytes([0xCC] * 32), _ALGO_ED25519)
        self.assertEqual(pk1, pk2)


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaDerivePublicKeyErrors(unittest.TestCase):
    """Test _derive_public_key error handling."""

    def test_invalid_algorithm_raises_data_error(self):
        """Invalid algorithm value raises DataError."""
        from trezor import wire

        private_key = bytes([0x01] * 32)
        with self.assertRaises(wire.DataError):
            _derive_public_key(private_key, 0xFF)

    def test_multisig_not_supported(self):
        """MULTISIG algorithm raises DataError."""
        from trezor import wire

        private_key = bytes([0x01] * 32)
        with self.assertRaises(wire.DataError):
            _derive_public_key(private_key, _ALGO_MULTISIG)

    def test_empty_private_key_secp256k1(self):
        """Empty private key for secp256k1 raises error."""
        with self.assertRaises(ValueError):
            _derive_public_key(b"", _ALGO_SECP256K1)

    def test_short_private_key_secp256k1(self):
        """Private key shorter than 32 bytes for secp256k1 raises error."""
        with self.assertRaises(ValueError):
            _derive_public_key(b"\x01" * 16, _ALGO_SECP256K1)


# ==============================================================================
# Session state management tests
# ==============================================================================


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaSessionState(unittest.TestCase):
    """Test module-level session state management and cleanup."""

    def setUp(self):
        _cleanup()

    def test_initial_state_active(self):
        """Session starts inactive."""
        from apps.keeta import sign_block

        self.assertFalse(sign_block._active)

    def test_initial_state_parser(self):
        """Parser is None initially."""
        from apps.keeta import sign_block

        self.assertIsNone(sign_block._parser)

    def test_initial_state_hasher(self):
        """Hasher is None initially."""
        from apps.keeta import sign_block

        self.assertIsNone(sign_block._hasher)

    def test_initial_state_private_key(self):
        """Private key is None initially."""
        from apps.keeta import sign_block

        self.assertIsNone(sign_block._private_key)

    def test_initial_state_keeta_seed(self):
        """Keeta seed is None initially."""
        from apps.keeta import sign_block

        self.assertIsNone(sign_block._keeta_seed)

    def test_initial_state_address_n(self):
        """Address_n is None initially."""
        from apps.keeta import sign_block

        self.assertIsNone(sign_block._address_n)

    def test_initial_state_algorithm(self):
        """Algorithm is None initially."""
        from apps.keeta import sign_block

        self.assertIsNone(sign_block._algorithm)

    def test_initial_state_network_id(self):
        """Network ID is None initially."""
        from apps.keeta import sign_block

        self.assertIsNone(sign_block._network_id)

    def test_initial_state_expected_index(self):
        """Expected index starts at 0."""
        from apps.keeta import sign_block

        self.assertEqual(sign_block._expected_index, 0)

    def test_initial_state_first_chunk_time(self):
        """First chunk time starts at 0."""
        from apps.keeta import sign_block

        self.assertEqual(sign_block._first_chunk_time, 0)

    def test_initial_state_completed_ops(self):
        """Completed operations starts as empty list."""
        from apps.keeta import sign_block

        self.assertEqual(sign_block._completed_ops, [])

    def test_cleanup_resets_active(self):
        """Cleanup resets _active to False."""
        from apps.keeta import sign_block

        sign_block._active = True
        _cleanup()
        self.assertFalse(sign_block._active)

    def test_cleanup_resets_parser(self):
        """Cleanup resets _parser to None."""
        from apps.keeta import sign_block
        from apps.keeta.der_parser import DerParser

        sign_block._parser = DerParser()
        _cleanup()
        self.assertIsNone(sign_block._parser)

    def test_cleanup_resets_hasher(self):
        """Cleanup resets _hasher to None."""
        from trezor.crypto.hashlib import sha3_256

        from apps.keeta import sign_block

        sign_block._hasher = sha3_256(keccak=False)
        _cleanup()
        self.assertIsNone(sign_block._hasher)

    def test_cleanup_resets_private_key(self):
        """Cleanup resets _private_key to None."""
        from apps.keeta import sign_block

        sign_block._private_key = bytearray(b"\x01" * 32)
        _cleanup()
        self.assertIsNone(sign_block._private_key)

    def test_cleanup_resets_keeta_seed(self):
        """Cleanup resets _keeta_seed to None."""
        from apps.keeta import sign_block

        sign_block._keeta_seed = bytearray(b"\x02" * 32)
        _cleanup()
        self.assertIsNone(sign_block._keeta_seed)

    def test_cleanup_resets_address_n(self):
        """Cleanup resets _address_n to None."""
        from apps.keeta import sign_block

        sign_block._address_n = [44, 8887, 0, 0, 0]
        _cleanup()
        self.assertIsNone(sign_block._address_n)

    def test_cleanup_resets_algorithm(self):
        """Cleanup resets _algorithm to None."""
        from apps.keeta import sign_block

        sign_block._algorithm = 0x00
        _cleanup()
        self.assertIsNone(sign_block._algorithm)

    def test_cleanup_resets_network_id(self):
        """Cleanup resets _network_id to None."""
        from apps.keeta import sign_block

        sign_block._network_id = 0x54455354
        _cleanup()
        self.assertIsNone(sign_block._network_id)

    def test_cleanup_resets_expected_index(self):
        """Cleanup resets _expected_index to 0."""
        from apps.keeta import sign_block

        sign_block._expected_index = 42
        _cleanup()
        self.assertEqual(sign_block._expected_index, 0)

    def test_cleanup_resets_first_chunk_time(self):
        """Cleanup resets _first_chunk_time to 0."""
        from apps.keeta import sign_block

        sign_block._first_chunk_time = 99999
        _cleanup()
        self.assertEqual(sign_block._first_chunk_time, 0)

    def test_cleanup_clears_completed_ops(self):
        """Cleanup clears _completed_ops list."""
        from apps.keeta import sign_block

        sign_block._completed_ops = [(0xA0, b"\x01\x02")]
        _cleanup()
        self.assertEqual(sign_block._completed_ops, [])

    def test_cleanup_zeroes_private_key_data(self):
        """Cleanup zeros the private key bytearray before releasing it."""
        from apps.keeta import sign_block

        key = bytearray(b"\xaa" * 32)
        sign_block._private_key = key
        _cleanup()
        # The bytearray should be zeroed
        self.assertEqual(key, bytearray(b"\x00" * 32))

    def test_cleanup_zeroes_keeta_seed_data(self):
        """Cleanup zeros the keeta_seed bytearray before releasing it."""
        from apps.keeta import sign_block

        seed = bytearray(b"\xbb" * 32)
        sign_block._keeta_seed = seed
        _cleanup()
        # The bytearray should be zeroed
        self.assertEqual(seed, bytearray(b"\x00" * 32))

    def test_cleanup_idempotent(self):
        """Calling cleanup multiple times is safe."""
        from apps.keeta import sign_block

        _cleanup()  # Already once in setUp
        _cleanup()  # Second call
        self.assertFalse(sign_block._active)
        self.assertIsNone(sign_block._parser)
        self.assertIsNone(sign_block._hasher)
        self.assertIsNone(sign_block._private_key)
        self.assertEqual(sign_block._expected_index, 0)
        self.assertEqual(sign_block._completed_ops, [])

    def test_cleanup_after_failure(self):
        """Cleanup works correctly after a simulated failure state."""
        from apps.keeta import sign_block

        sign_block._active = True
        sign_block._expected_index = 5
        sign_block._private_key = bytearray(b"\xcc" * 32)
        _cleanup()
        self.assertFalse(sign_block._active)
        self.assertIsNone(sign_block._private_key)
        self.assertEqual(sign_block._expected_index, 0)


# ==============================================================================
# Hash chaining tests
# ==============================================================================


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaHashChaining(unittest.TestCase):
    """Test SHA3-256 hasher accumulation across chunks."""

    def setUp(self):
        _cleanup()

    def _fresh_hasher(self):
        """Create a fresh SHA3-256 hasher (NIST mode, keccak=False)."""
        from trezor.crypto.hashlib import sha3_256

        return sha3_256(keccak=False)

    def test_empty_chunk_no_update(self):
        """Empty chunk data does not overwrite hasher state."""
        hasher = self._fresh_hasher()
        hasher.update(b"hello")
        hasher.update(b"")
        digest1 = hasher.digest()

        hasher2 = self._fresh_hasher()
        hasher2.update(b"hello")
        digest2 = hasher2.digest()
        self.assertEqual(digest1, digest2)

    def test_accumulate_two_chunks(self):
        """Feeding data in two chunks produces same digest as one chunk."""
        hasher_split = self._fresh_hasher()
        hasher_split.update(b"chunk_one_")
        hasher_split.update(b"chunk_two")
        digest_split = hasher_split.digest()

        hasher_single = self._fresh_hasher()
        hasher_single.update(b"chunk_one_chunk_two")
        digest_single = hasher_single.digest()
        self.assertEqual(digest_split, digest_single)

    def test_accumulate_many_chunks(self):
        """Multiple small chunks accumulate correctly."""
        hasher_multi = self._fresh_hasher()
        parts = [b"a", b"b", b"c", b"d", b"e", b"f"]
        for p in parts:
            hasher_multi.update(p)
        digest_multi = hasher_multi.digest()

        hasher_single = self._fresh_hasher()
        hasher_single.update(b"abcdef")
        digest_single = hasher_single.digest()
        self.assertEqual(digest_multi, digest_single)

    def test_accumulate_known_golden(self):
        """Accumulated hash matches known golden value."""
        data = b"Keeta block signing test data for hash chaining"
        hasher = self._fresh_hasher()
        mid = len(data) // 2
        hasher.update(data[:mid])
        hasher.update(data[mid:])
        result = hasher.digest()

        expected = unhexlify(
            "d7f4dae2a7432f4fabc60e71255d55e0d3441be0b8bce0d4e632128fbf24e72c"
        )
        self.assertEqual(result, expected)

    def test_deterministic_digest(self):
        """Same input produces same digest every time."""
        hasher1 = self._fresh_hasher()
        hasher1.update(b"deterministic_test_data")
        d1 = hasher1.digest()

        hasher2 = self._fresh_hasher()
        hasher2.update(b"deterministic_test_data")
        d2 = hasher2.digest()
        self.assertEqual(d1, d2)

    def test_single_byte_chunks(self):
        """Processing data one byte at a time produces correct digest."""
        data = b"Single byte at a time test"
        hasher = self._fresh_hasher()
        for b in data:
            hasher.update(bytes([b]))
        result = hasher.digest()

        expected = unhexlify(
            "3eee32d32b42b1a3b0ae527ff1f25ba57601fe766de8064b195b6479f39b82b9"
        )
        self.assertEqual(result, expected)


# ==============================================================================
# Network name constants tests
# ==============================================================================


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaNetworkNames(unittest.TestCase):
    """Test _NETWORK_NAMES constant mapping."""

    def test_testnet_name(self):
        """Network ID 0x54455354 maps to 'Testnet'."""
        self.assertEqual(_NETWORK_NAMES[0x54455354], "Testnet")

    def test_mainnet_name(self):
        """Network ID 0x5382 maps to 'Mainnet'."""
        self.assertEqual(_NETWORK_NAMES[0x5382], "Mainnet")

    def test_testnet_value_is_ascii_test(self):
        """0x54455354 decodes to ASCII 'TEST'."""
        value = 0x54455354
        as_bytes = value.to_bytes(4, "big")
        self.assertEqual(as_bytes, b"TEST")

    def test_unknown_network_not_in_dict(self):
        """Unknown network IDs are not in _NETWORK_NAMES."""
        self.assertTrue(0x1234 not in _NETWORK_NAMES)

    def test_network_names_dict_type(self):
        """_NETWORK_NAMES is a dict."""
        self.assertIsInstance(_NETWORK_NAMES, dict)


# ==============================================================================
# Module-level state isolation tests
# ==============================================================================


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaStateIsolation(unittest.TestCase):
    """Test that module state resets between test cases and doesn't leak."""

    def setUp(self):
        _cleanup()

    def test_cleanup_does_not_affect_imports(self):
        """Cleanup does not break module imports or constants."""
        from apps.keeta.constants import SLIP44_ID

        self.assertEqual(SLIP44_ID, 8887)

    def test_import_side_effects(self):
        """Importing sign_block does not activate session."""
        from apps.keeta import sign_block

        self.assertFalse(sign_block._active)

    def test_repeated_cleanup_stable(self):
        """Repeated cleanup cycles do not corrupt module state."""
        for _ in range(10):
            _cleanup()
            from apps.keeta import sign_block

            self.assertFalse(sign_block._active)
            self.assertIsNone(sign_block._private_key)
            self.assertIsNone(sign_block._keeta_seed)
            self.assertEqual(sign_block._expected_index, 0)

    def test_set_and_cleanup_cycle(self):
        """Setting state then cleaning up fully restores initial conditions."""
        from apps.keeta import sign_block

        # Set various states
        sign_block._active = True
        sign_block._private_key = bytearray(b"\xdd" * 32)
        sign_block._keeta_seed = bytearray(b"\xee" * 32)
        sign_block._expected_index = 10
        sign_block._completed_ops = [(0xA0, b"data")]

        _cleanup()

        # Verify all reset
        self.assertFalse(sign_block._active)
        self.assertIsNone(sign_block._private_key)
        self.assertIsNone(sign_block._keeta_seed)
        self.assertEqual(sign_block._expected_index, 0)
        self.assertEqual(sign_block._completed_ops, [])


# ==============================================================================
# Entry point
# ==============================================================================

if __name__ == "__main__":
    unittest.main()

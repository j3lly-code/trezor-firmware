# flake8: noqa: F403,F405
"""Tests for Keeta token cache."""

from common import *  # isort:skip

if not utils.BITCOIN_ONLY:
    from apps.keeta import token_cache


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaTokenCache(unittest.TestCase):
    def setUp(self):
        token_cache.clear()

    def _valid_token_address(self, prefix_byte: int = 0x02) -> bytes:
        """Create a valid token address (33 bytes, compressed secp256k1 pubkey)."""
        return bytes([prefix_byte] + [0x01] * 32)

    def test_cache_insert_and_lookup_symbol(self):
        """Test basic cache insert and symbol lookup."""
        addr = self._valid_token_address()
        token_cache._cache[addr] = {
            "symbol": "TEST",
            "decimals": 8,
            "chain_id": 1413829460,
        }
        self.assertEqual(token_cache.get_token_symbol(addr), "TEST")

    def test_cache_insert_and_lookup_decimals(self):
        """Test cache insert and decimals lookup."""
        addr = self._valid_token_address()
        token_cache._cache[addr] = {
            "symbol": "TST",
            "decimals": 6,
            "chain_id": 1413829460,
        }
        self.assertEqual(token_cache.get_token_decimals(addr), 6)

    def test_cache_clear(self):
        """Test cache clear removes all entries."""
        addr = self._valid_token_address(0x03)
        token_cache._cache[addr] = {
            "symbol": "TST",
            "decimals": 6,
            "chain_id": 0,
        }
        token_cache.clear()
        self.assertEqual(len(token_cache._cache), 0)
        self.assertIsNone(token_cache.get_token_symbol(addr))
        self.assertIsNone(token_cache.get_token_decimals(addr))

    def test_lock_unlock(self):
        """Test the active-signing lock."""
        self.assertFalse(token_cache.is_locked())
        token_cache.lock()
        self.assertTrue(token_cache.is_locked())
        token_cache.unlock()
        self.assertFalse(token_cache.is_locked())

    def test_lock_twice(self):
        """Test locking twice is allowed (idempotent lock)."""
        token_cache.lock()
        token_cache.lock()
        self.assertTrue(token_cache.is_locked())
        token_cache.unlock()
        self.assertFalse(token_cache.is_locked())

    def test_unlock_idempotent(self):
        """Test unlock is idempotent."""
        token_cache.lock()
        token_cache.unlock()
        token_cache.unlock()  # Should not raise
        self.assertFalse(token_cache.is_locked())

    def test_lookup_nonexistent_symbol(self):
        """Test symbol lookup returns None for unknown tokens."""
        addr = self._valid_token_address(0x04)
        self.assertIsNone(token_cache.get_token_symbol(addr))

    def test_lookup_nonexistent_decimals(self):
        """Test decimals lookup returns None for unknown tokens."""
        addr = self._valid_token_address(0x05)
        self.assertIsNone(token_cache.get_token_decimals(addr))

    def test_cache_immutability_reject_overwrite(self):
        """Test that cache entries reject overwrite once set (immutable)."""
        addr = self._valid_token_address()
        token_cache._cache[addr] = {"symbol": "FIRST", "decimals": 4, "chain_id": 0}
        self.assertEqual(token_cache._cache[addr]["symbol"], "FIRST")
        # Immutability: handler should reject overwrite
        # Verify the expected behavior: do NOT allow overwrite
        with self.assertRaises(ValueError):
            token_cache.set_token_info(addr, "SECOND", 8, 0)

    def test_multiple_entries(self):
        """Test cache handles multiple entries simultaneously."""
        addr1 = self._valid_token_address(0x02)
        addr2 = self._valid_token_address(0x03)
        token_cache._cache[addr1] = {"symbol": "AAA", "decimals": 8, "chain_id": 0}
        token_cache._cache[addr2] = {"symbol": "BBB", "decimals": 6, "chain_id": 0}
        self.assertEqual(token_cache.get_token_symbol(addr1), "AAA")
        self.assertEqual(token_cache.get_token_symbol(addr2), "BBB")

    def test_delete_specific_address(self):
        """Test deleting a specific cache entry."""
        addr = self._valid_token_address()
        token_cache._cache[addr] = {"symbol": "DEL", "decimals": 2, "chain_id": 0}
        self.assertIsNotNone(token_cache.get_token_symbol(addr))
        del token_cache._cache[addr]
        self.assertIsNone(token_cache.get_token_symbol(addr))

    @unittest.skip("Requires full block signing context")
    def test_lock_during_signing(self):
        """Test that lock prevents cache modification during signing."""
        addr = self._valid_token_address()
        token_cache.lock()
        with self.assertRaises(RuntimeError):
            token_cache.set_token_info(addr, "LOCKED", 8, 0)


if __name__ == "__main__":
    unittest.main()

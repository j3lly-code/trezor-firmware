# flake8: noqa: F403,F405
"""Tests for Keeta UI confirmation screens.

Mocks all trezor.ui.layouts primitives and verifies that each layout function
passes the correct parameters to those primitives.
"""

from common import *  # isort:skip
from mock import MockAsync, patch
from trezor.enums import ButtonRequestType

if not utils.BITCOIN_ONLY:
    from apps.keeta import layout


def _patch_layout(attr: str, mock_obj):
    """Patch an attribute on the layout module."""
    return patch(layout, attr, mock_obj)


def _props(mock) -> list:
    """Extract the props/items list from a confirm_properties mock call (3rd positional arg)."""
    return mock.calls[0][0][2]


def _data(mock) -> str:
    """Extract the data string from a confirm_text mock call (3rd positional arg)."""
    return mock.calls[0][0][2]


def _content(mock) -> str:
    """Extract the content string from a show_danger/show_warning mock call (2nd positional arg)."""
    return mock.calls[0][0][1]


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestKeetaLayout(unittest.TestCase):
    """Test all UI confirmation screen functions in keeta/layout.py.

    Each function delegates to a trezor.ui.layouts primitive.  Tests verify
    that the correct primitive is called with the expected arguments.
    """

    # ==================================================================
    # confirm_signing_interrupted
    # ==================================================================
    def test_confirm_signing_interrupted(self):
        """Warns that prior signing was interrupted."""
        mock_show = MockAsync()
        with _patch_layout("show_warning", mock_show):
            await_result(layout.confirm_signing_interrupted())

        self.assertEqual(len(mock_show.calls), 1)
        _, kwargs = mock_show.calls[0]
        self.assertIs(kwargs["br_code"], ButtonRequestType.Warning)
        self.assertIn("INTERRUPTED", _content(mock_show).upper())
        self.assertIn(
            "Review new transaction carefully",
            kwargs.get("subheader", ""),
        )

    # ==================================================================
    # confirm_signing_account  (3 algorithm variants + edge cases)
    # ==================================================================
    def _check_signing_account(self, algorithm: str) -> None:
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_signing_account("keeta_abc123", algorithm))

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        self.assertIs(kwargs["br_code"], ButtonRequestType.Other)
        props = _props(mock_props)
        self.assertIn(("Address", "keeta_abc123", True), props)
        self.assertIn(("Algorithm", algorithm, False), props)

    def test_confirm_signing_account_secp256k1(self):
        """secp256k1 algorithm name displayed."""
        self._check_signing_account("secp256k1")

    def test_confirm_signing_account_ed25519(self):
        """ed25519 algorithm name displayed."""
        self._check_signing_account("ed25519")

    def test_confirm_signing_account_secp256r1(self):
        """secp256r1 algorithm name displayed."""
        self._check_signing_account("secp256r1")

    def test_confirm_signing_account_empty_address(self):
        """Empty address edge case."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_signing_account("", "secp256k1"))

        props = _props(mock_props)
        self.assertIn(("Address", "", True), props)

    # ==================================================================
    # confirm_keeta_address
    # ==================================================================
    def test_confirm_keeta_address_no_chunkify(self):
        """Full address verification without chunkify."""
        mock_addr = MockAsync()
        with _patch_layout("show_address", mock_addr):
            await_result(
                layout.confirm_keeta_address("keeta_deadbeef", "m/44'/8887'/0'")
            )

        self.assertEqual(len(mock_addr.calls), 1)
        _, kwargs = mock_addr.calls[0]
        self.assertEqual(kwargs["address"], "keeta_deadbeef")
        self.assertEqual(kwargs["path"], "m/44'/8887'/0'")
        self.assertEqual(kwargs["network"], "Keeta Network")
        self.assertFalse(kwargs.get("chunkify", False))

    def test_confirm_keeta_address_with_chunkify(self):
        """Full address verification with chunkify enabled."""
        mock_addr = MockAsync()
        with _patch_layout("show_address", mock_addr):
            await_result(
                layout.confirm_keeta_address(
                    "keeta_feed1234",
                    "m/44'/8887'/0'/0'/0'",
                    chunkify=True,
                )
            )

        _, kwargs = mock_addr.calls[0]
        self.assertEqual(kwargs["address"], "keeta_feed1234")
        self.assertTrue(kwargs.get("chunkify", False))

    def test_confirm_keeta_address_various_paths(self):
        """Multiple path formats are passed correctly."""
        mock_addr = MockAsync()
        paths = [
            "m/44'/8887'/0'",
            "m/44'/8887'/1'/0'/0'",
            "m/44'/8887'/0'/0'/0'",
        ]
        for path in paths:
            mock_addr.calls.clear()
            with _patch_layout("show_address", mock_addr):
                await_result(layout.confirm_keeta_address("keeta_test", path))
            self.assertEqual(mock_addr.calls[0][1]["path"], path)

    def test_confirm_keeta_address_long_address(self):
        """Long address passed through correctly."""
        long_addr = "keeta_" + "a" * 60
        mock_addr = MockAsync()
        with _patch_layout("show_address", mock_addr):
            await_result(layout.confirm_keeta_address(long_addr, "m/44'/8887'/0'"))
        self.assertEqual(mock_addr.calls[0][1]["address"], long_addr)

    def test_confirm_keeta_address_empty_address(self):
        """Empty address edge case."""
        mock_addr = MockAsync()
        with _patch_layout("show_address", mock_addr):
            await_result(layout.confirm_keeta_address("", "m/44'/8887'/0'"))
        self.assertEqual(mock_addr.calls[0][1]["address"], "")

    # ==================================================================
    # confirm_delegate_signing
    # ==================================================================
    def test_confirm_delegate_signing_different(self):
        """Different signer and account addresses."""
        mock_danger = MockAsync()
        mock_props = MockAsync()
        with _patch_layout("show_danger", mock_danger):
            with _patch_layout("confirm_properties", mock_props):
                await_result(
                    layout.confirm_delegate_signing("keeta_signer", "keeta_account")
                )

        # First call: show_danger warning
        self.assertEqual(len(mock_danger.calls), 1)
        danger_kwargs = mock_danger.calls[0][1]
        self.assertIs(danger_kwargs["br_code"], ButtonRequestType.Warning)
        self.assertIn("DELEGATE", _content(mock_danger).upper())

        # Second call: confirm_properties with both addresses
        self.assertEqual(len(mock_props.calls), 1)
        props_kwargs = mock_props.calls[0][1]
        self.assertIs(props_kwargs["br_code"], ButtonRequestType.ConfirmOutput)
        props = _props(mock_props)
        self.assertIn(("Signer", "keeta_signer", True), props)
        self.assertIn(("Account", "keeta_account", True), props)

    def test_confirm_delegate_signing_same(self):
        """Same address for signer and account (edge case)."""
        mock_danger = MockAsync()
        mock_props = MockAsync()
        with _patch_layout("show_danger", mock_danger):
            with _patch_layout("confirm_properties", mock_props):
                await_result(
                    layout.confirm_delegate_signing("keeta_same", "keeta_same")
                )

        props = _props(mock_props)
        signer_val = next(v for k, v, _ in props if k == "Signer")
        account_val = next(v for k, v, _ in props if k == "Account")
        self.assertEqual(signer_val, account_val)

    # ==================================================================
    # confirm_send_operation
    # ==================================================================
    def test_confirm_send_operation_known_token(self):
        """Send with known token symbol."""
        mock_out = MockAsync()
        with _patch_layout("confirm_output", mock_out):
            await_result(layout.confirm_send_operation("keeta_recv", "100", "MYT"))

        self.assertEqual(len(mock_out.calls), 1)
        _, kwargs = mock_out.calls[0]
        self.assertEqual(kwargs["address"], "keeta_recv")
        self.assertEqual(kwargs["amount"], "100")
        self.assertEqual(kwargs["title"], "Send MYT")
        self.assertIs(kwargs["br_code"], ButtonRequestType.ConfirmOutput)

    def test_confirm_send_operation_default_token(self):
        """Defaults to KTA when no token symbol supplied."""
        mock_out = MockAsync()
        with _patch_layout("confirm_output", mock_out):
            await_result(layout.confirm_send_operation("keeta_recv", "5000"))

        _, kwargs = mock_out.calls[0]
        self.assertEqual(kwargs["title"], "Send KTA")

    def test_confirm_send_operation_empty_amount(self):
        """Empty amount string."""
        mock_out = MockAsync()
        with _patch_layout("confirm_output", mock_out):
            await_result(layout.confirm_send_operation("keeta_recv", ""))

        _, kwargs = mock_out.calls[0]
        self.assertEqual(kwargs["amount"], "")

    def test_confirm_send_operation_zero_amount(self):
        """Zero amount."""
        mock_out = MockAsync()
        with _patch_layout("confirm_output", mock_out):
            await_result(layout.confirm_send_operation("keeta_recv", "0"))

        _, kwargs = mock_out.calls[0]
        self.assertEqual(kwargs["amount"], "0")

    def test_confirm_send_operation_special_chars_token(self):
        """Token symbol with special characters."""
        mock_out = MockAsync()
        with _patch_layout("confirm_output", mock_out):
            await_result(layout.confirm_send_operation("keeta_recv", "100", "S-TKN"))

        self.assertEqual(mock_out.calls[0][1]["title"], "Send S-TKN")

    # ==================================================================
    # confirm_receive
    # ==================================================================
    def test_confirm_receive_with_token(self):
        """Receive with a specific token."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_receive("keeta_acc", "keeta_sender", "200", "TKN")
            )

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_acc", True), props)
        self.assertIn(("From", "keeta_sender", True), props)
        self.assertIn(("Amount", "200 TKN", False), props)
        self.assertIs(kwargs["br_code"], ButtonRequestType.ConfirmOutput)

    def test_confirm_receive_without_token(self):
        """Defaults to KTA when no token provided."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_receive("keeta_acc", "keeta_sender", "100"))

        props = _props(mock_props)
        self.assertIn(("Amount", "100 KTA", False), props)

    def test_confirm_receive_without_from_addr(self):
        """Empty from address."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_receive("keeta_acc", "", "50", "KTA"))

        props = _props(mock_props)
        self.assertIn(("From", "", True), props)

    # ==================================================================
    # confirm_set_rep  (+ warnings)
    # ==================================================================
    def test_confirm_set_rep(self):
        """Set representative confirmation."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_set_rep("keeta_acc", "keeta_rep"))

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_acc", True), props)
        self.assertIn(("Representative", "keeta_rep", True), props)
        self.assertIs(kwargs["br_code"], ButtonRequestType.ConfirmOutput)

    def test_confirm_set_rep_empty_representative(self):
        """Empty representative edge case."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_set_rep("keeta_acc", ""))

        props = _props(mock_props)
        self.assertIn(("Representative", "", True), props)

    def test_confirm_set_rep_warning(self):
        """Warning about delegating voting power."""
        mock_danger = MockAsync()
        with _patch_layout("show_danger", mock_danger):
            await_result(layout.confirm_set_rep_warning())

        self.assertEqual(len(mock_danger.calls), 1)
        _, kwargs = mock_danger.calls[0]
        self.assertIs(kwargs["br_code"], ButtonRequestType.Warning)

    def test_confirm_set_rep_self_warning(self):
        """Warning when setting self as representative."""
        mock_warn = MockAsync()
        with _patch_layout("show_warning", mock_warn):
            await_result(layout.confirm_set_rep_self_warning())

        self.assertEqual(len(mock_warn.calls), 1)
        _, kwargs = mock_warn.calls[0]
        self.assertIs(kwargs["br_code"], ButtonRequestType.Other)
        self.assertIn(
            "yourself",
            kwargs.get("subheader", ""),
        )

    # ==================================================================
    # confirm_set_info
    # ==================================================================
    def test_confirm_set_info(self):
        """Account metadata update with all fields."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_set_info(
                    "keeta_acc",
                    "My Account",
                    "Test description",
                    "READ",
                    "NONE",
                    "PENDING",
                )
            )

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_acc", True), props)
        self.assertIn(("Name", "My Account", False), props)
        self.assertIn(("Description", "Test description", False), props)
        self.assertIn(("Default Permission", "READ", False), props)
        self.assertIn(("External Permissions", "NONE", False), props)
        self.assertIn(("Metadata Status", "PENDING", False), props)

    def test_confirm_set_info_empty_fields(self):
        """Empty strings for optional info fields."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_set_info("keeta_acc", "", "", "ACCESS", "ACCESS", "SET")
            )

        props = _props(mock_props)
        self.assertIn(("Name", "", False), props)
        self.assertIn(("Description", "", False), props)

    # ==================================================================
    # confirm_create_identifier_multisig
    # ==================================================================
    def test_confirm_create_identifier_multisig(self):
        """Multisig identifier with signers."""
        mock_props = MockAsync()
        mock_text = MockAsync()
        signers = ["keeta_s1", "keeta_s2", "keeta_s3"]
        with _patch_layout("confirm_properties", mock_props):
            with _patch_layout("confirm_text", mock_text):
                await_result(
                    layout.confirm_create_identifier_multisig(
                        "keeta_acc", "MULTISIG", 2, signers
                    )
                )

        # Summary screen
        self.assertEqual(len(mock_props.calls), 1)
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_acc", True), props)
        self.assertIn(("Type", "MULTISIG", False), props)
        self.assertIn(("Quorum", "2", False), props)
        self.assertIn(("Signers", "3 signer(s)", False), props)

        # Individual signer screens
        self.assertEqual(len(mock_text.calls), 3)
        for i, call in enumerate(mock_text.calls):
            _, kwargs = call
            self.assertEqual(
                call[0][2],
                signers[i],
            )

    def test_confirm_create_identifier_multisig_no_signers(self):
        """Multisig with empty signer list."""
        mock_props = MockAsync()
        mock_text = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            with _patch_layout("confirm_text", mock_text):
                await_result(
                    layout.confirm_create_identifier_multisig(
                        "keeta_acc", "MULTISIG", 1, []
                    )
                )

        props = _props(mock_props)
        self.assertIn(("Signers", "0 signer(s)", False), props)
        self.assertEqual(len(mock_text.calls), 0)

    # ==================================================================
    # confirm_create_identifier_swap
    # ==================================================================
    def test_confirm_create_identifier_swap(self):
        """Swap identifier creation."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_create_identifier_swap(
                    "keeta_acc",
                    "SWAP",
                    "KTA",
                    "1.5",
                    "USDC",
                    "1.0",
                    "100",
                )
            )

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_acc", True), props)
        self.assertIn(("Type", "SWAP", False), props)
        self.assertIn(("Sell Token", "KTA", False), props)
        self.assertIn(("Sell Rate", "1.5", False), props)
        self.assertIn(("Buy Token", "USDC", False), props)
        self.assertIn(("Buy Rate", "1.0", False), props)
        self.assertIn(("Quantity", "100", False), props)

    # ==================================================================
    # confirm_create_identifier_bare
    # ==================================================================
    def test_confirm_create_identifier_bare(self):
        """Bare identifier creation."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_create_identifier_bare("keeta_acc", "SWAP"))

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_acc", True), props)
        self.assertIn(("Type", "SWAP", False), props)
        self.assertEqual(len(props), 2)

    # ==================================================================
    # confirm_token_admin  (mint / burn / set)
    # ==================================================================
    def test_confirm_token_admin_mint(self):
        """Token admin supply: mint."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_token_admin("keeta_tkn", "mint", "1000000"))

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_tkn", True), props)
        self.assertIn(("Action", "mint", False), props)
        self.assertIn(("Amount", "1000000", False), props)

    def test_confirm_token_admin_burn(self):
        """Token admin supply: burn."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_token_admin("keeta_tkn", "burn", "500"))

        props = _props(mock_props)
        self.assertIn(("Action", "burn", False), props)

    def test_confirm_token_admin_set(self):
        """Token admin supply: set (zero amount)."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_token_admin("keeta_tkn", "set", "0"))

        props = _props(mock_props)
        self.assertIn(("Action", "set", False), props)
        self.assertIn(("Amount", "0", False), props)

    # ==================================================================
    # confirm_modify_balance  (add / subtract / set)
    # ==================================================================
    def test_confirm_modify_balance_add(self):
        """Balance modification: add (no danger screen)."""
        mock_props = MockAsync()
        mock_danger = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            with _patch_layout("show_danger", mock_danger):
                await_result(
                    layout.confirm_modify_balance(
                        "keeta_acc", "keeta_tkn", "add", "100"
                    )
                )

        self.assertEqual(len(mock_danger.calls), 0)
        self.assertEqual(len(mock_props.calls), 1)
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_acc", True), props)
        self.assertIn(("Token", "keeta_tkn", True), props)
        self.assertIn(("Action", "add", False), props)
        self.assertIn(("Amount", "100", False), props)

    def test_confirm_modify_balance_subtract(self):
        """Balance modification: subtract."""
        mock_props = MockAsync()
        mock_danger = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            with _patch_layout("show_danger", mock_danger):
                await_result(
                    layout.confirm_modify_balance(
                        "keeta_acc", "keeta_tkn", "subtract", "50"
                    )
                )

        self.assertEqual(len(mock_danger.calls), 0)
        props = _props(mock_props)
        self.assertIn(("Action", "subtract", False), props)

    def test_confirm_modify_balance_set(self):
        """Balance modification: set shows OVERWRITES danger."""
        mock_props = MockAsync()
        mock_danger = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            with _patch_layout("show_danger", mock_danger):
                await_result(
                    layout.confirm_modify_balance(
                        "keeta_acc", "keeta_tkn", "set", "999"
                    )
                )

        self.assertEqual(len(mock_danger.calls), 1)
        self.assertIn("OVERWRITES", _content(mock_danger).upper())
        self.assertEqual(len(mock_props.calls), 1)
        props = _props(mock_props)
        self.assertIn(("Action", "set", False), props)
        self.assertIn(("Amount", "999", False), props)

    def test_confirm_modify_balance_very_large_amount(self):
        """Balance modification with very large amount string."""
        mock_props = MockAsync()
        large_amount = "9" * 100
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_modify_balance(
                    "keeta_acc", "keeta_tkn", "add", large_amount
                )
            )

        props = _props(mock_props)
        self.assertIn(("Amount", large_amount, False), props)

    # ==================================================================
    # confirm_modify_permissions
    # ==================================================================
    def test_confirm_modify_permissions_with_target(self):
        """Permission modification with target address."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_modify_permissions(
                    "keeta_acc",
                    "keeta_principal",
                    "READ,WRITE",
                    "keeta_target",
                )
            )

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_acc", True), props)
        self.assertIn(("Principal", "keeta_principal", True), props)
        self.assertIn(("Permissions", "READ,WRITE", False), props)
        self.assertIn(("Target", "keeta_target", True), props)

    def test_confirm_modify_permissions_without_target(self):
        """Permission modification without target (None)."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_modify_permissions(
                    "keeta_acc", "keeta_principal", "ADMIN"
                )
            )

        props = _props(mock_props)
        self.assertEqual(len(_props(mock_props)), 3)
        prop_keys = [k for k, _, _ in props]
        self.assertIn("Account", prop_keys)
        self.assertIn("Principal", prop_keys)
        self.assertIn("Permissions", prop_keys)
        self.assertTrue("Target" not in prop_keys)

    def test_confirm_modify_permissions_many_permissions(self):
        """Permission string with many comma-separated values."""
        mock_props = MockAsync()
        perms = ",".join(f"PERM{i}" for i in range(20))
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_modify_permissions("keeta_acc", "keeta_principal", perms)
            )

        props = _props(mock_props)
        self.assertIn(("Permissions", perms, False), props)

    # ==================================================================
    # confirm_operation_summary  (single / multi / blind)
    # ==================================================================
    def _get_trezor_layouts(self):
        """Return the trezor.ui.layouts module (already imported by layout)."""
        import sys

        return sys.modules.get("trezor.ui.layouts")

    def test_confirm_operation_summary_single(self):
        """Single operation, no blind ops."""
        mock_text = MockAsync()
        with _patch_layout("confirm_text", mock_text):
            await_result(layout.confirm_operation_summary([{"type": "SEND"}]))

        self.assertEqual(len(mock_text.calls), 1)
        _, kwargs = mock_text.calls[0]
        self.assertIs(kwargs["br_code"], ButtonRequestType.ConfirmOutput)
        text = _data(mock_text)
        self.assertIn("SEND", text)

    def test_confirm_operation_summary_multiple_types(self):
        """Multiple operation types counted in summary."""
        mock_text = MockAsync()
        ops = [
            {"type": "SEND"},
            {"type": "SEND"},
            {"type": "RECEIVE"},
            {"type": "SET_INFO"},
            {"type": "SEND"},
        ]
        with _patch_layout("confirm_text", mock_text):
            await_result(layout.confirm_operation_summary(ops))

        self.assertEqual(len(mock_text.calls), 1)
        text = _data(mock_text)
        self.assertIn("SEND", text)
        self.assertIn("RECEIVE", text)
        self.assertIn("SET_INFO", text)

    def test_confirm_operation_summary_blind_ops(self):
        """Blind ops show BLIND SIGNING REQUIRED and detail prompts."""
        mock_text = MockAsync()
        mock_blob = MockAsync()
        tz_layouts = self._get_trezor_layouts()
        if tz_layouts is None:
            self.skipTest("trezor.ui.layouts not available in this environment")

        mock_should_show = MockAsync(return_value=False)
        ops = [
            {
                "type": "CUSTOM",
                "is_blind": True,
                "index": 0,
                "byte_count": 128,
                "hash_prefix": "a1b2c3",
            },
        ]
        with _patch_layout("confirm_text", mock_text):
            with _patch_layout("confirm_blob", mock_blob):
                with patch(tz_layouts, "should_show_more", mock_should_show):
                    await_result(layout.confirm_operation_summary(ops))

        text = _data(mock_text)
        self.assertIn("BLIND", text.upper())
        self.assertTrue(len(mock_should_show.calls) >= 1)

    def test_confirm_operation_summary_mixed(self):
        """Mixed blind and verified ops with detail expansion."""
        mock_text = MockAsync()
        mock_blob = MockAsync()
        tz_layouts = self._get_trezor_layouts()
        if tz_layouts is None:
            self.skipTest("trezor.ui.layouts not available in this environment")

        mock_should_show = MockAsync(return_value=True)
        ops = [
            {"type": "SEND"},
            {
                "type": "CUSTOM",
                "is_blind": True,
                "index": 2,
                "byte_count": 512,
                "hash_prefix": "deadbeef",
            },
        ]
        with _patch_layout("confirm_text", mock_text):
            with _patch_layout("confirm_blob", mock_blob):
                with patch(tz_layouts, "should_show_more", mock_should_show):
                    await_result(layout.confirm_operation_summary(ops))

        self.assertTrue(len(mock_should_show.calls) >= 1)
        self.assertTrue(len(mock_blob.calls) >= 1)

    # ==================================================================
    # confirm_oversized_operation_warning
    # ==================================================================
    def test_confirm_oversized_operation_warning(self):
        """Blind signing warning for oversized op (index 3 -> op #4)."""
        mock_warn = MockAsync()
        with _patch_layout("show_warning", mock_warn):
            await_result(layout.confirm_oversized_operation_warning(3))

        self.assertEqual(len(mock_warn.calls), 1)
        _, kwargs = mock_warn.calls[0]
        self.assertIs(kwargs["br_code"], ButtonRequestType.Warning)
        self.assertIn("4", kwargs.get("subheader", ""))

    # ==================================================================
    # confirm_block_header
    # ==================================================================
    def test_confirm_block_header_with_previous_hash(self):
        """Block summary with previous hash (bytes)."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_block_header(
                    "keeta_acc",
                    b"\x01\x02\x03\x04",
                    "2024-01-15",
                    "Keeta Testnet",
                )
            )

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        self.assertIn(("Account", "keeta_acc", True), props)
        self.assertIn(("Date", "2024-01-15", False), props)
        self.assertIn(("Network", "Keeta Testnet", False), props)
        self.assertIn(("Previous Hash", "01020304", True), props)
        self.assertIs(kwargs["br_code"], ButtonRequestType.SignTx)

    def test_confirm_block_header_without_previous_hash(self):
        """Block summary without previous hash (None)."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(
                layout.confirm_block_header(
                    "keeta_acc", None, "2024-06-01", "Keeta Mainnet"
                )
            )

        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        prop_keys = [k for k, _, _ in props]
        self.assertIn("Account", prop_keys)
        self.assertIn("Date", prop_keys)
        self.assertIn("Network", prop_keys)
        self.assertTrue("Previous Hash" not in prop_keys)

    # ==================================================================
    # confirm_blind_signing_warning
    # ==================================================================
    def test_confirm_blind_signing_warning(self):
        """Blind signing mode warning."""
        mock_danger = MockAsync()
        with _patch_layout("show_danger", mock_danger):
            await_result(layout.confirm_blind_signing_warning())

        self.assertEqual(len(mock_danger.calls), 1)
        _, kwargs = mock_danger.calls[0]
        self.assertIs(kwargs["br_code"], ButtonRequestType.Warning)
        self.assertIn("BLIND", _content(mock_danger).upper())

    # ==================================================================
    # confirm_token_info
    # ==================================================================
    def test_confirm_token_info(self):
        """Token cache information display."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_token_info("keeta_token_addr", "TST", 8))

        self.assertEqual(len(mock_props.calls), 1)
        _, kwargs = mock_props.calls[0]
        props = _props(mock_props)
        self.assertIn(("Address", "keeta_token_addr", True), props)
        self.assertIn(("Symbol", "TST", False), props)
        self.assertIn(("Decimals", "8", False), props)
        self.assertIs(kwargs["br_code"], ButtonRequestType.Other)

    def test_confirm_token_info_zero_decimals(self):
        """Token with 0 decimals."""
        mock_props = MockAsync()
        with _patch_layout("confirm_properties", mock_props):
            await_result(layout.confirm_token_info("keeta_zdec", "ZERO", 0))

        props = _props(mock_props)
        self.assertIn(("Decimals", "0", False), props)

    # ==================================================================
    # confirm_network_mismatch
    # ==================================================================
    def test_confirm_network_mismatch(self):
        """Network mismatch shows both expected and actual names."""
        mock_danger = MockAsync()
        with _patch_layout("show_danger", mock_danger):
            await_result(
                layout.confirm_network_mismatch("Keeta Mainnet", "Keeta Testnet")
            )

        self.assertEqual(len(mock_danger.calls), 1)
        _, kwargs = mock_danger.calls[0]
        self.assertIs(kwargs["br_code"], ButtonRequestType.Warning)
        value = kwargs.get("value", "")
        self.assertIn("Keeta Mainnet", value)
        self.assertIn("Keeta Testnet", value)


if __name__ == "__main__":
    unittest.main()

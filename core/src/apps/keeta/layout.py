"""
Keeta Network UI confirmation screens for block signing.

All functions are async and use Trezor's existing layout primitives.
"""

from trezor.enums import ButtonRequestType
from trezor.ui.layouts import (
    confirm_blob,
    confirm_output,
    confirm_properties,
    confirm_text,
    show_address,
    show_danger,
    show_warning,
)

try:
    from ubinascii import hexlify
except ImportError:
    from binascii import hexlify


async def confirm_signing_interrupted() -> None:
    """Show warning that prior signing was interrupted."""
    await show_warning(
        "confirm_signing_interrupted",
        "SIGNING INTERRUPTED",
        subheader="Review new transaction carefully",
        br_code=ButtonRequestType.Warning,
    )


async def confirm_signing_account(address: str, algorithm_name: str) -> None:
    """MANDATORY pre-sign account display. FIRST screen before any operations."""
    await confirm_properties(
        "confirm_signing_account",
        "Signing with",
        [
            ("Address", address, True),
            ("Algorithm", algorithm_name, False),
        ],
        br_code=ButtonRequestType.Other,
    )


async def confirm_keeta_address(
    address: str,
    path: str,
    chunkify: bool = False,
) -> None:
    """Show full Keeta address for verification."""
    await show_address(
        address=address,
        path=path,
        network="Keeta Network",
        chunkify=chunkify,
    )


async def confirm_delegate_signing(
    signer_address: str,
    account_address: str,
) -> None:
    """Shows both signer and account addresses with warning."""
    await show_danger(
        "confirm_delegate_signing",
        "SIGNING AS DELEGATE FOR ANOTHER ACCOUNT",
        verb_cancel=None,
        br_code=ButtonRequestType.Warning,
    )
    await confirm_properties(
        "confirm_delegate_signing_accounts",
        "Delegate Signing",
        [
            ("Signer", signer_address, True),
            ("Account", account_address, True),
        ],
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_send_operation(
    recipient: str,
    amount: str,
    token_symbol: str | None = None,
) -> None:
    """Confirm a SEND operation."""
    token_str = token_symbol or "KTA"
    await confirm_output(
        address=recipient,
        amount=amount,
        title=f"Send {token_str}",
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_receive(
    account: str,
    from_addr: str,
    amount: str,
    token: str | None = None,
) -> None:
    """Confirm a RECEIVE operation."""
    token_str = token or "KTA"
    await confirm_properties(
        "confirm_receive",
        "Receive",
        [
            ("Account", account, True),
            ("From", from_addr, True),
            ("Amount", f"{amount} {token_str}", False),
        ],
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_operation_summary(ops: list[dict]) -> None:
    """Multi-operation summary. For blind ops, show index, byte count, hash prefix."""
    from trezor.ui.layouts import should_show_more

    # Count operations by type
    type_counts: dict[str, int] = {}
    blind_ops: list[dict] = []
    for op in ops:
        op_type = op.get("type", "Unknown")
        type_counts[op_type] = type_counts.get(op_type, 0) + 1
        if op.get("is_blind"):
            blind_ops.append(op)

    summary_lines: list[str] = []
    for op_type, count in type_counts.items():
        summary_lines.append(f"{op_type}: {count}")

    if blind_ops:
        summary_lines.append("")
        summary_lines.append("BLIND SIGNING REQUIRED")

    summary = "\n".join(summary_lines)
    await confirm_text(
        "confirm_operation_summary",
        "Operation Summary",
        summary,
        br_code=ButtonRequestType.ConfirmOutput,
    )

    # Show details for each blind op if user wants to see more
    for op in blind_ops:
        op_index = op.get("index", 0)
        byte_count = op.get("byte_count", 0)
        hash_prefix = op.get("hash_prefix", "")

        should_show = await should_show_more(
            f"Blind Op #{op_index + 1}",
            [
                (f"Bytes: {byte_count}", False),
            ],
            button_text="Show details",
            br_code=ButtonRequestType.Other,
        )

        if should_show:
            await confirm_blob(
                f"blind_op_{op_index}",
                f"Blind Op #{op_index + 1}",
                hash_prefix,
                description="Hash prefix",
                br_code=ButtonRequestType.Other,
            )


async def confirm_oversized_operation_warning(op_index: int) -> None:
    """BLIND SIGNING -- OPERATION NOT VERIFIED for oversized ops."""
    await show_warning(
        "confirm_oversized_operation_warning",
        "BLIND SIGNING",
        subheader=f"Operation #{op_index + 1} is too large to verify",
        br_code=ButtonRequestType.Warning,
    )


async def confirm_block_header(
    account: str,
    previous_hash: bytes | None,
    date: str,
    network: str,
) -> None:
    """Show block summary before signing."""
    props: list[tuple[str, str, bool]] = [
        ("Account", account, True),
        ("Date", date, False),
        ("Network", network, False),
    ]
    if previous_hash:
        props.append(
            ("Previous Hash", hexlify(previous_hash).decode(), True),
        )

    await confirm_properties(
        "confirm_block_header",
        "Block Summary",
        props,
        br_code=ButtonRequestType.SignTx,
    )


async def confirm_blind_signing_warning() -> None:
    """Prominent warning when blind signing is used."""
    await show_danger(
        "confirm_blind_signing_warning",
        "BLIND SIGNING",
        value="The contents of some operations cannot be verified on your device",
        br_code=ButtonRequestType.Warning,
    )


async def confirm_token_info(
    token_address: str,
    symbol: str,
    decimals: int,
) -> None:
    """Token cache confirmation."""
    await confirm_properties(
        "confirm_token_info",
        "Token Information",
        [
            ("Address", token_address, True),
            ("Symbol", symbol, False),
            ("Decimals", str(decimals), False),
        ],
        br_code=ButtonRequestType.Other,
    )


async def confirm_set_rep(account: str, representative: str) -> None:
    """Set representative confirmation."""
    await confirm_properties(
        "confirm_set_rep",
        "Set Representative",
        [
            ("Account", account, True),
            ("Representative", representative, True),
        ],
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_set_rep_warning() -> None:
    """WARNING: This delegates your voting power to a representative."""
    await show_danger(
        "confirm_set_rep_warning",
        "WARNING",
        value="This delegates your voting power to a representative",
        br_code=ButtonRequestType.Warning,
    )


async def confirm_set_rep_self_warning() -> None:
    """This delegates voting power to yourself (no change)."""
    await show_warning(
        "confirm_set_rep_self_warning",
        "Set Representative",
        subheader="This delegates voting power to yourself (no change)",
        br_code=ButtonRequestType.Other,
    )


async def confirm_set_info(
    account: str,
    name: str,
    description: str,
    default_permission: str,
    external_perms: str,
    metadata_status: str,
) -> None:
    """Account metadata update confirmation."""
    await confirm_properties(
        "confirm_set_info",
        "Set Account Info",
        [
            ("Account", account, True),
            ("Name", name, False),
            ("Description", description, False),
            ("Default Permission", default_permission, False),
            ("External Permissions", external_perms, False),
            ("Metadata Status", metadata_status, False),
        ],
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_create_identifier_multisig(
    account: str,
    identifier_type: str,
    quorum: int,
    signers: list[str],
) -> None:
    """Multisig identifier creation."""
    await confirm_properties(
        "confirm_create_identifier_multisig",
        "Create Multisig Identifier",
        [
            ("Account", account, True),
            ("Type", identifier_type, False),
            ("Quorum", str(quorum), False),
            ("Signers", f"{len(signers)} signer(s)", False),
        ],
        br_code=ButtonRequestType.ConfirmOutput,
    )

    # Show each signer individually
    for i, signer in enumerate(signers):
        await confirm_text(
            f"multisig_signer_{i}",
            f"Signer #{i + 1}",
            signer,
            br_code=ButtonRequestType.Other,
        )


async def confirm_create_identifier_swap(
    account: str,
    identifier_type: str,
    sell_token: str,
    sell_rate: str,
    buy_token: str,
    buy_rate: str,
    quantity: str,
) -> None:
    """Swap identifier creation."""
    await confirm_properties(
        "confirm_create_identifier_swap",
        "Create Swap Identifier",
        [
            ("Account", account, True),
            ("Type", identifier_type, False),
            ("Sell Token", sell_token, False),
            ("Sell Rate", sell_rate, False),
            ("Buy Token", buy_token, False),
            ("Buy Rate", buy_rate, False),
            ("Quantity", quantity, False),
        ],
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_create_identifier_bare(
    account: str,
    identifier_type: str,
) -> None:
    """Bare identifier creation."""
    await confirm_properties(
        "confirm_create_identifier_bare",
        "Create Identifier",
        [
            ("Account", account, True),
            ("Type", identifier_type, False),
        ],
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_token_admin(
    account: str,
    action: str,
    amount: str,
) -> None:
    """Token admin supply confirmation (mint/burn)."""
    await confirm_properties(
        "confirm_token_admin",
        f"Token Admin: {(action[0].upper() + action[1:]) if action else action}",
        [
            ("Account", account, True),
            ("Action", action, False),
            ("Amount", amount, False),
        ],
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_modify_balance(
    account: str,
    token: str,
    action: str,
    amount: str,
) -> None:
    """Balance modification. For Set: show OVERWRITES entire balance to exact value."""
    if action.lower() == "set":
        await show_danger(
            "confirm_modify_balance_set_warning",
            "OVERWRITES entire balance",
            value=f"Balance will be set to exactly {amount}",
            br_code=ButtonRequestType.Warning,
        )

    await confirm_properties(
        "confirm_modify_balance",
        "Modify Balance",
        [
            ("Account", account, True),
            ("Token", token, True),
            ("Action", action, False),
            ("Amount", amount, False),
        ],
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_modify_permissions(
    account: str,
    principal: str,
    permissions: str,
    target: str | None = None,
) -> None:
    """Permission modification confirmation."""
    props: list[tuple[str, str, bool]] = [
        ("Account", account, True),
        ("Principal", principal, True),
        ("Permissions", permissions, False),
    ]
    if target is not None:
        props.append(("Target", target, True))

    await confirm_properties(
        "confirm_modify_permissions",
        "Modify Permissions",
        props,
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def confirm_network_mismatch(expected: str, actual: str) -> None:
    """Network mismatch warning."""
    await show_danger(
        "confirm_network_mismatch",
        "NETWORK MISMATCH",
        value=f"Expected: {expected}, Actual: {actual}",
        br_code=ButtonRequestType.Warning,
    )

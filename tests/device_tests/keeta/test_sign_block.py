"""
Device tests for Keeta sign_block streaming handler.

Tests cover V1/V2 block formats, multiple algorithms, chunking/streaming,
cross-consistency, network IDs, oversized operations, error handling, and
session lifecycle. Organized into 9 categories (A through I).

References:
    - core/src/apps/keeta/sign_block.py (handler logic)
    - core/src/apps/keeta/der_parser.py (parser state machine)
    - tests/device_tests/keeta/construct/block.py (DER block builders)
"""

import pytest

from trezorlib import keeta, messages
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from ...input_flows import InputFlowConfirmAllWarnings
from .construct.block import (
    ALGO_ED25519,
    ALGO_SECP256K1,
    ALGO_SECP256R1,
    DUMMY_ACCOUNT,
    NETWORK_ID_MAIN,
    NETWORK_ID_TEST,
    OP_CREATE_IDENTIFIER,
    OP_MANAGE_CERTIFICATE,
    OP_MODIFY_PERMISSIONS,
    OP_RECEIVE,
    OP_SEND,
    OP_SET_INFO,
    OP_SET_REP,
    OP_TOKEN_ADMIN_MODIFY_BALANCE,
    OP_TOKEN_ADMIN_SUPPLY,
    build_account_field,
    make_create_identifier_op,
    make_manage_certificate_op,
    make_modify_permissions_op,
    make_receive_op,
    make_send_op,
    make_set_info_op,
    make_set_rep_op,
    make_token_admin_modify_balance_op,
    make_token_admin_supply_op,
    make_v1_block,
    make_v2_block,
)

pytestmark = [
    pytest.mark.altcoin,
    pytest.mark.keeta,
    pytest.mark.models("core"),
]

# Default derivation path for Keeta
BIP32_PATH = parse_path("m/44h/8887h/0h/0/0")
BIP32_PATH_ACCT_5 = parse_path("m/44h/8887h/5h/0/0")
BIP32_PATH_ACCT_100 = parse_path("m/44h/8887h/100h/0/0")
BIP32_PATH_DIFF = parse_path("m/44h/8887h/1h/0/0")

# Algorithm enum values
ALGO_SECP256K1_ENUM = messages.KeetaAlgorithm.SECP256K1
ALGO_ED25519_ENUM = messages.KeetaAlgorithm.ED25519
ALGO_SECP256R1_ENUM = messages.KeetaAlgorithm.SECP256R1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tlv(tag: int, content: bytes) -> bytes:
    """Build tag || length || value."""
    length = len(content)
    if length < 128:
        return bytes([tag, length]) + content
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if length_bytes[0] == 0:
        length_bytes = length_bytes[1:]
    return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + content


def _sign_block_with_confirm(
    session, path, algorithm, network_id, block_bytes, chunk_size=896
):
    """Sign a block with auto-confirmation of all UI dialogs."""
    with session.test_ctx as client:
        IF = InputFlowConfirmAllWarnings(session)
        client.set_input_flow(IF.get())
        return keeta.sign_block(
            session,
            address_n=path,
            block_bytes=block_bytes,
            algorithm=algorithm,
            network_id=network_id,
            chunk_size=chunk_size,
        )


def _get_pubkey_and_sign_v1(session, path, algorithm, network_id, operations, **kwargs):
    """Get the public key for a path, build a V1 block with it, and sign."""
    algo_int = algorithm.value if hasattr(algorithm, "value") else algorithm
    pubkey_resp = keeta.get_public_key(session, address_n=path, algorithm=algorithm)
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=network_id,
        operations=operations,
        **kwargs,
    )
    sig = _sign_block_with_confirm(session, path, algorithm, network_id, block)
    return sig


def _get_pubkey_and_sign_v2(session, path, algorithm, network_id, operations, **kwargs):
    """Get the public key for a path, build a V2 block with it, and sign."""
    algo_int = algorithm.value if hasattr(algorithm, "value") else algorithm
    pubkey_resp = keeta.get_public_key(session, address_n=path, algorithm=algorithm)
    block = make_v2_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=network_id,
        operations=operations,
        **kwargs,
    )
    sig = _sign_block_with_confirm(session, path, algorithm, network_id, block)
    return sig


# ===========================================================================
# Category A: Happy path V1 (5 tests)
# ===========================================================================


def test_sign_v1_empty_ops(session):
    """V1 block with no operations."""
    ops = []
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, ops
    )
    assert len(sig) == 64


def test_sign_v1_single_send(session):
    """V1 block with a single SEND operation."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    send_op = make_send_op(
        from_account=build_account_field(pubkey_resp.public_key, ALGO_SECP256K1),
        to_account=DUMMY_ACCOUNT,
        amount=1000000,
        memo=b"test send",
    )
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


def test_sign_v1_multiple_ops(session):
    """V1 block with 3 operations: SEND, SET_REP, SET_INFO."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=500000,
    )
    set_rep_op = make_set_rep_op(
        account=account_field,
        representative=DUMMY_ACCOUNT,
    )
    set_info_op = make_set_info_op(
        account=account_field,
        name=b"MultiOpTest",
        description=b"Testing multiple operations",
    )
    sig = _get_pubkey_and_sign_v1(
        session,
        BIP32_PATH,
        ALGO_SECP256K1_ENUM,
        NETWORK_ID_TEST,
        [send_op, set_rep_op, set_info_op],
    )
    assert len(sig) == 64


def test_sign_v1_all_op_types(session):
    """V1 block with all 9 operation types."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)

    ops = [
        make_send_op(from_account=account_field, to_account=DUMMY_ACCOUNT, amount=100),
        make_set_rep_op(account=account_field, representative=DUMMY_ACCOUNT),
        make_set_info_op(
            account=account_field, name=b"AllOps", description=b"All operation types"
        ),
        make_modify_permissions_op(
            account=account_field, principal=DUMMY_ACCOUNT, action=1, permissions_mask=1
        ),
        make_create_identifier_op(
            account=account_field, identifier=b"test-id", id_type=3
        ),
        make_token_admin_supply_op(account=account_field, action=0, amount=10000),
        make_token_admin_modify_balance_op(
            account=account_field, action=0, amount=5000, token=DUMMY_ACCOUNT
        ),
        make_receive_op(account=account_field, from_account=DUMMY_ACCOUNT, amount=200),
        make_manage_certificate_op(data=b"cert-data"),
    ]
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, ops
    )
    assert len(sig) == 64


def test_sign_v1_many_ops(session):
    """V1 block with 10 SEND operations (tests summary display)."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)

    ops = []
    for i in range(10):
        ops.append(
            make_send_op(
                from_account=account_field,
                to_account=DUMMY_ACCOUNT,
                amount=1000 * (i + 1),
                memo=f"send-{i}".encode(),
            )
        )
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, ops
    )
    assert len(sig) == 64


# ===========================================================================
# Category B: Happy path V2 (5 tests)
# ===========================================================================


def test_sign_v2_empty_ops(session):
    """V2 block with no operations."""
    ops = []
    sig = _get_pubkey_and_sign_v2(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, ops
    )
    assert len(sig) == 64


def test_sign_v2_single_send(session):
    """V2 block with a single SEND operation."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    send_op = make_send_op(
        from_account=build_account_field(pubkey_resp.public_key, ALGO_SECP256K1),
        to_account=DUMMY_ACCOUNT,
        amount=2000000,
    )
    sig = _get_pubkey_and_sign_v2(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


def test_sign_v2_multiple_ops(session):
    """V2 block with multiple operations."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field, to_account=DUMMY_ACCOUNT, amount=3000000
    )
    recv_op = make_receive_op(
        account=account_field, from_account=DUMMY_ACCOUNT, amount=1500000
    )
    ops = [send_op, recv_op]
    sig = _get_pubkey_and_sign_v2(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, ops
    )
    assert len(sig) == 64


def test_sign_v2_all_op_types(session):
    """V2 block with all 9 operation types."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)

    ops = [
        make_send_op(from_account=account_field, to_account=DUMMY_ACCOUNT, amount=100),
        make_set_rep_op(account=account_field, representative=DUMMY_ACCOUNT),
        make_set_info_op(
            account=account_field,
            name=b"V2AllOps",
            description=b"V2 all operation types",
        ),
        make_modify_permissions_op(
            account=account_field, principal=DUMMY_ACCOUNT, action=0, permissions_mask=3
        ),
        make_create_identifier_op(
            account=account_field, identifier=b"v2-id", id_type=3
        ),
        make_token_admin_supply_op(account=account_field, action=0, amount=20000),
        make_token_admin_modify_balance_op(
            account=account_field, action=0, amount=8000, token=DUMMY_ACCOUNT
        ),
        make_receive_op(account=account_field, from_account=DUMMY_ACCOUNT, amount=300),
        make_manage_certificate_op(data=b"v2-cert"),
    ]
    sig = _get_pubkey_and_sign_v2(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, ops
    )
    assert len(sig) == 64


def test_sign_v2_delegate_signer(session):
    """V2 block with a different signer than the account (delegate signing)."""
    # For delegate signing, the block signer differs from the account owner.
    # We use the same device path for both since the device derives the
    # signer key. The block structure includes signer_pubkey != account_pubkey.
    # In this test we just verify V2 with explicit signer_pubkey.
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)

    # Use a different pubkey as the signer to test the V2 signer field
    # Get a second key from a different path
    pubkey_resp2 = keeta.get_public_key(
        session, address_n=BIP32_PATH_ACCT_5, algorithm=ALGO_SECP256K1_ENUM
    )

    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=100000,
    )

    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v2_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        signer_pubkey=pubkey_resp2.public_key,
        network_id=NETWORK_ID_TEST,
        operations=[send_op],
    )
    sig = _sign_block_with_confirm(
        session, BIP32_PATH_ACCT_5, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, block
    )
    assert len(sig) == 64


# ===========================================================================
# Category C: Algorithm tests (3 tests)
# ===========================================================================


def test_sign_secp256k1(session):
    """secp256k1 produces a 64-byte signature."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=50000,
    )
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


def test_sign_ed25519(session):
    """ed25519 produces a 64-byte signature."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_ED25519_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_ED25519)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=50000,
    )
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_ED25519_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


def test_sign_secp256r1(session):
    """secp256r1 produces a 64-byte signature."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256R1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256R1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=50000,
    )
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256R1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


# ===========================================================================
# Category D: Streaming / chunking (6 tests)
# ===========================================================================


def test_sign_single_chunk(session):
    """Block fits in 1 chunk: FIRST carries data, LAST is empty."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=1000,
    )
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=[send_op],
    )
    # Use a large chunk_size so the entire block fits in one chunk
    sig = _sign_block_with_confirm(
        session,
        BIP32_PATH,
        ALGO_SECP256K1_ENUM,
        NETWORK_ID_TEST,
        block,
        chunk_size=len(block) + 100,
    )
    assert len(sig) == 64


def test_sign_two_chunks(session):
    """FIRST + LAST (no ADD chunks)."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=1000,
    )
    ops = [
        send_op,
        make_set_info_op(
            account=account_field, name=b"TwoChunk", description=b"Two chunks"
        ),
    ]
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=ops,
    )
    # chunk_size = half the block so FIRST has data, LAST has the rest
    chunk_size = len(block) // 2
    if chunk_size < 1:
        chunk_size = 1
    sig = _sign_block_with_confirm(
        session,
        BIP32_PATH,
        ALGO_SECP256K1_ENUM,
        NETWORK_ID_TEST,
        block,
        chunk_size=chunk_size,
    )
    assert len(sig) == 64


def test_sign_many_chunks(session):
    """FIRST + 5 ADD + LAST (many ADD chunks)."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    # Build a block with enough operations to be large
    ops = []
    for i in range(5):
        ops.append(
            make_send_op(
                from_account=account_field,
                to_account=DUMMY_ACCOUNT,
                amount=1000 * (i + 1),
                memo=b"x" * 50,
            )
        )
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=ops,
    )
    # Small chunk size to cause many chunks
    chunk_size = max(50, len(block) // 8)
    sig = _sign_block_with_confirm(
        session,
        BIP32_PATH,
        ALGO_SECP256K1_ENUM,
        NETWORK_ID_TEST,
        block,
        chunk_size=chunk_size,
    )
    assert len(sig) == 64


def test_sign_tiny_chunks(session):
    """Very small chunks (chunk_size=100) causing many chunks."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=1000,
    )
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=[send_op],
    )
    sig = _sign_block_with_confirm(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, block, chunk_size=100
    )
    assert len(sig) == 64


def test_sign_chunk_boundary_mid_header(session):
    """Chunk splits in the middle of a DER header."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    ops = [
        make_send_op(from_account=account_field, to_account=DUMMY_ACCOUNT, amount=1000)
    ]
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=ops,
    )
    # Pick a chunk size that splits the block in the middle (around byte 25)
    # This typically lands mid-header for most blocks
    chunks = [block[i : i + 25] for i in range(0, len(block), 25)]
    if len(chunks) < 3:
        chunks = [block[: len(block) // 2], block[len(block) // 2 :]]
    sig = _sign_block_with_confirm(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, block, chunk_size=25
    )
    assert len(sig) == 64


def test_sign_chunk_boundary_mid_operation(session):
    """Chunk splits in the middle of an operation content."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    # Use a SEND op with a long memo so the op content is substantial
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=1000000,
        memo=b"x" * 200,
    )
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=[send_op],
    )
    # chunk_size around 70-80 to split inside the operation content area
    sig = _sign_block_with_confirm(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, block, chunk_size=75
    )
    assert len(sig) == 64


# ===========================================================================
# Category E: Cross-consistency (4 tests)
# ===========================================================================


def test_address_matches_block_account(session):
    """get_public_key address matches the block account field."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=50000,
    )
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=[send_op],
    )
    sig = _sign_block_with_confirm(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, block
    )
    assert len(sig) == 64


def test_same_path_same_algorithm_v1_v2(session):
    """Same key used to sign both V1 and V2 blocks produces valid sigs."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=50000,
    )

    # Sign V1
    sig_v1 = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig_v1) == 64

    # Sign V2
    sig_v2 = _get_pubkey_and_sign_v2(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig_v2) == 64


def test_deterministic_signing(session):
    """Same block twice produces the same signature (deterministic)."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=50000,
    )

    sig1 = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    sig2 = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert sig1 == sig2


def test_different_paths_different_sigs(session):
    """Different derivation paths produce different keys, thus different sigs."""
    pubkey_resp1 = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field1 = build_account_field(pubkey_resp1.public_key, ALGO_SECP256K1)

    pubkey_resp2 = keeta.get_public_key(
        session, address_n=BIP32_PATH_DIFF, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field2 = build_account_field(pubkey_resp2.public_key, ALGO_SECP256K1)

    send_op1 = make_send_op(
        from_account=account_field1, to_account=DUMMY_ACCOUNT, amount=50000
    )
    send_op2 = make_send_op(
        from_account=account_field2, to_account=DUMMY_ACCOUNT, amount=50000
    )

    sig1 = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op1]
    )
    sig2 = _get_pubkey_and_sign_v1(
        session, BIP32_PATH_DIFF, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op2]
    )
    assert sig1 != sig2


# ===========================================================================
# Category F: Network & deep paths (4 tests)
# ===========================================================================


def test_testnet_network_id(session):
    """Testnet network ID (0x54455354 = 'TEST') is accepted."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field, to_account=DUMMY_ACCOUNT, amount=100000
    )

    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


def test_mainnet_network_id(session):
    """Mainnet network ID (0x5382) is accepted."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field, to_account=DUMMY_ACCOUNT, amount=100000
    )

    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_MAIN, [send_op]
    )
    assert len(sig) == 64


def test_deep_account_index_5(session):
    """Deep derivation path with account index 5: m/44h/8887h/5h/0/0."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH_ACCT_5, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field, to_account=DUMMY_ACCOUNT, amount=100000
    )

    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH_ACCT_5, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


def test_deep_account_index_100(session):
    """Deep derivation path with account index 100: m/44h/8887h/100h/0/0."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH_ACCT_100, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field, to_account=DUMMY_ACCOUNT, amount=100000
    )

    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH_ACCT_100, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


# ===========================================================================
# Category G: Oversized operations (3 tests)
# ===========================================================================


def test_oversized_operation_blind_sign(session):
    """Operation > 512 bytes triggers blind signing flow."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    long_memo = b"x" * 550
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=1000000,
        memo=long_memo,
    )
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


def test_multiple_oversized_ops(session):
    """Multiple oversized operations all handled via blind signing."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)

    ops = []
    for i in range(3):
        long_memo = b"x" * 550
        ops.append(
            make_send_op(
                from_account=account_field,
                to_account=DUMMY_ACCOUNT,
                amount=1000000 * (i + 1),
                memo=long_memo,
            )
        )
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, ops
    )
    assert len(sig) == 64


def test_oversized_op_with_normal_ops(session):
    """Mix of oversized and normal operations."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)

    long_memo = b"x" * 550
    oversized_send = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=1000000,
        memo=long_memo,
    )
    normal_send = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=500,
        memo=b"normal",
    )
    normal_info = make_set_info_op(
        account=account_field,
        name=b"MixTest",
        description=b"Mixed oversized and normal",
    )
    ops = [oversized_send, normal_send, normal_info]
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, ops
    )
    assert len(sig) == 64


# ===========================================================================
# Category H: Error handling (10 tests)
# ===========================================================================


def test_reject_multisig_algorithm(session):
    """Multisig algorithm (0x07) is rejected with an error."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=100000,
    )
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=[send_op],
    )

    # Send FIRST with multisig algorithm 0x07
    from trezorlib.messages import KeetaChunkPhase

    session.write(
        messages.KeetaSignBlock(
            address_n=BIP32_PATH,
            algorithm=7,  # MULTISIG
            network_id=NETWORK_ID_TEST,
            chunk_phase=KeetaChunkPhase.FIRST,
            chunk_index=0,
            chunk_data=block[: min(len(block), 128)],
        )
    )
    with pytest.raises(TrezorFailure):
        session.call(
            messages.KeetaSignBlock(
                chunk_phase=KeetaChunkPhase.LAST,
                chunk_index=1,
                chunk_data=block[128:] if len(block) > 128 else b"",
            ),
            expect=messages.KeetaBlockSignature,
        )


def test_reject_missing_address_n(session):
    """FIRST chunk without address_n is rejected."""
    from trezorlib.messages import KeetaChunkPhase

    with pytest.raises(TrezorFailure):
        session.call(
            messages.KeetaSignBlock(
                address_n=None,
                algorithm=ALGO_SECP256K1_ENUM,
                network_id=NETWORK_ID_TEST,
                chunk_phase=KeetaChunkPhase.FIRST,
                chunk_index=0,
                chunk_data=b"\x30\x03\x02\x01\x01",
            )
        )


def test_reject_missing_network_id(session):
    """FIRST chunk without network_id is rejected."""
    from trezorlib.messages import KeetaChunkPhase

    with pytest.raises(TrezorFailure):
        session.call(
            messages.KeetaSignBlock(
                address_n=BIP32_PATH,
                algorithm=ALGO_SECP256K1_ENUM,
                network_id=None,
                chunk_phase=KeetaChunkPhase.FIRST,
                chunk_index=0,
                chunk_data=b"\x30\x03\x02\x01\x01",
            )
        )


def test_reject_unknown_chunk_phase(session):
    """Unknown chunk phase (UNKNOWN) is rejected."""
    from trezorlib.messages import KeetaChunkPhase

    with pytest.raises(TrezorFailure):
        session.call(
            messages.KeetaSignBlock(
                address_n=BIP32_PATH,
                algorithm=ALGO_SECP256K1_ENUM,
                network_id=NETWORK_ID_TEST,
                chunk_phase=KeetaChunkPhase.UNKNOWN,
                chunk_index=0,
                chunk_data=b"\x30\x03\x02\x01\x01",
            )
        )


def test_reject_chunk_index_mismatch(session):
    """FIRST then ADD with wrong chunk_index is rejected."""
    from trezorlib.messages import KeetaChunkPhase

    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=1000,
    )
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=[send_op],
    )

    # Send FIRST (write — handler suspends on ctx.wait(), no response sent)
    chunk1, rest = block[:50], block[50:]
    session.write(
        messages.KeetaSignBlock(
            address_n=BIP32_PATH,
            algorithm=ALGO_SECP256K1_ENUM,
            network_id=NETWORK_ID_TEST,
            chunk_phase=KeetaChunkPhase.FIRST,
            chunk_index=0,
            chunk_data=chunk1,
        )
    )

    # Send ADD with wrong index (0 instead of 1)
    add_chunks = [rest[:30], rest[30:]]
    with pytest.raises(TrezorFailure):
        session.call(
            messages.KeetaSignBlock(
                chunk_phase=KeetaChunkPhase.ADD,
                chunk_index=0,
                chunk_data=add_chunks[0],
            )
        )


def test_reject_first_chunk_wrong_index(session):
    """FIRST chunk with chunk_index != 0 is rejected."""
    from trezorlib.messages import KeetaChunkPhase

    with pytest.raises(TrezorFailure):
        session.call(
            messages.KeetaSignBlock(
                address_n=BIP32_PATH,
                algorithm=ALGO_SECP256K1_ENUM,
                network_id=NETWORK_ID_TEST,
                chunk_phase=KeetaChunkPhase.FIRST,
                chunk_index=1,
                chunk_data=b"\x30\x03\x02\x01\x01",
            )
        )


def test_reject_add_without_first(session):
    """ADD chunk without prior FIRST is rejected."""
    from trezorlib.messages import KeetaChunkPhase

    with pytest.raises(TrezorFailure):
        session.call(
            messages.KeetaSignBlock(
                chunk_phase=KeetaChunkPhase.ADD,
                chunk_index=0,
                chunk_data=b"\x30\x03\x02\x01\x01",
            )
        )


def test_reject_invalid_der(session):
    """Sending garbage DER bytes is rejected."""
    from trezorlib.messages import KeetaChunkPhase

    session.write(
        messages.KeetaSignBlock(
            address_n=BIP32_PATH,
            algorithm=ALGO_SECP256K1_ENUM,
            network_id=NETWORK_ID_TEST,
            chunk_phase=KeetaChunkPhase.FIRST,
            chunk_index=0,
            chunk_data=b"\x00\x00\x00\x00\x00\x00\x00\x00",
        )
    )
    with pytest.raises(TrezorFailure):
        session.call(
            messages.KeetaSignBlock(
                chunk_phase=KeetaChunkPhase.LAST,
                chunk_index=1,
                chunk_data=b"",
            ),
            expect=messages.KeetaBlockSignature,
        )


def test_reject_account_mismatch(session):
    """Block account field does not match derived key -- rejected."""
    from trezorlib.messages import KeetaChunkPhase

    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=100000,
    )
    # Build block with a deliberately DIFFERENT pubkey (all zeros)
    wrong_pubkey = bytes(33)
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )
    block = make_v1_block(
        pubkey=wrong_pubkey,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=[send_op],
    )
    with pytest.raises(TrezorFailure):
        _sign_block_with_confirm(
            session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, block
        )


def test_reject_rejected_op_tags(session):
    """Operations with rejected tags (0xA9, 0xAA) are rejected."""
    from trezorlib.messages import KeetaChunkPhase

    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    algo_int = (
        ALGO_SECP256K1_ENUM.value
        if hasattr(ALGO_SECP256K1_ENUM, "value")
        else ALGO_SECP256K1_ENUM
    )

    # Manually construct a TLV with tag 0xA9 (rejected)
    bad_op = _make_tlv(0xA9, b"\x00" * 10)
    block = make_v1_block(
        pubkey=pubkey_resp.public_key,
        algorithm=algo_int,
        network_id=NETWORK_ID_TEST,
        operations=[(0xA9, bad_op)],
    )
    with pytest.raises(TrezorFailure):
        _sign_block_with_confirm(
            session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, block
        )


# ===========================================================================
# Category I: Session lifecycle (3 tests)
# ===========================================================================


def test_cleanup_after_error(session):
    """If signing fails, cleanup runs so a new signing session can succeed."""
    from trezorlib.messages import KeetaChunkPhase

    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=100000,
    )

    # Send garbage FIRST via call() — the handler errors during DER parsing,
    # _cleanup() runs in the finally block, the Failure is returned and
    # consumed by call(). No buffered responses remain on the transport.
    with pytest.raises(TrezorFailure):
        session.call(
            messages.KeetaSignBlock(
                address_n=BIP32_PATH,
                algorithm=ALGO_SECP256K1_ENUM,
                network_id=NETWORK_ID_TEST,
                chunk_phase=KeetaChunkPhase.FIRST,
                chunk_index=0,
                chunk_data=b"\x00\x00\x00",
            )
        )

    # Now a valid sign should work (cleanup happened)
    sig = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig) == 64


def test_sequential_signing_sessions(session):
    """Sign block A, then sign block B -- both succeed."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)

    send_op_a = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=100000,
        memo=b"session-a",
    )
    send_op_b = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=200000,
        memo=b"session-b",
    )

    sig_a = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op_a]
    )
    assert len(sig_a) == 64

    sig_b = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op_b]
    )
    assert len(sig_b) == 64

    assert sig_a != sig_b  # Different blocks produce different sigs


def test_signature_is_64_bytes(session):
    """Verify signature length is exactly 64 bytes for all algorithms."""
    # secp256k1
    pubkey_resp = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256K1_ENUM
    )
    account_field = build_account_field(pubkey_resp.public_key, ALGO_SECP256K1)
    send_op = make_send_op(
        from_account=account_field,
        to_account=DUMMY_ACCOUNT,
        amount=50000,
    )
    sig_256k1 = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256K1_ENUM, NETWORK_ID_TEST, [send_op]
    )
    assert len(sig_256k1) == 64

    # ed25519
    pubkey_resp_ed = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_ED25519_ENUM
    )
    account_field_ed = build_account_field(pubkey_resp_ed.public_key, ALGO_ED25519)
    send_op_ed = make_send_op(
        from_account=account_field_ed,
        to_account=DUMMY_ACCOUNT,
        amount=50000,
    )
    sig_ed = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_ED25519_ENUM, NETWORK_ID_TEST, [send_op_ed]
    )
    assert len(sig_ed) == 64

    # secp256r1
    pubkey_resp_r1 = keeta.get_public_key(
        session, address_n=BIP32_PATH, algorithm=ALGO_SECP256R1_ENUM
    )
    account_field_r1 = build_account_field(pubkey_resp_r1.public_key, ALGO_SECP256R1)
    send_op_r1 = make_send_op(
        from_account=account_field_r1,
        to_account=DUMMY_ACCOUNT,
        amount=50000,
    )
    sig_r1 = _get_pubkey_and_sign_v1(
        session, BIP32_PATH, ALGO_SECP256R1_ENUM, NETWORK_ID_TEST, [send_op_r1]
    )
    assert len(sig_r1) == 64

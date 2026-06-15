"""DER block construction helpers for Keeta device tests.

Builds valid V1 and V2 DER-encoded Keeta blocks for the sign_block
streaming handler. Pure Python -- no device or trezorlib dependencies.

Reference: core/src/apps/keeta/der_parser.py (parser state machine)
           core/src/apps/keeta/operations.py (sub-TLV structures)
"""

from typing import List, Optional, Tuple

# Algorithm prefix bytes
ALGO_SECP256K1 = 0x00
ALGO_ED25519 = 0x01
ALGO_SECP256R1 = 0x06

# Operation tags
OP_SEND = 0xA0
OP_SET_REP = 0xA1
OP_SET_INFO = 0xA2
OP_MODIFY_PERMISSIONS = 0xA3
OP_CREATE_IDENTIFIER = 0xA4
OP_TOKEN_ADMIN_SUPPLY = 0xA5
OP_TOKEN_ADMIN_MODIFY_BALANCE = 0xA6
OP_RECEIVE = 0xA7
OP_MANAGE_CERTIFICATE = 0xA8

# DER tags
TAG_SEQUENCE = 0x30
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_UTF8_STRING = 0x0C
TAG_GENERALIZED_TIME = 0x18
TAG_CONTEXT_1 = 0xA1

# Network IDs
NETWORK_ID_TEST = 0x54455354  # "TEST"
NETWORK_ID_MAIN = 0x5382

DUMMY_ACCOUNT = bytes([0x00]) + bytes([0x02]) + bytes(32)  # 1 algo byte + 33 compressed pubkey = 34 bytes


def _encode_der_length(length: int) -> bytes:
    """Encode DER length. Short (<128): single byte. Long: 0x8N || N-byte big-endian."""
    if length < 128:
        return bytes([length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if length_bytes[0] == 0:
        length_bytes = length_bytes[1:]
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def _make_tlv(tag: int, content: bytes) -> bytes:
    """Build tag || length || value."""
    return bytes([tag]) + _encode_der_length(len(content)) + content


def build_account_field(pubkey: bytes, algorithm: int) -> bytes:
    """Return algo_byte || pubkey."""
    return bytes([algorithm]) + pubkey


def make_v1_block(
    pubkey: bytes,
    algorithm: int,
    *,
    network_id: int = 0x54455354,
    version: int = 1,
    date: bytes = b"20250101000000Z",
    purpose: bytes = b"test",
    prev_hash: Optional[bytes] = None,
    operations: Optional[List[Tuple[int, bytes]]] = None,
) -> bytes:
    """
    Build V1 DER block:
    30 <len>
      02 01 <version>
      04 <len> <network_id_be>       # 4-byte big-endian network ID
      04 <len> <algo||pubkey>        # account OCTET STRING
      18 <len> <date>                # GeneralizedTime
      0C <len> <purpose>             # UTF8String (if non-empty)
      04 20 <prev_hash>              # OCTET STRING (32 bytes, zeros if None)
      30 <ops_len>                   # operations SEQUENCE
        <op_tlvs concatenated>
      03 41 00<64_zero_bytes>        # BIT STRING placeholder
    """
    fields: list[bytes] = []
    # version
    fields.append(_make_tlv(TAG_INTEGER, bytes([version])))
    # network_id as 4-byte big-endian OCTET STRING
    net_bytes = network_id.to_bytes(4, "big")
    fields.append(_make_tlv(TAG_OCTET_STRING, net_bytes))
    # account: algo_byte + pubkey
    fields.append(_make_tlv(TAG_OCTET_STRING, build_account_field(pubkey, algorithm)))
    # date (GeneralizedTime)
    fields.append(_make_tlv(TAG_GENERALIZED_TIME, date))
    # purpose (UTF8String)
    if purpose:
        fields.append(_make_tlv(TAG_UTF8_STRING, purpose))
    # prev_hash (OCTET STRING, 32 bytes)
    if prev_hash is None:
        prev_hash = bytes(32)
    fields.append(_make_tlv(TAG_OCTET_STRING, prev_hash))
    # operations SEQUENCE
    ops_content = b"".join(op_tlv for _tag, op_tlv in (operations or []))
    fields.append(_make_tlv(TAG_SEQUENCE, ops_content))
    # signature BIT STRING placeholder (unused bits=0, 64 zero bytes)
    fields.append(_make_tlv(TAG_BIT_STRING, b"\x00" + bytes(64)))

    content = b"".join(fields)
    return _make_tlv(TAG_SEQUENCE, content)


def make_v2_block(
    pubkey: bytes,
    algorithm: int,
    *,
    signer_pubkey: Optional[bytes] = None,
    network_id: int = 0x54455354,
    date: bytes = b"20250101000000Z",
    purpose: bytes = b"test",
    operations: Optional[List[Tuple[int, bytes]]] = None,
) -> bytes:
    """
    Build V2 DER block:
    A1 <wrapper_len>
      30 <inner_len>
        04 <len> <algo||pubkey>      # account
        04 <len> <algo||signer>      # signer
        02 04 <network_id_be>        # INTEGER (4 bytes)
        18 <len> <date>              # GeneralizedTime
        0C <len> <purpose>           # UTF8String
        30 <ops_len>                 # operations SEQUENCE
          <op_tlvs>
      30 <sigs_len>
        03 41 00<64_zero_bytes>      # BIT STRING
    """
    inner_fields: list[bytes] = []
    # account
    inner_fields.append(
        _make_tlv(TAG_OCTET_STRING, build_account_field(pubkey, algorithm))
    )
    # signer
    signer = signer_pubkey if signer_pubkey is not None else pubkey
    inner_fields.append(
        _make_tlv(TAG_OCTET_STRING, build_account_field(signer, algorithm))
    )
    # network_id as INTEGER (4 bytes big-endian)
    net_bytes = network_id.to_bytes(4, "big")
    inner_fields.append(_make_tlv(TAG_INTEGER, net_bytes))
    # date
    inner_fields.append(_make_tlv(TAG_GENERALIZED_TIME, date))
    # purpose
    if purpose:
        inner_fields.append(_make_tlv(TAG_UTF8_STRING, purpose))
    # operations SEQUENCE
    ops_content = b"".join(op_tlv for _tag, op_tlv in (operations or []))
    inner_fields.append(_make_tlv(TAG_SEQUENCE, ops_content))

    inner_content = b"".join(inner_fields)
    inner_sequence = _make_tlv(TAG_SEQUENCE, inner_content)

    # signatures SEQUENCE with BIT STRING placeholder
    sig_placeholder = _make_tlv(TAG_BIT_STRING, b"\x00" + bytes(64))
    sigs_sequence = _make_tlv(TAG_SEQUENCE, sig_placeholder)

    wrapper_content = inner_sequence + sigs_sequence
    return _make_tlv(TAG_CONTEXT_1, wrapper_content)


def make_send_op(
    from_account: Optional[bytes] = None,
    to_account: Optional[bytes] = None,
    amount: int = 1000000,
    token: Optional[bytes] = None,
    memo: bytes = b"",
) -> tuple[int, bytes]:
    """SEND (0xA0). Sub-TLVs: [0]=from, [1]=to, [2]=amount, [3]=token?, [4]=memo?"""
    children: list[bytes] = []
    if from_account is not None:
        children.append(_make_tlv(0x80, from_account))
    if to_account is not None:
        children.append(_make_tlv(0x81, to_account))
    amount_bytes = amount.to_bytes((amount.bit_length() + 7) // 8 or 1, "big")
    children.append(_make_tlv(0x82, amount_bytes))
    if token is not None:
        children.append(_make_tlv(0x83, token))
    if memo:
        children.append(_make_tlv(0x84, memo))
    tag = OP_SEND
    return tag, _make_tlv(tag, b"".join(children))


def make_set_rep_op(
    account: Optional[bytes] = None,
    representative: Optional[bytes] = None,
) -> tuple[int, bytes]:
    """SET_REP (0xA1). [0]=account, [1]=representative."""
    children: list[bytes] = []
    if account is not None:
        children.append(_make_tlv(0x80, account))
    if representative is not None:
        children.append(_make_tlv(0x81, representative))
    tag = OP_SET_REP
    return tag, _make_tlv(tag, b"".join(children))


def make_set_info_op(
    account: Optional[bytes] = None,
    name: bytes = b"TestAccount",
    description: bytes = b"Test description",
    default_permission: int = 0,
    external_perms: bytes = b"",
    metadata: bytes = b"",
) -> tuple[int, bytes]:
    """SET_INFO (0xA2). [0]=account, [1]=name, [2]=description, [3]=defaultPermission, [4]=externalPerms, [5]=metadata."""
    children: list[bytes] = []
    if account is not None:
        children.append(_make_tlv(0x80, account))
    if name:
        children.append(_make_tlv(0x81, name))
    if description:
        children.append(_make_tlv(0x82, description))
    children.append(_make_tlv(0x83, bytes([default_permission & 0xFF])))
    if external_perms:
        children.append(_make_tlv(0x84, external_perms))
    if metadata:
        children.append(_make_tlv(0x85, metadata))
    tag = OP_SET_INFO
    return tag, _make_tlv(tag, b"".join(children))


def make_modify_permissions_op(
    account: Optional[bytes] = None,
    principal: Optional[bytes] = None,
    action: int = 1,  # 0=Add, 1=Subtract, 2=Set
    permissions_mask: int = 1,
    target: Optional[bytes] = None,
) -> tuple[int, bytes]:
    """MODIFY_PERMISSIONS (0xA3). [0]=account, [1]=principal, [2]=action, [3]=permissions, [4]=target?"""
    children: list[bytes] = []
    if account is not None:
        children.append(_make_tlv(0x80, account))
    if principal is not None:
        children.append(_make_tlv(0x81, principal))
    children.append(_make_tlv(0x82, bytes([action & 0xFF])))
    perm_bytes = permissions_mask.to_bytes(
        (permissions_mask.bit_length() + 7) // 8 or 1, "big"
    )
    children.append(_make_tlv(0x83, perm_bytes))
    if target is not None:
        children.append(_make_tlv(0x84, target))
    tag = OP_MODIFY_PERMISSIONS
    return tag, _make_tlv(tag, b"".join(children))


def make_create_identifier_op(
    account: Optional[bytes] = None,
    identifier: bytes = b"test-id",
    id_type: int = 1,  # CORRECTED: 1=Multisig, 2=Swap, 3=Bare
    # Multisig fields (id_type=1)
    quorum: int = 2,
    participants: Optional[list[bytes]] = None,
    # Swap fields (id_type=2)
    sell_token: Optional[bytes] = None,
    sell_rate: int = 0,
    buy_token: Optional[bytes] = None,
    buy_rate: int = 0,
    quantity: int = 0,
) -> tuple[int, bytes]:
    """CREATE_IDENTIFIER (0xA4). Type: 1=Multisig, 2=Swap, 3=Bare."""
    children: list[bytes] = []
    if account is not None:
        children.append(_make_tlv(0x80, account))
    children.append(_make_tlv(0x81, identifier))
    children.append(_make_tlv(0x82, bytes([id_type & 0xFF])))
    if id_type == 1:  # Multisig
        children.append(_make_tlv(0x83, bytes([quorum & 0xFF])))
        for i, participant in enumerate(participants or []):
            children.append(_make_tlv(0x84 + i, participant))
    elif id_type == 2:  # Swap
        if sell_token is not None:
            children.append(_make_tlv(0x83, sell_token))
        rate_bytes = sell_rate.to_bytes((sell_rate.bit_length() + 7) // 8 or 1, "big")
        children.append(_make_tlv(0x84, rate_bytes))
        if buy_token is not None:
            children.append(_make_tlv(0x85, buy_token))
        rate_bytes = buy_rate.to_bytes((buy_rate.bit_length() + 7) // 8 or 1, "big")
        children.append(_make_tlv(0x86, rate_bytes))
        qty_bytes = quantity.to_bytes((quantity.bit_length() + 7) // 8 or 1, "big")
        children.append(_make_tlv(0x87, qty_bytes))
    tag = OP_CREATE_IDENTIFIER
    return tag, _make_tlv(tag, b"".join(children))


def make_token_admin_supply_op(
    account: Optional[bytes] = None,
    action: int = 0,  # 0=Mint, 1=Burn, 2=Set
    amount: int = 1000000,
    token: Optional[bytes] = None,
) -> tuple[int, bytes]:
    """TOKEN_ADMIN_SUPPLY (0xA5). [0]=account, [1]=action, [2]=amount, [3]=token?"""
    children: list[bytes] = []
    if account is not None:
        children.append(_make_tlv(0x80, account))
    children.append(_make_tlv(0x81, bytes([action & 0xFF])))
    amount_bytes = amount.to_bytes((amount.bit_length() + 7) // 8 or 1, "big")
    children.append(_make_tlv(0x82, amount_bytes))
    if token is not None:
        children.append(_make_tlv(0x83, token))
    tag = OP_TOKEN_ADMIN_SUPPLY
    return tag, _make_tlv(tag, b"".join(children))


def make_token_admin_modify_balance_op(
    account: Optional[bytes] = None,
    token: Optional[bytes] = None,
    action: int = 0,  # 0=Add, 1=Subtract, 2=Set
    amount: int = 1000000,
) -> tuple[int, bytes]:
    """TOKEN_ADMIN_MODIFY_BALANCE (0xA6). [0]=account, [1]=token, [2]=action, [3]=amount."""
    children: list[bytes] = []
    if account is not None:
        children.append(_make_tlv(0x80, account))
    if token is not None:
        children.append(_make_tlv(0x81, token))
    children.append(_make_tlv(0x82, bytes([action & 0xFF])))
    amount_bytes = amount.to_bytes((amount.bit_length() + 7) // 8 or 1, "big")
    children.append(_make_tlv(0x83, amount_bytes))
    tag = OP_TOKEN_ADMIN_MODIFY_BALANCE
    return tag, _make_tlv(tag, b"".join(children))


def make_receive_op(
    account: Optional[bytes] = None,
    from_account: Optional[bytes] = None,
    amount: int = 1000000,
    token: Optional[bytes] = None,
    exact_match: bool = False,
    forward_to: Optional[bytes] = None,
) -> tuple[int, bytes]:
    """RECEIVE (0xA7). [0]=account, [1]=from, [2]=amount, [3]=token?, [4]=exact_match?, [5]=forward_to?"""
    children: list[bytes] = []
    if account is not None:
        children.append(_make_tlv(0x80, account))
    if from_account is not None:
        children.append(_make_tlv(0x81, from_account))
    amount_bytes = amount.to_bytes((amount.bit_length() + 7) // 8 or 1, "big")
    children.append(_make_tlv(0x82, amount_bytes))
    if token is not None:
        children.append(_make_tlv(0x83, token))
    if exact_match:
        children.append(_make_tlv(0x84, b"\xff"))
    if forward_to is not None:
        children.append(_make_tlv(0x85, forward_to))
    tag = OP_RECEIVE
    return tag, _make_tlv(tag, b"".join(children))


def make_manage_certificate_op(
    data: bytes = b"certificate-data",
) -> tuple[int, bytes]:
    """MANAGE_CERTIFICATE (0xA8). Blind-sign operation -- wraps content as opaque blob."""
    tag = OP_MANAGE_CERTIFICATE
    return tag, _make_tlv(tag, data)

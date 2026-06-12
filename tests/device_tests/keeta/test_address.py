# This file is part of the Trezor project.
#
# Copyright (C) 2012-2025 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

"""Device tests for KeetaGetAddress."""

import pytest

from trezorlib import keeta, messages
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

pytestmark = [pytest.mark.altcoin, pytest.mark.models("core")]

PATH = parse_path("m/44h/8887h/0h/0/0")
PATH_ACCOUNT_5 = parse_path("m/44h/8887h/5h/0/0")


def test_get_address_secp256k1(session: Session):
    """Basic secp256k1 address with 32-byte MAC."""
    resp = keeta.get_authenticated_address(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    assert isinstance(resp.address, str)
    assert resp.address.startswith("keeta_")
    assert isinstance(resp.mac, bytes)
    assert len(resp.mac) == 32


def test_get_address_ed25519(session: Session):
    """ed25519 address with MAC."""
    resp = keeta.get_authenticated_address(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.ED25519
    )
    assert resp.address.startswith("keeta_")
    assert len(resp.mac) == 32


def test_get_address_secp256r1(session: Session):
    """secp256r1 address with MAC."""
    resp = keeta.get_authenticated_address(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256R1
    )
    assert resp.address.startswith("keeta_")
    assert len(resp.mac) == 32


def test_get_address_default_algorithm(session: Session):
    """Default algorithm is secp256k1."""
    resp = keeta.get_authenticated_address(session, address_n=PATH)
    assert resp.address.startswith("keeta_")
    assert len(resp.mac) == 32


def test_get_address_string_convenience(session: Session):
    """get_address() convenience wrapper returns string."""
    addr = keeta.get_address(session, address_n=PATH)
    assert isinstance(addr, str)
    assert addr.startswith("keeta_")


def test_get_address_deterministic(session: Session):
    """Same path + algorithm returns same address and MAC."""
    resp1 = keeta.get_authenticated_address(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    resp2 = keeta.get_authenticated_address(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    assert resp1.address == resp2.address
    assert resp1.mac == resp2.mac


def test_get_address_different_paths(session: Session):
    """Different paths produce different addresses and MACs."""
    resp1 = keeta.get_authenticated_address(session, address_n=PATH)
    resp2 = keeta.get_authenticated_address(session, address_n=PATH_ACCOUNT_5)
    assert resp1.address != resp2.address
    assert resp1.mac != resp2.mac


def test_get_address_different_algorithms(session: Session):
    """Same path, different algorithms -- different addresses and MACs."""
    resp_secp = keeta.get_authenticated_address(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    resp_ed = keeta.get_authenticated_address(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.ED25519
    )
    assert resp_secp.address != resp_ed.address
    assert resp_secp.mac != resp_ed.mac


def test_get_address_with_display(session: Session):
    """show_display=True succeeds with UI confirmation."""
    from ...input_flows import InputFlowConfirmAllWarnings

    with session.test_ctx as client:
        IF = InputFlowConfirmAllWarnings(session)
        client.set_input_flow(IF.get())
        resp = keeta.get_authenticated_address(
            session, address_n=PATH, show_display=True
        )
    assert resp.address.startswith("keeta_")
    assert len(resp.mac) == 32


def test_get_address_chunkify(session: Session):
    """chunkify=True succeeds."""
    resp = keeta.get_authenticated_address(session, address_n=PATH, chunkify=True)
    assert resp.address.startswith("keeta_")
    assert len(resp.mac) == 32


def test_get_address_matches_get_public_key(session: Session):
    """get_address() and get_public_key() return same address for same params."""
    pubkey_resp = keeta.get_public_key(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    addr_resp = keeta.get_authenticated_address(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    assert pubkey_resp.address == addr_resp.address

    # Also test ed25519
    pubkey_resp2 = keeta.get_public_key(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.ED25519
    )
    addr_resp2 = keeta.get_authenticated_address(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.ED25519
    )
    assert pubkey_resp2.address == addr_resp2.address


def test_get_address_invalid_path(session: Session):
    """Wrong coin_type raises TrezorFailure."""
    bad_path = parse_path("m/44h/0h/0h/0/0")
    with pytest.raises(TrezorFailure):
        keeta.get_authenticated_address(session, address_n=bad_path)


def test_get_address_multisig_rejected(session: Session):
    """MULTISIG algorithm is rejected."""
    with pytest.raises(TrezorFailure):
        keeta.get_authenticated_address(
            session,
            address_n=PATH,
            algorithm=messages.KeetaAlgorithm.MULTISIG,
        )

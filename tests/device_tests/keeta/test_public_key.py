# This file is part of the Trezor project.
#
# Copyright (C) 2012-2023 SatoshiLabs and contributors
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

"""Device tests for KeetaGetPublicKey."""

import pytest

from trezorlib import keeta, messages
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

pytestmark = [pytest.mark.altcoin, pytest.mark.models("core")]

# Standard test paths
PATH = parse_path("m/44h/8887h/0h/0/0")
PATH_ACCOUNT_5 = parse_path("m/44h/8887h/5h/0/0")


def test_get_public_key_secp256k1(session: Session):
    """Basic secp256k1: returns 33-byte compressed pubkey + keeta_ address."""
    resp = keeta.get_public_key(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    assert isinstance(resp.public_key, bytes)
    assert len(resp.public_key) == 33
    assert resp.public_key[0] in (0x02, 0x03)
    assert isinstance(resp.address, str)
    assert resp.address.startswith("keeta_")


def test_get_public_key_ed25519(session: Session):
    """ed25519: returns 32-byte pubkey + keeta_ address."""
    resp = keeta.get_public_key(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.ED25519
    )
    assert isinstance(resp.public_key, bytes)
    assert len(resp.public_key) == 32
    assert isinstance(resp.address, str)
    assert resp.address.startswith("keeta_")


def test_get_public_key_secp256r1(session: Session):
    """secp256r1: returns 33-byte compressed pubkey + keeta_ address."""
    resp = keeta.get_public_key(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256R1
    )
    assert isinstance(resp.public_key, bytes)
    assert len(resp.public_key) == 33
    assert resp.public_key[0] in (0x02, 0x03)
    assert resp.address.startswith("keeta_")


def test_get_public_key_default_algorithm(session: Session):
    """Omitting algorithm defaults to secp256k1."""
    resp = keeta.get_public_key(session, address_n=PATH)
    assert len(resp.public_key) == 33
    assert resp.address.startswith("keeta_")


def test_get_public_key_deterministic(session: Session):
    """Same path + algorithm returns same pubkey and address."""
    resp1 = keeta.get_public_key(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    resp2 = keeta.get_public_key(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    assert resp1.public_key == resp2.public_key
    assert resp1.address == resp2.address


def test_get_public_key_different_paths(session: Session):
    """Different BIP-32 paths produce different pubkeys."""
    resp1 = keeta.get_public_key(session, address_n=PATH)
    resp2 = keeta.get_public_key(session, address_n=PATH_ACCOUNT_5)
    assert resp1.public_key != resp2.public_key
    assert resp1.address != resp2.address


def test_get_public_key_different_algorithms(session: Session):
    """Same path, different algorithms produce different pubkeys."""
    resp_secp = keeta.get_public_key(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.SECP256K1
    )
    resp_ed = keeta.get_public_key(
        session, address_n=PATH, algorithm=messages.KeetaAlgorithm.ED25519
    )
    assert resp_secp.public_key != resp_ed.public_key
    assert resp_secp.address != resp_ed.address


def test_get_public_key_with_display(session: Session):
    """show_display=True succeeds (UI confirmation via InputFlow)."""
    from ...input_flows import InputFlowConfirmAllWarnings

    with session.test_ctx as client:
        IF = InputFlowConfirmAllWarnings(session)
        client.set_input_flow(IF.get())
        resp = keeta.get_public_key(session, address_n=PATH, show_display=True)
    assert resp.address.startswith("keeta_")
    assert len(resp.public_key) == 33


def test_get_public_key_invalid_path(session: Session):
    """Wrong coin_type path raises TrezorFailure."""
    bad_path = parse_path("m/44h/0h/0h/0/0")  # Bitcoin coin_type
    with pytest.raises(TrezorFailure):
        keeta.get_public_key(session, address_n=bad_path)


def test_get_public_key_multisig_rejected(session: Session):
    """MULTISIG algorithm (0x07) is rejected."""
    with pytest.raises(TrezorFailure):
        keeta.get_public_key(
            session, address_n=PATH, algorithm=messages.KeetaAlgorithm.MULTISIG
        )


def test_get_public_key_secp256r1_with_display(session: Session):
    """secp256r1 with display enabled works."""
    from ...input_flows import InputFlowConfirmAllWarnings

    with session.test_ctx as client:
        IF = InputFlowConfirmAllWarnings(session)
        client.set_input_flow(IF.get())
        resp = keeta.get_public_key(
            session,
            address_n=PATH,
            algorithm=messages.KeetaAlgorithm.SECP256R1,
            show_display=True,
        )
    assert len(resp.public_key) == 33
    assert resp.address.startswith("keeta_")

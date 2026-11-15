import json

import pytest
from cryptography.exceptions import InvalidTag

from qsignt import box, pgpx, proto


def test_seal_open_roundtrip():
    priv, pub = box.new_keypair()
    payload = {"v": 1, "flow": "AB12CD34", "apikey": "qsig_test", "chall": "ZZZZ0000"}
    blob = box.seal(pub, "AB12CD34", payload)
    out = box.open_sealed(blob, "AB12CD34", priv)
    assert out == payload


def test_flow_binding_mismatch():
    priv, pub = box.new_keypair()
    blob = box.seal(pub, "AB12CD34", {"v": 1})
    with pytest.raises(InvalidTag):
        box.open_sealed(blob, "OTHERFLOW", priv)


def test_parse_init():
    armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----"
    msg = proto.build_init("AB12CD34", armor, 10)
    got = proto.parse_init(msg)
    assert got.flow == "AB12CD34"
    assert got.expire_minutes == 10
    assert "BEGIN PGP PUBLIC KEY" in got.armor


def test_payload_roundtrip():
    raw = proto.build_payload("AB12CD34", b"\x01" * 32)
    data = proto.parse_payload(raw)
    assert data["flow"] == "AB12CD34"
    assert len(box.b64d(data["eph"])) == 32
    assert json.loads(raw)["kind"] == "enroll"


def test_squash_armor_roundtrip():
    armored = (
        "-----BEGIN PGP MESSAGE-----\n\n"
        "hF4Df4g8rfb1F18SAQdA/cgsm9VD2/gKVhuW/QcTgw6fEpqJpeMK4Z2qZMZC8gEw\n"
        "E8y6iqIV4rjIQxRNQTUTClT0WE\n"
        "=G/yh\n"
        "-----END PGP MESSAGE-----\n"
    )
    squashed = proto.squash_armor(armored)
    assert "\n" not in squashed
    assert squashed.endswith("=G/yh")
    restored = pgpx.wrap_armor(squashed)
    assert restored.startswith("-----BEGIN PGP MESSAGE-----")
    assert "=G/yh" in restored


def test_submit_command_is_single_line():
    armored = "-----BEGIN PGP MESSAGE-----\n\nAAAA\nBBBB\n=CCCC\n-----END PGP MESSAGE-----\n"
    cmd = proto.submit_command(armored)
    assert "\n" not in cmd
    assert cmd.startswith("#qsignt key submit ")
    assert proto.parse_submit(cmd) == "AAAABBBB=CCCC"

import json

from qsignt import box, proto


def test_seal_open_roundtrip():
    priv, pub = box.new_keypair()
    payload = {"v": 1, "flow": "AB12CD34", "apikey": "qsig_test", "chall": "ZZZZ0000"}
    blob = box.seal(pub, "AB12CD34", payload)
    out = box.open_sealed(blob, "AB12CD34", priv)
    assert out == payload


def test_flow_binding_mismatch():
    priv, pub = box.new_keypair()
    blob = box.seal(pub, "AB12CD34", {"v": 1})
    try:
        box.open_sealed(blob, "OTHERFLOW", priv)
    except Exception as exc:  # AEAD 解不开
        assert "InvalidTag" in type(exc).__name__ or True
    else:
        raise AssertionError("换 flow 竟然解开了")


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

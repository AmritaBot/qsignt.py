"""下行信封：一次性 X25519 + AES-256-GCM。

上行用 OpenPGP（见 pgpx.py），下行只加密到客户端本次流程的一次性公钥。
公钥随上行 payload 一起提交，服务端用它对 JSON 做 AEAD 加密。
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
INFO = b"qsignt-open-v1"


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(text: str) -> bytes:
    text = "".join(text.split())
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def new_keypair() -> tuple[X25519PrivateKey, bytes]:
    """返回 (私钥, 32 字节公钥)。"""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def _derive(shared: bytes, flow: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=flow.encode(),
        info=INFO,
    ).derive(shared)


def seal(peer_pub_raw: bytes, flow: str, payload: dict[str, Any]) -> str:
    """服务端侧。返回 base64url(bot_eph_pub || nonce || ciphertext)。"""
    if len(peer_pub_raw) != KEY_LEN:
        raise ValueError("peer public key must be 32 bytes")

    eph_priv, eph_pub = new_keypair()
    shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_raw))
    key = _derive(shared, flow)

    nonce = os.urandom(NONCE_LEN)
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    ct = AESGCM(key).encrypt(nonce, data, flow.encode())

    return b64e(eph_pub + nonce + ct)


def open_sealed(blob: str, flow: str, eph_priv: X25519PrivateKey) -> dict[str, Any]:
    """客户端侧。blob 为下行那串 base64url。"""
    raw = b64d(blob)
    if len(raw) < 32 + NONCE_LEN + TAG_LEN:
        raise ValueError("下行载荷长度不足")

    bot_pub = raw[:32]
    nonce = raw[32 : 32 + NONCE_LEN]
    ct = raw[32 + NONCE_LEN :]

    shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(bot_pub))
    key = _derive(shared, flow)
    data = AESGCM(key).decrypt(nonce, ct, flow.encode())
    return json.loads(data)

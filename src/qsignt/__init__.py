"""qsignt —— QsigNT signer 注册工具。

上行 OpenPGP 加密，下行一次性 X25519 + AES-256-GCM。
"""

from .box import b64d, b64e, new_keypair, open_sealed, seal
from .proto import build_init, build_payload, parse_init, parse_payload

__all__ = [
    "b64d",
    "b64e",
    "new_keypair",
    "open_sealed",
    "seal",
    "build_init",
    "build_payload",
    "parse_init",
    "parse_payload",
]

__version__ = "0.1.0"

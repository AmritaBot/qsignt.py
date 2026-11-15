"""qsignt —— QsigNT signer 注册工具。

上行 OpenPGP 加密，下行一次性 X25519 + AES-256-GCM。
"""

from .box import b64d, b64e, new_keypair, open_sealed, seal
from .proto import build_init, build_payload, parse_init, parse_payload

# 签名申请只在这一个群发放，其他地方不接。
COMMUNITY_GROUP = "1132696493"

__all__ = [
    "COMMUNITY_GROUP",
    "b64d",
    "b64e",
    "build_init",
    "build_payload",
    "new_keypair",
    "open_sealed",
    "parse_init",
    "parse_payload",
    "seal",
]

__version__ = "0.1.1"

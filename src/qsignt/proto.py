"""协议里的文本形态：初始化消息、上行 payload、指令拼装。"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass

from . import pgpx
from .box import b64e

HEADER = "SIGNER-KEY-V1"
FLOW_RE = re.compile(r"flow=([0-9A-Za-z]{4,16})")
EXP_RE = re.compile(r"exp=(\d+)\s*(m|min|分钟)?")


@dataclass
class InitMessage:
    flow: str
    armor: str
    expire_minutes: int | None


def build_init(flow: str, armored_pub: str, expire_minutes: int = 10) -> str:
    return f"{HEADER} flow={flow} exp={expire_minutes}m\n{armored_pub.strip()}\n"


def parse_init(text: str) -> InitMessage:
    m = FLOW_RE.search(text)
    if not m:
        raise ValueError("初始化消息里没有 flow 标识")
    e = EXP_RE.search(text)
    return InitMessage(
        flow=m.group(1),
        armor=pgpx.parse_armor(text),
        expire_minutes=int(e.group(1)) if e else None,
    )


def build_payload(flow: str, eph_pub: bytes, kind: str = "enroll") -> bytes:
    return json.dumps(
        {
            "v": 1,
            "kind": kind,
            "flow": flow,
            "eph": b64e(eph_pub),
            "ts": int(time.time()),
        },
        separators=(",", ":"),
    ).encode()


def parse_payload(raw: bytes) -> dict:
    data = json.loads(raw)
    if data.get("v") != 1:
        raise ValueError("payload 版本不认识")
    for key in ("flow", "eph"):
        if key not in data:
            raise ValueError(f"payload 缺少 {key}")
    return data


def submit_command(armored_ct: str) -> str:
    return "#qsignt key submit " + armored_ct.strip()


def open_command(blob: str) -> str:
    return "#qsignt key open " + blob.strip()


def verify_command(chall: str) -> str:
    return "#qsignt verify " + chall.strip()

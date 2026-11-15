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


SUBMIT_HEAD = "#qsignt key submit"
OPEN_HEAD = "#qsignt key open"
VERIFY_HEAD = "#qsignt verify"
ARMOR_BEGIN = "-----BEGIN PGP MESSAGE-----"
ARMOR_END = "-----END PGP MESSAGE-----"


def squash_armor(armored: str) -> str:
    """把 armor 密文压成单行。

    armor 的头部、校验行和空行只是给人看的，gpg --decrypt 允许省略；
    正文本身是 base64，去掉换行不会改变语义。压成一行后整条指令不再换行，
    在 QQ 输入框里粘完直接回车发送，不会在中途被当成断句发出去。
    """
    text = armored.strip()
    begin = text.find(ARMOR_BEGIN)
    end = text.find(ARMOR_END, begin if begin >= 0 else 0)
    body = text[begin + len(ARMOR_BEGIN) : end] if begin >= 0 and end > begin else text
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    # CRC 行（=XXXX）要保留：gpg 缺了它会把 END 那行当成数据，末尾十来个
    # 减号报 invalid radix64 character，虽然能解出内容但退出码是 2
    return "".join(lines)


def submit_command(armored_ct: str) -> str:
    return f"{SUBMIT_HEAD} {squash_armor(armored_ct)}"


def parse_submit(body: str) -> str:
    """从整条指令里取回提交载荷，兼容被换行切断的情况。"""
    idx = body.find(SUBMIT_HEAD)
    if idx < 0:
        raise ValueError("文本里没有 key submit 指令")
    return "".join(body[idx + len(SUBMIT_HEAD) :].split())


def open_command(blob: str) -> str:
    return f"{OPEN_HEAD} {''.join(blob.split())}"


def verify_command(chall: str) -> str:
    return f"{VERIFY_HEAD} {chall.strip()}"

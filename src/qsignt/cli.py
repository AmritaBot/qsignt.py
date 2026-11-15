"""命令行入口。

人只做三件事：贴初始化消息、贴回包、把工具打印出的指令发回群里。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import box, pgpx, proto


def state_dir() -> Path:
    root = os.environ.get("QSIGNT_STATE") or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "qsignt"
    )
    p = Path(root)
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, 0o700)
    return p


def _save(name: str, data: dict) -> None:
    path = state_dir() / name
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, 0o600)


def _load(name: str) -> dict | None:
    path = state_dir() / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def cmd_enroll(args: argparse.Namespace) -> int:
    init = proto.parse_init(args.msg)
    priv, pub = box.new_keypair()
    payload = proto.build_payload(init.flow, pub)
    ct = pgpx.encrypt_to(init.armor, payload)

    _save("flow.json", {
        "flow": init.flow,
        "eph": box.b64e(priv.private_bytes_raw()),
    })
    print("把下面这条整段发到群里：\n")
    print(proto.submit_command(ct))
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    st = _load("flow.json")
    if not st:
        print("没有进行中的流程，先跑 enroll", file=sys.stderr)
        return 2

    blob = args.msg.strip()
    # 回执可能是合并转发里带说明的一整段，先切到指令本身
    marker = "#qsignt key open"
    if marker in blob:
        blob = blob.split(marker, 1)[1]
    elif "key open" in blob:
        blob = blob.split("key open", 1)[1]
    blob = "".join(blob.split())

    priv = box.X25519PrivateKey.from_private_bytes(box.b64d(st["eph"]))
    data = box.open_sealed(blob, st["flow"], priv)

    if data.get("flow") != st["flow"]:
        print("回包的 flow 和本地不一致，丢弃", file=sys.stderr)
        return 3

    _save("token.json", {
        "apikey": data["apikey"],
        "flow": st["flow"],
        "exp": data.get("exp"),
        "state": "pending",
    })
    print(f"apikey 已保存到 {state_dir() / 'token.json'}\n")
    print("把下面这条发到群里完成激活：\n")
    print(proto.verify_command(data["chall"]))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    tok = _load("token.json")
    if not tok:
        print("本地没有 apikey", file=sys.stderr)
        return 2
    print(tok["apikey"])
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    home = Path(args.out).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    fpr, armor = pgpx.generate(str(home), args.identity)
    print(f"指纹 {fpr}\n")
    print(armor)
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    raw = pgpx.decrypt_with(args.home, args.msg)
    print(json.dumps(proto.parse_payload(raw), ensure_ascii=False))
    return 0


def cmd_seal(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.json).read_text(encoding="utf-8"))
    print(box.seal(box.b64d(args.eph), args.flow, payload))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="qsignt", description="QsigNT signer 注册工具")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("enroll", help="用群里的初始化消息生成提交指令")
    e.add_argument("--msg", required=True, help="整段初始化消息（含 flow 与公钥）")
    e.set_defaults(func=cmd_enroll)

    o = sub.add_parser("open", help="解开 bot 回包，取出 apikey")
    o.add_argument("--msg", required=True, help="bot 回的 key open 那条")
    o.set_defaults(func=cmd_open)

    s = sub.add_parser("show", help="打印本地 apikey")
    s.set_defaults(func=cmd_show)

    k = sub.add_parser("keygen", help="生成 bot 侧 OpenPGP 密钥对")
    k.add_argument("--out", required=True)
    k.add_argument("--identity", default="qsignt-bot")
    k.set_defaults(func=cmd_keygen)

    d = sub.add_parser("decrypt", help="服务端解密上行 payload")
    d.add_argument("--home", required=True, help="GNUPGHOME")
    d.add_argument("--msg", required=True, help="armor 密文")
    d.set_defaults(func=cmd_decrypt)

    sl = sub.add_parser("seal", help="服务端生成下行密文")
    sl.add_argument("--eph", required=True, help="客户端一次性公钥 base64url")
    sl.add_argument("--flow", required=True)
    sl.add_argument("--json", required=True, help="待加密 JSON 文件路径")
    sl.set_defaults(func=cmd_seal)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, pgpx.GPGError) as exc:
        print(f"失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

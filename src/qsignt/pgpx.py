"""gpg 命令行薄封装。

不重写 OpenPGP。理由很实际：RFC 4880 的 ECDH 加密要手工拼 MPI、KDF 参数和
AES key wrap，自己写等于给协议开新坑；gpg 是现成的、经过审计的实现。

前提：本机有 gpg 2.3 以上。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

GPG = shutil.which("gpg") or shutil.which("gpg2")


class GPGError(RuntimeError):
    pass


def _require() -> str:
    if not GPG:
        raise GPGError("找不到 gpg，请先安装 gnupg 2.3+")
    return GPG


def _run(args: list[str], homedir: str, stdin: bytes | None = None) -> bytes:
    env = dict(os.environ)
    env["GNUPGHOME"] = homedir
    env.pop("GPG_AGENT_INFO", None)
    proc = subprocess.run(
        [_require(), "--homedir", homedir, "--batch", "--yes", "--no-tty", *args],
        input=stdin,
        capture_output=True,
        env=env,
        timeout=120,
    )
    if proc.returncode != 0:
        msg = proc.stderr.decode(errors="replace").strip()
        raise GPGError(msg or f"gpg 退出码 {proc.returncode}")
    return proc.stdout


@contextmanager
def homedir(path: str | Path | None = None) -> Iterator[str]:
    """临时 GNUPGHOME，权限 0700。"""
    if path is not None:
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        os.chmod(p, 0o700)
        yield str(p)
        return

    with tempfile.TemporaryDirectory(prefix="qsignt-gpg-") as tmp:
        os.chmod(tmp, 0o700)
        yield tmp


def _fingerprints(homedir_path: str) -> list[str]:
    out = _run(["--with-colons", "--list-keys"], homedir_path).decode(errors="replace")
    fprs: list[str] = []
    want = False
    for line in out.splitlines():
        fields = line.split(":")
        if fields[0] in ("pub", "sub"):
            want = True
        elif fields[0] == "fpr" and want:
            fprs.append(fields[9])
            want = False
    return fprs


def generate(homedir_path: str, identity: str = "qsignt-bot", expire: str = "2y") -> tuple[str, str]:
    """生成 Ed25519 主钥 + cv25519 加密子钥，返回 (指纹, armored 公钥)。"""
    _run(
        ["--passphrase", "", "--quick-generate-key", identity, "ed25519", "sign", expire],
        homedir_path,
    )
    fprs = _fingerprints(homedir_path)
    if not fprs:
        raise GPGError("生成主钥后拿不到指纹")
    main = fprs[0]

    _run(["--passphrase", "", "--quick-add-key", main, "cv25519", "encr", expire], homedir_path)
    armor = export_public(homedir_path, main)
    return main, armor


def export_public(homedir_path: str, fpr: str | None = None) -> str:
    args = ["--armor", "--export"]
    if fpr:
        args.append(fpr)
    return _run(args, homedir_path).decode()


def import_public(homedir_path: str, armored: str) -> str:
    _run(["--import"], homedir_path, stdin=armored.encode())
    fprs = _fingerprints(homedir_path)
    if not fprs:
        raise GPGError("导入公钥后拿不到指纹")
    return fprs[0]


def encrypt_to(armored_pub: str, plaintext: bytes) -> str:
    """用一段 armor 公钥加密，返回 armor 密文。"""
    with homedir() as tmp:
        fpr = import_public(tmp, armored_pub)
        out = _run(
            ["--armor", "--trust-model", "always", "--recipient", fpr, "--encrypt"],
            tmp,
            stdin=plaintext,
        )
    return out.decode()


def decrypt_with(homedir_path: str, armored_ct: str) -> bytes:
    return _run(["--decrypt"], homedir_path, stdin=armored_ct.encode())


def parse_armor(text: str) -> str:
    """从一段混杂文本里抽出第一个 armor 公钥块。"""
    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = "-----END PGP PUBLIC KEY BLOCK-----"
    start = text.find(begin)
    if start < 0:
        raise ValueError("文本里没有 PGP 公钥块")
    stop = text.find(end, start)
    if stop < 0:
        raise ValueError("公钥块没有结束标记")
    return text[start:stop + len(end)]

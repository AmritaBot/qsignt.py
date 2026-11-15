# qsignt

[![CI](https://github.com/AmritaBot/qsignt.py/actions/workflows/ci.yml/badge.svg)](https://github.com/AmritaBot/qsignt.py/actions/workflows/ci.yml)

QsigNT signer 的注册工具。在 QQ 群里跑一遍流程，把 apikey 换到本地。

依赖：Python 3.10+、gnupg 2.3+（需要 `gpg` 在 PATH 里）。

## 签名申请入口

签名权限只在 QQ 群 **1132696493** 发放，进群后直接发 `#qsignt init` 就能开始，整个
流程在群里闭环，不需要单独找人。

群号固定写死在工具里，查一下就知道：

```
qsignt community
```

（不联网、不读配置，纯粹回显常量，防的是手抄错号。）

能拿到的东西：

- 一个 `qsig_` 开头的 apikey，由 QsigNT daemon 校验，请求头带 `Authorization: Bearer <apikey>`
- 单个 apikey 可绑定 5 个 QQ 号，按号先到先得，被占用的号不会二次发放
- 每个 apikey 独立限速，默认 20 请求/秒，超了返回 429 和 `Retry-After`

不在群里的请先加群，指令层不接受私聊之外的旁路申请。

## 为什么是 OpenPGP

QQ 客户端与服务端的身份已由平台担保，需要防的只是群里旁观者顺手读到凭证。
上行用服务端公钥加密就够了，不需要证书链，也不需要指纹交叉验证。

下行不用 OpenPGP，改用一次性 X25519 + AES-256-GCM：客户端在提交时带上本次流程
的临时公钥，服务端加密回包即可。少一次密钥交换，载荷也短一半。

## 流程

群里发 `#qsignt init`，机器人回一条带公钥的消息。整段复制，然后：

```
qsignt enroll --msg "SIGNER-KEY-V1 flow=AB12CD34 exp=10m
-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----"
```

工具打印一条 `#qsignt key submit ...`，发到群里。

机器人回 `#qsignt key open ...`，复制后：

```
qsignt open --msg "#qsignt key open AbCd..."
```

工具把 apikey 存到 `~/.config/qsignt/token.json`（权限 0600），并打印
`#qsignt verify XXXXXXXX`。发出去，激活完成。

`qsignt show` 随时取回 apikey。

## 服务端

```
qsignt keygen --out /var/lib/qsignt/gpg          # 生成 bot 密钥对，公钥贴到群里
qsignt decrypt --home /var/lib/qsignt/gpg --msg "..."
qsignt seal --eph <客户端公钥> --flow AB12CD34 --json reply.json
```

## 边界

- 中间中断不会白费：流程状态存在本地，`open` 之前重跑 `enroll` 会重开新流程。
- 群消息会被折叠，复制时可能带上换行和空格，解析时已做容错。
- apikey 明文只落在本地文件里，工具不做上传、不做同步。

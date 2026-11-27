# 案例：天翼网关 TEVA-7501V（天邑 / 海思平台）

> 作业时间：2026-11-26 ~ 11-27（Asia/Shanghai）
> 设备归属：用户自有家庭光猫　状态：**已完成并双向验证**，telnet 已关闭
> 方法论：[01-methodology.md](01-methodology.md)

---

## 1. 设备档案

| 项 | 值 |
|---|---|
| 型号 | `TEWA-7501V` / `TEVA-7501V`（标签：10Gbit/s 天翼网关用户端设备，10G EPON/XG-PON ONU，无 WiFi）|
| 固件 | `Tianyi_V1.0_JS2511`（Vendor `tianyi`，Province `JS`，Operator `CTC`） |
| 平台 | 海思（`hsan` 主机名，`Linux 5.10.0 #2 SMP Wed Jun 17 15:51:14 CST 2026 armv7l`，musl 1.2.3，`publisher@u22-builder9.rd.scty`）|
| MAC | `CC:6D:55:xx:xx:CD`（= `br0`） |
| SN / 设备标识 | `TY7501VJ<序列号>` / `<设备标识>` |
| ProductSN | `CC6D55-xxxxxxxxxxxx` |
| LOID | `25B5<LOID>` |
| 光功率 | `-22.52 dBm`，`reg_status=1`、`itms_reg_status=1` |
| WAN | `100.93.x.x`（PPPoE，账号 `<宽带账号>`）|
| 出厂日期 | 2026-09-28（标签）|
| 端口 | `80`（LuCI/uhttpd+SAF）、`8080`（`Server: HomeGateway`，`/usr/bin/web`）、`192.168.1.1:17998`（局端管理）、`:23`（默认关闭）|

---

## 2. 结论：口令与入口

| 用途 | 入口 | 账号 | 口令 |
|---|---|---|---|
| **超级管理员** | `http://192.168.1.1:8080` | `telecomadmin` | **`telecomadmin<8位数字>`** |
| 普通用户 | `http://192.168.1.1/cgi-bin/luci` | `useradmin` | `<标签口令>` |
| telnet（LAN） | `192.168.1.1:23` | `telnetadmin` | `telnetadmin` |
| su（本地提权） | telnet 内 | — | `<A1衍生值>`（= A1 表5 对 br0 MAC 派生）|
| PPPoE | — | `<宽带账号>` | `<PPPoE口令>` |
| TR-069 ACS | — | `<ACS用户>` | `<ACS口令>`（ConnReq `<ConnReq口令>`）|
| FTP | 默认关闭 | `useradmin` | `<标签口令>` |
| WiFi（无模块，配置残留） | — | — | `ChinaNet-XXXX` / `<WiFi口令>` |

**80 端口不认 `telecomadmin`**。
它走 `CheckUAPasswd` 分支，只校验用户账号。
设计如此，不是口令错，详见 §4。

---

## 3. 关键机制（三处"卡点"的正解）

### 3.1 打开 telnet：`POST /entelnet.cgi`

```bash
# 信息模式（取种子）
curl -s -X POST http://192.168.1.1:8080/entelnet.cgi
# → {"retcode":"0","data":{"result":"BaseMac=(CC6D55xxxxxxCD)"}}

# 真开（必须 form body，放 query 会被无视）
curl -s -X POST http://192.168.1.1:8080/entelnet.cgi --data 'Verification_code=<A1衍生值>'
# → {"retcode":"0","data":{"status=SUCCESS"}}   随后 23/tcp open

# 关（收尾必做）
curl -s -X POST http://192.168.1.1:8080/distelnet.cgi
```

**参数语义（实测）**：
body 里 `Verification_code` 为空或省缺 → 回种子。
非空 → 走校验；放 query 一律当空的。

### 3.2 A1 派生值：五张表，别只试一张

本机 MAC `CC6D55xxxxxxCD` 的五组结果：

```
表1 MTBjwaFr    表2 fKCaedbq    表3 bUwqNNSa
表4 MTBvHaFD    表5 <A1衍生值>   ← 7501V 吃这张（海思版）
```

前 4 张打 `entelnet`，全是 `Verification code Error!`。
第 5 张立刻 `SUCCESS`。
**"工具对该型号无效"是误传**，真因是选错表。
算法实现与五张表原文见 `reports/intel.md`、`sualgo/a5.py`。

### 3.3 su 的真实校验源（反汇编坐实）

```
su_main
 ├─ ttyname() 必须以 /dev/pts/ 开头      # 0x33b00
 ├─ access("/tmp/opensoure_smt") 必须不存在
 ├─ ioctl(SIOCGIFHWADDR) on br0          # 0x1a6a7c
 ├─ encode_password()                    # 0x1a6700，128 字节表
 └─ strcmp(candidate, 派生值)            # 0x1a6b64
```

结论：`<A1衍生值>` 就是 `encode_password(br0 MAC)` 的结果。
它**不是** `/etc/shadow` 里的东西。
（shadow 里 root 与 telnetadmin 的 `$6$` 哈希都等于字符串 `telnetadmin`，是幌子。）

⚠️ **假阴性陷阱**：
管道喂 stdin 时，busybox `su` 不打印 `Password:`，静默 `exit 1`。
所以"投口令得 `Error!`"完全可能是流程错。
必须真 tty 交互，脚本见 `su/su_tty.py`。

### 3.4 配置解密：设备自己动手

```
调用链：hi_decrypt_file@0x51bc
   → hi_ipc_call("hi_hi_decrypt_file_call", len=0x100)
   → encrypt 线程(pid 1489) handler
   → hi_hi_decrypt_file_ipc@0x51d4 → hi_encrypt_defile@0x4cac → hi_encrypt_aes_cbc_de@0x2198
AES ctx：+0x00 key ptr / +0x04 IV ptr / +0x0c inlen / +0x10 key(32B) / +0x30 keylen / +0x34 mode(=2 CBC)
rootkey：hi_encrypt_mng_init@0x5018 以 access("/config/work/.componet4") 为闸门；
         缺文件 → hi_rand_bytes(0x10) 现场随机 → 只存活于进程内存
```

实测 `/config/work/.componet4` 与 `/log/.componet1~3` **全部不存在**。
所以 rootkey 每次启动随机，无法离线解。
正解是让设备自解：

```bash
su -c "hi_ipc /home/cmd/encrypt/decrypt_file -v ifile /config/work/lastgood.xml ofile /tmp/lg.xml"
# → succ.  /tmp/lg.xml = 233333 B 明文
```

加密格式为 `c2 02 00 00` + 2B(`a6 c9`) + 19328B 密文（=1208×16）。
离线尝试全灭。
1500 组弱 key + 13824 组 PBKDF2 + 67 组身份派生 + 各种偏移/模式。
记录见 `reports/t2-key-forensics.md`。

---

## 4. 为什么 80 登不上（本轮最贵的教训）

| 实验 | 结果 | 结论 |
|---|---|---|
| `useradmin` / `<标签口令>` @ 80 | `302` + `Set-Cookie: sysauth=60980a95…` | 通道正常 |
| `telecomadmin` / `telecomadmin<8位数字>` @ 80 | `200`，无 sysauth | 该账号被拒（不是格式错） |
| `telecomadmin` / `telecomadmin<8位数字>` @ 8080 | `{"result":"success_telecomadmin"}` | **超管入口是 8080** |
| 设备 DBus `GetTAPasswd` | `('telecomadmin<8位数字>', uint32 0, '')` | 运行态 == 落盘 |

80 是 `uhttpd -r SAF`。
`/www` 为空，登录走 SAF 插件里的 `CheckUAPasswd` 分支。
8080 才是 `/usr/bin/web`。
它读 `IgdSysmngAccountAttrConfTab`（CM 表），那里才有超管账号。

**免额度 oracle**：
不消耗 web 登录次数，也不触发 3 次锁。

```bash
gdbus call --system --dest com.ctc.igd1.SysCmd \
  --object-path /com/ctc/igd1/Telecom/System \
  --method com.ctc.igd1.SysCmd.CheckTAPasswd telecomadmin<8位数字>
# → (uint32 0, '')           正确
# 负样本 → (uint32 1, 'invalid passowrd')   ← 固件拼写错误，可当指纹
```

注意真名是 `com.ctc.igd1.SysCmd`，对象路径 `/com/ctc/igd1/Telecom/System`。
从根路径调用会报 UnknownMethod。

---

## 5. 端点面速查

### 8080（`/usr/bin/web`）
- 公开页：`/usr_logon.html`(15022B)、`/rgst.html`、`/rgstsc.html`、`/rgsting.html`、`/itms.html`、`/config/config.js`(129352B，只有字段定义无值)
- 免登录 CGI：`/web_loid_auth_show.cgi`、`/web_query_register_status.cgi`、`/session_key_show.cgi`、`/entelnet.cgi`、`/distelnet.cgi`
- 需登录：`/web_login_exe`、`/index_content.html`、`/get_telnet_show.cgi`、`/web_query_user_show.cgi`
- 拦在登录后面（403/`logout`）：`web_password_show`、`web_loid_show`、`web_password_auth_over`、`device_reset`、`restore_verify_code`、`onu_restore_factory_full`
- **290 个真实处理器清单** → `reports/p8080_cgi_handlers.txt`

### 80（LuCI）
- 登录：`POST /cgi-bin/luci`（`username` + `psd`）→ `302` + `sysauth`
- 只读：`admin/settings/gwinfo?get=all`、`admin/settings/gwstatus`、`admin/allInfo`
- **无角色层**：`useradmin` 即全部功能；110 个导出/备份候选名全 404
- 唯一硬洞：`POST /admin/device/rmBlackHost` 不校验 CSRF token

### 超管会话（8080 内）
- 标志：`#userlevel=1`、`CONFIG_WEB_USER=0`，`/index_content_user.html` 对超管 404（模板互斥）
- 菜单：一级 7 / 二级 38 / 三级 120+（`reports/p8080/menu.json`）
- 超管独占：整个「诊断」、`Help`（唯一 `mode:1`）、「管理」下 账号/设备/日志/维护
- 隐藏项（`display=0`）：`NN_VPN`、`Secu_MACWhiteList`、`Secu_Other`、`App_BroadBandSrv`、`App_QoE`、`Sta_BucpeInfo`

---

## 6. 证据链（谁证了什么）

| 证据 | 位置 | 强度 |
|---|---|---|
| 明文配置原文 | `igd/raw/lastgood.dec.xml`（233333B，md5 `d99711a5…(md5 前8位)`）| 强（设备自解）|
| backup 配置交叉验证 | 同文件另解 `backup_lastgood.xml` → 逐字节相同 | 强 |
| 运行态 DBus | `reports/live_accounts.md`（`GetTAPasswd` 原始返回）| 强 |
| 8080 实登 | `success_telecomadmin` + 31 位 session_key | 强 |
| 字节级复核 | `value len=20`，hex `74656c...3831`，无尾空格/CR | 强 |
| 数据源定死 | `reports/auth80_source.md`（80 走 CM 运行态，读不了落盘）| 强 |

---

## 7. 作业纪律与额度

- **零写操作**：没改密码、没恢复出厂、没动 LOID/TR-069、没点"维护结束"
- 失败锁额度：80 累计 3 次（出厂默认 1 + 超密 1 + 控制实验成功 1）；8080 用 1 次（成功，剩 2）
- telnet 授权锁：清过 `/tmp/login/login_status_log`（该文件 `0666`）
- 设备侧清场：删 `/tmp` 下全部本任务临时件（`lg.xml`/`lgb.xml`/`*.gz`/`*.b64`/`memscan*`/`acc_live.txt` 等），telnet 已关（本地复核 `Connection refused`）
- 备用件 `/tmp/config_file/`、`config_file.tar.gz`(92B)、`g_auc`(76B) 是设备原有，未动

---

## 8. 时间线（压缩版）

| 时间 | 阶段 | 结果 |
|---|---|---|
| 11-26 19:32 | 面测绘 | 80/8080 双门；`useradmin`/`<标签口令>` 打通 80 |
| 11-26 19:5x | 端点枚举 | 290 个真实 CGI；发现 `entelnet.cgi`（GET 曾误判不存在）|
| 11-26 20:0x | A1 五表 | 表5 `<A1衍生值>` → telnet 打通 |
| 11-26 20:3x | su | 管道假阴性（误判 3 轮）→ 真 tty 拿到 root |
| 11-26 23:2x | 配置解密 | 离线全灭 → `decrypt_file` 让设备自解 → 明文 |
| 11-27 00:4x | 首版交付 | 超密出土 |
| 11-27 01:0x | 验证 | 80 失败 → 8080 成功 → DBus 双向确认 |
| 11-27 01:0x | 清场 | telnet 关闭、临时件清空 |
| 11-27 13:5x | 工程化 | `recover_superpass.py` 写就并实跑通过（2 分钟/次）|

---

## 9. 复现

```bash
cd <你的工作目录>
python3 ../scripts/recover_superpass_template.py          # 全流程，自清场（先填顶部 CONFIG）
# 只用已解出的明文配置提取口令：
grep -o 'aucTeleAccountPassword" Value="[^"]*"' lastgood.dec.xml
```

脚本按这个顺序跑：先 `distelnet`，再 `entelnet(Verification_code=<A1衍生值>)`。
然后 telnet（telnetadmin），清锁，`su` 输 `<A1衍生值>`。
接着 `hi_ipc decrypt_file`，分块拉回并做 md5 对账。
最后提取 `aucTeleAccountPassword`，`distelnet` 收尾。

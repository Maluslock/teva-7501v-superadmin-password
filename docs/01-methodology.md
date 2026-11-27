# 网关口令与配置取证方法论

> 来源：2026-11-26 ~ 27，中国电信天翼网关 TEVA-7501V（天邑、海思平台、`Tianyi_V1.0_JS2511`）实机作业。
> 本文抽掉型号与凭据，只留可迁移的方法、判据与踩过的坑；机型细节见 [03-case-study-tewa7501v.md](03-case-study-tewa7501v.md)。
> 适用前提：**设备是自有财产**，目的是接管自己家的网关，不涉及他人设备。

---

## 0. 一句话结论

嵌入式网关的"超级口令"几乎不可能靠猜，但 **99% 的情况下固件里有一段代码会把明文口令读出来给别人看**——
你要做的不是破解密码学，而是找到那段代码的调度入口，并且分清"接口不存在"和"我不够权限"这两种 400/403 的真假含义。

本次真正解决问题的三步是：

1. **`POST /entelnet.cgi` + 硬件标识派生的 `Verification_code`** → 打开 LAN telnet；
2. **真 tty 交互投喂 `su` 口令**（这个口令就是同一个派生值）→ 拿到 root；
3. **让设备自己解配置**：`hi_ipc /home/cmd/encrypt/decrypt_file -v ifile <加密配置> ofile /tmp/out.xml` → 明文里的 `aucTeleAccountPassword`。

离线逆 AES 是**死路**，别把时间浪费在那儿（原因见 §3.4）。

---

## 1. 五阶段流程

```
① 面测绘 ──→ ② 鉴权模型推断 ──→ ③ 提权（LAN shell）──→ ④ 数据获取 ──→ ⑤ 验证与清场
  端口/页面        会话 vs 角色           su/派生口令          让设备自解        双向验证
  端点命名规则      cookie/token 语义      假阴性排查           而非逆密钥        锁额度/关端口
```

每个阶段的**判据**比动作重要——判错一次，后面全跑偏（本次跑了三轮冤枉路全是因为判据错）。

---

## 2. 阶段①：面测绘（Surface Mapping）

### 2.1 先看端口，不看页面

```bash
nmap -Pn -n --open -p 21,22,23,53,80,443,8080,8443,7547,1900,69,161,17998 <GW_IP>
```

要读的**不是"开了几个"，而是"哪几个是同一套固件的不同门"**：

| 现象 | 推断 |
|---|---|
| 80 与 8080 同时开、`Server` 头不同（一个空、一个 `HomeGateway`） | **两套独立程序**：80 是 LuCI/uhttpd，8080 是厂商中间件（`/usr/bin/web`）。账号体系可能不同源 |
| 80 的 `Last-Modified` 是 2022 年、静态资源带 `?version=5400` | 老框架 + 版本串，可作为固件指纹 |
| 8080 给未知路径回 `400 Bad Request`（而不是 404） | 请求**没进 CGI 派发层**——路径/方法错，不代表处理器不存在（见 §5 坑 1） |
| 17998 之类怪端口在监听 | 局端/TR-069 管理面，通常更硬，别当第一入口 |

### 2.2 页面分三类，语义完全不同

用同一批 `curl -i` 打一遍，把响应归成四档——**这四档的区分是整份方法论的地基**：

| 响应 | 含义 | 能不能继续挖 |
|---|---|---|
| `200` + 正常 HTML | 公开页 | 读它的 inline script，端点名都在里面 |
| `302 → /login.html` | 处理器存在，但要登录 | 记下来，等拿到会话再打 |
| `403` + 具体错误串（如 `invalid Session Key`） | 处理器存在，**鉴权层在它前面** | 找鉴权层怎么满足 |
| `404` / `400 malformed` | 路径没注册 / 没进派发 | 换方法（GET↔POST）再判一次 |

> 本次教训：`/entelnet.cgi` 早期被我判成"不存在"，真因是**用 GET 打的**。这机器所有 `.cgi` 只接受 POST，GET 一律 400 —— 差一点就错过了正解。

### 2.3 端点名不要猜，要从二进制里"读"

猜词表（`web_query_*` × 46 个名词 × 184 种组合）几乎必然是浪费——**真实名字写在固件字符串里**。

本次的正解是从 `/usr/bin/web` 里翻日志格式串：

```
[WEB:%s(%d)]>>ENTER xxx_cgi
```

一条 `strings | grep ">>ENTER"` 就枚举出 **290 个真实 CGI 处理器**（该清单属实机产物，未随仓库发布）。
同理，`[HI_IPC] ipc call %s fail` 这类串会直接告诉你 IPC 命名空间。

**这就是"猜"和"读"的差距：184 次盲打 vs 一次 strings。**

### 2.4 免费情报：报错信息

- LuCI 的 Lua 异常会回显绝对路径 → 直接得到后端源码结构（`/usr/lib/lua/luci/controller/admin/device.lua:42`）。
- 固件拼写错误是**免费指纹**：`invalid passowrd`（少了 `s`）这种串，用来确认"我打的是同一台、同一版本"。
- 前端 JS 里的 `isValidAscii()`、`G_sessionkey`、`encrypt_info()` 等函数名，等于把加密方案写在脸上。

---

## 3. 阶段②③：鉴权模型与提权

### 3.1 先分清"会话层"和"角色层"

用同一个账号登进去，把菜单/接口全打一遍，看**有没有任何一处因身份不同而被拒**：

- 如果没有 → 这套 UI **只有会话层没有角色层**，`useradmin` 实际等于全部功能，"越权到超管"这个目标本身不存在（本次 80 端口就是这样，白花了一轮）。
- 真正挡住你的是**另一个程序**（8080 中间件），它才分 telecomadmin / useradmin。

判定技巧：登录后看 cookie 里有没有 role 字段、页面里有没有 `userlevel`、`#userlevel=1` 这类标志、两套模板是否互斥（`/index_content_user.html` 对超管会话返回 404 = 模板互斥发布）。

### 3.2 会话凭证的可伪性

| 观察 | 结论 |
|---|---|
| 两次登录 `Set-Cookie: sysauth=` 值完全不同（32 hex 随机） | 服务端会话表，**不可伪造、不可预测** |
| `Sessionkey` 一次一用（同 key 第二次打同端点返 403） | 取 key 与用 key 必须紧邻；打 N 个接口要取 N 个 key |
| 登录态落在 `/tmp/logininfo` 这类文件 | **不要急着伪造**——先用 atime 探针验证"未登录请求到底读不读它"（本次结论：不读，伪造无效） |

atime 探针（低成本证伪法）：

```bash
# 在设备上伪造记录 → touch -a 到过去 → 从外面连打几个请求 → 再看
touch -a -t 202001010000 /tmp/logininfo
ls -lu /tmp/logininfo        # 若 atime 没变 ⇒ 这条链根本不 open 这个文件，伪造无意义
```

### 3.3 su 的"假阴性"——本次最大的坑

现象：`echo '<口令>' | su -c id` → `Error!`，所有人（包括三个 agent）一致判"口令错"。

真相：**busybox `su` 在 stdin 不是 tty 时不会打印 `Password:`，直接 `exit 1`**。
反汇编 `su_main` 可见：先 `ttyname()` 判 `/dev/pts/` 前缀 → 不是则静默失败；是才 `ioctl(SIOCGIFHWADDR)` 取 `br0` MAC → `encode_password()` → `strcmp()`。

正确姿势：真 tty 交互，**等 `Password:` 出现再投**：

```python
tn.write(b"su -c 'id'\n")
tn.read_until(b"Password:", timeout=8)   # 关键：等提示符
tn.write(b"<口令>\n")
tn.read_until(b"# ", timeout=10)
```

同一个坑还有两种变体：
- **tty 前缀判定**：某些机型只允许 `/dev/pts/*` 的 tty 走 su，串口/管道一律拒。
- **`/etc/securetty` 缺失**：`login_main` 对 uid 0 先查 securetty，查不到直接 `Error!`（**根本不校验口令**）→ 于是"root 从 telnet 永远登不进"，但 `su` 还是好使的。

### 3.4 口令派生：硬件标识 + 固定表

天邑（TEWA/TEVA）系列的 `Verification_code` / `su` 口令是同一族算法：

```
输入：设备标识（MAC 后 8 位倒序）
算法：位运算混合 + 一张 128 字符置换表 → 8 字符
变体：5 张表（ct1..ct5），机型不同选表不同
```

- 官方页面 `mao.trustavo.com/mac_a1` 的内联 JS 就是完整算法（3 张表）；
- 社区仓库 `invinciberry/tewa-modem-extractor` 带 5 张表；
- **"这工具对该型号无效"多半是选错表**——本次 7501V 吃表 5（海思版），表 1-4 全被拒。

派生值的三处复用（记住这条，能省一半力气）：
`entelnet 的 Verification_code` = `telnet 的 su 口令` = `A1(表N, MAC)`。

### 3.5 锁与额度：别把自己锁死

| 锁 | 表现 | 解法 |
|---|---|---|
| telnet 授权锁 60s，**全局**（跨会话共享） | `Authorization Locked, Try again after N seconds!` | 计数器常在 `/tmp/login/login_status_log`（`0666`）→ `: > 该文件` 清零 |
| web 登录 3 次/60s | 返回 `three_error_login` | 先查 `web_login_error.cgi` 之类端点**确认没锁定**再投；成功不累加计数 |
| 连续重试把 telnetd 打死 | 端口开着但无 banner | 先 `distelnet` 再 `entelnet`，一次不成等 2-3 分钟，别高频重连 |

---

## 4. 阶段④：数据获取——"让设备自己解" > "逆密钥"

### 4.1 先判配置是不是加密的

```bash
head -c 16 lastgood.xml | xxd          # c2 02 00 00 开头 = 厂商私有封装
strings  lastgood.xml | head            # 无 XML 标签 = 真加密
```

排除法（按顺序做，快且不留遗憾）：
1. 常见压缩魔数：`1f8b`(gzip) / `BZh`(bz2) / `fd377a58`(xz) / offset 0-80 全扫一遍；
2. 明文试探：`grep -c '<Dir\|<?xml'`；
3. 单字节 XOR：256 键扫已知明文；
4. 16 字节块重复率：有重复 ⇒ ECB 裸加密（可切块分析）；IC≈1/256 ⇒ 均匀，是真加密；
5. 弱 key 字典：MAC/SN/型号/厂商/全零/`"admin"` × 各长度 × ECB/CBC × 各偏移。

本次 1~5 全灭，且二进制的加密库里**没有任何硬编码 key**（AES ctx 的 key 指针由调用方传入），
rootkey 由 `hi_encrypt_mng_init` 在启动时 `hi_rand_bytes()` 生成、只活在进程内存（4 个 component 文件全 ENOENT）——
**结构上就不存在"离线解"这回事**。识别出这一点，比再爆破一万个 key 有价值。

### 4.2 正解：找设备自带的解密命令

厂商为了让自己的别的进程读配置，**一定**留了一条"喂文件名 → 吐明文"的 IPC 命令。找它的方法：

```bash
# 1) 看有哪些 shell 封装（很多时候是个 /bin/sh 脚本，不是 ELF）
file /bin/hipcbox && cat /bin/hipcbox
# 2) 里面通常长这样：
#    cm_tab_dump(){ hi_ipc $CMDDIR/cm_tab_dump -v tabid "$1" inst "$2"; }
# 3) 命令描述符目录里找 decrypt_file
ls /home/cmd/*/ | head -40      # 看到 encrypt/decrypt_file 就成了
cat /home/cmd/encrypt/decrypt_file
#   functionname=hi_decrypt_file; attributenum=2;
#   alias<ifile>  alias<ofile>
# 4) 打一次
hi_ipc /home/cmd/encrypt/decrypt_file -v ifile /config/work/lastgood.xml ofile /tmp/out.xml
```

### 4.3 把文件搬回本地

光猫到 LAN 常**不能回连**（策略路由走 CGNAT 侧），所以不要指望 `nc -e`。可靠通道是"设备把文件切碎、你逐块拉"：

```bash
# 设备侧（一次性）
gzip -9 -c /tmp/out.xml > /tmp/o.gz; base64 /tmp/o.gz | tr -d '\n' > /tmp/o.b64
# 本地逐块（bs×skip，块间 sleep ~1.2s，telnetd 太脆）
dd if=/tmp/o.b64 bs=98304 skip=N count=1
# 拉完 base64 -d | gunzip -dc，用设备端 md5 对账
```

关键：**必须有 md5 对账**，否则你不知道拼出来的文件是不是被截断的。

---

## 5. 反面模式清单（每一条都是真金白银换的）

| # | 错误做法 | 真因 | 正确做法 |
|---|---|---|---|
| 1 | 用 GET 打 `.cgi` 得 400 → 判"接口不存在" | 服务器只接受 POST | 同路径换 POST，空 body 也打一次 |
| 2 | 管道喂 `su` 得 `Error!` → 判"口令错" | 无 tty 不打 `Password:`，静默失败 | 真 tty 等提示符（§3.3） |
| 3 | 拿落盘配置当"运行态真值" | 内存与磁盘可能不一致（改了没存/启动加载别的） | 用设备自带 oracle（如 `CheckTAPasswd`）交叉验证 |
| 4 | 用**字符偏移**解析含中文的 XML | 中文按字节算，字符/字节差 8 | 一律用**字节**偏移，加 bmap 校验 |
| 5 | 400~800 词表硬 fuzz | 会打死 httpd，还拿不到真名 | 从二进制 `>>ENTER` 串读真名 |
| 6 | 把 cookie 存 `/tmp` | 某些执行环境每次调用是独立 tmpfs | 存工作区 |
| 7 | 无限猜 su 口令 | 60s **全局**锁，越猜越久 | 先清 `/tmp/login/*` 计数，一轮 ≤3 次 |
| 8 | 点后台"维护结束"/"恢复出厂" | TR-069 会重新随机化超密，前功尽弃 | 只用只读接口；配置改动一律不做 |
| 9 | 只验证一个入口就宣布成功 | 80 登不上 ≠ 口令错，可能该账号只认 8080 | 控制实验 + 双入口验证（§6） |
| 10 | 多个 agent 同时连 telnet | telnetd 单会话，互相踢，人人以为自己被锁 | 指定唯一"通道持有者" |

---

## 6. 阶段⑤：验证与清场

### 6.1 控制实验（必须做，1 次额度）

拿到"疑似口令"后，先证明**通道本身是好的**：

```
用已知正确的普通账号登一次 → 302 + Set-Cookie = 通道正常
用疑似超管口令登 → 200（无 cookie） = 该账号口令被拒（而不是通道坏/格式错）
```

不做这一步，你永远分不清"口令错"和"我请求写错了"——本次 80 端口就是这么被排除的（80 只认用户账号）。

### 6.2 双向验证

| 路径 | 判据 |
|---|---|
| 设备自带 oracle（DBus/IPC） | `CheckTAPasswd <候选>` → `(uint32 0, '')` = 真 |
| 真实 web 登录 | `success_telecomadmin` / `302 + Set-Cookie` |
| 两条路结果一致 | 才敢写进交付物 |

### 6.3 清场清单

```bash
# 设备侧
: > /tmp/login/login_status_log            # 清授权锁计数
rm -f /tmp/<你的临时文件>                    # 解密件、上传件、脚本
curl -s -X POST http://<GW>:8080/distelnet.cgi   # 关 telnet
# 本地复核（一定要自己验，不要只听汇报）
timeout 5 bash -c 'exec 3<>/dev/tcp/<GW>/23' || echo "23 已关"
```

### 6.4 交付物最低要求

1. 口令 + **生效入口**（同一台设备不同口子认不同账号，写清楚）；
2. 来源证据（哪一行、什么偏移、md5）；
3. 一条可复现命令（脚本 ≤ 100 行，能跑通并自清场）；
4. 额度/写操作记录（证明没弄坏设备）。

---

## 7. 可复用清单（换个型号照着勾）

```
[ ] 端口扫描：列出所有开放端口 + Server 头 + 静态资源版本串
[ ] 四档分类：200 / 302 / 403 / 404-400，每档都记原始响应
[ ] 公开页里的 inline script 全存下来 → grep 端点名/token/加密函数
[ ] 二进制 strings：grep '>>ENTER|_cgi|hi_ipc|Session Key'
[ ] 判鉴权模型：只有会话层？还是有角色层？两套模板互斥？
[ ] 找 LAN 维护通道：telnet/ftp 开关端点（注意 GET/POST 语义）
[ ] 派生口令：设备标识 + 官方/社区算法（多张表都试，别只试一张）
[ ] 提权：真 tty 交互 su；先清锁计数；一轮 ≤3 次
[ ] 配置加密判定：魔数/压缩/XOR/ECB/弱 key 五连
[ ] 找 decrypt IPC：/home/cmd + hipcbox 类脚本
[ ] 搬运：gzip+base64+dd 分块 + md5 对账
[ ] 验证：控制实验 + 双入口 + 设备 oracle
[ ] 清场：锁计数、临时文件、关端口，本地复核
```

---

## 8. 边界

- 只对**自有设备**做；本次是家里自己买的光猫，目的是接管自己的网关。
- 全程**零写操作**：没改密码、没恢复出厂、没动 LOID/TR-069 配置。
- TR-069 是超密被随机化的根源；真要长期稳定，方向是"把 ACS 地址置空"而不是删连接（删了可能断网）。

---

**下一步读什么**

- 机型专属细节、证据链：[03-case-study-tewa7501v.md](03-case-study-tewa7501v.md)
- 一键复现脚本模板：[scripts/recover_superpass_template.py](../scripts/recover_superpass_template.py)
- 反面模式与清单：本文 §5 / §7

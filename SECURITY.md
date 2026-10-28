# 安全架构与代码安全防御（dsh-system-guard）

> 本文是插件《代码安全防御架构规则》v1.0 的符合性证据汇总，随包发布（公开设计原则：安全不依赖本文保密）。
> 规则映射：A 信任边界/授权 · B 认证 · C 访问控制 · D 密码学 · E 输入输出 · F 供应链 · G 配置与暴露面 · H 审计响应 · I 流程 · J 分发自检。

---

## 1. 资产与信任边界（A-01 / A-05）

**受保护资产**：系统核心文件（可执行/内核/驱动）、隐藏备份（备份目录 + manifest）、插件自身完整性（integrity.json）、用户决策权（删除/修复是否需要确认）。

```
┌──────────────────────────── 本机 ────────────────────────────┐
│                                                              │
│  [浏览器面板 client.js]  ←── 不信任 ──┐                       │
│        │ 同源 HTTP（Origin/Host 校验）  │                       │
│        ▼                              │                       │
│  [Host 插件 index.js / core.js]  ←── 不信任 ──┐               │
│        │ 受控动作表 dispatch()                │               │
│        ▼                                     │               │
│  [PowerShell helper scripts/guard.ps1]  ← 本地子进程（参数数组，不经 shell 字符串）│
│        │                                     │               │
│        ▼                                     │               │
│  [Windows 系统文件 / 备份目录 / 管理员令牌]    │               │
└───────────────────────┬──────────────────────┘               │
                        │ ctx.web（只读、官方域名白名单）
                        ▼
                 [互联网官方文档]  ←── 不信任，只取文本做摘要
```

| 边界 | 一侧 | 另一侧 | 控制措施 |
| --- | --- | --- | --- |
| B1 | 浏览器面板 | Host HTTP API | 只允许 loopback 同源（Origin/Host 校验，`lib/httpapi.js`）；GET 只读、POST 动作走白名单 |
| B2 | Host 插件 | PowerShell helper | 动作名白名单；参数写 JSON 文件而非命令行拼接；结果文件 JSON 解析后校验形状 |
| B3 | Host 插件 | Windows 系统 | 全部写操作经 `lib/privilege.js` 单点门控 + 管理员 helper；只写备份区/quarantine/白名单垃圾目录 |
| B4 | Host 插件 | 互联网 | 只读 GET 官方域名（`lib/calibrate.js` OFFICIAL_DOMAINS 白名单）；只发系统版本信息，不发文件路径/用户信息 |
| B5 | 备份目录 | 普通用户进程 | 隐藏属性 + ACL 拒绝删除 + manifest 镜像 + 巡查校验 |
| B6 | 用户 | 危险操作 | 面板二次确认（`confirm:true`）+ 提权 UAC |

## 2. 默认拒绝（A-03 / A-06）

- **动作默认拒绝**：`lib/core.js#dispatch` 只接受显式登记的动作名；未登记动作返回 `unknown-action`，不进入任何分支（有测试 `白名单外动作被拒`）。
- **权限默认拒绝**：`lib/privilege.js#assertSystemAction` 白名单外的动作抛 `PrivilegeError('privilege-denied')`；守护权限只含保护类动作（analyze/patrol/backup/restore/repair/…），不含任意命令执行。
- **网络默认拒绝**：HTTP 非本机同源请求一律 403；未登记的路径一律 404。
- **删除默认拒绝**：垃圾删除必须 `confirm:true` + 目录白名单 + 逐条判定；系统记忆类（`kind='memory'`）永久排除。
- **开放设计**：安全依赖代码白名单与哈希校验（integrity.json），不依赖本文档保密；源码公开（GitHub/Gitee/npm）。

## 3. 纵深防御（A-04 / A-07 / A-08）

| 关键资产 | 防线 1 | 防线 2 | 防线 3 |
| --- | --- | --- | --- |
| 系统文件写入 | `assertSystemAction` 动作白名单 | 管理员 UAC 提权（最小权限，按需） | 只写白名单目录（备份/quarantine/垃圾白名单） |
| 插件完整性 | `integrity.json` 16 文件 SHA-256 自校验 | 校验失败时**失败关闭**：拒绝全部写操作并告警 | 发布签名（Ed25519）+ SBOM + git tag |
| 隐藏备份 | `attrib +h +s` 隐藏 | ACL 拒绝普通用户删除 | 数据目录 `backup-mirror.json` 冗余清单 + 巡查缺失检测 |
| 危险操作 | 面板二次确认 | 权限白名单 + 提权 | 操作日志（state.json / lastError） |
| 垃圾删除 | 目录白名单 | 逐条路径校验 | `confirm:true` |

**最小权限**：插件进程以当前用户运行，不默认申请管理员；仅保护类动作在用户授权后经 UAC 提权；不读桌面/文档/下载等用户目录；不访问网络除官方文档。
**权限分离**：高风险动作（修复/还原/删除）同时需要「用户授权（UAC 或面板确认）」+「动作在保护白名单内」两个独立条件。

## 4. 输入校验与输出编码（E-01 / E-02 / E-05 / E-06 / E-07）

- HTTP 请求体上限 4 MiB（`MAX_BODY_BYTES`），超限直接断开；JSON.parse 失败返回 400。
- 动作参数逐个类型校验（`items[].path` 必须 string、`items` 非空、`confirm === true`）。
- 删除路径：`path.resolve` 规范化 + 目录白名单前缀匹配（TEMP、Windows\Temp、SoftwareDistribution\Download、Windows\Logs、Panther、WER、thumbcache）→ 防目录穿越与系统目录误删。
- 子进程：`spawn(powershell.exe, [参数数组])`，**不拼接 shell 字符串**；PS 参数经 JSON 文件传递，避免引号注入。
- 输出：前端用 React 文本节点（自动 HTML 转义）、JSON 走 `JSON.stringify`；错误只回传 message，不回传堆栈（G-02）。
- 反序列化：只解析自家写入的 JSON（settings/state/analysis/manifest），不解析不可信来源的结构化数据，不 eval。
- 文件上传：本项目无上传接口（N/A）。

## 5. 密码学与数据（D-01 / D-03 / D-06 / D-08）

- 只用 Node 内置 `node:crypto` 标准算法：SHA-256（完整性）、`crypto.sign`/Ed25519（发布签名）。
- 无自研加密；无口令存储；无会话令牌（本地插件，无账号体系；等价控制见第 2 节「网络默认拒绝」+ 同源校验）。
- 校验失败关闭：`integrity.json` 不匹配 → 拒绝写操作（fail-closed），不降级为跳过。
- 数据最小化：不采集文件内容（哈希除外）、不采集用户名/路径清单；联网校准只发送系统版本。
- 敏感数据不落明文：插件不存储任何密钥/令牌；发布私钥保存在 `$DSH_HOME/system-guard/release-ed25519.pem`（不在仓库、不在发布包）。

## 6. 供应链与发布（F-01 / F-02 / F-03 / F-04 / F-05 / F-08 / J-03 / J-04）

- **零第三方依赖**：`package.json` 无 dependencies；无 lockfile 需求（无可浮动版本）；全部代码为仓库内源码。
- **禁止非官方二进制**：不引入预编译二进制；`guard.ps1` 是仓库内文本脚本。
- **SBOM**：每次发布生成 `sbom.cdx.json`（CycloneDX 1.5，归档到仓库与发布说明）。
- **发布签名**：`scripts/sign-release.mjs` 用 Ed25519 对发布 tarball 签名，公钥 `keys/release.pub` 入库；发布时记录 SHA-256 + 签名，安装前可用公钥验证。
- **SLSA**：源码即产物（无编译、无网络构建依赖）；`integrity.json` 提供构建后/发布前两次哈希一致性；git tag `v1.0.0` 作为源版本锚点。
- **可分发自检（J-04）**：运行时路径全部由 `import.meta.url`、`os.tmpdir()`、`process.env.PUBLIC/DSH_HOME` 动态解析，无硬编码绝对路径；`npm pack` 后干净目录安装可启动（发布前实测）。

## 7. 配置与暴露面（G-02 / G-03 / G-06）

- 不监听端口（复用宿主 webServer）；只注册一个 prefix 路由 `/dsh-system-guard/api`。
- 无调试接口、无远程管理入口；错误响应不含堆栈。
- 文件权限：数据目录仅当前用户；备份目录 ACL 拒绝普通用户删除；quarantine 保留 30 天。
- 使用非管理员进程运行，提权按需。

## 8. 审计、告警与响应（H-01 / H-04 / H-05）

- 审计记录（`state.json`）：`lastAnalyzeAt`、`lastPatrolAt`、`lastCalibration`、`lastRepairAt`、`privilege.granted`、`lastError`；备份 manifest 记录每个文件哈希。
- 告警：面板警示（备份缺失/损坏、非豁免变化、自校验失败）；巡查结果可人工复核。
- 响应流程（README）：① 面板看「巡查结果」定位变化文件 → ② 点修复红点从备份还原 → ③ 仍异常则 SFC/DISM → ④ 备份缺失则立即备份重建；自校验失败则重装插件。

## 9. STRIDE 威胁建模摘要（I-01）

| 威胁 | 场景 | 控制 |
| --- | --- | --- |
| Spoofing | 伪造本机面板请求 | Origin/Host 同源校验 |
| Tampering | 篡改系统文件/插件代码 | 巡查 SHA-256 比对 + integrity 自校验 + 备份还原 |
| Repudiation | 否认做过危险操作 | state.json + 面板二次确认 |
| Information disclosure | 读取用户隐私 | 只扫系统目录、不读文件内容、不上传 |
| Denial of service | 扫描拖垮机器 | 深度/条目/超时预算 + 低优先级子进程 + 可取消 |
| Elevation of privilege | 借插件拿管理员权限做别的事 | 动作白名单 + 单点门控 + 只保护类动作 |

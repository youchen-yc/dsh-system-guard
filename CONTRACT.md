# 系统保护插件（dsh-system-guard）· 开发契约

> 本文件是并行开发的唯一接口契约。所有文件归属、数据结构、CLI/HTTP 协议以此为准；
> 实现前先读本文件，实现后逐条对照。**不得修改不属于自己的文件。**

---

## 1. 目标与产品边界（必须如实遵守）

**目标**：在 DSH Web 里做一个「系统守护」插件：分析系统文件、分类系统垃圾、备份核心系统文件、
定期巡查、发现损坏/篡改时告警并从备份修复、联网校准系统文件版本。

**诚实边界（写进 README 与界面文案，不得夸大）**

| 需求 | 能做到什么 | 做不到什么 |
| --- | --- | --- |
| 「最高权限」 | 用户点「授予守护权限」后弹 UAC，以管理员身份运行受控 helper；权限只经 `lib/privilege.js` 单点门控，动作白名单只含保护类操作 | 无法真正「凌驾于所有插件/内核之上」；不是操作系统级特权 |
| 「底层逻辑不可修改」 | 写死在 `lib/privilege.js` 的动作白名单 + 核心文件 SHA-256 自校验；被改则拒绝所有写操作并告警 | 本地源码对拥有文件写权限的用户终究可改；自校验只能发现，不能物理阻止 |
| 「拦截恶意篡改」 | 巡查发现核心文件哈希/大小异常时告警，并从隐藏备份还原 | 没有文件系统过滤驱动，不能在内核层阻断写入；只能在写入后检测+回滚 |
| 「备份被删除时拦截」 | 隐藏备份 + 冗余清单 + 删除检测告警 + 自愈重建 | 不能阻止管理员手动删除；只能检测并尽量恢复 |
| 「联网校准」 | 用 DSH `ctx.web` 搜官方渠道核对版本/支持状态并生成报告 | 微软等官方站不提供逐文件哈希清单，校准是「官方版本信息 + 本地完整性验证」，不是逐文件下载比对 |
| 巡检时效 | 插件随 DSH 进程运行；DSH 关闭期间不巡查 | 不是常驻系统服务，不注册 Windows 服务 |

不得为了「看起来满足需求」而写假结果：每个能力要么真跑命令，要么明确标注「未验证/不可用」。

### 1.5 安全、隐私与分发约束（用户明确要求，硬性）

**这是自己用也要发出去给别人用的插件，不是本机专用脚本。分析类操作必须守住下面红线。**

1. **只读分析**：分析 / 扫描 / 巡查阶段绝不修改系统文件、注册表、服务、计划任务；唯一允许的写入是插件数据目录与隐藏备份目录。
2. **不碰用户隐私**：不递归扫描桌面 / 文档 / 图片 / 下载 / 聊天记录 / 浏览器数据等用户目录；垃圾扫描只限系统临时与缓存目录；不读取、不统计、不上传任何用户文件内容。
3. **不硬编码本机**：路径一律由 `%SystemRoot%`、`os.homedir()`、环境变量解析；备份盘按「剩余容量最大」动态选择，绝不写死 `F:`；不假设用户名、盘符、语言、Administrator 目录。
4. **不误判**：拿不准的文件归 `support` 或写进 `warnings`，绝不因为拿不准就当垃圾建议删除；`kind='memory'` 的系统记忆类文件永不参与删除。
5. **资源自律**：扫描限制深度、条目数、超时（垃圾扫描 ≤60 秒，单个长任务 ≤180 秒），跳过 `WinSxS` / `Program Files` / 用户目录等巨型目录；PowerShell 子进程尽量低优先级（`Start-Process -Priority BelowNormal`），不让用户机器卡顿。
6. **可中断**：长任务必须响应 `AbortSignal`（`backend` 方法可接收 `{ signal }`，子进程要能 `kill`），面板提供「取消」。
7. **不编造**：扫描失败只写 `warnings`，不填空数据；报告里如实标注未验证项。
8. **权限最小化**：UAC 只在用户点击「授予守护权限」时弹；提权 helper 只接受白名单动作，不执行任意命令；临时文件用完清理，敏感输出不进日志。
9. **联网只读**：校准只访问官方文档/接口，只发送系统版本信息，不发送文件路径清单或用户信息。

**分发要求**

10. 零第三方依赖、纯 ESM、Node ≥20；helper 脚本随包携带，不依赖本机外部脚本。
11. 除插件数据目录与用户选定的备份目录外不写任何位置；卸载后数据目录保留可手动删（README 说明）。
12. `package.json` 的 `version` / `description` / `license` / `author` / `keywords` 完整；提供 `LICENSE`（MIT）与 README（中文为主）。
13. 图标、locale 为原创资源；不打包本机测试产物。
14. 数据目录固定为 `$DSH_HOME/system-guard`（或配置的 `dataDir`），多机器自适应。

---

## 2. 目录与文件归属（严格互斥）

```
system-guard/
├─ package.json / cordis.patch.yml / index.js / CONTRACT.md / README.md   ← Lead
├─ lib/config.js            ← Lead   配置读写
├─ lib/privilege.js         ← Lead   权限门控 + 不可变底层逻辑 + 自校验
├─ lib/core.js              ← Lead   平台路由、状态机、任务队列编排
├─ lib/patrol.js            ← Lead   巡查编排、定时器
├─ lib/httpapi.js           ← Lead   HTTP 路由与 dispatch
├─ client.js                ← ui     主面板 + 侧栏图标
├─ locale/en.json, zh.json  ← ui
├─ icon.svg                 ← ui
├─ lib/ps.js                ← win-sys PowerShell 执行封装
├─ lib/win-backend.js       ← win-sys Windows backend
├─ scripts/guard.ps1        ← win-sys Windows 动作分发脚本（核心）
├─ test/win-live.mjs        ← win-sys 真机只读验证脚本
├─ lib/posix-backend.js     ← posix  macOS/Linux backend
├─ lib/calibrate.js         ← posix  联网校准
└─ test/selftest.mjs        ← posix  纯逻辑/契约自测
```

**硬规则**

- 只写自己的文件；`index.js`、`package.json` 由 Lead 独立维护，队友**不得**修改。
- 零第三方依赖：只用 Node 20 内置模块 + 全局 `fetch` + PowerShell 自带命令。
- ESM（`"type": "module"`），中文注释用简体（「進/漢/蕐/厦」四个字除外）。
- 不运行 `pnpm`、不装包、不改 `$DSH_HOME` / profile 下的任何文件。
- 所有系统副作用型操作必须可 dry-run 或至少可解释；测试时只能用只读动作。
- 报告要如实：跑了什么命令、结果如何、哪些没验证。

---

## 3. 统一数据结构（JSON 可序列化，跨平台一致）

### Probe（系统事实）

```json
{
  "platform": "windows",
  "osName": "Microsoft Windows 10 专业工作站版",
  "osVersion": "10.0.19045",
  "osBuild": "19045",
  "arch": "AMD64",
  "admin": false,
  "systemRoot": "C:\\Windows",
  "systemDrive": "C:",
  "volumes": [
    { "id": "F:", "label": "游戏", "fs": "NTFS",
      "totalBytes": 333447168000, "freeBytes": 185660000000, "isSystem": false }
  ],
  "tools": { "sfc": true, "dism": true, "wbadmin": false, "vssadmin": true,
             "bcdedit": true, "checkpoint": true, "takeown": true, "icacls": true },
  "updateWindow": { "from": "2026-10-01T00:00:00.000Z", "to": "2026-10-27T00:00:00.000Z" },
  "warnings": []
}
```

- `updateWindow`：最近一次 Windows 更新/补丁安装时间往前推
  `excludeUpdateWindowMinutes`（默认 1440 分钟）形成的窗口，用于巡查豁免；没有则 `null`。
- `admin` 必须真实检测；`tools` 为「命令是否可用」的布尔值。

### FileRef（一个受保护的系统文件）

```json
{ "id": "kernel-ntoskrnl", "path": "C:\\Windows\\System32\\ntoskrnl.exe",
  "role": "core", "group": "kernel", "size": 12345, "sha256": "…",
  "version": "10.0.19041.1", "critical": true, "exists": true }
```

- `role`：`core`（核心，坏了系统起不来或运行异常）| `support`（普通系统文件）| `memory`（系统记忆类）| `junk`（垃圾）。
- `critical=true` 的文件缺失/变更必须告警，并进入可修复集合。

### JunkGroup（垃圾与系统记忆分类）

```json
{ "id": "temp-user", "title": "用户临时文件", "kind": "junk", "note": "删掉不影响系统运行",
  "safeToDelete": true,
  "items": [ { "id": "temp-user-001", "path": "C:\\Users\\…\\Temp\\a.tmp", "size": 123, "exists": true } ],
  "totalBytes": 123, "itemCount": 1 }
```

- `kind`：`junk`（可删除，用户打钩后删）| `memory`（系统记忆类：转储、休眠、崩溃日志等，
  **只展示、不参与删除**）。
- `items` 最多返回 3000 条（超出的统计进 `totalBytes`/`itemCount`，并在 `note` 里说明）。
- 每一项必须是真实存在且可访问的路径；扫描失败写进 `warnings`，不得编造。

### Analysis（`analyze` 结果）

```json
{ "analyzedAt": 1761555000000, "durationMs": 1234,
  "coreCount": 412, "coreBytes": 123456789,
  "supportCount": 1200, "supportBytes": 0,
  "files": [FileRef…],          // 最多 800 条，核心文件优先
  "groups": [JunkGroup…],
  "totalJunkBytes": 0,
  "baselineSource": "builtin",  // builtin | calibrated
  "calibratedAt": null,
  "warnings": [] }
```

### PatrolReport（巡查）

```json
{ "checkedAt": 1761555000000, "durationMs": 12345, "total": 412, "unchanged": 400,
  "changed": [ { "path": "…", "expectedSha": "…", "actualSha": "…",
                 "exempted": true, "reason": "windows-update-window" } ],
  "missing": ["C:\\Windows\\System32\\…"],
  "verdict": "healthy",   // healthy | changed | damaged | unknown
  "sfc": { "ran": false, "passed": null, "detail": "" },
  "backup": { "state": "ok" },   // ok | none | missing | partial
  "warnings": [] }
```

- `changed[].exempted=true` 表示本次变化落在更新窗口内（视为 Windows 更新导致，**不告警、不修复**）。
- `verdict`：有 `exempted` 变化仍算 `healthy`；有非豁免变化为 `changed`；缺失/损坏为 `damaged`；
  无法判断为 `unknown`。

### BackupInfo（备份状态）

```json
{ "root": "F:\\SystemGuardBackup\\.system-guard",
  "hidden": true, "volume": "F:", "createdAt": 1761555000000,
  "fileCount": 412, "totalBytes": 123456789, "manifestPath": "…\\manifest.json",
  "state": "ok",   // ok | none | missing | partial
  "verifiedAt": 1761555000000,
  "missingFiles": [], "corruptFiles": [] }
```

### RepairReport（修复）

```json
{ "ok": true,
  "mode": "restore",   // restore | sfc | dism | restore-point | backup
  "actions": [ { "step": "restore:C:\\Windows\\System32\\ntdll.dll", "ok": true, "detail": "" } ],
  "output": "命令输出的截断文本（≤4000 字）",
  "warnings": [] }
```

### DeleteReport（删除垃圾）

```json
{ "requested": 5, "deleted": ["C:\\…\\a.tmp"],
  "failed": [ { "path": "C:\\…\\b.tmp", "error": "access-denied" } ],
  "freedBytes": 12345, "elevated": true }
```

### Facts（校准输入）

```json
{ "platform": "windows", "osName": "…", "osVersion": "10.0.19045", "osBuild": "19045",
  "arch": "AMD64",
  "files": [ { "path": "C:\\Windows\\System32\\ntoskrnl.exe", "version": "10.0.19041.1",
               "sha256": "…" } ],
  "warnings": [] }
```

### CalibrationReport（校准输出）

```json
{ "ok": true, "checkedAt": 1761555000000,
  "sources": [ { "title": "Windows release health", "url": "https://…" } ],
  "findings": [ { "level": "info", "text": "…", "source": "https://…" } ],
  "summary": "一句话结论", "note": "校准方法说明（见 §1 边界）" }
```

失败时返回 `{ "ok": false, "error": { "code": "…", "message": "…" } }`，**不得伪造检查结果**。

---

## 4. Backend 接口（每个平台模块导出同名函数）

`lib/win-backend.js` 导出 `createWindowsBackend(options)`；
`lib/posix-backend.js` 导出 `createPosixBackend(options)`。
两者返回同一形状的对象（`options` 由 `lib/core.js` 传入）：

```js
{
  platform: 'windows' | 'macos' | 'linux',
  async probe(): Probe,
  async analyze({ files }): Analysis,          // 首次分析：清单+分类+垃圾
  async patrol({ baseline, opts }): PatrolReport,
  async junkScan(): JunkReport,                // { groups, totalBytes, warnings }
  async junkDelete({ items }): DeleteReport,   // items: [{path}]
  async backup({ files }): BackupInfo,
  async backupStatus(): BackupInfo,
  async restore({ paths }): RepairReport,
  async repair({ mode, paths }): RepairReport, // mode: sfc | dism | restore-point
  async calibrateFacts(): Facts,
  async dispose(): void,
}
```

`options` 包含：`{ dataDir, config, log, elevated }`；`config` 是已解析的插件配置对象；
`log` 至少提供 `warn`/`info`。

**实现建议（Windows）**：Node 侧只做参数准备与 JSON 解析；所有系统读写都交给
`scripts/guard.ps1`（见 §5）。这样提权与非提权路径完全一致。

---

## 5. `scripts/guard.ps1` 协议（Windows 唯一系统入口）

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File guard.ps1 \
  -Action <action> -OutFile <result.json> [-Params <params.json>] [-TimeoutSec <n>]
```

- `-Params`：JSON 参数文件（UTF-8，避免命令行引号/长度问题），内容为对象。
- 结果**必须**写入 `-OutFile`（UTF-8 无 BOM）：
  - 成功：`{ "ok": true, "action": "analyze", "value": {…} }`
  - 失败：`{ "ok": false, "action": "analyze", "error": { "code": "…", "message": "…" } }`
- 进程退出码：0 = 结果文件已写（无论 ok 真假）；非 0 = helper 本身崩溃，Node 侧报错。
- **不得**在 stdout 里塞业务数据（stdout 只留给日志）。

动作清单（与 §4 一一对应）：
`probe` `analyze` `patrol` `junk-scan` `junk-delete` `backup` `backup-status`
`restore` `repair` `calibrate-facts` `restore-point`

`analyze` / `patrol` 的 `-Params` 可能带 `{ "files": [FileRef…] }`（已存在的基线清单，用于增量检查）。

---

## 6. HTTP API（Client ↔ Host，同源，仅本机）

前缀 `/dsh-system-guard/api`：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/state` | 全量状态：`{ ok, settings, probe, analysis, backup, lastPatrol, lastCalibrate, tasks, privilege }` |
| POST | `/action` | body `{ action, payload? }`，短操作直接返回 `{ ok, value }`，长操作返回 `{ ok, taskId }` |
| GET | `/task?id=` | `{ ok, task: { id, kind, state, startedAt, finishedAt, progress, result, error } }` |
| GET | `/events` | 保留（可不实现） |

`action` 取值：`analyze` `patrol` `backup` `backup-status` `junk-scan` `junk-delete`
`repair` `restore-point` `calibrate` `settings-save` `elevate` `reset-baseline` `cancel-task`

长任务集合：`analyze` `patrol` `backup` `repair` `junk-scan`（返回 `taskId`，UI 轮询 `/task`）。
`repair` 需要管理员；无权限时返回
`{ ok:false, error:{ code:"need-elevation", message:"需要管理员权限，请在面板点「授予守护权限」" } }`。

---

## 7. 工具（Agent 侧）

工具名 `system_guard`，参数 `{ action, payload? }`，`action` 与 §6 相同（不含 `elevate` /
`settings-save` 之外的写操作，`junk-delete` 必须带 `confirm: true`）。
工具返回 `{ ok, value | error }`；长任务工具同步等待完成（`repair`/`patrol` 可设超时）。

---

## 8. 权限门控（`lib/privilege.js`，Lead 实现，其他模块调用）

```js
import { PRIVILEGE_POLICY, assertSystemAction, selfCheck } from './privilege.js'
```

- `PRIVILEGE_POLICY`：冻结（`Object.freeze`）的常量对象，含
  `allowedActions`（保护类动作白名单）、`forbidden`（描述禁止的用途）、`version`。
- `assertSystemAction(action)`：动作不在白名单 → 抛 `PrivilegeError`。
  **所有**会写系统（备份、恢复、删除、修复、提权）的调用前必须过它。
- `selfCheck({ dataDir })`：校验本插件核心文件哈希（`integrity.json`，Lead 生成），
  被改则返回 `{ ok: false, tampered: [...] }`，写操作被拒绝。
- 提权入口：`requestElevation()` 返回 `{ ok, message }`（Windows 上触发 UAC helper；
  其他系统返回 `{ ok:false, code:'unsupported' }`）。

---

## 9. 开发与验证要求

- 每个模块写完后：`node --check <file>`（JS）与 PowerShell 语法检查
  （`[System.Management.Automation.Language.Parser]::ParseFile`）。
- `test/win-live.mjs`：只读动作真机验证（probe / analyze 的清单与垃圾扫描），输出 PASS/FAIL 明细。
- `test/selftest.mjs`：不依赖平台的纯逻辑与契约校验（数据结构形状、白名单、校准解析）。
- 完成报告格式：`完成项 / 未完成项 / 真机验证结果 / 需要 Lead 集成的事项`。

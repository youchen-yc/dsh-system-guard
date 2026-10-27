/**
 * dsh-system-guard · POSIX（macOS / Linux）系统 backend
 *
 * ⚠️ 诚实声明（请勿删除）：本文件是在 Windows 开发机上编写的，
 * **没有在真实 macOS / Linux 机器上运行验证过**。本机只验证了：
 *   1) 在 Windows 上被调用时 probe() 等不崩、返回结构合法（降级路径）；
 *   2) 纯逻辑/契约自测 `test/selftest.mjs`（不联网、不依赖 POSIX 命令）。
 * 因此实现刻意保持「声明式、可解释、防御式」：
 *   - 声明式：核心文件清单、垃圾目录分组写死在模块顶部，没有隐式魔法；
 *   - 可解释：所有 shell 调用都走 execFile(命令, 参数数组)（不拼字符串），
 *     单次子进程超时 ≤20 秒，失败一律写进 warnings，不抛给上层；
 *   - 防御式：扫描有深度（≤3 层）、条目数、时间预算上限，不跟随符号链接，
 *     **不删除任何东西**（junkDelete 统一返回 unsupported-on-platform）。
 *   - 可中断：所有长任务接收 { signal }（AbortSignal），子进程带 signal 可被 kill，
 *     取消时抛出 code='aborted' 的错误交给 core 标记「已取消」。
 *
 * 与 Windows backend 的差异（如实标注）：
 *   - 没有 VSS / SFC 等价物；macOS 的系统文件修复只能走「恢复模式」，
 *     所以 repair() 对 macOS 返回 { ok:false, error:{ code:'manual-required' } }，
 *     不假装修好了；
 *   - Linux 的完整性校验用发行版自带包管理器（debsums / rpm -Va），
 *     但**不自动执行重装**（apt-get install --reinstall 只提示，不代跑）；
 *   - POSIX 上「系统更新窗口」没有可靠来源，故 updateWindow 恒为 null，
 *     巡查的 exempted 恒为 false（宁可多报，不假装豁免）。
 *
 * 隐私与分发（CONTRACT §1.5）：本文件不硬编码任何本机路径/用户名/盘符，
 * 只扫描系统临时与缓存目录（不递归桌面/文档/下载等用户目录），
 * 只读、不读取文件内容（除计算哈希之外），不上传任何数据。
 */

import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createReadStream, constants as fsConstants, promises as fsp } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

// ---------------------------------------------------------------------------
// 常量与上限（改这些数值前请先想清楚扫描成本）
// ---------------------------------------------------------------------------

/** 单次 shell 调用的超时上限（契约要求 ≤20s）。 */
const SHELL_TIMEOUT_MS = 20000
const DF_TIMEOUT_MS = 8000
const SUDO_PROBE_TIMEOUT_MS = 3000
const SW_VERS_TIMEOUT_MS = 5000

/** 资源自律（CONTRACT §1.5）：垃圾扫描 ≤60s，其它单动作 ≤180s。 */
const JUNK_SCAN_TIMEOUT_MS = 60000
const ACTION_TIMEOUT_MS = 180000

/** 单个文件超过这个大小就不算哈希（避免卡在巨型日志/镜像上）。 */
const MAX_HASH_BYTES = 64 * 1024 * 1024
const MAX_ANALYSIS_FILES = 800
const MAX_ITEMS_PER_GROUP = 3000
const MAX_SCAN_ENTRIES_PER_GROUP = 8000
const MAX_SCAN_DEPTH = 3
const MAX_FACTS_FILES = 50
const MAX_GLOB_MATCHES = 4
const MAX_REPAIR_OUTPUT = 4000
const MAX_WARNINGS = 200

const BACKUP_DIR_NAME = '.system-guard'
const BACKUP_MANIFEST_NAME = 'manifest.json'
const BACKUP_POINTER_NAME = 'posix-backup.json'

/** 命令探测结果缓存（同一个进程里只扫一次 PATH）。 */
const executableCache = new Map()

// ---------------------------------------------------------------------------
// 平台识别
// ---------------------------------------------------------------------------

/** 识别当前（或注入的）平台；只认 windows / macos / linux，其他原样返回。 */
export function detectPosixPlatform() {
  if (process.platform === 'win32') return 'windows'
  if (process.platform === 'darwin') return 'macos'
  if (process.platform === 'linux') return 'linux'
  return process.platform
}

function isPosixPlatform(platform) {
  return platform === 'linux' || platform === 'macos'
}

// ---------------------------------------------------------------------------
// 核心文件清单（声明式，写死；未在真实 macOS/Linux 验证过路径细节）
// ---------------------------------------------------------------------------

/** Linux 核心文件：kernel / init / shell / 认证 / 动态链接器 / 关键库 / 配置。 */
export const LINUX_CORE_FILES = Object.freeze([
  { id: 'kernel-vmlinuz', glob: { dir: '/boot', prefix: 'vmlinuz' }, group: 'kernel', critical: true },
  { id: 'kernel-initrd', glob: { dir: '/boot', prefix: 'initrd' }, group: 'kernel', critical: true },
  // RHEL/Fedora 系用 initramfs-* 命名，单独列一条避免漏检。
  { id: 'kernel-initramfs', glob: { dir: '/boot', prefix: 'initramfs' }, group: 'kernel', critical: true },
  { id: 'kernel-modules', path: '/lib/modules', group: 'kernel', critical: true, directory: true },
  { id: 'systemd', path: '/usr/lib/systemd/systemd', group: 'init', critical: true },
  { id: 'systemd-journald', path: '/usr/lib/systemd/systemd-journald', group: 'init', critical: false },
  { id: 'bash', candidates: ['/usr/bin/bash', '/bin/bash'], group: 'shell', critical: false },
  { id: 'fstab', path: '/etc/fstab', group: 'config', critical: true },
  { id: 'passwd', path: '/etc/passwd', group: 'auth', critical: true },
  // /etc/shadow 只读元数据（大小/存在性），不读内容、不算哈希。
  { id: 'shadow', path: '/etc/shadow', group: 'auth', critical: true, metadataOnly: true },
  { id: 'os-release', path: '/etc/os-release', group: 'config', critical: false },
  { id: 'resolv-conf', path: '/etc/resolv.conf', group: 'config', critical: false },
  {
    id: 'ld-linux',
    candidates: [
      '/lib64/ld-linux-x86-64.so.2',
      '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
      '/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1',
      '/lib/ld-linux.so.2',
    ],
    group: 'loader',
    critical: true,
  },
  {
    id: 'libc',
    candidates: ['/lib/x86_64-linux-gnu/libc.so.6', '/lib64/libc.so.6', '/lib/aarch64-linux-gnu/libc.so.6'],
    group: 'libs',
    critical: true,
  },
  { id: 'sudo', candidates: ['/usr/bin/sudo', '/bin/sudo'], group: 'tool', critical: false },
  { id: 'dpkg', path: '/usr/bin/dpkg', group: 'pkg', critical: false },
])

/** macOS 核心文件：内核 / 引导 / 动态链接器 / launchd / 关键配置。 */
export const MACOS_CORE_FILES = Object.freeze([
  { id: 'mach-kernel', path: '/System/Library/Kernels/kernel', group: 'kernel', critical: true },
  { id: 'dyld', path: '/usr/lib/dyld', group: 'loader', critical: true },
  { id: 'launchd', path: '/sbin/launchd', group: 'init', critical: true },
  { id: 'opendirectoryd', path: '/usr/libexec/opendirectoryd', group: 'service', critical: false },
  { id: 'coreservices', path: '/System/Library/CoreServices', group: 'system', critical: true, directory: true },
  {
    id: 'system-version',
    path: '/System/Library/CoreServices/SystemVersion.plist',
    group: 'config',
    critical: true,
  },
  { id: 'etc-passwd', path: '/private/etc/passwd', group: 'auth', critical: true },
  { id: 'etc-hosts', path: '/private/etc/hosts', group: 'config', critical: false },
  { id: 'etc-fstab', path: '/private/etc/fstab', group: 'config', critical: false },
  { id: 'etc-sshd-config', path: '/private/etc/ssh/sshd_config', group: 'config', critical: false },
  { id: 'etc-sudoers', path: '/private/etc/sudoers', group: 'config', critical: false },
  { id: 'libSystem', path: '/usr/lib/libSystem.B.dylib', group: 'libs', critical: true },
  { id: 'bash', path: '/bin/bash', group: 'shell', critical: false },
  { id: 'securityd', path: '/usr/libexec/securityd', group: 'service', critical: false },
  { id: 'efi-boot', path: '/System/Library/CoreServices/boot.efi', group: 'boot', critical: true },
])

/** 供自测/外部使用的声明清单（冻结，避免被误改）。 */
export const POSIX_CORE_FILES = Object.freeze({
  linux: LINUX_CORE_FILES,
  macos: MACOS_CORE_FILES,
})

// ---------------------------------------------------------------------------
// 垃圾 / 系统记忆分组（声明式，只统计不删除）
// ---------------------------------------------------------------------------

/** Linux 垃圾分组：/tmp、/var/tmp、/var/log、包缓存、用户缓存、回收站。 */
export const LINUX_JUNK_GROUPS = Object.freeze([
  {
    id: 'tmp',
    title: '/tmp 临时文件',
    kind: 'junk',
    note: '系统与运行中程序可能正在使用，默认只统计、不删除',
    safeToDelete: false,
    roots: ['/tmp'],
  },
  {
    id: 'var-tmp',
    title: '/var/tmp 持久临时文件',
    kind: 'junk',
    note: '重启后仍保留的临时文件，默认只统计、不删除',
    safeToDelete: false,
    roots: ['/var/tmp'],
  },
  {
    id: 'var-log',
    title: '/var/log 系统日志',
    kind: 'junk',
    note: '日志便于排障，只统计不删除',
    safeToDelete: false,
    roots: ['/var/log'],
  },
  {
    id: 'apt-archives',
    title: 'APT 软件包缓存',
    kind: 'junk',
    note: 'deb 安装包缓存，删掉不影响系统运行（可用 apt clean 清理）',
    safeToDelete: true,
    roots: ['/var/cache/apt/archives'],
  },
  {
    id: 'pacman-pkg',
    title: 'Pacman 软件包缓存',
    kind: 'junk',
    note: 'Arch 安装包缓存，删掉不影响系统运行（可用 pacman -Sc 清理）',
    safeToDelete: true,
    roots: ['/var/cache/pacman/pkg'],
  },
  {
    id: 'user-cache',
    title: '用户缓存目录',
    kind: 'junk',
    note: '应用缓存，删掉通常只会让应用重新生成',
    safeToDelete: true,
    roots: ['~/.cache'],
  },
  {
    id: 'trash',
    title: '回收站',
    kind: 'junk',
    note: '清空后不可恢复，请确认里面没有要找回的文件',
    safeToDelete: true,
    roots: ['~/.local/share/Trash'],
  },
  {
    id: 'journal',
    title: 'systemd journal 日志',
    kind: 'memory',
    note: '系统记忆类：journal 日志只展示、不参与删除',
    safeToDelete: false,
    roots: ['/var/log/journal'],
  },
  {
    id: 'crash',
    title: '崩溃转储与 coredump',
    kind: 'memory',
    note: '系统记忆类：崩溃转储只展示、不参与删除',
    safeToDelete: false,
    roots: ['/var/crash', '/var/lib/systemd/coredump', '/var/log/dmesg'],
  },
])

/** macOS 垃圾分组：缓存 / 系统临时目录 / 回收站 / 日志 / 崩溃转储。 */
export const MACOS_JUNK_GROUPS = Object.freeze([
  {
    id: 'user-caches',
    title: '用户缓存（~/Library/Caches）',
    kind: 'junk',
    note: '应用缓存，删掉通常只会让应用重新生成',
    safeToDelete: true,
    roots: ['~/Library/Caches'],
  },
  {
    id: 'system-caches',
    title: '系统缓存（/Library/Caches）',
    kind: 'junk',
    note: '系统级缓存，清理通常需要管理员权限',
    safeToDelete: false,
    roots: ['/Library/Caches'],
  },
  {
    id: 'system-temp',
    title: '系统临时目录（/private/var/folders）',
    kind: 'junk',
    note: '系统临时目录，涉及运行中应用，只统计不删除',
    safeToDelete: false,
    roots: ['/private/var/folders'],
  },
  {
    id: 'trash',
    title: '废纸篓',
    kind: 'junk',
    note: '清空后不可恢复，请确认里面没有要找回的文件',
    safeToDelete: true,
    roots: ['~/.Trash'],
  },
  {
    id: 'var-log',
    title: '/var/log 系统日志',
    kind: 'junk',
    note: '日志便于排障，只统计不删除',
    safeToDelete: false,
    roots: ['/var/log'],
  },
  {
    id: 'user-logs',
    title: '用户日志（~/Library/Logs）',
    kind: 'junk',
    note: '应用日志，通常可安全清理',
    safeToDelete: true,
    roots: ['~/Library/Logs'],
  },
  {
    id: 'cores',
    title: '核心转储（/cores）',
    kind: 'memory',
    note: '系统记忆类：崩溃核心转储只展示、不参与删除',
    safeToDelete: false,
    roots: ['/cores'],
  },
  {
    id: 'panic-logs',
    title: '崩溃报告（DiagnosticReports）',
    kind: 'memory',
    note: '系统记忆类：崩溃报告只展示、不参与删除',
    safeToDelete: false,
    roots: ['/Library/Logs/DiagnosticReports', '~/Library/Logs/DiagnosticReports'],
  },
  {
    id: 'diagnostics',
    title: '系统诊断数据（/var/db/diagnostics）',
    kind: 'memory',
    note: '系统记忆类：诊断数据只展示、不参与删除',
    safeToDelete: false,
    roots: ['/var/db/diagnostics'],
  },
])

/** 供自测/外部使用的声明清单（冻结）。 */
export const POSIX_JUNK_GROUPS = Object.freeze({
  linux: LINUX_JUNK_GROUPS,
  macos: MACOS_JUNK_GROUPS,
})

/** 支持文件（role=support）扫描目录；只 stat 不算哈希。 */
const LINUX_SUPPORT_DIRS = Object.freeze([
  { dir: '/usr/bin', limit: 250 },
  { dir: '/usr/sbin', limit: 150 },
  { dir: '/etc', limit: 250 },
  { dir: '/usr/lib/systemd/system', limit: 150 },
])

const MACOS_SUPPORT_DIRS = Object.freeze([
  { dir: '/private/etc', limit: 200 },
  { dir: '/usr/libexec', limit: 200 },
  { dir: '/System/Library/LaunchDaemons', limit: 200 },
  { dir: '/Library/LaunchDaemons', limit: 200 },
])

// ---------------------------------------------------------------------------
// 基础工具：错误、预算、取消
// ---------------------------------------------------------------------------

/** 任务被取消时抛出的错误（core 依据 code==='aborted' 把任务标为「已取消」）。 */
function abortError() {
  const error = new Error('任务已被用户取消。')
  error.code = 'aborted'
  return error
}

/** 建立一个「时间预算」：signal 用于取消，deadline 用于资源自律上限。 */
function createBudget(signal, timeoutMs) {
  const safeTimeout = Math.max(1000, Number(timeoutMs) || ACTION_TIMEOUT_MS)
  return {
    signal: signal && typeof signal === 'object' ? signal : null,
    timeoutMs: safeTimeout,
    deadline: Date.now() + safeTimeout,
    expired: false,
  }
}

/** 已被取消则抛 aborted；返回 true 表示时间预算用完（调用方应停止扫描）。 */
function budgetExpired(budget) {
  if (budget && budget.signal && budget.signal.aborted) throw abortError()
  if (!budget) return false
  if (budget.expired) return true
  if (Date.now() > budget.deadline) {
    budget.expired = true
    return true
  }
  return false
}

/** 时间预算用尽时写一条 warning（结果不完整要如实说明）。 */
function noteBudgetExceeded(budget, warnings) {
  const seconds = Math.round((budget?.timeoutMs || ACTION_TIMEOUT_MS) / 1000)
  pushWarning(warnings, `已达到本动作时间上限（${seconds} 秒），结果可能不完整（资源自律限制）。`)
}

/** 截断文本（结果里只保留可读长度）。 */
function truncate(text, max = MAX_REPAIR_OUTPUT) {
  const value = typeof text === 'string' ? text : String(text ?? '')
  return value.length > max ? `${value.slice(0, max)}\n…（已截断）` : value
}

/** 统一的错误描述：带 code 时给出 code。 */
function describeError(error) {
  if (!error) return '未知错误'
  const code = error.code || error.name || ''
  const message = error.message || String(error)
  return code ? `${code}: ${message}` : message
}

/** 往 warnings 里追加（去重 + 上限），避免刷屏。 */
function pushWarning(warnings, message) {
  if (!warnings || typeof message !== 'string' || !message) return
  if (warnings.includes(message)) return
  if (warnings.length >= MAX_WARNINGS) return
  warnings.push(message)
}

/** 判断路径是否存在（不区分文件/目录）。 */
async function pathExists(target) {
  try {
    await fsp.access(target)
    return true
  } catch {
    return false
  }
}

/** lstat，不存在时返回 null（其他错误也返回 null，由调用方决定是否告警）。 */
async function lstatOrNull(target) {
  try {
    return await fsp.lstat(target)
  } catch {
    return null
  }
}

/** 计算文件 sha256（流式，不整文件读进内存；支持取消）。 */
async function sha256File(filePath, signal = null) {
  const hash = createHash('sha256')
  const stream = createReadStream(filePath)
  try {
    for await (const chunk of stream) {
      if (signal && signal.aborted) {
        stream.destroy()
        throw abortError()
      }
      hash.update(chunk)
    }
  } finally {
    stream.destroy()
  }
  return hash.digest('hex')
}

/** 求和 FileRef 的 size（目录/未知按 0 计）。 */
function sumSizes(files) {
  let total = 0
  for (const file of files || []) {
    if (file && Number.isFinite(file.size)) total += file.size
  }
  return total
}

/** 读文本文件；optional=true 时 ENOENT 不写 warning。 */
async function readTextFile(filePath, warnings, { optional = false, label = filePath } = {}) {
  try {
    return await fsp.readFile(filePath, 'utf8')
  } catch (error) {
    if (!(optional && (error?.code === 'ENOENT' || error?.code === 'ENOTDIR'))) {
      pushWarning(warnings, `无法读取 ${label}：${error?.code || error?.message}`)
    }
    return null
  }
}

/** 从 PATH 里探测命令是否可用（不执行命令，只有 stat）。 */
async function hasExecutable(name) {
  if (typeof name !== 'string' || !name) return false
  if (executableCache.has(name)) return executableCache.get(name)
  const candidates = []
  if (name.includes('/')) {
    candidates.push(name)
  } else {
    const dirs = String(process.env.PATH || '').split(path.delimiter).filter(Boolean)
    for (const dir of dirs) candidates.push(path.join(dir, name))
  }
  let found = false
  for (const candidate of candidates) {
    try {
      await fsp.access(candidate, fsConstants.X_OK)
      found = true
      break
    } catch {
      /* 继续找下一个候选 */
    }
  }
  executableCache.set(name, found)
  return found
}

/**
 * 用 execFile 跑一个命令（参数数组，不拼 shell 字符串）。
 * 永远 resolve，不 reject；失败信息放在返回值里；支持 AbortSignal（会 kill 子进程）。
 */
function runFile(command, args, { timeout = SHELL_TIMEOUT_MS, signal = null } = {}) {
  return new Promise((resolve) => {
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      resolve(value)
    }
    const options = { timeout, maxBuffer: 8 * 1024 * 1024, windowsHide: true }
    if (signal) options.signal = signal
    try {
      execFile(
        command,
        Array.isArray(args) ? args : [],
        options,
        (error, stdout, stderr) => {
          const out = typeof stdout === 'string' ? stdout : String(stdout ?? '')
          const err = typeof stderr === 'string' ? stderr : String(stderr ?? '')
          if (error) {
            const aborted = error.name === 'AbortError' || error.code === 'ABORT_ERR'
              || Boolean(signal && signal.aborted)
            const timedOut = error.killed === true || error.signal === 'SIGTERM'
            finish({
              ok: false,
              exitCode: typeof error.code === 'number' ? error.code : null,
              code: typeof error.code === 'string'
                ? error.code
                : (typeof error.code === 'number' ? `exit-${error.code}` : 'unknown'),
              stdout: out,
              stderr: err,
              timedOut,
              aborted,
              message: error.message || String(error),
            })
            return
          }
          finish({
            ok: true, exitCode: 0, code: 'ok', stdout: out, stderr: err, timedOut: false, aborted: false, message: '',
          })
        },
      )
    } catch (error) {
      finish({
        ok: false,
        exitCode: null,
        code: 'spawn-failed',
        stdout: '',
        stderr: '',
        timedOut: false,
        aborted: false,
        message: describeError(error),
      })
    }
  })
}

/** 子进程若因取消而结束，直接抛 aborted 交给 core。 */
function rethrowIfAborted(result) {
  if (result && result.aborted) throw abortError()
}

// ---------------------------------------------------------------------------
// 系统事实采集
// ---------------------------------------------------------------------------

/** 解析 /etc/os-release（KEY="value" 形式）。 */
function parseOsRelease(text) {
  const result = {}
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line)
    if (!match) continue
    let value = match[2].trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    result[match[1]] = value
  }
  return result
}

/** 读取系统标识（Linux 读 /etc/os-release，macOS 跑 sw_vers）。 */
async function readOsIdentity(platform, warnings, signal = null) {
  if (platform === 'macos') {
    const res = await runFile('sw_vers', [], { timeout: SW_VERS_TIMEOUT_MS, signal })
    rethrowIfAborted(res)
    const parsed = {}
    if (res.ok) {
      for (const line of res.stdout.split(/\r?\n/)) {
        const match = /^(ProductName|ProductVersion|BuildVersion):\s*(.+)$/.exec(line.trim())
        if (match) parsed[match[1]] = match[2].trim()
      }
    } else {
      pushWarning(warnings, `sw_vers 不可用（${res.code}），系统标识降级为 os 模块信息。`)
    }
    return {
      osName: parsed.ProductName || `macOS ${os.release()}`,
      osVersion: parsed.ProductVersion || os.release(),
      osBuild: parsed.BuildVersion || '',
    }
  }
  if (platform === 'linux') {
    const text = await readTextFile('/etc/os-release', warnings, { optional: true })
    const parsed = text ? parseOsRelease(text) : {}
    return {
      osName: parsed.PRETTY_NAME || parsed.NAME || `Linux ${os.release()}`,
      osVersion: parsed.VERSION_ID || '',
      osBuild: os.release(),
    }
  }
  return {
    osName: `${os.type()} ${os.release()}`,
    osVersion: os.release(),
    osBuild: '',
  }
}

/** 探测管理员权限：root 或 passwordless sudo（不阻塞等密码）。 */
async function detectAdmin(platform, warnings, signal = null) {
  if (typeof process.getuid === 'function' && process.getuid() === 0) return true
  if (!isPosixPlatform(platform)) return false
  const res = await runFile('sudo', ['-n', 'true'], { timeout: SUDO_PROBE_TIMEOUT_MS, signal })
  rethrowIfAborted(res)
  if (res.ok) return true
  if (res.code === 'ENOENT') {
    pushWarning(warnings, '未找到 sudo：以非管理员身份运行，备份/恢复/修复等写操作可能失败。')
    return false
  }
  if (res.timedOut) {
    pushWarning(warnings, 'sudo -n 试探超时（未等待密码）：按非管理员处理。')
    return false
  }
  pushWarning(warnings, `sudo -n 试探未通过（${res.code}）：当前不是 root，写系统目录的操作会失败。`)
  return false
}

/** 探测常用命令是否可用（只 stat，不执行）。 */
async function detectTools(platform, warnings) {
  const names = platform === 'macos'
    ? ['sudo', 'brew', 'sw_vers', 'softwareupdate', 'diskutil', 'tmutil', 'csrutil', 'shasum', 'df', 'launchctl']
    : ['sudo', 'apt', 'apt-get', 'dpkg', 'debsums', 'rpm', 'pacman', 'systemctl', 'sha256sum', 'df', 'journalctl']
  const entries = await Promise.all(names.map(async (name) => [name, await hasExecutable(name)]))
  const tools = Object.fromEntries(entries)
  if (!entries.some(([, available]) => available)) {
    pushWarning(warnings, '未在 PATH 中找到任何预期的 POSIX 系统工具，探测结果可能不完整。')
  }
  return tools
}

/** 伪文件系统 / 伪挂载点，不计入卷列表。 */
const PSEUDO_FS = new Set([
  'tmpfs', 'devtmpfs', 'devfs', 'overlay', 'overlay2', 'squashfs', 'proc', 'sysfs', 'devpts',
  'cgroup', 'cgroup2', 'ramfs', 'none', 'udev', 'autofs', 'mqueue', 'hugetlbfs', 'tracefs',
  'securityfs', 'pstore', 'bpf', 'debugfs', 'configfs', 'fusectl', 'efivarfs', 'nsfs', 'fuse.lxcfs',
])

const PSEUDO_MOUNTS = [/^\/proc(\/|$)/, /^\/sys(\/|$)/, /^\/dev(\/|$)/]

/** 用 `df -kP` 读取各挂载点容量（过滤 tmpfs/devtmpfs/overlay 与伪挂载点）。 */
async function readVolumes(warnings, signal = null) {
  const res = await runFile('df', ['-kP'], { timeout: DF_TIMEOUT_MS, signal })
  rethrowIfAborted(res)
  if (!res.ok) {
    pushWarning(warnings, `df -kP 执行失败（${res.timedOut ? '超时' : res.code}），卷容量不可用。`)
    return []
  }
  const volumes = []
  const seen = new Set()
  const lines = res.stdout.split(/\r?\n/)
  for (let index = 1; index < lines.length; index += 1) {
    const line = lines[index].trim()
    if (!line) continue
    const parts = line.split(/\s+/)
    if (parts.length < 6) continue
    const fsName = parts[0]
    const totalBlocks = Number(parts[1])
    const availBlocks = Number(parts[3])
    const mount = parts.slice(5).join(' ')
    if (!mount.startsWith('/')) continue
    if (PSEUDO_FS.has(fsName.replace(/^.*\//, '').toLowerCase())) continue
    if (PSEUDO_MOUNTS.some((pattern) => pattern.test(mount))) continue
    if (seen.has(mount)) continue
    if (!Number.isFinite(totalBlocks) || !Number.isFinite(availBlocks)) continue
    seen.add(mount)
    volumes.push({
      id: mount,
      label: mount === '/' ? '系统盘' : (path.posix.basename(mount) || mount),
      // df -kP 不提供文件系统类型：留空，不编造。
      fs: '',
      totalBytes: totalBlocks * 1024,
      freeBytes: availBlocks * 1024,
      isSystem: mount === '/',
    })
  }
  if (volumes.length === 0) pushWarning(warnings, '未解析到任何可用挂载点（df -kP 输出异常）。')
  return volumes
}

// ---------------------------------------------------------------------------
// 文件引用（FileRef）构造
// ---------------------------------------------------------------------------

/** 从文件名推断内核版本（仅对 vmlinuz/initrd 一类文件有效）。 */
function deriveVersionFromName(filePath) {
  const base = path.posix.basename(String(filePath || ''))
  const match = /(?:vmlinuz|initrd(?:\.img)?)-(.+)$/i.exec(base)
  return match ? match[1] : null
}

/** 展开单条声明式 spec 为实际路径列表（glob / candidates / path 三种写法）。 */
async function resolveCoreSpecPaths(spec, warnings) {
  if (Array.isArray(spec.candidates) && spec.candidates.length > 0) {
    for (const candidate of spec.candidates) {
      if (await pathExists(candidate)) return [candidate]
    }
    return [spec.candidates[0]]
  }
  if (spec.glob) {
    let entries
    try {
      entries = await fsp.readdir(spec.glob.dir, { withFileTypes: true })
    } catch (error) {
      const code = error?.code
      if (code !== 'ENOENT' && code !== 'ENOTDIR') {
        pushWarning(warnings, `无法读取 ${spec.glob.dir}：${code || error?.message}`)
      } else {
        pushWarning(warnings, `目录 ${spec.glob.dir} 不存在，跳过 ${spec.id}。`)
      }
      return []
    }
    const matched = entries
      .filter((entry) => entry.isFile() && entry.name.startsWith(spec.glob.prefix))
      .map((entry) => path.posix.join(spec.glob.dir, entry.name))
      .sort()
    if (matched.length === 0) {
      pushWarning(warnings, `未在 ${spec.glob.dir} 匹配到 ${spec.glob.prefix}*，跳过 ${spec.id}（可能使用统一内核镜像）。`)
      return []
    }
    return matched.slice(0, MAX_GLOB_MATCHES)
  }
  return [spec.path]
}

/** 构造一个 FileRef：存在性 + 大小 + 可选 sha256 + 可选版本。 */
async function buildFileRef(spec, filePath, { warnings, hashFiles = true, role = 'core', version = null, budget = null } = {}) {
  const ref = {
    id: spec.id,
    path: filePath,
    role,
    group: spec.group || 'core',
    size: null,
    sha256: null,
    version,
    critical: spec.critical === true,
    exists: false,
  }
  let stat
  try {
    stat = await fsp.stat(filePath)
  } catch (error) {
    if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') {
      pushWarning(warnings, `无法读取 ${filePath}：${error?.code || error?.message}`)
    }
    return ref
  }
  ref.exists = true
  if (stat.isDirectory()) return ref
  ref.size = stat.size
  if (spec.metadataOnly) return ref
  if (hashFiles) {
    if (stat.size > MAX_HASH_BYTES) {
      pushWarning(warnings, `文件过大（${stat.size} 字节）未计算哈希：${filePath}`)
    } else {
      try {
        ref.sha256 = await sha256File(filePath, budget?.signal || null)
      } catch (error) {
        if (error?.code === 'aborted') throw error
        pushWarning(warnings, `无法计算 ${filePath} 的哈希：${error?.code || error?.message}`)
      }
    }
  }
  if (!ref.version) ref.version = deriveVersionFromName(filePath)
  return ref
}

/** 收集 platform 对应的核心文件清单。 */
async function collectCoreFiles({ platform, warnings, hashFiles = true, maxFiles = MAX_ANALYSIS_FILES, budget = null } = {}) {
  const specs = platform === 'macos' ? MACOS_CORE_FILES : platform === 'linux' ? LINUX_CORE_FILES : []
  const refs = []
  for (const spec of specs) {
    if (refs.length >= maxFiles) break
    if (budgetExpired(budget)) {
      noteBudgetExceeded(budget, warnings)
      break
    }
    const paths = await resolveCoreSpecPaths(spec, warnings)
    for (const filePath of paths) {
      if (refs.length >= maxFiles) break
      if (budgetExpired(budget)) {
        noteBudgetExceeded(budget, warnings)
        break
      }
      const id = paths.length > 1 ? `${spec.id}-${refs.length + 1}` : spec.id
      refs.push(await buildFileRef({ ...spec, id }, filePath, { warnings, hashFiles, budget }))
    }
  }
  return refs
}

/** 扫描支持文件（role=support，只 stat 不算哈希），供 analyze 分类展示。 */
async function scanSupportFiles({ platform, warnings, maxFiles = MAX_ANALYSIS_FILES, budget = null } = {}) {
  const dirs = platform === 'macos' ? MACOS_SUPPORT_DIRS : platform === 'linux' ? LINUX_SUPPORT_DIRS : []
  const refs = []
  let scannedCount = 0
  let totalBytes = 0
  let seq = 0
  for (const { dir, limit } of dirs) {
    if (refs.length >= maxFiles) break
    if (budgetExpired(budget)) {
      noteBudgetExceeded(budget, warnings)
      break
    }
    let entries
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true })
    } catch (error) {
      const code = error?.code
      if (code !== 'ENOENT' && code !== 'ENOTDIR') {
        pushWarning(warnings, `无法读取支持目录 ${dir}：${code || error?.message}`)
      }
      continue
    }
    entries.sort((a, b) => a.name.localeCompare(b.name))
    let taken = 0
    for (const entry of entries) {
      if (taken >= limit || refs.length >= maxFiles) break
      if (budgetExpired(budget)) {
        noteBudgetExceeded(budget, warnings)
        break
      }
      if (!entry.isFile()) continue
      const fullPath = path.posix.join(dir, entry.name)
      let stat
      try {
        stat = await fsp.stat(fullPath)
      } catch {
        continue
      }
      taken += 1
      scannedCount += 1
      totalBytes += stat.size
      seq += 1
      refs.push({
        id: `support-${String(seq).padStart(4, '0')}`,
        path: fullPath,
        role: 'support',
        group: 'support',
        size: stat.size,
        sha256: null,
        version: null,
        critical: false,
        exists: true,
      })
    }
  }
  return { refs, scannedCount, totalBytes }
}

// ---------------------------------------------------------------------------
// 垃圾扫描
// ---------------------------------------------------------------------------

/** 展开 ~ 为用户 home（POSIX 与测试注入两用）。 */
function expandHome(root) {
  if (typeof root !== 'string') return root
  if (root === '~') return os.homedir()
  if (root.startsWith('~/')) return path.join(os.homedir(), root.slice(2))
  return root
}

/** 递归扫描单个根目录，深度 ≤3，不跟随符号链接，只收文件。 */
async function walkJunkRoot(root, { warnings, items, addItem, state, budget = null }) {
  const stack = [{ dir: root, depth: 0 }]
  while (stack.length > 0) {
    if (budgetExpired(budget)) {
      noteBudgetExceeded(budget, warnings)
      state.interrupted = true
      return
    }
    if (state.scanEntries >= MAX_SCAN_ENTRIES_PER_GROUP) {
      state.truncated = true
      return
    }
    const { dir, depth } = stack.pop()
    let entries
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true })
    } catch (error) {
      const code = error?.code
      if (code !== 'ENOENT' && code !== 'ENOTDIR') {
        pushWarning(warnings, `无法读取目录 ${dir}：${code || error?.message}`)
      }
      continue
    }
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (budgetExpired(budget)) {
        noteBudgetExceeded(budget, warnings)
        state.interrupted = true
        return
      }
      if (state.scanEntries >= MAX_SCAN_ENTRIES_PER_GROUP) {
        state.truncated = true
        return
      }
      const fullPath = path.posix.join(dir, entry.name)
      const stat = await lstatOrNull(fullPath)
      if (!stat) continue
      // 符号链接不跟随：避免把链接指向的大目录/系统目录算进来。
      if (stat.isSymbolicLink()) continue
      state.scanEntries += 1
      if (stat.isDirectory()) {
        if (depth + 1 <= MAX_SCAN_DEPTH) stack.push({ dir: fullPath, depth: depth + 1 })
      } else if (stat.isFile()) {
        addItem(fullPath, stat.size)
      }
    }
  }
}

/** 扫描一个垃圾分组，返回 JunkGroup 或 null（无内容时返回 null）。 */
async function scanJunkGroup(spec, { warnings, budget = null } = {}) {
  const items = []
  const state = { scanEntries: 0, truncated: false, interrupted: false }
  let itemCount = 0
  let totalBytes = 0
  const addItem = (itemPath, size) => {
    itemCount += 1
    totalBytes += size
    if (items.length < MAX_ITEMS_PER_GROUP) {
      items.push({ id: `${spec.id}-${String(itemCount).padStart(4, '0')}`, path: itemPath, size, exists: true })
    }
  }
  for (const root of spec.roots) {
    if (budgetExpired(budget)) {
      noteBudgetExceeded(budget, warnings)
      state.interrupted = true
      break
    }
    const expanded = expandHome(root)
    if (!expanded) continue
    const stat = await lstatOrNull(expanded)
    if (!stat) continue
    if (stat.isSymbolicLink()) continue
    if (stat.isFile()) {
      itemCount += 1
      totalBytes += stat.size
      if (items.length < MAX_ITEMS_PER_GROUP) {
        items.push({ id: `${spec.id}-${String(itemCount).padStart(4, '0')}`, path: expanded, size: stat.size, exists: true })
      }
      continue
    }
    if (!stat.isDirectory()) continue
    await walkJunkRoot(expanded, { warnings, items, addItem, state, budget })
    if (state.interrupted) break
  }
  if (itemCount === 0) return null
  let note = spec.note
  if (state.truncated) {
    note += `（已达单组扫描上限 ${MAX_SCAN_ENTRIES_PER_GROUP} 项，总量为下限）`
  }
  if (itemCount > MAX_ITEMS_PER_GROUP) {
    note += `（仅列出前 ${MAX_ITEMS_PER_GROUP} 项，共 ${itemCount} 项）`
  }
  if (state.interrupted) {
    note += '（扫描被时间上限打断，统计不完整）'
  }
  return {
    id: spec.id,
    title: spec.title,
    kind: spec.kind,
    note,
    safeToDelete: spec.safeToDelete === true,
    items,
    totalBytes,
    itemCount,
  }
}

/** 扫描全部分组；warnings 由调用方传入共享。 */
async function scanJunkGroups(platform, warnings, budget = null) {
  const specs = platform === 'macos' ? MACOS_JUNK_GROUPS : platform === 'linux' ? LINUX_JUNK_GROUPS : []
  const groups = []
  for (const spec of specs) {
    if (budgetExpired(budget)) {
      noteBudgetExceeded(budget, warnings)
      break
    }
    const group = await scanJunkGroup(spec, { warnings, budget })
    if (group) groups.push(group)
  }
  return { groups, totalBytes: groups.reduce((sum, group) => sum + group.totalBytes, 0) }
}

// ---------------------------------------------------------------------------
// 备份（备份目录：最大空闲挂载点下的 <mount>/.system-guard/，权限 0700）
// ---------------------------------------------------------------------------

/** 生成一个字段齐全的 BackupInfo（避免各处漏字段）。 */
function makeBackupInfo(overrides = {}) {
  return {
    root: overrides.root || '',
    hidden: overrides.hidden !== false,
    volume: overrides.volume || '',
    createdAt: overrides.createdAt ?? null,
    fileCount: overrides.fileCount ?? 0,
    totalBytes: overrides.totalBytes ?? 0,
    manifestPath: overrides.manifestPath || '',
    state: overrides.state || 'none',
    verifiedAt: overrides.verifiedAt ?? null,
    missingFiles: overrides.missingFiles || [],
    corruptFiles: overrides.corruptFiles || [],
    // BackupInfo 契约之外补充 warnings，方便界面解释「为什么不是 ok」。
    warnings: overrides.warnings || [],
  }
}

/** 读取备份指针文件（dataDir 下的小 JSON）。 */
async function readBackupPointer(dataDir, warnings) {
  if (!dataDir) return null
  const pointerPath = path.join(dataDir, BACKUP_POINTER_NAME)
  const text = await readTextFile(pointerPath, warnings, { optional: true })
  if (!text) return null
  try {
    const parsed = JSON.parse(text)
    if (parsed && typeof parsed.root === 'string' && typeof parsed.manifestPath === 'string') return parsed
  } catch (error) {
    pushWarning(warnings, `备份指针文件损坏（${pointerPath}）：${error?.message}`)
  }
  return null
}

/** 扫描各挂载点，寻找已有备份（指针丢失时的冗余发现）。 */
async function discoverBackupRoots(warnings, signal = null) {
  const volumes = await readVolumes(warnings, signal)
  const mounts = new Set(['/', ...volumes.map((volume) => volume.id)])
  for (const mount of mounts) {
    const root = mount === '/' ? `/${BACKUP_DIR_NAME}` : path.posix.join(mount, BACKUP_DIR_NAME)
    const manifestPath = path.posix.join(root, BACKUP_MANIFEST_NAME)
    if (await pathExists(manifestPath)) return { root, manifestPath }
  }
  return null
}

/** 读取并解析 manifest。 */
async function readManifest(manifestPath, warnings) {
  const text = await readTextFile(manifestPath, warnings, { optional: false, label: `备份清单 ${manifestPath}` })
  if (!text) return null
  try {
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch (error) {
    pushWarning(warnings, `备份清单解析失败（${manifestPath}）：${error?.message}`)
    return null
  }
}

/** 把字符串路径规整为字符串数组（去空、去重）。 */
function normalizePaths(input) {
  const list = Array.isArray(input) ? input : (typeof input === 'string' ? [input] : [])
  const result = []
  for (const item of list) {
    const value = typeof item === 'string' ? item : (item && typeof item.path === 'string' ? item.path : null)
    if (!value) continue
    if (!result.includes(value)) result.push(value)
  }
  return result
}

// ---------------------------------------------------------------------------
// 公共入口
// ---------------------------------------------------------------------------

/**
 * 创建 POSIX backend（macOS / Linux）。
 *
 * @param {{
 *   dataDir?: string,
 *   config?: object,
 *   log?: { warn?: Function, info?: Function },
 *   web?: unknown,
 *   pluginDir?: string,
 *   viaElevated?: boolean,
 *   elevated?: boolean,
 *   platform?: string, // 仅自测注入用；生产由 detectPosixPlatform() 决定
 * }} [options]
 */
export function createPosixBackend(options = {}) {
  const source = options && typeof options === 'object' ? options : {}
  const dataDir = typeof source.dataDir === 'string' && source.dataDir
    ? source.dataDir
    : path.join(os.tmpdir(), 'dsh-system-guard')
  const activePlatform = typeof source.platform === 'string' && source.platform
    ? source.platform
    : detectPosixPlatform()
  const posixLike = isPosixPlatform(activePlatform)
  let config = source.config && typeof source.config === 'object' ? { ...source.config } : {}
  const log = source.log && typeof source.log === 'object' ? source.log : {}
  const emitWarn = (message) => {
    try {
      if (typeof log.warn === 'function') log.warn(`[system-guard:posix] ${message}`)
    } catch {
      /* 日志失败不影响主流程 */
    }
  }
  const emitInfo = (message) => {
    try {
      if (typeof log.info === 'function') log.info(`[system-guard:posix] ${message}`)
    } catch {
      /* 同上 */
    }
  }
  const actionTimeoutMs = () => Number(config.posixActionTimeoutMs) || ACTION_TIMEOUT_MS
  const junkTimeoutMs = () => Number(config.posixJunkScanTimeoutMs) || JUNK_SCAN_TIMEOUT_MS

  /** 非 POSIX 平台的降级警告文案。 */
  function fallbackWarning() {
    return `本机为 ${activePlatform === 'windows' ? 'Windows' : activePlatform}，posix 后端只做兜底：不执行任何 POSIX 命令，仅返回降级结构（Windows 请使用 win-backend）。`
  }

  // -------------------------------------------------------------------------
  // probe
  // -------------------------------------------------------------------------
  async function probe({ signal } = {}) {
    const warnings = []
    const budget = createBudget(signal, actionTimeoutMs())
    const probeResult = {
      platform: activePlatform,
      osName: '',
      osVersion: '',
      osBuild: '',
      arch: os.arch(),
      admin: false,
      systemRoot: '/',
      systemDrive: '/',
      volumes: [],
      tools: {},
      updateWindow: null,
      warnings,
    }
    if (typeof source.platform === 'string' && source.platform !== detectPosixPlatform()) {
      pushWarning(warnings, `platform 由自测注入（${source.platform}），与实际运行平台 ${detectPosixPlatform()} 不同；仅用于纯逻辑验证。`)
    }
    if (!posixLike) {
      const identity = await readOsIdentity(activePlatform, warnings, budget.signal)
      probeResult.osName = identity.osName
      probeResult.osVersion = identity.osVersion
      probeResult.osBuild = identity.osBuild
      probeResult.systemRoot = process.env.SystemRoot || process.env.SYSTEMROOT || ''
      probeResult.systemDrive = probeResult.systemRoot
        ? (path.parse(probeResult.systemRoot).root || '').replace(/[\\/]+$/, '')
        : ''
      pushWarning(warnings, fallbackWarning())
      return probeResult
    }
    const identity = await readOsIdentity(activePlatform, warnings, budget.signal)
    probeResult.osName = identity.osName
    probeResult.osVersion = identity.osVersion
    probeResult.osBuild = identity.osBuild
    probeResult.admin = source.elevated === true ? true : await detectAdmin(activePlatform, warnings, budget.signal)
    probeResult.volumes = await readVolumes(warnings, budget.signal)
    probeResult.tools = await detectTools(activePlatform, warnings)
    pushWarning(warnings, 'POSIX 平台暂未实现「系统更新窗口」检测：巡查不做更新豁免（exempted 恒为 false）。')
    return probeResult
  }

  // -------------------------------------------------------------------------
  // analyze
  // -------------------------------------------------------------------------
  async function analyze({ files, signal } = {}) {
    const startedAt = Date.now()
    const warnings = []
    const budget = createBudget(signal, actionTimeoutMs())
    if (!posixLike) pushWarning(warnings, fallbackWarning())
    let coreRefs = []
    let supportRefs = []
    let supportCount = 0
    let supportBytes = 0
    let supportFromBaseline = false
    const provided = Array.isArray(files) ? files.filter((item) => item && typeof item.path === 'string') : null
    if (provided && provided.length > 0) {
      // 增量模式：沿用上次基线的清单，只刷新存在性/大小/哈希，不重复扫描目录。
      const allRefs = []
      for (const item of provided) {
        if (allRefs.length >= MAX_ANALYSIS_FILES) break
        if (budgetExpired(budget)) {
          noteBudgetExceeded(budget, warnings)
          break
        }
        // 只给核心文件/原本有哈希的条目重新算哈希；support 文件只刷新 stat。
        const shouldHash = item.role === 'core' || item.critical === true || typeof item.sha256 === 'string'
        const ref = await buildFileRef(
          {
            id: typeof item.id === 'string' && item.id ? item.id : `baseline-${allRefs.length + 1}`,
            group: typeof item.group === 'string' && item.group ? item.group : 'baseline',
            critical: item.critical === true,
          },
          item.path,
          {
            warnings,
            hashFiles: shouldHash,
            role: typeof item.role === 'string' ? item.role : 'core',
            version: typeof item.version === 'string' ? item.version : null,
            budget,
          },
        )
        allRefs.push(ref)
      }
      coreRefs = allRefs.filter((ref) => ref.role === 'core')
      supportRefs = allRefs.filter((ref) => ref.role !== 'core')
      supportCount = supportRefs.length
      supportBytes = sumSizes(supportRefs)
      supportFromBaseline = true
    } else {
      coreRefs = await collectCoreFiles({ platform: activePlatform, warnings, budget })
    }
    if (!supportFromBaseline) {
      const support = await scanSupportFiles({ platform: activePlatform, warnings, budget })
      supportRefs = support.refs
      supportCount = support.scannedCount
      supportBytes = support.totalBytes
    }
    const junk = await scanJunkGroups(activePlatform, warnings, budget)
    const filesOut = [...coreRefs, ...supportRefs].slice(0, MAX_ANALYSIS_FILES)
    return {
      analyzedAt: Date.now(),
      durationMs: Date.now() - startedAt,
      coreCount: coreRefs.length,
      coreBytes: sumSizes(coreRefs),
      supportCount,
      supportBytes,
      files: filesOut,
      groups: junk.groups,
      totalJunkBytes: junk.totalBytes,
      baselineSource: config.baselineSource === 'calibrated' ? 'calibrated' : 'builtin',
      calibratedAt: Number.isFinite(config.calibratedAt) ? config.calibratedAt : null,
      warnings,
    }
  }

  // -------------------------------------------------------------------------
  // patrol
  // -------------------------------------------------------------------------
  async function patrol({ baseline, opts, signal } = {}) {
    const startedAt = Date.now()
    const warnings = []
    const budget = createBudget(signal, actionTimeoutMs())
    if (!posixLike) pushWarning(warnings, fallbackWarning())
    const list = normalizeBaseline(baseline)
    const report = {
      checkedAt: Date.now(),
      durationMs: 0,
      total: list.length,
      unchanged: 0,
      changed: [],
      missing: [],
      verdict: 'unknown',
      sfc: { ran: false, passed: null, detail: '' },
      backup: { state: 'none' },
      warnings,
    }
    if (list.length === 0) {
      pushWarning(warnings, '基线为空：没有可比对的核心文件清单，巡查结论为 unknown。')
    }
    if (opts && opts.updateWindow) {
      pushWarning(warnings, 'POSIX 平台未实现系统更新窗口检测：本次巡查不做更新豁免（exempted 恒为 false）。')
    }
    if (opts && opts.sfc) {
      pushWarning(warnings, 'POSIX 平台不执行 Windows 的 sfc 命令；Linux 的完整性校验用包管理器（debsums / rpm -Va），macOS 需恢复模式。')
    }
    let unverifiable = 0
    let interrupted = false
    for (const item of list) {
      if (budgetExpired(budget)) {
        noteBudgetExceeded(budget, warnings)
        interrupted = true
        break
      }
      const targetPath = item.path
      const expectedSha = typeof item.sha256 === 'string' && item.sha256 ? item.sha256.toLowerCase() : null
      let stat
      try {
        stat = await fsp.stat(targetPath)
      } catch (error) {
        if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') {
          report.missing.push(targetPath)
        } else {
          pushWarning(warnings, `巡查时无法读取 ${targetPath}：${error?.code || error?.message}`)
          report.missing.push(targetPath)
        }
        continue
      }
      if (stat.isDirectory()) {
        if (expectedSha) {
          unverifiable += 1
          pushWarning(warnings, `目录无法做哈希比对：${targetPath}`)
        } else {
          report.unchanged += 1
        }
        continue
      }
      if (!expectedSha) {
        // 没有基线哈希（例如 /etc/shadow 只存元数据、或 support 文件只做展示）：
        // 只核对存在性，并在 warnings 里说明，而不是把「无法比对」当成系统损坏。
        report.unchanged += 1
        pushWarning(warnings, `仅检查存在性（基线无 sha256，不做内容比对）：${targetPath}`)
        continue
      }
      let actualSha
      try {
        actualSha = await sha256File(targetPath, budget.signal)
      } catch (error) {
        if (error?.code === 'aborted') throw error
        unverifiable += 1
        pushWarning(warnings, `无法计算 ${targetPath} 的哈希：${error?.code || error?.message}`)
        continue
      }
      if (actualSha === expectedSha) {
        report.unchanged += 1
      } else {
        // 无法判断更新窗口：exempted 一律 false，宁可报变化也不假装豁免。
        report.changed.push({ path: targetPath, expectedSha, actualSha, exempted: false, reason: '' })
      }
    }
    try {
      const status = await backupStatus({ signal: budget.signal })
      report.backup = { state: status.state }
    } catch (error) {
      if (error?.code === 'aborted') throw error
      pushWarning(warnings, `备份状态检查失败：${error?.message || error}`)
      report.backup = { state: 'unknown' }
    }
    report.durationMs = Date.now() - startedAt
    if (interrupted) report.verdict = 'unknown'
    else if (report.missing.length > 0) report.verdict = 'damaged'
    else if (report.changed.length > 0) report.verdict = 'changed'
    else if (report.total === 0 || unverifiable > 0) report.verdict = 'unknown'
    else report.verdict = 'healthy'
    return report
  }

  /** baseline 既可能是 FileRef[]，也可能是 core 持久化的 { files: FileRef[] }。 */
  function normalizeBaseline(baseline) {
    const files = Array.isArray(baseline)
      ? baseline
      : (baseline && Array.isArray(baseline.files) ? baseline.files : [])
    // 只核对「有基线哈希或属于核心文件」的条目：support 文件没有哈希时只用于展示，
    // 若强行计入，verdict 会永远 unknown（无法比对 ≠ 系统损坏）。
    return files.filter((item) => item && typeof item.path === 'string'
      && (item.role === 'core' || item.critical === true
        || (typeof item.sha256 === 'string' && item.sha256.length > 0)))
  }

  // -------------------------------------------------------------------------
  // junkScan / junkDelete
  // -------------------------------------------------------------------------
  async function junkScan({ signal } = {}) {
    const warnings = []
    const budget = createBudget(signal, junkTimeoutMs())
    if (!posixLike) {
      pushWarning(warnings, fallbackWarning())
      return { groups: [], totalBytes: 0, warnings }
    }
    const junk = await scanJunkGroups(activePlatform, warnings, budget)
    if (junk.groups.length === 0) {
      pushWarning(warnings, '未发现可统计的垃圾目录（目录不存在或当前用户无权读取）。')
    }
    return { groups: junk.groups, totalBytes: junk.totalBytes, warnings }
  }

  async function junkDelete({ items } = {}) {
    const list = Array.isArray(items) ? items : []
    const failed = list.map((item) => ({
      path: typeof item === 'string' ? item : String(item?.path ?? ''),
      error: 'unsupported-on-platform',
    }))
    emitWarn('POSIX 平台未实现垃圾删除（未在真实 macOS/Linux 上验证删除安全性），按契约统一返回 unsupported-on-platform。')
    return {
      requested: list.length,
      deleted: [],
      failed,
      freedBytes: 0,
      elevated: false,
    }
  }

  // -------------------------------------------------------------------------
  // backup / backupStatus / restore
  // -------------------------------------------------------------------------
  async function backup({ files, signal } = {}) {
    const warnings = []
    const budget = createBudget(signal, actionTimeoutMs())
    if (!posixLike) {
      pushWarning(warnings, fallbackWarning())
      return makeBackupInfo({ state: 'none', warnings })
    }
    const list = Array.isArray(files) ? files.filter((item) => item && typeof item.path === 'string') : []
    const hasRole = list.some((item) => typeof item.role === 'string')
    const candidates = list.filter((item) => item.exists !== false
      && (!hasRole || item.role === 'core' || item.critical === true))
    if (candidates.length === 0) {
      pushWarning(warnings, '没有可备份的核心文件（清单为空或只含 support 文件），未创建备份。')
      return makeBackupInfo({ state: 'none', warnings })
    }
    const volumes = await readVolumes(warnings, budget.signal)
    const target = [...volumes].sort((a, b) => (b.freeBytes || 0) - (a.freeBytes || 0))[0]
    const mount = target?.id || '/'
    const root = mount === '/' ? `/${BACKUP_DIR_NAME}` : path.posix.join(mount, BACKUP_DIR_NAME)
    const filesDir = path.posix.join(root, 'files')
    try {
      await fsp.mkdir(filesDir, { recursive: true, mode: 0o700 })
      await fsp.chmod(root, 0o700)
    } catch (error) {
      pushWarning(warnings, `创建备份目录失败 ${root}：${error?.code || error?.message}`)
      return makeBackupInfo({ root, volume: mount, state: 'none', warnings })
    }
    const entries = []
    const missingFiles = []
    let totalBytes = 0
    let interrupted = false
    for (const file of candidates) {
      if (budgetExpired(budget)) {
        noteBudgetExceeded(budget, warnings)
        interrupted = true
        break
      }
      let stat
      try {
        stat = await fsp.stat(file.path)
      } catch (error) {
        missingFiles.push(file.path)
        pushWarning(warnings, `备份源不存在或不可读：${file.path}（${error?.code || error?.message}）`)
        continue
      }
      if (!stat.isFile()) {
        // 目录（例如 /lib/modules）不复制，静默跳过，不当作备份缺失。
        continue
      }
      const relative = file.path.replace(/^\/+/, '')
      const destination = path.posix.join(filesDir, relative)
      try {
        await fsp.mkdir(path.posix.dirname(destination), { recursive: true, mode: 0o700 })
        await fsp.copyFile(file.path, destination)
        await fsp.chmod(destination, 0o600)
        const digest = typeof file.sha256 === 'string' && file.sha256
          ? file.sha256
          : await sha256File(destination, budget.signal)
        entries.push({ path: file.path, backupPath: destination, size: stat.size, sha256: digest, copiedAt: Date.now() })
        totalBytes += stat.size
      } catch (error) {
        if (error?.code === 'aborted') throw error
        missingFiles.push(file.path)
        pushWarning(warnings, `备份复制失败 ${file.path} → ${destination}：${error?.code || error?.message}`)
      }
    }
    const createdAt = Date.now()
    const manifestPath = path.posix.join(root, BACKUP_MANIFEST_NAME)
    const manifest = {
      version: 1,
      platform: activePlatform,
      root,
      volume: mount,
      createdAt,
      files: entries,
      warnings: warnings.slice(0, 20),
    }
    try {
      await fsp.writeFile(manifestPath, JSON.stringify(manifest, null, 2), { encoding: 'utf8', mode: 0o600 })
      await fsp.chmod(manifestPath, 0o600)
    } catch (error) {
      pushWarning(warnings, `写入备份清单失败 ${manifestPath}：${error?.code || error?.message}`)
      return makeBackupInfo({
        root, volume: mount, createdAt, fileCount: entries.length, totalBytes, manifestPath,
        state: 'partial', warnings,
      })
    }
    // 冗余「指针」：备份目录在别的挂载点，dataDir 里留个线索方便下次快速定位。
    try {
      await fsp.mkdir(dataDir, { recursive: true, mode: 0o700 })
      const pointerPath = path.join(dataDir, BACKUP_POINTER_NAME)
      await fsp.writeFile(
        pointerPath,
        JSON.stringify({ root, manifestPath, volume: mount, createdAt, fileCount: entries.length, totalBytes }, null, 2),
        { encoding: 'utf8', mode: 0o600 },
      )
    } catch (error) {
      pushWarning(warnings, `写入备份指针失败（不影响备份本体）：${error?.code || error?.message}`)
    }
    const state = interrupted
      ? 'partial'
      : (missingFiles.length > 0 ? 'partial' : (entries.length > 0 ? 'ok' : 'none'))
    emitInfo(`备份完成：${entries.length} 个文件 → ${root}（${state}）`)
    return makeBackupInfo({
      root,
      hidden: path.posix.basename(root).startsWith('.'),
      volume: mount,
      createdAt,
      fileCount: entries.length,
      totalBytes,
      manifestPath,
      state,
      verifiedAt: Date.now(),
      missingFiles,
      corruptFiles: [],
      warnings,
    })
  }

  async function backupStatus({ signal } = {}) {
    const warnings = []
    const budget = createBudget(signal, actionTimeoutMs())
    if (!posixLike) {
      pushWarning(warnings, fallbackWarning())
      return makeBackupInfo({ state: 'none', warnings })
    }
    let pointer = await readBackupPointer(dataDir, warnings)
    if (!pointer) pointer = await discoverBackupRoots(warnings, budget.signal)
    if (!pointer) {
      return makeBackupInfo({ state: 'none', warnings })
    }
    const { root, manifestPath } = pointer
    if (!(await pathExists(manifestPath))) {
      const rootExists = await pathExists(root)
      pushWarning(warnings, `备份清单不存在：${manifestPath}`)
      return makeBackupInfo({
        root,
        manifestPath,
        state: rootExists ? 'partial' : 'missing',
        warnings,
      })
    }
    const manifest = await readManifest(manifestPath, warnings)
    if (!manifest) {
      return makeBackupInfo({ root, manifestPath, state: 'partial', warnings })
    }
    const missingFiles = []
    const corruptFiles = []
    let totalBytes = 0
    let interrupted = false
    const entries = Array.isArray(manifest.files) ? manifest.files : []
    for (const entry of entries) {
      if (budgetExpired(budget)) {
        noteBudgetExceeded(budget, warnings)
        interrupted = true
        break
      }
      if (!entry || typeof entry.backupPath !== 'string') continue
      totalBytes += Number(entry.size) || 0
      if (!(await pathExists(entry.backupPath))) {
        missingFiles.push(entry.backupPath)
        continue
      }
      if (typeof entry.sha256 === 'string' && entry.sha256) {
        try {
          const actual = await sha256File(entry.backupPath, budget.signal)
          if (actual !== entry.sha256) corruptFiles.push(entry.backupPath)
        } catch (error) {
          if (error?.code === 'aborted') throw error
          corruptFiles.push(entry.backupPath)
        }
      }
    }
    const state = interrupted
      ? 'partial'
      : (missingFiles.length > 0 || corruptFiles.length > 0
        ? 'partial'
        : (entries.length > 0 ? 'ok' : 'none'))
    return makeBackupInfo({
      root,
      hidden: path.posix.basename(root).startsWith('.'),
      volume: typeof manifest.volume === 'string' ? manifest.volume : '',
      createdAt: Number.isFinite(manifest.createdAt) ? manifest.createdAt : null,
      fileCount: entries.length,
      totalBytes,
      manifestPath,
      state,
      verifiedAt: Date.now(),
      missingFiles,
      corruptFiles,
      warnings,
    })
  }

  async function restore({ paths, signal } = {}) {
    const warnings = []
    const budget = createBudget(signal, actionTimeoutMs())
    const report = { ok: false, mode: 'restore', actions: [], output: '', warnings }
    if (!posixLike) {
      pushWarning(warnings, fallbackWarning())
      report.error = { code: 'unsupported-on-platform', message: '当前平台不是 macOS/Linux，POSIX 恢复不可用。' }
      return report
    }
    const list = normalizePaths(paths)
    if (list.length === 0) {
      report.error = { code: 'invalid-input', message: '没有指定要恢复的文件路径。' }
      return report
    }
    const status = await backupStatus({ signal: budget.signal })
    if (status.state === 'none' || status.state === 'missing') {
      report.error = { code: 'backup-missing', message: '没有可用备份，无法恢复；请先执行「备份核心文件」。' }
      return report
    }
    const manifest = await readManifest(status.manifestPath, warnings)
    if (!manifest) {
      report.error = { code: 'backup-missing', message: '备份清单损坏或不可读，无法恢复。' }
      return report
    }
    const byPath = new Map(
      (Array.isArray(manifest.files) ? manifest.files : [])
        .filter((entry) => entry && typeof entry.path === 'string')
        .map((entry) => [entry.path, entry]),
    )
    // 先写 quarantine，再覆盖原文件（覆盖系统目录通常需要 root）。
    let quarantineDir = ''
    try {
      const stamp = new Date().toISOString().replace(/[:.]/g, '-')
      quarantineDir = path.join(dataDir, 'quarantine', stamp)
      await fsp.mkdir(quarantineDir, { recursive: true, mode: 0o700 })
    } catch (error) {
      pushWarning(warnings, `创建 quarantine 目录失败（${error?.code || error?.message}），仍尝试恢复。`)
    }
    let allOk = true
    let interrupted = false
    for (const targetPath of list) {
      if (budgetExpired(budget)) {
        noteBudgetExceeded(budget, warnings)
        interrupted = true
        break
      }
      const action = { step: `restore:${targetPath}`, ok: false, detail: '' }
      report.actions.push(action)
      const entry = byPath.get(targetPath)
      if (!entry) {
        action.detail = 'backup-missing: 备份清单中没有该文件的副本'
        allOk = false
        continue
      }
      if (!(await pathExists(entry.backupPath))) {
        action.detail = 'backup-missing: 备份副本已不存在'
        allOk = false
        continue
      }
      if (typeof entry.sha256 === 'string' && entry.sha256) {
        try {
          const actual = await sha256File(entry.backupPath, budget.signal)
          if (actual !== entry.sha256) {
            action.detail = 'backup-corrupt: 备份副本哈希不符，拒绝覆盖'
            allOk = false
            continue
          }
        } catch (error) {
          if (error?.code === 'aborted') throw error
          action.detail = `backup-unreadable: ${error?.code || error?.message}`
          allOk = false
          continue
        }
      }
      let quarantined = ''
      if (await pathExists(targetPath)) {
        try {
          const targetQuarantine = path.join(quarantineDir, targetPath.replace(/^\/+/, ''))
          await fsp.mkdir(path.dirname(targetQuarantine), { recursive: true, mode: 0o700 })
          await fsp.copyFile(targetPath, targetQuarantine)
          await fsp.chmod(targetQuarantine, 0o600)
          quarantined = targetQuarantine
        } catch (error) {
          pushWarning(warnings, `原文件隔离失败（${targetPath}）：${error?.code || error?.message}；仍尝试覆盖。`)
        }
      }
      try {
        await fsp.mkdir(path.dirname(targetPath), { recursive: true, mode: 0o755 })
        await fsp.copyFile(entry.backupPath, targetPath)
        action.ok = true
        action.detail = `已从 ${entry.backupPath} 恢复${quarantined ? `；原文件隔离在 ${quarantined}` : ''}`
      } catch (error) {
        action.detail = `写入失败：${error?.code || error?.message}（系统目录通常需要 root 权限）`
        allOk = false
      }
    }
    report.ok = allOk && !interrupted && report.actions.length > 0
    report.output = quarantineDir ? `quarantine 目录：${quarantineDir}` : ''
    if (!report.ok) {
      report.error = interrupted
        ? { code: 'timeout', message: '恢复动作超过时间上限，未完成；已完成部分见 actions。' }
        : {
          code: 'partially-failed',
          message: '部分文件未能恢复，详见 actions；系统目录需要 root 权限（插件未提权时如实失败，不假装成功）。',
        }
    }
    return report
  }

  // -------------------------------------------------------------------------
  // repair / restorePoint
  // -------------------------------------------------------------------------
  async function repair({ mode = 'sfc', paths, signal } = {}) {
    const warnings = []
    const actions = []
    const budget = createBudget(signal, actionTimeoutMs())
    const report = { ok: false, mode, actions, output: '', warnings }
    if (!posixLike) {
      pushWarning(warnings, fallbackWarning())
      report.error = { code: 'unsupported-on-platform', message: '当前平台不是 macOS/Linux，POSIX 修复不可用；Windows 请使用 win-backend。' }
      return report
    }
    // 从备份恢复属于 restore 的职责，core 默认 mode 可能是 'restore'。
    if (mode === 'restore') {
      return restore({ paths, signal: budget.signal })
    }
    if (activePlatform === 'macos') {
      report.error = {
        code: 'manual-required',
        message: 'macOS 不提供命令行级别的系统文件完整性修复：官方做法是进入恢复模式（Recovery），用「磁盘工具 - 急救」检查/修复磁盘，必要时重新安装 macOS。插件没有可靠方式自动修复，因此如实返回 manual-required，不假装修好了。',
      }
      return report
    }
    if (mode === 'dism' || mode === 'restore-point') {
      report.error = {
        code: 'manual-required',
        message: `Linux 没有与 Windows「${mode}」等价的机制：请使用发行版快照（btrfs/LVM/ZFS snapshot）或重新安装受损软件包；插件不会假装执行。`,
      }
      return report
    }
    if (mode !== 'sfc' && mode !== 'package') {
      report.error = {
        code: 'unsupported-mode',
        message: `Linux 上不支持修复模式「${mode}」；可用模式为 sfc（等价于包管理器完整性校验）或 restore（从备份恢复）。`,
      }
      return report
    }
    const targetPaths = normalizePaths(paths)
    // 优先 debsums（Debian/Ubuntu），其次 rpm -Va（RHEL/Fedora）。
    if (await hasExecutable('debsums')) {
      const res = await runFile('debsums', ['-s'], { timeout: SHELL_TIMEOUT_MS, signal: budget.signal })
      rethrowIfAborted(res)
      const combined = `${res.stdout}${res.stderr}`.trim()
      actions.push({
        step: 'debsums -s',
        ok: res.ok,
        detail: truncate(res.timedOut ? '超时（20s），结果不完整' : (combined || '（无输出；debsums 未报告校验失败的文件）'), 1200),
      })
      report.output = truncate(combined || (res.ok ? '（无输出）' : ''))
      report.ok = res.ok && !res.timedOut
      if (res.timedOut) pushWarning(warnings, 'debsums 校验超过 20 秒被终止，结果不完整。')
      if (!res.ok) {
        pushWarning(warnings, '包管理器报告有文件缺失或校验失败；插件不自动执行重装，请人工确认后运行：sudo apt-get install --reinstall <包名>。')
      }
      if (targetPaths.length > 0) {
        pushWarning(warnings, `本次给了 ${targetPaths.length} 个路径，但 debsums -s 是全量校验；请用输出对照路径。`)
      }
      return report
    }
    if (await hasExecutable('rpm')) {
      const res = await runFile('rpm', ['-Va'], { timeout: SHELL_TIMEOUT_MS, signal: budget.signal })
      rethrowIfAborted(res)
      const lines = res.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
      const relevant = targetPaths.length > 0
        ? lines.filter((line) => targetPaths.some((target) => line.endsWith(target)))
        : lines
      actions.push({
        step: 'rpm -Va',
        ok: res.ok,
        detail: truncate(res.timedOut ? '超时（20s），结果不完整' : (relevant.slice(0, 50).join('\n') || '（无输出；rpm 未报告校验失败的文件）'), 1200),
      })
      report.output = truncate(lines.slice(0, 200).join('\n'))
      report.ok = res.ok && !res.timedOut
      if (res.timedOut) pushWarning(warnings, 'rpm -Va 超过 20 秒被终止，结果不完整。')
      if (!res.ok) {
        pushWarning(warnings, 'rpm 报告有文件校验失败；可人工运行 sudo dnf reinstall <包名>（或 rpm -Uvh --replacepkgs）重新安装，插件不自动执行。')
      }
      return report
    }
    report.error = {
      code: 'tool-missing',
      message: '未找到 debsums 或 rpm，无法执行系统文件完整性校验。Debian/Ubuntu 可安装 debsums；RHEL/Fedora 使用 rpm -Va。插件不会自动安装软件包。',
    }
    return report
  }

  // -------------------------------------------------------------------------
  // 注意：本 backend **不导出** restorePoint()。
  // macOS/Linux 没有与 Windows 系统还原点等价的机制，core.js 在 backend 缺少该方法时
  // 会返回 { ok:false, error:{ code:'unsupported', message:'当前系统不支持由本插件创建还原点。' } }，
  // 这样界面不会误报「创建完成」；插件也不假装修复。
  // -------------------------------------------------------------------------

  // -------------------------------------------------------------------------
  // calibrateFacts
  // -------------------------------------------------------------------------
  async function calibrateFacts({ signal } = {}) {
    const warnings = []
    const budget = createBudget(signal, actionTimeoutMs())
    if (!posixLike) pushWarning(warnings, fallbackWarning())
    const identity = await readOsIdentity(activePlatform, warnings, budget.signal)
    const facts = {
      platform: activePlatform,
      osName: identity.osName,
      osVersion: identity.osVersion,
      osBuild: identity.osBuild,
      arch: os.arch(),
      files: [],
      warnings,
    }
    const coreRefs = await collectCoreFiles({
      platform: activePlatform,
      warnings,
      hashFiles: true,
      maxFiles: MAX_FACTS_FILES,
      budget,
    })
    for (const ref of coreRefs) {
      if (!ref.exists || !ref.sha256) continue
      facts.files.push({ path: ref.path, version: ref.version ?? null, sha256: ref.sha256 })
      if (facts.files.length >= MAX_FACTS_FILES) break
    }
    if (facts.files.length === 0) {
      pushWarning(warnings, '没有可用的核心文件哈希（核心文件不存在或无读取权限），Facts 只含系统标识。')
    }
    return facts
  }

  // -------------------------------------------------------------------------
  // 其它
  // -------------------------------------------------------------------------
  function updateConfig(next) {
    if (!next || typeof next !== 'object') return
    config = { ...config, ...next }
  }

  async function dispose() {
    // 没有常驻句柄/定时器，无需清理；保留接口让 core 可以统一调用。
  }

  return {
    platform: activePlatform,
    probe,
    analyze,
    patrol,
    junkScan,
    junkDelete,
    backup,
    backupStatus,
    restore,
    repair,
    calibrateFacts,
    updateConfig,
    dispose,
  }
}

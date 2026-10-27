/**
 * dsh-system-guard · PowerShell 执行封装（Windows 平台）
 *
 * 设计要点：
 * - Node 侧只做参数准备、进程调度与 JSON 解析，所有系统读写都交给 scripts/guard.ps1；
 * - 普通执行用 spawn，参数走数组（不做 shell 拼接），中文/空格路径安全；
 * - -Params 走独立 JSON 文件，不把 JSON 塞进命令行；
 * - 支持 AbortSignal：中止时 taskkill /T 杀进程树并抛 code='aborted'；
 * - 超时抛 code='timeout'；提权取消抛 code='elevation-cancelled'；
 * - guard.ps1 必须 UTF-8 with BOM，缺失时自动补写（PowerShell 5.1 否则会按 GBK 解析）；
 * - 临时文件放在 os.tmpdir()/dsh-system-guard/，保留最近 20 个便于排错。
 */

import { spawn, spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { existsSync } from 'node:fs'
import { promises as fsp } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/** 本项目 guard.ps1 的绝对路径（随包携带，不依赖外部脚本） */
const GUARD_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'guard.ps1',
)

/** 运行期临时目录（params / 结果 / 提权包装脚本） */
export const RUNTIME_DIR = path.join(os.tmpdir(), 'dsh-system-guard')

/**
 * 提权专用目录：放在公共目录下。
 * UAC 跨账户提权（标准用户 → 管理员账户）时，管理员令牌访问不到原用户的 %TEMP%，
 * 放 C:\Users\Public 这类公共目录两边都能读写，结果文件才能带回来。
 */
function elevatedRuntimeDir() {
  const publicDir = process.env.PUBLIC || process.env.PUBLIC_DIR || ''
  if (publicDir && existsSync(publicDir)) return path.join(publicDir, 'dsh-system-guard')
  return RUNTIME_DIR
}

const KEEP_RUNTIME_FILES = 20
const DEFAULT_TIMEOUT_MS = 120_000
const ELEVATED_TIMEOUT_MS = 180_000
const MAX_CAPTURE_BYTES = 64 * 1024
const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf])

/** 带 code 的执行错误，core 可按 code 分支处理 */
export class GuardError extends Error {
  constructor(code, message, detail = {}) {
    super(message)
    this.name = 'GuardError'
    this.code = code
    for (const [key, value] of Object.entries(detail)) {
      if (value !== undefined) this[key] = value
    }
  }
}

/** guard.ps1 的绝对路径 */
export function guardPath() {
  return GUARD_PATH
}

/** guard.ps1 是否存在 */
export function guardExists() {
  return existsSync(GUARD_PATH)
}

function assertWindows() {
  if (process.platform !== 'win32') {
    throw new GuardError('unsupported', 'PowerShell 网络层执行器只支持 Windows')
  }
}

function warn(log, message) {
  try {
    if (log && typeof log.warn === 'function') log.warn(`[dsh-system-guard] ${message}`)
  } catch {
    /* 日志失败不影响主流程 */
  }
}

function sanitizeAction(action) {
  return String(action || 'action').replace(/[^a-zA-Z0-9-]/g, '_')
}

async function ensureRuntimeDir() {
  await fsp.mkdir(RUNTIME_DIR, { recursive: true })
}

/**
 * guard.ps1 必须 UTF-8 with BOM：Windows PowerShell 5.1 对无 BOM 的 .ps1
 * 会按系统 ANSI（中文机器通常是 GBK）解析，中文注释会乱码甚至语法错误。
 * 每次执行前只读前 3 个字节做检查，缺失时补写（写回原文件），失败只记 warning。
 */
async function ensureGuardEncoding(log) {
  try {
    if (!existsSync(GUARD_PATH)) {
      warn(log, `helper 脚本不存在：${GUARD_PATH}`)
      return
    }
    let head = Buffer.alloc(0)
    const handle = await fsp.open(GUARD_PATH, 'r')
    try {
      const buffer = Buffer.alloc(3)
      const { bytesRead } = await handle.read(buffer, 0, 3, 0)
      head = buffer.subarray(0, bytesRead)
    } finally {
      await handle.close()
    }
    const hasBom = head.length >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf
    if (hasBom) return
    const body = await fsp.readFile(GUARD_PATH)
    await fsp.writeFile(GUARD_PATH, Buffer.concat([UTF8_BOM, body]))
    warn(log, 'guard.ps1 缺少 UTF-8 BOM，已自动补写（PowerShell 5.1 需要）')
  } catch (error) {
    warn(log, `检查 guard.ps1 编码失败：${error && error.message ? error.message : String(error)}`)
  }
}

/** 杀掉进程树（含 guard 启动的子命令，例如 sfc/dism），避免中止后留下孤儿进程 */
function killTree(pid) {
  if (!pid) return
  try {
    spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], {
      windowsHide: true,
      stdio: 'ignore',
      timeout: 15_000,
    })
  } catch {
    /* 尽力而为 */
  }
}

/**
 * 启动一个 powershell.exe，收集 stdout/stderr，支持超时与中止。
 * 注意：guard.ps1 自己会把优先级降到 BelowNormal，避免抢占用户机器资源。
 */
function spawnPowerShell(args, { timeoutMs = DEFAULT_TIMEOUT_MS, signal } = {}) {
  return new Promise((resolve) => {
    let child
    try {
      child = spawn('powershell.exe', args, {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (error) {
      resolve({ exitCode: -1, stdout: '', stderr: '', timedOut: false, aborted: false, spawnError: error })
      return
    }

    let stdout = ''
    let stderr = ''
    let timedOut = false
    let aborted = false
    let settled = false
    let timer = null

    const onAbort = () => {
      aborted = true
      killTree(child.pid)
    }

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer)
        timer = null
      }
      if (signal && typeof signal.removeEventListener === 'function') {
        signal.removeEventListener('abort', onAbort)
      }
    }

    const finish = (extra = {}) => {
      if (settled) return
      settled = true
      cleanup()
      resolve({
        exitCode: typeof extra.exitCode === 'number' ? extra.exitCode : -1,
        stdout,
        stderr,
        timedOut,
        aborted,
        spawnError: extra.spawnError || null,
      })
    }

    child.stdout?.on('data', (chunk) => {
      if (stdout.length < MAX_CAPTURE_BYTES) stdout += chunk.toString('utf8')
    })
    child.stderr?.on('data', (chunk) => {
      if (stderr.length < MAX_CAPTURE_BYTES) stderr += chunk.toString('utf8')
    })
    child.on('error', (error) => finish({ spawnError: error }))
    child.on('close', (code) => finish({ exitCode: code }))

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true
        killTree(child.pid)
      }, timeoutMs)
      if (typeof timer.unref === 'function') timer.unref()
    }

    if (signal) {
      if (signal.aborted) onAbort()
      else if (typeof signal.addEventListener === 'function') {
        signal.addEventListener('abort', onAbort, { once: true })
      }
    }
  })
}

async function writeJsonFile(filePath, value) {
  await fsp.writeFile(filePath, JSON.stringify(value ?? {}), 'utf8')
}

async function readResultFile(filePath) {
  try {
    const text = await fsp.readFile(filePath, 'utf8')
    if (!text.trim()) return null
    return JSON.parse(text)
  } catch {
    return null
  }
}

/** 只清理本模块自己产生的 json/ps1 临时文件，保留最近 20 个便于排错 */
async function pruneRuntimeDir(dir = RUNTIME_DIR) {
  try {
    const entries = await fsp.readdir(dir)
    const files = []
    for (const name of entries) {
      if (!/^(?:[a-z0-9_-]+)-[0-9a-f-]+(?:\.params)?\.(?:json|ps1)$/i.test(name)) continue
      const full = path.join(dir, name)
      try {
        const stat = await fsp.stat(full)
        if (stat.isFile()) files.push({ full, mtime: stat.mtimeMs })
      } catch {
        /* 忽略 */
      }
    }
    files.sort((a, b) => b.mtime - a.mtime)
    for (const item of files.slice(KEEP_RUNTIME_FILES)) {
      try {
        await fsp.unlink(item.full)
      } catch {
        /* 忽略 */
      }
    }
  } catch {
    /* 清理失败不影响主流程 */
  }
}

function makeTempName(prefix) {
  return `${sanitizeAction(prefix)}-${Date.now()}-${randomUUID().slice(0, 8)}`
}

/**
 * 执行一次 guard.ps1 动作（非提权）。
 *
 * @param {string} action 动作名（probe / analyze / patrol / junk-scan / ...）
 * @param {object} [options]
 * @param {object} [options.params] 写入 -Params 参数文件的对象
 * @param {number} [options.timeoutMs] 超时毫秒（默认 120s）
 * @param {number} [options.timeoutSec] 传给 guard 的 -TimeoutSec（长命令内部超时）
 * @param {string} [options.dataDir] 插件数据目录（仅用于日志/调试，不写参数）
 * @param {object} [options.log] 至少含 warn/info 的日志器
 * @param {AbortSignal} [options.signal] 中止信号
 * @returns {Promise<any>} guard 结果里的 value
 */
export async function runGuard(action, options = {}) {
  assertWindows()
  const {
    params = null,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    timeoutSec = 0,
    log = null,
    signal = null,
  } = options

  if (!guardExists()) {
    throw new GuardError('guard-missing', `找不到系统守护脚本：${GUARD_PATH}`)
  }
  if (signal && signal.aborted) {
    throw new GuardError('aborted', `动作 ${action} 已取消`)
  }

  await ensureRuntimeDir()
  await ensureGuardEncoding(log)

  const baseName = makeTempName(action)
  const outFile = path.join(RUNTIME_DIR, `${baseName}.json`)
  let paramsFile = ''

  if (params !== null && params !== undefined) {
    paramsFile = path.join(RUNTIME_DIR, `${baseName}.params.json`)
    await writeJsonFile(paramsFile, params)
  }

  const args = [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    GUARD_PATH,
    '-Action',
    action,
    '-OutFile',
    outFile,
  ]
  if (paramsFile) args.push('-Params', paramsFile)
  if (Number(timeoutSec) > 0) args.push('-TimeoutSec', String(Math.floor(Number(timeoutSec))))

  const run = await spawnPowerShell(args, { timeoutMs, signal })
  const result = await readResultFile(outFile)
  await pruneRuntimeDir()

  if (run.spawnError) {
    throw new GuardError('spawn-failed', `无法启动 PowerShell：${run.spawnError.message}`, {
      stderr: run.stderr,
    })
  }
  if (run.aborted) {
    throw new GuardError('aborted', `动作 ${action} 已取消`, { outFile })
  }
  if (run.timedOut) {
    throw new GuardError('timeout', `动作 ${action} 超时（${timeoutMs} 毫秒）`, {
      stderr: run.stderr,
      outFile,
    })
  }
  if (!result) {
    throw new GuardError(
      'no-output',
      `动作 ${action} 没有写出结果文件（退出码 ${run.exitCode}）`,
      { stderr: run.stderr, stdout: run.stdout, outFile },
    )
  }
  if (result.ok === false) {
    const info = result.error || {}
    throw new GuardError(info.code || 'guard-failed', info.message || `动作 ${action} 失败`, {
      action: result.action || action,
      stdout: run.stdout,
      stderr: run.stderr,
    })
  }
  return result.value
}

/**
 * 生成提权包装脚本：UAC 弹窗 → 以管理员身份跑 guard.ps1 → 等待完成 → 回读结果。
 * 导出它是为了让测试能在不弹 UAC 的前提下做语法校验。
 */
export function buildElevatedWrapper({ action, outFile, paramsFile, timeoutSec }) {
  const quote = (text) => `"${String(text).replace(/"/g, '""')}"`
  const lines = [
    "$ErrorActionPreference = 'Stop'",
    `$outFile = ${quote(outFile)}`,
    '$argList = New-Object System.Collections.Generic.List[string]',
    "foreach ($item in @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass')) { $argList.Add($item) }",
    `$argList.Add('-File'); $argList.Add(${quote(GUARD_PATH)})`,
    `$argList.Add('-Action'); $argList.Add(${quote(action)})`,
    `$argList.Add('-OutFile'); $argList.Add(${quote(outFile)})`,
  ]
  if (paramsFile) {
    lines.push(`$argList.Add('-Params'); $argList.Add(${quote(paramsFile)})`)
  }
  if (Number(timeoutSec) > 0) {
    lines.push(`$argList.Add('-TimeoutSec'); $argList.Add(${quote(String(Math.floor(Number(timeoutSec))))})`)
  }
  lines.push(
    'try {',
    "  $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -WindowStyle Hidden -PassThru -ArgumentList $argList.ToArray()",
    "  if ($null -eq $proc) { [Console]::Error.WriteLine('DSH_ELEVATION_FAILED: Start-Process 未返回进程'); exit 1223 }",
    '  exit $proc.ExitCode',
    '} catch {',
    "  [Console]::Error.WriteLine(('DSH_ELEVATION_FAILED: ' + $_.Exception.Message))",
    '  exit 1223',
    '}',
  )
  return lines.join('\r\n')
}

/**
 * 以管理员身份执行一次 guard.ps1 动作（会弹 UAC）。
 * 只有在用户已点「授予守护权限」后才应调用；取消 UAC 抛 code='elevation-cancelled'。
 */
export async function runElevatedGuard(action, options = {}) {
  assertWindows()
  const {
    params = null,
    timeoutMs = ELEVATED_TIMEOUT_MS,
    timeoutSec = 0,
    log = null,
    signal = null,
  } = options

  if (!guardExists()) {
    throw new GuardError('guard-missing', `找不到系统守护脚本：${GUARD_PATH}`)
  }
  if (signal && signal.aborted) {
    throw new GuardError('aborted', `动作 ${action} 已取消`)
  }

  await ensureRuntimeDir()
  await ensureGuardEncoding(log)

  const shareDir = elevatedRuntimeDir()
  try {
    await fsp.mkdir(shareDir, { recursive: true })
  } catch {
    /* 公共目录不可用时退回用户临时目录 */
  }

  const baseName = makeTempName(`elevate-${action}`)
  const outFile = path.join(shareDir, `${baseName}.json`)
  const wrapperPath = path.join(RUNTIME_DIR, `${baseName}.ps1`)
  let paramsFile = ''

  if (params !== null && params !== undefined) {
    paramsFile = path.join(shareDir, `${baseName}.params.json`)
    await writeJsonFile(paramsFile, params)
  }

  const wrapper = buildElevatedWrapper({ action, outFile, paramsFile, timeoutSec })
  // 包装脚本同样需要 BOM（含中文路径时 PowerShell 5.1 才不会按 GBK 解析）
  await fsp.writeFile(wrapperPath, Buffer.concat([UTF8_BOM, Buffer.from(wrapper, 'utf8')]))

  const run = await spawnPowerShell(
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', wrapperPath],
    { timeoutMs, signal },
  )
  const result = await readResultFile(outFile)
  await pruneRuntimeDir()
  await pruneRuntimeDir(shareDir)

  if (run.spawnError) {
    throw new GuardError('spawn-failed', `无法启动提权进程：${run.spawnError.message}`, {
      stderr: run.stderr,
    })
  }
  if (run.aborted) {
    throw new GuardError('aborted', `动作 ${action} 已取消`, { outFile })
  }
  if (result) {
    if (result.ok === false) {
      const info = result.error || {}
      throw new GuardError(info.code || 'guard-failed', info.message || `动作 ${action} 失败`, {
        action: result.action || action,
        stderr: run.stderr,
      })
    }
    return result.value
  }
  if (run.timedOut) {
    throw new GuardError(
      'timeout',
      `提权动作 ${action} 超时（${timeoutMs} 毫秒）。如果 UAC 弹窗还在，请先处理它`,
      { stderr: run.stderr, outFile },
    )
  }
  const stderrText = String(run.stderr || '')
  const cancelled = run.exitCode === 1223 || /DSH_ELEVATION_FAILED/.test(stderrText) || /取消|cancel|cancelled|canceled/i.test(stderrText)
  if (cancelled) {
    throw new GuardError('elevation-cancelled', 'UAC 提权被取消或失败，未获得管理员权限', {
      stderr: stderrText,
      exitCode: run.exitCode,
    })
  }
  throw new GuardError(
    'elevation-failed',
    `提权动作 ${action} 未产生结果（退出码 ${run.exitCode}）`,
    { stderr: stderrText, exitCode: run.exitCode },
  )
}

let elevationCache = null

/**
 * 检测当前 DSH 进程是否具备管理员权限。
 * 结果缓存到进程生命周期，可用 { refresh: true } 重新检测。
 */
export async function detectElevation(options = {}) {
  const { refresh = false, log = null } = options
  if (!refresh && elevationCache !== null) return elevationCache
  if (process.platform !== 'win32') {
    elevationCache = false
    return false
  }
  const script =
    '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
  try {
    const run = await spawnPowerShell(
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { timeoutMs: 15_000 },
    )
    elevationCache = String(run.stdout || '').trim().toLowerCase().startsWith('true')
  } catch (error) {
    warn(log, `检测管理员权限失败：${error && error.message ? error.message : String(error)}`)
    elevationCache = false
  }
  return elevationCache
}

/** 重置管理员检测缓存（提权成功后 core 可调用） */
export function resetElevationCache() {
  elevationCache = null
}

export default {
  runGuard,
  runElevatedGuard,
  buildElevatedWrapper,
  detectElevation,
  resetElevationCache,
  guardPath,
  guardExists,
  GuardError,
  RUNTIME_DIR,
}

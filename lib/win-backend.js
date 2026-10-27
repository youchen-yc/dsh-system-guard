/**
 * dsh-system-guard · Windows backend（CONTRACT §4）
 *
 * 职责边界：
 * - Node 侧只做参数组装、结果校验与少量文件读写（插件数据目录里的冗余清单）；
 * - 所有系统级读写（CIM 查询、哈希、复制、删除、还原、sfc/dism）全部交给
 *   scripts/guard.ps1 → lib/ps.js；
 * - 提权动作只在 core 已授予权限（options.elevated === true）时执行，
 *   否则立即返回 need-elevation，绝不偷偷弹 UAC（CONTRACT §1.5 #8）。
 */

import { promises as fsp } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import {
  runGuard,
  runElevatedGuard,
  detectElevation,
  resetElevationCache,
} from './ps.js'

export const PLATFORM = 'windows'
export const BACKEND_VERSION = '1.0.0'

/** 插件默认配置（core 传入的 config 会覆盖这里的默认值） */
const DEFAULT_CONFIG = {
  excludeUpdateWindowMinutes: 1440,
  backupVolume: '',
  junkMaxItems: 3000,
  keepQuarantineDays: 7,
}

/** 动作超时（毫秒）。单次分析类动作控制在 180 秒内（CONTRACT §1.5 #5）。 */
const TIMEOUT = {
  probe: 30_000,
  analyze: 180_000,
  patrol: 180_000,
  junkScan: 120_000,
  junkDelete: 120_000,
  backup: 180_000,
  backupStatus: 60_000,
  facts: 30_000,
  restore: 180_000,
  // sfc / dism 是用户显式触发的系统修复，耗时不可控，单独放宽（内部还有 -TimeoutSec 兜底）
  systemRepair: 1_800_000,
  restorePoint: 300_000,
}

function defaultDataDir() {
  const dshHome = process.env.DSH_HOME
  if (dshHome) return path.join(dshHome, 'system-guard')
  return path.join(os.homedir() || os.tmpdir(), '.dsh', 'system-guard')
}

function numberOr(value, fallback) {
  const num = Number(value)
  return Number.isFinite(num) && num > 0 ? num : fallback
}

function warn(log, message) {
  try {
    if (log && typeof log.warn === 'function') log.warn(`[dsh-system-guard] ${message}`)
  } catch {
    /* 日志失败不影响主流程 */
  }
}

function info(log, message) {
  try {
    if (log && typeof log.info === 'function') log.info(`[dsh-system-guard] ${message}`)
  } catch {
    /* 忽略 */
  }
}

/** 把 items 统一成 guard 需要的 [{ path }]（不允许出现非路径字段，避免误删） */
function normalizeJunkItems(items) {
  if (!items) return []
  const list = Array.isArray(items) ? items : [items]
  const result = []
  for (const item of list) {
    if (!item) continue
    if (typeof item === 'string') {
      if (item.trim()) result.push({ path: item.trim() })
      continue
    }
    if (typeof item.path === 'string' && item.path.trim()) {
      result.push({ path: item.path.trim() })
    }
  }
  return result
}

function needElevationMessage() {
  return '需要管理员权限，请在面板点「授予守护权限」'
}

export function createWindowsBackend(options = {}) {
  const log = options.log || null
  const config = { ...DEFAULT_CONFIG, ...(options.config || {}) }
  const dataDir = options.dataDir || defaultDataDir()
  const mirrorPath = path.join(dataDir, 'backup-mirror.json')

  let lastBackupInfo = null
  let lastProbe = null

  /**
   * 读取 core 持久化的提权状态（<dataDir>/state.json 里的 privilege.granted）。
   * UAC 是进程级的，用户点过「授予守护权限」后 DSH 主进程本身仍是普通权限；
   * 这里把「已授权」当作允许调用提权 helper 的依据，具体动作再走一次受控 UAC。
   */
  async function hasPersistedGrant() {
    if (options.privilegeGranted === true) return true
    try {
      const text = await fsp.readFile(path.join(dataDir, 'state.json'), 'utf8')
      const stored = JSON.parse(text)
      return Boolean(stored && stored.privilege && stored.privilege.granted === true)
    } catch {
      return false
    }
  }

  /** 当前是否可以执行提权动作：优先用 core 传入的 options.elevated，其次持久化授权，最后真机检测 */
  async function isElevated() {
    if (typeof options.elevated === 'boolean') return options.elevated
    if (typeof options.isElevated === 'function') {
      try {
        if (await options.isElevated()) return true
      } catch {
        /* 忽略，继续用其它判断 */
      }
    }
    if (await hasPersistedGrant()) return true
    return detectElevation({ log })
  }

  /** 提权执行：core 可以提供自己的提权 runner（持久化 helper），否则走每次 UAC 包装 */
  async function runPrivileged(action, params, { timeoutMs, signal } = {}) {
    if (typeof options.elevatedRunner === 'function') {
      return options.elevatedRunner(action, params, { signal })
    }
    return runElevatedGuard(action, { params, dataDir, log, timeoutMs, signal })
  }

  /** 统一把异常转成 core 可直接展示的结构；aborted 继续向上抛（core 标记任务取消） */
  function toErrorResult(error, extra = {}) {
    if (error && error.code === 'aborted') throw error
    return {
      ok: false,
      ...extra,
      error: {
        code: (error && error.code) || 'backend-error',
        message: (error && error.message) || String(error),
      },
    }
  }

  /** 备份完成后把清单冗余保存到插件数据目录：备份被删时还能发现并重建 */
  async function writeMirrorManifest(backupInfo) {
    if (!backupInfo || !backupInfo.manifestPath) return
    try {
      const text = await fsp.readFile(backupInfo.manifestPath, 'utf8')
      const manifest = JSON.parse(text)
      const mirror = {
        mirrorVersion: 1,
        savedAt: Date.now(),
        info: {
          root: backupInfo.root,
          volume: backupInfo.volume,
          createdAt: backupInfo.createdAt,
          fileCount: backupInfo.fileCount,
          totalBytes: backupInfo.totalBytes,
          manifestPath: backupInfo.manifestPath,
        },
        manifest,
      }
      await fsp.mkdir(dataDir, { recursive: true })
      await fsp.writeFile(mirrorPath, JSON.stringify(mirror), 'utf8')
    } catch (error) {
      warn(log, `写入冗余备份清单失败（不影响本次备份）：${error && error.message ? error.message : String(error)}`)
    }
  }

  async function readMirrorManifest() {
    try {
      const text = await fsp.readFile(mirrorPath, 'utf8')
      if (!text.trim()) return null
      return JSON.parse(text)
    } catch {
      return null
    }
  }

  // --- CONTRACT §4 方法 -----------------------------------------------------

  async function probe() {
    const value = await runGuard('probe', {
      params: { excludeUpdateWindowMinutes: config.excludeUpdateWindowMinutes },
      timeoutMs: TIMEOUT.probe,
      log,
    })
    lastProbe = value
    return value
  }

  async function analyze({ files = null, signal = null } = {}) {
    const params = {
      files: Array.isArray(files) ? files : null,
      junkMaxItems: config.junkMaxItems,
      maxDurationMs: 45_000,
      excludeUpdateWindowMinutes: config.excludeUpdateWindowMinutes,
    }
    // 已授权提权时，用管理员 helper 跑分析：prefetch、内存转储、事件日志等
    // 普通权限读不到的目录也能扫到，避免「部分目录无法访问」的警告。
    // 提权失败（用户取消 UAC 等）自动降级为普通权限，并在 warnings 里说明。
    if (await isElevated()) {
      try {
        const value = await runPrivileged('analyze', params, { timeoutMs: TIMEOUT.analyze, signal })
        return { ...value, elevated: true }
      } catch (error) {
        if (error && error.code === 'aborted') throw error
        warn(log, `管理员权限分析失败，降级为普通权限：${error && error.message ? error.message : String(error)}`)
      }
    }
    const value = await runGuard('analyze', {
      params,
      timeoutMs: TIMEOUT.analyze,
      log,
      signal,
    })
    return { ...value, elevated: false }
  }

  async function patrol({ baseline = null, opts = {}, signal = null } = {}) {
    const settings = (opts && opts.settings) || {}
    const baselineFiles = Array.isArray(baseline)
      ? baseline
      : Array.isArray(baseline && baseline.files)
        ? baseline.files
        : null
    const windowMinutes = numberOr(
      opts && opts.updateWindowMinutes,
      numberOr(settings.excludeUpdateWindowMinutes, config.excludeUpdateWindowMinutes),
    )
    const sfc = Boolean(opts && opts.sfc)
    const params = {
      files: baselineFiles,
      updateWindowMinutes: windowMinutes,
      excludeUpdateWindowMinutes: windowMinutes,
      sfc,
    }
    // 调用方若已计算过更新窗口（probe 结果），直接透传，省一次 CIM 查询
    if (opts && opts.updateWindow && opts.updateWindow.from && opts.updateWindow.to) {
      params.updateWindow = { from: opts.updateWindow.from, to: opts.updateWindow.to }
    }
    const value = await runGuard('patrol', {
      params,
      timeoutMs: sfc ? TIMEOUT.systemRepair : TIMEOUT.patrol,
      log,
      signal,
    })
    return value
  }

  async function junkScan({ signal = null } = {}) {
    const params = { junkMaxItems: config.junkMaxItems, maxDurationMs: 45_000 }
    // 同 analyze：已授权提权就用管理员 helper 扫描，prefetch / 内存转储目录也能读到。
    if (await isElevated()) {
      try {
        const value = await runPrivileged('junk-scan', params, { timeoutMs: TIMEOUT.junkScan, signal })
        return { ...value, elevated: true }
      } catch (error) {
        if (error && error.code === 'aborted') throw error
        warn(log, `管理员权限垃圾扫描失败，降级为普通权限：${error && error.message ? error.message : String(error)}`)
      }
    }
    const value = await runGuard('junk-scan', {
      params,
      timeoutMs: TIMEOUT.junkScan,
      log,
      signal,
    })
    return { ...value, elevated: false }
  }

  async function junkDelete({ items = null, signal = null } = {}) {
    const wanted = normalizeJunkItems(items)
    if (wanted.length === 0) {
      return {
        ok: false,
        requested: 0,
        deleted: [],
        failed: [],
        freedBytes: 0,
        elevated: await isElevated(),
        error: { code: 'invalid-params', message: '没有选择要删除的项目' },
      }
    }
    return runGuard('junk-delete', {
      params: { items: wanted },
      timeoutMs: TIMEOUT.junkDelete,
      log,
      signal,
    })
  }

  async function backup({ files = null, signal = null } = {}) {
    const value = await runGuard('backup', {
      params: {
        // files 只作为提示（当前实现按内置核心清单备份，避免调用方传入任意路径）
        fileCountHint: Array.isArray(files) ? files.length : 0,
        backupVolume: config.backupVolume || '',
        excludeUpdateWindowMinutes: config.excludeUpdateWindowMinutes,
        dataDir,
      },
      timeoutMs: TIMEOUT.backup,
      log,
      signal,
    })
    lastBackupInfo = value
    await writeMirrorManifest(value)
    info(log, `备份完成：${value.root}（${value.fileCount} 个文件，${value.totalBytes} 字节）`)
    return value
  }

  async function backupStatus() {
    const value = await runGuard('backup-status', {
      params: { dataDir },
      timeoutMs: TIMEOUT.backupStatus,
      log,
    })
    if (value && value.state === 'none') {
      // 隐藏备份目录 / 清单被删：用插件数据目录里的冗余清单给出“丢失”状态
      const mirror = await readMirrorManifest()
      if (mirror && mirror.info && mirror.info.root) {
        return {
          ...value,
          state: 'missing',
          root: mirror.info.root,
          volume: mirror.info.volume,
          createdAt: mirror.info.createdAt || null,
          fileCount: mirror.info.fileCount || 0,
          totalBytes: mirror.info.totalBytes || 0,
          manifestPath: mirror.info.manifestPath || null,
          missingFiles: [mirror.info.root],
          recoveredFrom: 'data-mirror',
          warnings: [
            ...(value.warnings || []),
            '备份目录或清单已丢失，但插件数据目录里有冗余清单，可以据此重建备份',
          ],
        }
      }
    }
    return value
  }

  async function restore({ paths = [], signal = null } = {}) {
    const wanted = Array.isArray(paths) ? paths.filter((p) => typeof p === 'string' && p.trim()) : []
    if (wanted.length === 0) {
      return toErrorResult(
        { code: 'invalid-params', message: '没有指定要还原的文件' },
        { mode: 'restore', actions: [], output: '', warnings: [] },
      )
    }
    const elevated = await isElevated()
    if (!elevated) {
      return {
        ok: false,
        mode: 'restore',
        actions: [],
        output: '',
        warnings: [],
        error: { code: 'need-elevation', message: needElevationMessage() },
      }
    }
    try {
      return await runPrivileged(
        'restore',
        { paths: wanted, dataDir, keepQuarantineDays: config.keepQuarantineDays },
        { timeoutMs: TIMEOUT.restore, signal },
      )
    } catch (error) {
      return toErrorResult(error, { mode: 'restore', actions: [], output: '', warnings: [] })
    }
  }

  async function repair({ mode = '', paths = [], signal = null } = {}) {
    const wanted = String(mode || '').toLowerCase()
    const allowed = ['restore', 'sfc', 'dism', 'restore-point', 'backup']
    if (!allowed.includes(wanted)) {
      return {
        ok: false,
        mode: wanted,
        actions: [],
        output: '',
        warnings: [],
        error: { code: 'invalid-params', message: `未知修复模式：${mode}` },
      }
    }
    if (wanted === 'restore') return restore({ paths, signal })

    if (wanted === 'backup') {
      try {
        const info = await backup({ signal })
        return {
          ok: info.state === 'ok',
          mode: 'backup',
          actions: [{ step: 'backup', ok: info.state === 'ok', detail: info.root || '' }],
          output: `备份目录：${info.root || ''}；文件数：${info.fileCount || 0}`,
          warnings: info.warnings || [],
        }
      } catch (error) {
        return toErrorResult(error, { mode: 'backup', actions: [], output: '', warnings: [] })
      }
    }

    const elevated = await isElevated()
    if (!elevated) {
      return {
        ok: false,
        mode: wanted,
        actions: [],
        output: '',
        warnings: [],
        error: { code: 'need-elevation', message: needElevationMessage() },
      }
    }

    try {
      return await runPrivileged(
        'repair',
        {
          mode: wanted,
          paths: Array.isArray(paths) ? paths : [],
          dataDir,
          keepQuarantineDays: config.keepQuarantineDays,
        },
        { timeoutMs: TIMEOUT.systemRepair, signal },
      )
    } catch (error) {
      return toErrorResult(error, { mode: wanted, actions: [], output: '', warnings: [] })
    }
  }

  async function restorePoint({ signal = null } = {}) {
    const elevated = await isElevated()
    if (!elevated) {
      return {
        ok: false,
        message: needElevationMessage(),
        restorePointAt: null,
        error: { code: 'need-elevation', message: needElevationMessage() },
      }
    }
    try {
      return await runPrivileged(
        'restore-point',
        { dataDir },
        { timeoutMs: TIMEOUT.restorePoint, signal },
      )
    } catch (error) {
      if (error && error.code === 'aborted') throw error
      return {
        ok: false,
        message: (error && error.message) || '创建系统还原点失败',
        restorePointAt: null,
        error: { code: (error && error.code) || 'backend-error', message: (error && error.message) || '创建系统还原点失败' },
      }
    }
  }

  async function calibrateFacts({ signal = null } = {}) {
    return runGuard('calibrate-facts', {
      params: { excludeUpdateWindowMinutes: config.excludeUpdateWindowMinutes },
      timeoutMs: TIMEOUT.facts,
      log,
      signal,
    })
  }

  /**
   * 运行时更新配置（core 保存设置后调用，可选接口）。
   * 返回合并后的配置副本；backupVolume 变化时会清掉缓存，下次备份按新配置重新选盘。
   */
  function updateConfig(next = {}) {
    if (!next || typeof next !== 'object') return { ...config }
    const previousVolume = config.backupVolume
    Object.assign(config, next)
    // 数值项做一次兜底，避免 core 传来字符串或 0
    config.excludeUpdateWindowMinutes = numberOr(config.excludeUpdateWindowMinutes, DEFAULT_CONFIG.excludeUpdateWindowMinutes)
    config.junkMaxItems = Math.min(3000, numberOr(config.junkMaxItems, DEFAULT_CONFIG.junkMaxItems))
    config.keepQuarantineDays = numberOr(config.keepQuarantineDays, DEFAULT_CONFIG.keepQuarantineDays)
    config.backupVolume = typeof config.backupVolume === 'string' ? config.backupVolume : ''
    if (previousVolume !== config.backupVolume) lastBackupInfo = null
    return { ...config }
  }

  async function dispose() {
    lastBackupInfo = null
    lastProbe = null
  }

  // --- 返回 backend 对象 ----------------------------------------------------

  return {
    platform: PLATFORM,
    version: BACKEND_VERSION,

    probe,
    analyze,
    patrol,
    junkScan,
    junkDelete,
    backup,
    backupStatus,
    restore,
    repair,
    restorePoint,
    calibrateFacts,
    updateConfig,
    dispose,

    // 附加（非契约必需，方便 core/调试使用）
    get dataDir() {
      return dataDir
    },
    get config() {
      return { ...config }
    },
    get lastBackup() {
      return lastBackupInfo
    },
    get lastProbe() {
      return lastProbe
    },
    /** 重新检测管理员权限（提权成功后 core 可调用，清掉缓存） */
    refreshElevation() {
      resetElevationCache()
      return isElevated()
    },
  }
}

export default createWindowsBackend

/**
 * 系统守护 · 配置与状态存储。
 *
 * 两个文件，全部放在数据目录（默认 `$DSH_HOME/system-guard`）：
 *   - `settings.json`：用户可改的设置（巡查间隔、校准询问间隔等）；
 *   - `state.json`：运行状态与上次结果快照（分析、巡查、备份、权限、基线）。
 *
 * 写盘一律「先写临时文件再改名」，避免断电/崩溃留下半个 JSON。
 * 读盘一律「缺字段补默认、坏文件备份后回落」，绝不因为配置坏了让插件起不来。
 */

import os from 'node:os'
import path from 'node:path'
import { mkdir, readFile, rename, writeFile, copyFile, unlink } from 'node:fs/promises'

export const SETTINGS_VERSION = 1

/** 用户设置默认值。数值范围由 sanitizeSettings 收紧。 */
export const DEFAULT_SETTINGS = Object.freeze({
  /** 自动巡查间隔（天）。 */
  patrolIntervalDays: 7,
  /** 每隔多久询问一次「联网校准系统文件版本」（天）。 */
  calibrateAskIntervalDays: 30,
  /** 最近一次系统更新前后多久内的文件变化视为正常更新（分钟）。 */
  excludeUpdateWindowMinutes: 1440,
  /** 首次分析时是否自动创建核心文件备份。 */
  autoBackupOnAnalyze: true,
  /** 备份盘符（如 `F:`）；null 表示自动选择剩余容量最大的固定盘。 */
  backupVolume: null,
  /** 是否在界面显示巡查结果提醒。 */
  notify: true,
  /** 每类垃圾最多列出多少条（其余只计入统计）。 */
  junkMaxItems: 3000,
  /** 是否允许联网校准（关闭后只做本地完整性验证）。 */
  calibrateEnabled: true,
  /** 隔离区（被替换下来的旧文件）保留天数。 */
  keepQuarantineDays: 30,
})

/** 运行状态默认值。 */
export const DEFAULT_STATE = Object.freeze({
  version: 1,
  lastAnalyzeAt: null,
  lastPatrolAt: null,
  lastCalibrateAt: null,
  /** 下一次该询问用户「联网校准」的时间戳（毫秒）；null 表示从未询问。 */
  nextCalibrateAskAt: null,
  /** 核心文件基线；source 为 builtin（内置清单）或 calibrated（联网校准后）。 */
  baseline: Object.freeze({ source: 'builtin', calibratedAt: null, coreCount: 0, total: 0 }),
  /** 备份状态快照（BackupInfo）。 */
  backup: null,
  /** 权限快照：granted 表示用户已点过「授予守护权限」并确认过 UAC。 */
  privilege: Object.freeze({ granted: false, grantedAt: null, level: 'none', lastCheckedAt: null }),
  /** 上次巡查报告（截断版）。 */
  lastPatrol: null,
  /** 上次校准报告快照。 */
  lastCalibration: null,
})

const SETTINGS_LIMITS = {
  patrolIntervalDays: [1, 365],
  calibrateAskIntervalDays: [1, 365],
  excludeUpdateWindowMinutes: [0, 10080],
  junkMaxItems: [100, 5000],
  keepQuarantineDays: [1, 365],
}

function messageOf(error) {
  return String(error && error.message ? error.message : error)
}

/** 展开 `~` 开头的路径。 */
export function resolveHome(value) {
  const text = String(value || '').trim()
  if (!text) return text
  if (text === '~') return os.homedir()
  if (text.startsWith('~/') || text.startsWith('~\\')) return path.join(os.homedir(), text.slice(2))
  return text
}

/** 解析数据目录：配置优先，其次 `$DSH_HOME/system-guard`，再次 `~/.dsh/system-guard`。 */
export function resolveDataDir(config) {
  const custom = config && typeof config.dataDir === 'string' ? resolveHome(config.dataDir) : ''
  if (custom) return path.resolve(custom)
  const home = process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
  return path.join(home, 'system-guard')
}

function clampInt(value, fallback, min, max) {
  const number = Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.min(max, Math.max(min, Math.round(number)))
}

/** 把任意输入收紧成合法设置对象；未知字段丢弃。 */
export function normalizeSettings(input) {
  const raw = input && typeof input === 'object' ? input : {}
  const result = { ...DEFAULT_SETTINGS }
  result.patrolIntervalDays = clampInt(
    raw.patrolIntervalDays, DEFAULT_SETTINGS.patrolIntervalDays,
    ...SETTINGS_LIMITS.patrolIntervalDays,
  )
  result.calibrateAskIntervalDays = clampInt(
    raw.calibrateAskIntervalDays, DEFAULT_SETTINGS.calibrateAskIntervalDays,
    ...SETTINGS_LIMITS.calibrateAskIntervalDays,
  )
  result.excludeUpdateWindowMinutes = clampInt(
    raw.excludeUpdateWindowMinutes, DEFAULT_SETTINGS.excludeUpdateWindowMinutes,
    ...SETTINGS_LIMITS.excludeUpdateWindowMinutes,
  )
  result.junkMaxItems = clampInt(
    raw.junkMaxItems, DEFAULT_SETTINGS.junkMaxItems, ...SETTINGS_LIMITS.junkMaxItems,
  )
  result.keepQuarantineDays = clampInt(
    raw.keepQuarantineDays, DEFAULT_SETTINGS.keepQuarantineDays,
    ...SETTINGS_LIMITS.keepQuarantineDays,
  )
  result.autoBackupOnAnalyze = raw.autoBackupOnAnalyze !== false
  result.notify = raw.notify !== false
  result.calibrateEnabled = raw.calibrateEnabled !== false
  result.backupVolume = typeof raw.backupVolume === 'string' && /^[A-Za-z]:$/.test(raw.backupVolume.trim())
    ? raw.backupVolume.trim().toUpperCase()
    : null
  return result
}

/** 只接受设置对象里存在的键；返回合法化后的补丁。 */
export function sanitizeSettingsPatch(patch) {
  if (!patch || typeof patch !== 'object') return {}
  const allowed = new Set(Object.keys(DEFAULT_SETTINGS))
  const picked = {}
  for (const [key, value] of Object.entries(patch)) {
    if (allowed.has(key)) picked[key] = value
  }
  const merged = normalizeSettings({ ...DEFAULT_SETTINGS, ...picked })
  const result = {}
  for (const key of Object.keys(picked)) result[key] = merged[key]
  return result
}

/** 状态对象只做浅合并与形状兜底，避免旧版本状态弄坏新界面。 */
export function normalizeState(input) {
  const raw = input && typeof input === 'object' ? input : {}
  const state = {
    ...DEFAULT_STATE,
    ...raw,
    version: 1,
    baseline: { ...DEFAULT_STATE.baseline, ...(raw.baseline && typeof raw.baseline === 'object' ? raw.baseline : {}) },
    privilege: { ...DEFAULT_STATE.privilege, ...(raw.privilege && typeof raw.privilege === 'object' ? raw.privilege : {}) },
  }
  for (const key of ['lastAnalyzeAt', 'lastPatrolAt', 'lastCalibrateAt', 'nextCalibrateAskAt']) {
    const value = Number(state[key])
    state[key] = Number.isFinite(value) && value > 0 ? value : null
  }
  return state
}

async function readJsonFile(file, log, tag) {
  try {
    const text = await readFile(file, 'utf8')
    if (!text.trim()) return null
    return JSON.parse(text)
  } catch (error) {
    if (error && error.code === 'ENOENT') return null
    // 坏文件不静默丢弃：改名留档，回头能查。
    try {
      await rename(file, `${file}.broken-${Date.now()}`)
    } catch {
      /* 改名失败就算了，落回默认值 */
    }
    log?.warn?.(`[system-guard] ${tag} 读取失败，已回落默认值：${messageOf(error)}`)
    return null
  }
}

async function writeJsonAtomic(file, value) {
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}`
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
  await rename(tmp, file)
}

/**
 * 建立数据目录读写器。
 * @param {{ dataDir: string, log?: { warn?: Function, info?: Function } }} options
 */
export function createStore({ dataDir, log }) {
  const settingsFile = path.join(dataDir, 'settings.json')
  const stateFile = path.join(dataDir, 'state.json')
  let loadedSettings = null
  let loadedState = null
  let ensurePromise = null

  async function ensure() {
    if (!ensurePromise) {
      ensurePromise = mkdir(dataDir, { recursive: true }).catch((error) => {
        ensurePromise = null
        throw error
      })
    }
    return ensurePromise
  }

  return {
    dataDir,
    settingsFile,
    stateFile,

    /** 读取设置与状态（带内存缓存）。 */
    async load() {
      await ensure()
      if (!loadedSettings) {
        const raw = await readJsonFile(settingsFile, log, '设置')
        loadedSettings = normalizeSettings({ ...DEFAULT_SETTINGS, ...(raw && typeof raw === 'object' ? raw : {}) })
        if (!raw) await writeJsonAtomic(settingsFile, loadedSettings).catch(() => {})
      }
      if (!loadedState) {
        loadedState = normalizeState(await readJsonFile(stateFile, log, '状态'))
      }
      return { settings: { ...loadedSettings }, state: { ...loadedState } }
    },

    /** 合并并保存设置补丁。 */
    async saveSettings(patch) {
      await ensure()
      const current = loadedSettings || (await this.load()).settings
      const next = normalizeSettings({ ...current, ...sanitizeSettingsPatch(patch) })
      await writeJsonAtomic(settingsFile, next)
      loadedSettings = next
      return { ...next }
    },

    /** 合并并保存状态补丁。 */
    async saveState(patch) {
      await ensure()
      const current = loadedState || (await this.load()).state
      const next = normalizeState({ ...current, ...(patch && typeof patch === 'object' ? patch : {}) })
      await writeJsonAtomic(stateFile, next)
      loadedState = next
      return { ...next }
    },

    /** 任意 JSON 读写（备份清单、校准缓存等）。 */
    async readJson(name, fallback = null) {
      await ensure()
      const value = await readJsonFile(path.join(dataDir, name), log, name)
      return value === null ? fallback : value
    },
    async writeJson(name, value) {
      await ensure()
      const file = path.join(dataDir, name)
      await writeJsonAtomic(file, value)
      return file
    },

    /** 把文件复制进数据目录留档（用来备份基线、旧配置等）。 */
    async archive(absolutePath, name) {
      await ensure()
      const target = path.join(dataDir, name)
      await copyFile(absolutePath, target)
      return target
    },

    async remove(file) {
      await unlink(file).catch(() => {})
    },
  }
}

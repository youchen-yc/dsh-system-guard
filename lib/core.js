/**
 * 系统守护 · 核心编排。
 *
 * 职责：
 *   - 选平台后端（Windows → lib/win-backend.js；macOS/Linux → lib/posix-backend.js）；
 *   - 管理设置/状态、最近一次分析、垃圾扫描、备份快照的内存缓存；
 *   - 串行任务队列（分析/巡查/备份/修复这类长任务一次只跑一个）；
 *   - 动作分发 dispatch()：HTTP 与 Agent 工具共用，保证「一份实现两个入口」。
 *
 * 所有写系统动作都先过 privilege.assertSystemAction()；没有第二处提权入口。
 */

import os from 'node:os'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { stat } from 'node:fs/promises'

import { createStore, resolveDataDir } from './config.js'
import {
  PRIVILEGE_POLICY,
  assertSystemAction,
  isProtectionAction,
  requestElevation,
  selfCheck,
} from './privilege.js'
import { computeSchedule } from './patrol.js'

const VERSION = '1.0.0'
const DAY_MS = 24 * 60 * 60 * 1000
/** 长任务：dispatch 立即返回 taskId，由 UI 轮询。 */
const LONG_TASKS = new Set(['analyze', 'patrol', 'backup', 'repair', 'junk-scan', 'calibrate'])

function messageOf(error) {
  return String(error && error.message ? error.message : error)
}

function fail(code, message) {
  return { ok: false, error: { code: String(code || 'internal-error'), message: String(message || '') } }
}

/** 判断当前平台；只认 windows / macos / linux，其他归 linux（posix 兜底）。 */
export function detectPlatform() {
  if (process.platform === 'win32') return 'windows'
  if (process.platform === 'darwin') return 'macos'
  return 'linux'
}

/** 截断长数组，避免状态文件与 HTTP 响应过大。 */
function truncateArray(value, max) {
  if (!Array.isArray(value)) return []
  return value.slice(0, max)
}

/**
 * 建立核心实例。
 * @param {{
 *   dataDir?: string,
 *   pluginDir: string,
 *   log?: { warn?: Function, info?: Function },
 *   web?: unknown,
 * }} options
 */
export function createCore({ dataDir: customDataDir, pluginDir, log, web }) {
  const dataDir = customDataDir || resolveDataDir({})
  const store = createStore({ dataDir, log })
  const platform = detectPlatform()

  const state = {
    ready: null,
    settings: null,
    persisted: null,
    backend: null,
    backendError: null,
    probe: null,
    analysis: null,
    junk: null,
    backup: null,
    tasks: new Map(),
    queue: [],
    runningTask: null,
    taskSeq: 0,
    privilege: null,
    selfCheck: null,
    lastError: null,
  }

  // ---------------------------------------------------------------------------
  // 初始化
  // ---------------------------------------------------------------------------

  async function ensureReady() {
    if (state.ready) return state.ready
    state.ready = (async () => {
      const loaded = await store.load()
      state.settings = loaded.settings
      state.persisted = loaded.state
      // 分析/垃圾扫描结果落盘缓存：DSH 重启后首屏仍能看到上次分类，不用立刻重扫。
      try {
        const cached = await store.readJson('analysis.json', null)
        if (cached && cached.analysis && typeof cached.analysis === 'object') {
          state.analysis = cached.analysis
          state.junk = cached.junk && typeof cached.junk === 'object' ? cached.junk : null
        }
      } catch (error) {
        log?.warn?.(`[system-guard] 读取分析缓存失败（不影响使用）：${messageOf(error)}`)
      }
      try {
        state.selfCheck = await selfCheck({ pluginDir })
      } catch (error) {
        state.selfCheck = { ok: false, sealed: false, message: `自校验异常：${messageOf(error)}` }
      }
      return state
    })()
    state.ready.catch(() => {
      state.ready = null
    })
    return state.ready
  }

  /** 把最近一次分析与垃圾分类写盘（截断版，避免文件无限增长）。 */
  async function persistAnalysisCache() {
    if (!state.analysis) return
    try {
      await store.writeJson('analysis.json', {
        version: 1,
        savedAt: Date.now(),
        analysis: {
          ...state.analysis,
          files: truncateArray(state.analysis.files, 800),
          groups: truncateArray(state.analysis.groups, 40),
        },
        junk: state.junk
          ? {
            ...state.junk,
            groups: truncateArray(state.junk.groups, 40).map((group) => ({
              ...group,
              items: truncateArray(group.items, 3000),
            })),
          }
          : null,
      })
    } catch (error) {
      log?.warn?.(`[system-guard] 分析缓存写入失败（不影响结果）：${messageOf(error)}`)
    }
  }

  /** 懒加载平台后端；失败时记住原因，不反复抛。 */
  async function ensureBackend() {
    await ensureReady()
    if (state.backend) return state.backend
    if (state.backendError) throw state.backendError
    try {
      const options = {
        dataDir,
        config: state.settings,
        log: log || console,
        web,
        pluginDir,
      }
      if (platform === 'windows') {
        const module = await import('./win-backend.js')
        state.backend = module.createWindowsBackend(options)
      } else {
        const module = await import('./posix-backend.js')
        state.backend = module.createPosixBackend(options)
      }
      if (!state.backend || typeof state.backend.probe !== 'function') {
        throw new Error(`平台后端 ${platform} 未实现 probe()`)
      }
      return state.backend
    } catch (error) {
      state.backendError = new Error(`平台后端不可用（${platform}）：${messageOf(error)}`)
      state.backendError.code = 'backend-unavailable'
      throw state.backendError
    }
  }

  // ---------------------------------------------------------------------------
  // 任务队列
  // ---------------------------------------------------------------------------

  function publicTask(task) {
    if (!task) return null
    return {
      id: task.id,
      kind: task.kind,
      state: task.state,
      createdAt: task.createdAt,
      startedAt: task.startedAt,
      finishedAt: task.finishedAt,
      progress: task.progress,
      stage: task.stage,
      result: task.result === undefined ? null : task.result,
      error: task.error || null,
    }
  }

  function updateTask(task, patch) {
    Object.assign(task, patch)
  }

  function enqueueTask(kind, runner) {
    // 每个长任务自带 AbortController：面板点「取消」→ abort → 后端杀子进程。
    const controller = new AbortController()
    const task = {
      id: `task-${Date.now().toString(36)}-${randomUUID().slice(0, 6)}`,
      kind,
      state: 'queued',
      createdAt: Date.now(),
      startedAt: null,
      finishedAt: null,
      progress: 0,
      stage: '排队中',
      runs: runner,
      controller,
      result: null,
      error: null,
    }
    state.tasks.set(task.id, task)
    state.queue.push(task)
    pumpQueue()
    return publicTask(task)
  }

  function pumpQueue() {
    if (state.runningTask) return
    const next = state.queue.shift()
    if (!next) return
    state.runningTask = next
    updateTask(next, { state: 'running', startedAt: Date.now(), stage: '开始执行', progress: 0.02 })
    const taskPromise = Promise.resolve()
      .then(() => next.runs({
        setStage: (stage, progress) => updateTask(next, {
          stage: String(stage || ''),
          progress: typeof progress === 'number' ? progress : next.progress,
        }),
        signal: next.controller.signal,
      }))
      .then((value) => {
        // 长任务用返回 {ok:false,error} 表示失败（例如没基线、需要管理员）；
        // 统一抛成 failed 状态，界面才不会把「没做成」显示成「完成」。
        if (value && value.ok === false && value.error) {
          const error = new Error(value.error.message || '任务失败')
          error.code = value.error.code || 'task-failed'
          throw error
        }
        updateTask(next, {
          state: 'done',
          finishedAt: Date.now(),
          progress: 1,
          stage: '完成',
          result: value === undefined ? null : value,
        })
        return value
      })
      .catch((error) => {
        const aborted = Boolean(error && error.code === 'aborted')
        updateTask(next, {
          state: aborted ? 'cancelled' : 'failed',
          finishedAt: Date.now(),
          progress: 1,
          stage: aborted ? '已取消' : '失败',
          error: {
            code: error && error.code ? String(error.code) : 'internal-error',
            message: aborted ? '任务已被用户取消。' : messageOf(error),
          },
        })
        if (!aborted) state.lastError = { at: Date.now(), kind: next.kind, message: messageOf(error) }
        throw error
      })
      .finally(() => {
        state.runningTask = null
        // 只保留最近 20 个任务记录。
        const all = [...state.tasks.values()].sort((a, b) => a.createdAt - b.createdAt)
        while (all.length > 20) {
          const oldest = all.shift()
          state.tasks.delete(oldest.id)
        }
        pumpQueue()
      })
    // 失败已记进 task，不产生未处理拒绝。
    taskPromise.catch(() => {})
  }

  function latestRunningTask() {
    if (state.runningTask) return publicTask(state.runningTask)
    const queued = state.queue[0]
    return queued ? publicTask(queued) : null
  }

  // ---------------------------------------------------------------------------
  // 保存与快照
  // ---------------------------------------------------------------------------

  async function persistState(patch) {
    state.persisted = await store.saveState(patch)
    return state.persisted
  }

  async function saveBaseline({ files, source, calibratedAt }) {
    await store.writeJson('baseline.json', {
      version: 1,
      source,
      calibratedAt: calibratedAt || null,
      savedAt: Date.now(),
      files: truncateArray(files, 2000),
    })
    return persistState({
      baseline: {
        source,
        calibratedAt: calibratedAt || null,
        coreCount: files.filter((file) => file && file.role === 'core').length,
        total: files.length,
      },
    })
  }

  async function loadBaseline() {
    const data = await store.readJson('baseline.json', null)
    if (data && Array.isArray(data.files) && data.files.length > 0) return data
    return null
  }

  async function refreshProbe({ force = false } = {}) {
    await ensureBackend()
    const now = Date.now()
    const fresh = !force && state.probe && state.probeAt && now - state.probeAt < 60 * 1000
    if (fresh) return state.probe
    try {
      state.probe = await state.backend.probe()
      state.probeAt = now
      return state.probe
    } catch (error) {
      state.lastError = { at: Date.now(), kind: 'probe', message: messageOf(error) }
      throw error
    }
  }

  async function refreshBackupStatus({ force = false } = {}) {
    await ensureBackend()
    const now = Date.now()
    if (!force && state.backup && state.backupAt && now - state.backupAt < 30 * 1000) return state.backup
    try {
      state.backup = await state.backend.backupStatus()
      state.backupAt = now
      await persistState({ backup: state.backup })
      return state.backup
    } catch (error) {
      state.lastError = { at: Date.now(), kind: 'backup-status', message: messageOf(error) }
      return state.backup || null
    }
  }

  function publicAnalysis() {
    if (!state.analysis) return null
    return {
      ...state.analysis,
      files: truncateArray(state.analysis.files, 800),
      groups: truncateArray(state.analysis.groups, 40),
    }
  }

  function publicJunk() {
    if (!state.junk) return null
    return {
      ...state.junk,
      groups: truncateArray(state.junk.groups, 40),
    }
  }

  /**
   * 状态接口只给摘要：完整文件清单和垃圾条目动辄上兆，
   * 每次轮询都传会拖慢面板；明细走 /analysis。
   */
  function publicAnalysisSummary() {
    const analysis = state.analysis
    if (!analysis) return null
    return {
      analyzedAt: analysis.analyzedAt || null,
      durationMs: analysis.durationMs || null,
      coreCount: analysis.coreCount || 0,
      coreBytes: analysis.coreBytes || 0,
      supportCount: analysis.supportCount || 0,
      supportBytes: analysis.supportBytes || 0,
      supportSampleCount: analysis.supportSampleCount || 0,
      supportScope: analysis.supportScope || '',
      memoryCount: analysis.memoryCount || 0,
      memoryBytes: analysis.memoryBytes || 0,
      totalJunkBytes: analysis.totalJunkBytes || 0,
      baselineSource: analysis.baselineSource || state.persisted?.baseline?.source || 'builtin',
      calibratedAt: analysis.calibratedAt || null,
      // 本次分析是否以管理员权限运行（能读到 prefetch / 内存转储等目录）。
      elevated: analysis.elevated === true,
      warnings: truncateArray(analysis.warnings, 20),
    }
  }

  function publicJunkSummary() {
    const junk = state.junk
    if (!junk) return null
    return {
      scannedAt: junk.scannedAt || null,
      totalBytes: junk.totalBytes || 0,
      warnings: truncateArray(junk.warnings, 20),
      groups: truncateArray(junk.groups, 40).map((group) => ({
        id: group.id,
        title: group.title,
        kind: group.kind,
        note: group.note || '',
        safeToDelete: group.safeToDelete !== false,
        totalBytes: group.totalBytes || 0,
        itemCount: group.itemCount || 0,
      })),
    }
  }

  // ---------------------------------------------------------------------------
  // 动作实现
  // ---------------------------------------------------------------------------

  async function actionStatus() {
    await ensureReady()
    // 首屏预热：第一次取状态时后台读一次系统信息（约 1~2 秒），
    // 不阻塞响应；下一次轮询/刷新就能看到 OS 与磁盘信息。
    if (!state.probe) {
      refreshProbe().catch(() => {})
    }
    const schedule = computeSchedule({
      settings: state.settings,
      persisted: state.persisted,
      now: Date.now(),
      dayMs: DAY_MS,
    })
    return {
      ok: true,
      version: VERSION,
      platform,
      dataDir,
      policy: PRIVILEGE_POLICY.charter,
      allowedActions: PRIVILEGE_POLICY.allowedActions,
      forbiddenPurposes: PRIVILEGE_POLICY.forbiddenPurposes,
      settings: { ...state.settings },
      privilege: {
        ...(state.persisted.privilege || {}),
        elevation: state.privilege || null,
      },
      selfCheck: state.selfCheck,
      schedule,
      probe: state.probe || null,
      // 重启后内存里的备份状态是空的，先回退到上次持久化快照，避免面板误报「没有备份」。
      backup: state.backup || state.persisted.backup || null,
      lastPatrol: state.persisted.lastPatrol || null,
      lastCalibration: state.persisted.lastCalibration || null,
      baseline: state.persisted.baseline,
      lastAnalyzeAt: state.persisted.lastAnalyzeAt,
      lastPatrolAt: state.persisted.lastPatrolAt,
      lastCalibrateAt: state.persisted.lastCalibrateAt,
      analysis: publicAnalysisSummary(),
      junk: publicJunkSummary(),
      tasks: [latestRunningTask()].filter(Boolean),
      lastError: state.lastError,
    }
  }

  async function actionAnalyze({ setStage, payload, signal } = {}) {
    assertSystemAction('analyze')
    const set = typeof setStage === 'function' ? setStage : () => {}
    set('读取系统信息', 0.05)
    const probe = await refreshProbe({ force: true })

    let calibratedAt = null
    if (state.settings.calibrateEnabled && !(payload && payload.skipCalibration)) {
      set('联网校准系统文件版本', 0.15)
      try {
        const facts = await state.backend.calibrateFacts({ signal })
        const { calibrate } = await import('./calibrate.js')
        const report = await calibrate({
          facts,
          web,
          config: state.settings,
          log: log || console,
        })
        if (report && report.ok) {
          calibratedAt = report.checkedAt || Date.now()
          await persistState({ lastCalibration: report })
        } else {
          log?.warn?.(`[system-guard] 联网校准未成功：${report && report.error ? report.error.message : '未知原因'}`)
        }
      } catch (error) {
        log?.warn?.(`[system-guard] 联网校准异常（继续用内置清单）：${messageOf(error)}`)
      }
    }

    set('解析核心文件清单并分类', 0.3)
    const previous = await loadBaseline()
    const analysis = await state.backend.analyze({ files: previous ? previous.files : null, signal })
    state.analysis = {
      ...analysis,
      analyzedAt: analysis.analyzedAt || Date.now(),
      baselineSource: calibratedAt ? 'calibrated' : 'builtin',
      calibratedAt,
    }
    if (analysis && Array.isArray(analysis.groups)) {
      state.junk = {
        groups: analysis.groups,
        totalBytes: analysis.totalJunkBytes || 0,
        warnings: analysis.warnings || [],
      }
    }

    set('保存基线', 0.85)
    await saveBaseline({
      files: analysis.files || [],
      source: calibratedAt ? 'calibrated' : 'builtin',
      calibratedAt,
    })
    await persistState({
      lastAnalyzeAt: Date.now(),
      lastCalibration: calibratedAt ? state.persisted.lastCalibration : state.persisted.lastCalibration,
    })
    await persistAnalysisCache()

    if (state.settings.autoBackupOnAnalyze && !(payload && payload.skipBackup)) {
      set('备份核心系统文件', 0.9)
      try {
        state.backup = await state.backend.backup({ files: analysis.files || [], signal })
        state.backupAt = Date.now()
        await persistState({ backup: state.backup })
      } catch (error) {
        log?.warn?.(`[system-guard] 自动备份失败（分析结果不受影响）：${messageOf(error)}`)
      }
    }

    set('完成', 1)
    return { ok: true, analysis: publicAnalysisSummary(), backup: state.backup, probe }
  }

  async function actionJunkScan({ setStage, signal } = {}) {
    assertSystemAction('junk-scan')
    const set = typeof setStage === 'function' ? setStage : () => {}
    set('扫描系统运行时产生的垃圾文件', 0.2)
    await ensureBackend()
    const report = await state.backend.junkScan({ signal })
    state.junk = {
      ...report,
      scannedAt: Date.now(),
    }
    await persistAnalysisCache()
    return { ok: true, junk: publicJunkSummary() }
  }

  async function actionJunkDelete(payload) {
    assertSystemAction('junk-delete')
    const body = payload && typeof payload === 'object' ? payload : {}
    if (body.confirm !== true) {
      return fail('confirm-required', '删除系统垃圾前需要用户明确确认（confirm: true）。')
    }
    const items = Array.isArray(body.items) ? body.items.filter((item) => item && typeof item.path === 'string') : []
    if (items.length === 0) return fail('empty-selection', '没有选中要删除的项目。')
    if (state.selfCheck && state.selfCheck.ok === false) {
      return fail('self-check-failed', state.selfCheck.message)
    }
    await ensureBackend()
    const result = await state.backend.junkDelete({ items })
    // 删除后重扫一遍，界面上的数字才是真的。
    try {
      state.junk = { ...(await state.backend.junkScan()), scannedAt: Date.now() }
      await persistAnalysisCache()
    } catch {
      /* 重扫失败不影响删除结果 */
    }
    return { ok: true, result, junk: publicJunkSummary() }
  }

  async function actionPatrol({ setStage, payload, signal } = {}) {
    assertSystemAction('patrol')
    const set = typeof setStage === 'function' ? setStage : () => {}
    set('读取系统信息与基线', 0.1)
    const probe = await refreshProbe({ force: true })
    const baseline = await loadBaseline()
    if (!baseline) {
      return fail('no-baseline', '还没有核心文件基线，请先点「分析」建立基线。')
    }
    set('逐个核对核心文件完整性', 0.3)
    const options = {
      settings: state.settings,
      updateWindowMinutes: state.settings.excludeUpdateWindowMinutes,
      sfc: Boolean(payload && payload.sfc),
    }
    const report = await state.backend.patrol({ baseline, opts: options, signal })
    const trimmed = {
      ...report,
      checkedAt: report.checkedAt || Date.now(),
      changed: truncateArray(report.changed, 200),
      missing: truncateArray(report.missing, 200),
    }
    set('检查备份状态', 0.85)
    try {
      state.backup = await state.backend.backupStatus()
      state.backupAt = Date.now()
      trimmed.backup = { state: state.backup.state }
    } catch {
      trimmed.backup = { state: 'unknown' }
    }
    await persistState({ lastPatrolAt: Date.now(), lastPatrol: trimmed, backup: state.backup })
    set('完成', 1)
    return { ok: true, patrol: trimmed, probe }
  }

  async function actionBackup({ setStage, payload, signal } = {}) {
    assertSystemAction('backup')
    const set = typeof setStage === 'function' ? setStage : () => {}
    set('选择备份位置', 0.1)
    await ensureBackend()
    const baseline = await loadBaseline()
    const files = baseline && Array.isArray(baseline.files) && baseline.files.length > 0
      ? baseline.files
      : (payload && Array.isArray(payload.files) ? payload.files : [])
    if (files.length === 0) {
      return fail('no-baseline', '还没有核心文件清单，请先点「分析」。')
    }
    set('复制核心系统文件', 0.35)
    const info = await state.backend.backup({ files, signal })
    state.backup = info
    state.backupAt = Date.now()
    await persistState({ backup: info })
    set('完成', 1)
    return { ok: true, backup: info }
  }

  async function actionBackupStatus() {
    assertSystemAction('backup-status')
    await ensureBackend()
    const info = await state.backend.backupStatus()
    state.backup = info
    state.backupAt = Date.now()
    await persistState({ backup: info })
    return { ok: true, backup: info }
  }

  async function actionRepair({ setStage, payload, signal } = {}) {
    assertSystemAction('repair')
    const set = typeof setStage === 'function' ? setStage : () => {}
    const body = payload && typeof payload === 'object' ? payload : {}
    const mode = typeof body.mode === 'string' ? body.mode : 'restore'
    const paths = Array.isArray(body.paths) ? body.paths.filter((item) => typeof item === 'string') : []
    set('准备修复', 0.1)
    await ensureBackend()
    const report = await state.backend.repair({ mode, paths, signal })
    set('完成', 1)
    if (report && report.ok === false && report.error) {
      return fail(report.error.code || 'repair-failed', report.error.message || '修复失败')
    }
    await persistState({ lastRepairAt: Date.now() })
    return { ok: true, repair: report }
  }

  async function actionRestorePoint() {
    assertSystemAction('restore-point')
    await ensureBackend()
    if (typeof state.backend.restorePoint !== 'function') {
      return fail('unsupported', '当前系统不支持由本插件创建还原点。')
    }
    const result = await state.backend.restorePoint()
    if (result && result.ok === false) {
      return fail(
        (result.error && result.error.code) || 'restore-point-failed',
        (result.error && result.error.message) || result.message || '创建系统还原点失败。',
      )
    }
    return { ok: true, result }
  }

  async function actionCalibrate({ setStage, payload, signal } = {}) {
    assertSystemAction('calibrate')
    const set = typeof setStage === 'function' ? setStage : () => {}
    if (!state.settings.calibrateEnabled) {
      return fail('calibrate-disabled', '联网校准已在设置中关闭。')
    }
    set('收集本机系统文件信息', 0.2)
    await ensureBackend()
    const facts = await state.backend.calibrateFacts({ signal })
    const { calibrate } = await import('./calibrate.js')
    const report = await calibrate({ facts, web, config: state.settings, log: log || console })
    if (report && report.ok) {
      await persistState({
        lastCalibrateAt: report.checkedAt || Date.now(),
        lastCalibration: report,
        nextCalibrateAskAt: (report.checkedAt || Date.now()) + state.settings.calibrateAskIntervalDays * DAY_MS,
        baseline: { ...state.persisted.baseline, source: 'calibrated', calibratedAt: report.checkedAt || Date.now() },
      })
      // 校准结论里若带官方的核心文件提示，记录下来供巡查参考（不改动本地清单）。
      const existing = await loadBaseline()
      if (existing) {
        existing.calibratedAt = report.checkedAt || Date.now()
        existing.source = 'calibrated'
        await store.writeJson('baseline.json', existing)
      }
    }
    set('完成', 1)
    return { ok: true, calibration: report }
  }

  async function actionSettingsSave(payload) {
    const patch = payload && typeof payload === 'object' && payload.patch ? payload.patch : payload
    const settings = await store.saveSettings(patch)
    state.settings = settings
    if (typeof state.backend?.updateConfig === 'function') {
      try {
        state.backend.updateConfig(settings)
      } catch {
        /* 后端不支持热更新就算了，下次操作会用新配置 */
      }
    }
    return { ok: true, settings }
  }

  async function actionElevate() {
    assertSystemAction('elevate')
    if (platform !== 'windows') {
      const result = await requestElevation({ platform })
      return { ok: false, error: { code: result.level === 'unsupported' ? 'unsupported' : 'not-windows', message: result.message } }
    }
    let runElevatedProbe = null
    try {
      const ps = await import('./ps.js')
      if (ps && typeof ps.runElevatedGuard === 'function') {
        runElevatedProbe = () => ps.runElevatedGuard('probe', { dataDir, log })
      }
    } catch (error) {
      log?.warn?.(`[system-guard] 提权执行器不可用：${messageOf(error)}`)
    }
    const result = await requestElevation({ platform, runElevatedProbe })
    state.privilege = { at: Date.now(), ...result }
    if (result.granted) {
      await persistState({
        privilege: { granted: true, grantedAt: Date.now(), level: result.level, lastCheckedAt: Date.now() },
      })
      // 提权后刷新 probe，让界面上的 admin 状态变成真的。
      try {
        await refreshProbe({ force: true })
      } catch {
        /* probe 失败不影响授权结果 */
      }
    } else {
      await persistState({
        privilege: { ...(state.persisted.privilege || {}), lastCheckedAt: Date.now() },
      })
    }
    return result.ok ? { ok: true, privilege: result, probe: state.probe } : fail(result.level === 'elevation-cancelled' ? 'elevation-cancelled' : 'elevation-failed', result.message)
  }

  async function actionResetBaseline() {
    assertSystemAction('analyze')
    await store.remove(path.join(dataDir, 'baseline.json'))
    await persistState({
      baseline: { source: 'builtin', calibratedAt: null, coreCount: 0, total: 0 },
      lastAnalyzeAt: null,
    })
    state.analysis = null
    state.junk = null
    return { ok: true }
  }

  // ---------------------------------------------------------------------------
  // dispatch
  // ---------------------------------------------------------------------------

  /**
   * 统一动作分发。
   * @param {string} action
   * @param {unknown} payload
   * @param {{ longTask?: boolean }} options
   * @returns {Promise<object>}
   */
  async function dispatch(action, payload, options = {}) {
    const name = String(action || '').trim()
    try {
      await ensureReady()
      if (!isProtectionAction(name) && name !== 'status' && name !== 'settings-save'
        && name !== 'reset-baseline' && name !== 'cancel-task') {
        throw Object.assign(new Error(`未知动作：${name}`), { code: 'unknown-action' })
      }

      if (name === 'status') return await actionStatus()

      if (name === 'cancel-task') {
        const target = payload && typeof payload === 'object' ? payload.id : payload
        const running = state.runningTask
        if (running && (!target || running.id === target)) {
          try {
            running.controller.abort()
          } catch {
            /* 已经结束的任务 abort 也不报错 */
          }
          return { ok: true, cancelled: running.id }
        }
        const before = state.queue.length
        state.queue = state.queue.filter((task) => !target || task.id !== target)
        return { ok: true, cancelled: before !== state.queue.length ? (target || 'all') : null }
      }

      if (name === 'settings-save') return await actionSettingsSave(payload)

      if (name === 'junk-delete') return await actionJunkDelete(payload)

      if (name === 'backup-status') return await actionBackupStatus()

      if (name === 'elevate') {
        const task = await actionElevate()
        return task
      }

      if (name === 'reset-baseline') return await actionResetBaseline()

      // 长任务：入队，立即返回 taskId。
      if (LONG_TASKS.has(name)) {
        const runnerMap = {
          analyze: actionAnalyze,
          patrol: actionPatrol,
          backup: actionBackup,
          repair: actionRepair,
          'junk-scan': actionJunkScan,
          calibrate: actionCalibrate,
        }
        const runner = runnerMap[name]
        if (!runner) return fail('unknown-action', `动作 ${name} 没有实现。`)
        // 同一种长任务已在跑：直接复用，避免用户连点造成多份系统扫描。
        const running = state.runningTask
        if (running && running.kind === name) return { ok: true, taskId: running.id, reused: true }
        const queuedSame = state.queue.find((task) => task.kind === name)
        if (queuedSame) return { ok: true, taskId: queuedSame.id, reused: true }
        const task = enqueueTask(name, (helpers) => runner({ ...helpers, payload }))
        return { ok: true, taskId: task.id, task: publicTask(state.tasks.get(task.id)) }
      }

      if (name === 'restore-point') {
        const task = enqueueTask('restore-point', () => actionRestorePoint())
        return { ok: true, taskId: task.id, task: publicTask(state.tasks.get(task.id)) }
      }

      return fail('unknown-action', `未知动作：${name}`)
    } catch (error) {
      const code = error && error.code ? String(error.code) : 'internal-error'
      const message = messageOf(error)
      if (!['unknown-action', 'need-elevation', 'privilege-denied'].includes(code)) {
        state.lastError = { at: Date.now(), kind: name, message }
      }
      return fail(code, message)
    }
  }

  /** 读取任务；不存在返回 null。 */
  function getTask(id) {
    return publicTask(state.tasks.get(String(id || '')))
  }

  /** 完整分析结果（含文件清单与垃圾条目），供 UI 单独拉取。 */
  async function getAnalysis() {
    await ensureReady()
    return {
      ok: true,
      analysis: publicAnalysis(),
      junk: publicJunk(),
      probe: state.probe || null,
      // 重启后内存里的备份状态是空的，先回退到上次持久化快照，避免面板误报「没有备份」。
      backup: state.backup || state.persisted.backup || null,
    }
  }

  /** 供定时器使用：是否到巡查时间。 */
  async function dueInfo() {
    await ensureReady()
    return computeSchedule({ settings: state.settings, persisted: state.persisted, now: Date.now(), dayMs: DAY_MS })
  }

  async function dispose() {
    try {
      if (state.backend && typeof state.backend.dispose === 'function') await state.backend.dispose()
    } catch (error) {
      log?.warn?.(`[system-guard] 后端释放失败：${messageOf(error)}`)
    }
  }

  /** 首次运行判断：是否已经做过分析。 */
  async function isFirstRun() {
    await ensureReady()
    return !state.persisted.lastAnalyzeAt
  }

  return {
    platform,
    dataDir,
    version: VERSION,
    state,
    detectPlatform,
    ensureReady,
    ensureBackend,
    dispatch,
    getTask,
    getAnalysis,
    dueInfo,
    dispose,
    isFirstRun,
    refreshProbe,
    getSettings: () => state.settings,
    getPersisted: () => state.persisted,
    getPluginDir: () => pluginDir,
    getWeb: () => web,
    DAY_MS,
    VERSION,
  }
}

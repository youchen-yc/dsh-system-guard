/**
 * 系统守护（dsh-system-guard）· Host 插件入口。
 *
 * 做四件事：
 *   1. 首次运行：分析本机系统，联网核对系统文件版本，把核心文件 / 普通系统文件 /
 *      运行时垃圾 / 系统记忆类文件分好类（不删除，交给用户决定）；
 *   2. 把核心系统文件隐藏备份到剩余容量最大的硬盘，供损坏/被篡改时修复替换；
 *   3. 按设置的间隔自动巡查完整性；发现非 Windows 更新导致的改动就告警；
 *   4. 校准提醒：按设置的间隔提醒用户「要不要联网校准系统文件版本」。
 *
 * 权限边界写在 lib/privilege.js：守护权限只用于保护系统，白名单之外的动作一律拒绝。
 * 本文件只做装配，不写业务逻辑；HTTP 与 Agent 工具共用 lib/core.js 的 dispatch()。
 */

import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { createCore } from './lib/core.js'
import { API_PREFIX, handleApi } from './lib/httpapi.js'

export const name = 'system-guard'
export const inject = ['tools']

const VERSION = '1.0.0'
const PLUGIN_DIR = path.dirname(fileURLToPath(import.meta.url))
const CHECK_INTERVAL_MS = 15 * 60 * 1000

function messageOf(error) {
  return String(error && error.message ? error.message : error)
}

/** 在插件目录下解析文件（安装后由 bundle 链接或复制到 profile）。 */
function resolvePluginPath(relative) {
  return path.join(PLUGIN_DIR, relative)
}

/** 等待一个长任务结束（工具调用需要同步结果）。 */
async function waitForTask(core, taskId, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const task = core.getTask(taskId)
    if (!task) return { ok: false, error: { code: 'task-not-found', message: `任务不存在：${taskId}` } }
    if (task.state === 'done') return { ok: true, task }
    if (task.state === 'failed') {
      return {
        ok: false,
        error: {
          code: task.error && task.error.code ? task.error.code : 'task-failed',
          message: task.error && task.error.message ? task.error.message : '任务失败',
        },
        task,
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 700))
  }
  return {
    ok: false,
    error: { code: 'task-timeout', message: '任务超时未完成，可稍后在面板或再用 status 查看结果。' },
  }
}

export function apply(ctx, rawConfig = {}) {
  const log = ctx.logger ?? console
  const config = rawConfig && typeof rawConfig === 'object' ? rawConfig : {}
  const dataDir = typeof config.dataDir === 'string' && config.dataDir.trim()
    ? config.dataDir.trim()
    : undefined

  function readWebService() {
    try {
      return typeof ctx.get === 'function' ? ctx.get('web') : undefined
    } catch {
      return undefined
    }
  }
  const web = readWebService()

  const core = createCore({
    dataDir,
    pluginDir: PLUGIN_DIR,
    log,
    web,
  })

  // 启动即把设置/状态读起来（失败只记日志，不影响注册）。
  core.ensureReady().catch((error) => {
    log.warn?.(`[system-guard] 初始化失败：${messageOf(error)}`)
  })

  // ---------------------------------------------------------------------------
  // HTTP 接口（面板用）
  // ---------------------------------------------------------------------------
  const registerHttp = (webCtx) => {
    try {
      webCtx.effect(() => webCtx.webServer.register({
        kind: 'prefix',
        path: API_PREFIX,
        handler: (req, res) => handleApi(req, res, {
          core,
          originOf: () => {
            try {
              return webCtx.webServer.getOrigin()
            } catch {
              return ''
            }
          },
        }),
      }))
    } catch (error) {
      log.warn?.(`[system-guard] 面板接口注册失败（Agent 工具不受影响）：${messageOf(error)}`)
    }
  }
  try {
    if (typeof ctx.inject === 'function') {
      ctx.inject(['webServer'], registerHttp)
    } else if (typeof ctx.get === 'function' && ctx.get('webServer')) {
      registerHttp(ctx)
    }
  } catch (error) {
    log.warn?.(`[system-guard] 面板接口注册失败（Agent 工具不受影响）：${messageOf(error)}`)
  }

  // ---------------------------------------------------------------------------
  // Agent 工具：和面板共用 core.dispatch()
  // ---------------------------------------------------------------------------
  const tool = {
    name: 'system_guard',
    description:
      '系统守护：分析并分类本机系统文件（核心/普通/垃圾/系统记忆类），把核心系统文件隐藏备份到剩余容量最大的硬盘，'
      + '定期巡查完整性，发现损坏或被篡改时告警并从备份修复，联网校准系统文件版本。\n'
      + '权限边界：守护权限只用于保护系统，无法用于保护系统以外的事情。\n'
      + 'action=status：查看守护状态（系统信息、权限、备份、上次巡查、下次巡查/校准时间）。\n'
      + 'action=analyze：首次分析（联网核对 + 分类 + 自动备份），耗时较长。\n'
      + 'action=patrol：立即巡查核心文件完整性；发现的变化若落在 Windows 更新窗口内会被豁免、不告警。\n'
      + 'action=junk-scan：扫描系统运行时产生的垃圾文件（只扫描不删除）。\n'
      + 'action=junk-delete：删除用户选中的垃圾（必须带 confirm=true 与 items 列表）；系统记忆类文件永远不会被删除。\n'
      + 'action=backup：把核心系统文件备份到隐藏备份目录；action=backup-status：查看备份状态。\n'
      + 'action=repair：修复损坏文件。mode=restore（从备份还原，默认）/ sfc / dism / restore-point；需要管理员权限；'
      + '必须带 confirm=true。\n'
      + 'action=restore-point：创建系统还原点。\n'
      + 'action=calibrate：联网校准系统文件版本（只读查询官方渠道）。\n'
      + 'action=settings-save：修改设置（patrolIntervalDays 巡查间隔天数、calibrateAskIntervalDays 校准询问间隔天数等）。\n'
      + '注意：授予守护权限（UAC）只能由用户在面板上点，Agent 不能代为授权。',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: [
            'status',
            'analyze',
            'patrol',
            'junk-scan',
            'junk-delete',
            'backup',
            'backup-status',
            'repair',
            'restore-point',
            'calibrate',
            'settings-save',
          ],
          description: '要执行的动作',
        },
        payload: {
          type: 'object',
          additionalProperties: true,
          description: '动作参数。junk-delete：{confirm:true, items:[{path}]}；repair：{confirm:true, mode:"restore"|"sfc"|"dism", paths:[...]}；'
            + 'settings-save：{patch:{patrolIntervalDays:7, calibrateAskIntervalDays:30}}。',
        },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => {
        if (!value || typeof value !== 'object') return [{ type: 'text', text: String(value) }]
        if (value.ok === false && value.error) {
          return [{ type: 'text', text: `失败：${value.error.message || value.error.code || '未知错误'}` }]
        }
        return [{ type: 'text', text: JSON.stringify(value, null, 2) }]
      },
    },
    timeoutMs: 300000,
    async execute(args = {}) {
      const action = String(args.action || '').trim()
      let payload = args.payload && typeof args.payload === 'object' ? args.payload : null

      // 危险动作用户必须明确确认；工具侧做最后一道门。
      if (action === 'junk-delete' || action === 'repair') {
        if (!payload || payload.confirm !== true) {
          return {
            ok: false,
            error: {
              code: 'confirm-required',
              message: `${action} 会修改系统，必须先得到用户明确同意并在 payload 里带 confirm:true。`,
            },
          }
        }
      }
      if (action === 'repair' && payload) {
        const mode = String(payload.mode || 'restore')
        if (!['restore', 'sfc', 'dism', 'restore-point'].includes(mode)) {
          return { ok: false, error: { code: 'bad-mode', message: `不支持的修复方式：${mode}` } }
        }
      }

      try {
        const result = await core.dispatch(action, payload)
        if (result && result.ok && result.taskId) {
          return await waitForTask(core, result.taskId, 280000)
        }
        return result
      } catch (error) {
        return { ok: false, error: { code: error && error.code ? String(error.code) : 'internal-error', message: messageOf(error) } }
      }
    },
  }

  ctx.effect(() => ctx.tools.register(tool))

  // ---------------------------------------------------------------------------
  // 定时检查：到点自动巡查 + 校准提醒
  // ---------------------------------------------------------------------------
  async function checkSchedule(reason) {
    try {
      const schedule = await core.dueInfo()
      // 校准提醒：到点就挂提醒，等用户在面板点确认，绝不自动联网。
      if (schedule.calibrate.due) {
        core.state.pendingCalibrationAsk = true
      } else if (core.state.pendingCalibrationAsk) {
        core.state.pendingCalibrationAsk = false
      }
      // 自动巡查：建立过基线之后才自动跑。
      const persisted = core.getPersisted()
      if (schedule.patrol.due && persisted && persisted.lastAnalyzeAt) {
        const running = core.state.runningTask
        const alreadyQueued = core.state.queue.some((task) => task.kind === 'patrol')
        if (!(running && running.kind === 'patrol') && !alreadyQueued) {
          log.info?.(`[system-guard] 到巡查时间（${reason}），开始自动巡查。`)
          const result = await core.dispatch('patrol', null)
          if (result && result.ok === false) {
            log.warn?.(`[system-guard] 自动巡查失败：${result.error ? result.error.message : '未知错误'}`)
          }
        }
      }
    } catch (error) {
      log.warn?.(`[system-guard] 定时检查失败：${messageOf(error)}`)
    }
  }

  let disposed = false
  ctx.effect(() => {
    const timer = setInterval(() => {
      if (disposed) return
      checkSchedule('timer').catch(() => {})
    }, CHECK_INTERVAL_MS)
    if (typeof timer.unref === 'function') timer.unref()
    // 启动后 60 秒做一次检查（等 webServer 与后端就绪）。
    const kickoff = setTimeout(() => {
      if (disposed) return
      checkSchedule('startup').catch(() => {})
    }, 60 * 1000)
    if (typeof kickoff.unref === 'function') kickoff.unref()
    return () => {
      disposed = true
      clearInterval(timer)
      clearTimeout(kickoff)
      core.dispose().catch(() => {})
    }
  })

  return {
    dataDir: core.dataDir,
    version: VERSION,
    platform: core.platform,
    pluginDir: PLUGIN_DIR,
    resolvePluginPath,
  }
}

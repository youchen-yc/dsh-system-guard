/**
 * 系统守护 · 巡查与校准的排期计算（纯函数，便于测试）。
 *
 * 两条节奏：
 *   - 自动巡查：每 patrolIntervalDays 天一次完整性巡查；
 *   - 联网校准询问：每 calibrateAskIntervalDays 天提醒用户一次
 *     「要不要联网校准系统文件版本」——提醒不是自动联网，必须用户点确认。
 */

const DAY_MS = 24 * 60 * 60 * 1000

function toNumber(value, fallback = null) {
  const number = Number(value)
  return Number.isFinite(number) && number > 0 ? number : fallback
}

/** 把毫秒时间戳格式化成「YYYY-MM-DD HH:mm」，给界面显示用。 */
export function formatTime(timestamp) {
  const value = toNumber(timestamp)
  if (!value) return ''
  const date = new Date(value)
  const pad = (input) => String(input).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} `
    + `${pad(date.getHours())}:${pad(date.getMinutes())}`
}

/**
 * 计算巡查与校准排期。
 *
 * @param {{
 *   settings: { patrolIntervalDays: number, calibrateAskIntervalDays: number },
 *   persisted: { lastPatrolAt?: number|null, lastCalibrateAt?: number|null,
 *                nextCalibrateAskAt?: number|null, lastAnalyzeAt?: number|null },
 *   now?: number,
 *   dayMs?: number,
 * }} input
 */
export function computeSchedule({ settings, persisted, now = Date.now(), dayMs = DAY_MS } = {}) {
  const safeSettings = settings && typeof settings === 'object' ? settings : {}
  const safePersisted = persisted && typeof persisted === 'object' ? persisted : {}
  const patrolIntervalDays = toNumber(safeSettings.patrolIntervalDays, 7)
  const calibrateIntervalDays = toNumber(safeSettings.calibrateAskIntervalDays, 30)

  const lastPatrolAt = toNumber(safePersisted.lastPatrolAt)
  const lastAnalyzeAt = toNumber(safePersisted.lastAnalyzeAt)
  const lastCalibrateAt = toNumber(safePersisted.lastCalibrateAt)

  const patrolIntervalMs = patrolIntervalDays * dayMs
  // 从未巡查过：建立基线（分析完成）之后才算「到期」，避免每次启动都提醒。
  const patrolBase = lastPatrolAt || lastAnalyzeAt || null
  const nextPatrolAt = patrolBase ? patrolBase + patrolIntervalMs : null
  const patrolDue = Boolean(nextPatrolAt && now >= nextPatrolAt)
  const patrolOverdueMs = patrolDue ? now - nextPatrolAt : 0

  const calibrateIntervalMs = calibrateIntervalDays * dayMs
  const calibrateBase = lastCalibrateAt || null
  const nextCalibrateAskAt = toNumber(safePersisted.nextCalibrateAskAt)
    || (calibrateBase ? calibrateBase + calibrateIntervalMs : null)
  const calibrateAskDue = Boolean(nextCalibrateAskAt && now >= nextCalibrateAskAt)

  return {
    now,
    patrol: {
      intervalDays: patrolIntervalDays,
      nextAt: nextPatrolAt,
      nextText: nextPatrolAt ? formatTime(nextPatrolAt) : '分析完成后开始计时',
      due: patrolDue,
      overdueDays: patrolOverdueMs > 0 ? Math.floor(patrolOverdueMs / dayMs) : 0,
    },
    calibrate: {
      intervalDays: calibrateIntervalDays,
      nextAskAt: nextCalibrateAskAt,
      nextAskText: nextCalibrateAskAt ? formatTime(nextCalibrateAskAt) : '尚未安排',
      due: calibrateAskDue,
      lastAt: lastCalibrateAt,
      lastText: lastCalibrateAt ? formatTime(lastCalibrateAt) : '从未校准',
    },
  }
}

/**
 * 系统守护 · 同源 HTTP 接口。
 *
 * 前缀 `/dsh-system-guard/api`：
 *   GET  /state            全量状态（轻量，不含完整文件清单）
 *   GET  /analysis         完整分析结果（含核心文件清单与垃圾条目）
 *   GET  /task?id=         长任务状态轮询
 *   POST /action           { action, payload }
 *
 * 只接受本机同源请求：面板页面与 DSH Web 同源，直接用相对路径 fetch 即可。
 * 这个接口和 Agent 工具共用 core.dispatch()，不存在两套业务逻辑。
 */

const API_PREFIX = '/dsh-system-guard/api'
const MAX_BODY_BYTES = 4 * 1024 * 1024

function messageOf(error) {
  return String(error && error.message ? error.message : error)
}

/** 发送 JSON 响应。 */
function sendJson(res, statusCode, value) {
  let body
  try {
    body = JSON.stringify(value === undefined ? null : value)
  } catch (error) {
    statusCode = 500
    body = JSON.stringify({ ok: false, error: { code: 'serialize-error', message: messageOf(error) } })
  }
  try {
    res.statusCode = statusCode
    res.setHeader('content-type', 'application/json; charset=utf-8')
    res.setHeader('cache-control', 'no-store')
    res.end(body)
  } catch {
    /* 连接已断开，忽略 */
  }
}

/** 读取 JSON 请求体（有大小上限）。 */
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('请求体过大'), { code: 'body-too-large' }))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8').trim()
      if (!text) return resolve(null)
      try {
        resolve(JSON.parse(text))
      } catch (error) {
        reject(Object.assign(new Error(`请求体不是合法 JSON：${messageOf(error)}`), { code: 'bad-json' }))
      }
    })
    req.on('error', reject)
  })
}

/** 只允许本机同源：Origin 的 host 必须与 Host 一致；无 Origin 的本地请求放行。 */
function requestAllowed(req, origin) {
  const host = req.headers && req.headers.host ? String(req.headers.host) : ''
  const requestOrigin = req.headers && req.headers.origin ? String(req.headers.origin) : ''
  if (!requestOrigin) return true
  try {
    const originUrl = new URL(requestOrigin)
    if (!host) return false
    return originUrl.host === host || (origin ? originUrl.host === new URL(origin).host : false)
  } catch {
    return false
  }
}

/**
 * 注册 HTTP 路由。
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{ core: object, originOf: () => string }} deps
 */
export async function handleApi(req, res, { core, originOf }) {
  try {
    const origin = typeof originOf === 'function' ? originOf() : ''
    if (!requestAllowed(req, origin)) {
      return sendJson(res, 403, { ok: false, error: { code: 'forbidden', message: '只允许本机同源请求' } })
    }
    const url = new URL(req.url || '/', 'http://127.0.0.1')
    const pathname = url.pathname

    if (req.method === 'GET' && (pathname === `${API_PREFIX}/state` || pathname === `${API_PREFIX}/state/`)) {
      const status = await core.dispatch('status', null)
      if (status && status.ok) {
        status.pendingCalibrationAsk = Boolean(core.state.pendingCalibrationAsk)
        // 面板同时读 schedule.* 与顶层扁平字段，两套都给，避免字段名歧义。
        const schedule = status.schedule && typeof status.schedule === 'object' ? status.schedule : {}
        const patrol = schedule.patrol && typeof schedule.patrol === 'object' ? schedule.patrol : null
        const calibrate = schedule.calibrate && typeof schedule.calibrate === 'object' ? schedule.calibrate : null
        status.nextPatrolAt = patrol ? patrol.nextAt ?? null : null
        status.nextPatrolText = patrol ? patrol.nextText || '' : ''
        status.patrolDue = Boolean(patrol && patrol.due)
        status.nextCalibrateAskAt = calibrate ? calibrate.nextAskAt ?? null : null
        status.nextCalibrateAskText = calibrate ? calibrate.nextAskText || '' : ''
        status.calibrateAskDue = Boolean(calibrate && calibrate.due)
        // 当前 helper 进程是否管理员；提权授权状态单独给一个字段。
        status.admin = Boolean(status.probe && status.probe.admin === true)
        status.elevationGranted = Boolean(status.privilege && status.privilege.granted === true)
      }
      return sendJson(res, status && status.ok ? 200 : 500, status)
    }

    if (req.method === 'GET' && (pathname === `${API_PREFIX}/analysis` || pathname === `${API_PREFIX}/analysis/`)) {
      return sendJson(res, 200, await core.getAnalysis())
    }

    if (req.method === 'GET' && (pathname === `${API_PREFIX}/task` || pathname === `${API_PREFIX}/task/`)) {
      const id = url.searchParams.get('id') || ''
      const task = core.getTask(id)
      return sendJson(res, task ? 200 : 404, task
        ? { ok: true, task }
        : { ok: false, error: { code: 'task-not-found', message: `任务不存在：${id}` } })
    }

    if (req.method === 'POST' && (pathname === `${API_PREFIX}/action` || pathname === `${API_PREFIX}/action/`)) {
      let body = null
      try {
        body = await readJsonBody(req)
      } catch (error) {
        return sendJson(res, 400, { ok: false, error: { code: error.code || 'bad-request', message: messageOf(error) } })
      }
      const action = body && typeof body.action === 'string' ? body.action.trim() : ''
      if (!action) {
        return sendJson(res, 400, { ok: false, error: { code: 'missing-action', message: '缺少 action。' } })
      }
      const payload = body && body.payload !== undefined ? body.payload : null
      const result = await core.dispatch(action, payload)
      const statusCode = result && result.ok ? 200 : 400
      return sendJson(res, statusCode, result)
    }

    return sendJson(res, 404, { ok: false, error: { code: 'not-found', message: `未知接口：${pathname}` } })
  } catch (error) {
    return sendJson(res, 500, { ok: false, error: { code: 'internal-error', message: messageOf(error) } })
  }
}

export { API_PREFIX }

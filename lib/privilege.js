/**
 * 系统守护 · 守护权限门控与不可变底层逻辑。
 *
 * 用户要求：授予插件「最高权限」用于保护系统，但这份权限**只能**用来保护系统，
 * 不能用来做别的事；这条底层逻辑写死在这里、不随配置改变。
 *
 * 诚实的实现边界（也写在 README 里）：
 *   - 这是插件进程内的单点门控（所有写系统动作都必须先过 assertSystemAction），
 *     不是操作系统内核级特权，也不能真的「凌驾于所有插件之上」；
 *   - 没有文件系统过滤驱动，因此无法在内核层阻断写入，只能在写入后检测并回滚；
 *   - integrity.json 的自校验能「发现」核心代码被改，不能物理阻止有文件写权限的人改。
 *
 * 本文件是唯一允许调用提权入口与系统写操作的地方；其他模块只能通过这里的
 * assertSystemAction() 放行，动作白名单之外的请求一律拒绝。
 */

import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'

/** 白名单：真正写系统 / 需要管理员 / 动备份的动作。只允许这些。 */
const ALLOWED_SYSTEM_ACTIONS = Object.freeze([
  'analyze',
  'patrol',
  'junk-scan',
  'junk-delete',
  'backup',
  'backup-status',
  'restore',
  'repair',
  'restore-point',
  'calibrate',
  'calibrate-facts',
  'probe',
  'elevate',
])

/** 这份权限的用途边界：任何不在此列的用途都视为越权。 */
const FORBIDDEN_PURPOSES = Object.freeze([
  '读取、修改、上传用户的个人文件或隐私数据',
  '安装、卸载、更新第三方软件或驱动',
  '修改系统设置、注册表、服务、网络与安全策略（保护系统完整性所必需的最小写入除外）',
  '执行用户未在界面上确认的任意命令',
  '关闭、绕过或削弱系统安全防护（杀毒、防火墙、UAC、BitLocker 等）',
  '为其他插件或程序提权、代理执行其指令',
  '联网上传本机数据（联网校准只做只读查询）',
])

/**
 * 冻结的守护宪章。Object.freeze 只是防误改；真正的约束是：所有系统动作
 * 都必须经过 assertSystemAction，且白名单不可由配置注入。
 */
export const PRIVILEGE_POLICY = Object.freeze({
  version: '1.0.0',
  purpose: '本权限只用于保护电脑系统，无法用于保护系统以外的任何事情。',
  charter: Object.freeze({
    title: '守护权限底层逻辑',
    text: '守护权限只用于保护电脑系统：分析核心文件、分类系统垃圾、备份、巡查、修复。'
      + '它无法读取或上传你的个人文件，无法安装软件，无法修改系统设置，无法为其他程序提权。'
      + '这条逻辑写死在插件代码里，不可通过配置修改或删除。',
    immutable: true,
  }),
  allowedActions: ALLOWED_SYSTEM_ACTIONS,
  forbiddenPurposes: FORBIDDEN_PURPOSES,
})

/** 权限被拒绝时抛出的错误，带稳定 code 供上层区分。 */
export class PrivilegeError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'PrivilegeError'
    this.code = code
  }
}

/**
 * 写系统动作的放行检查。白名单之外一律抛 PrivilegeError。
 * @param {string} action 动作名
 */
export function assertSystemAction(action) {
  const name = String(action || '').trim()
  if (!ALLOWED_SYSTEM_ACTIONS.includes(name)) {
    throw new PrivilegeError(
      'privilege-denied',
      `守护权限只用于保护系统，动作「${name || '(空)'}」不在保护动作白名单内，已拒绝。`,
    )
  }
  return name
}

/** 判断动作是否在保护白名单内（不抛错版本）。 */
export function isProtectionAction(action) {
  return ALLOWED_SYSTEM_ACTIONS.includes(String(action || '').trim())
}

/**
 * 计算文件 sha256；读不到返回 null。
 * @param {string} file 绝对路径
 */
async function fileSha256(file) {
  try {
    const buffer = await readFile(file)
    return createHash('sha256').update(buffer).digest('hex')
  } catch {
    return null
  }
}

let selfCheckCache = { at: 0, value: null }

/**
 * 校验本插件核心代码是否被改动。
 *
 * `integrity.json` 在发布前由构建步骤生成，记录每个核心文件的 sha256。
 * 开发期没有 integrity.json 时返回 sealed=false（放行，但界面提示「未封存」）。
 *
 * @param {{ pluginDir: string, maxAgeMs?: number }} options
 */
export async function selfCheck({ pluginDir, maxAgeMs = 30000 }) {
  const now = Date.now()
  if (selfCheckCache.value && now - selfCheckCache.at < maxAgeMs) return selfCheckCache.value

  const integrityPath = path.join(pluginDir, 'integrity.json')
  let manifest = null
  try {
    manifest = JSON.parse(await readFile(integrityPath, 'utf8'))
  } catch {
    manifest = null
  }
  if (!manifest || typeof manifest !== 'object' || !manifest.files || typeof manifest.files !== 'object') {
    const value = {
      ok: true,
      sealed: false,
      tampered: [],
      missing: [],
      message: '插件尚未封存（开发模式），核心代码未做哈希校验。',
    }
    selfCheckCache = { at: now, value }
    return value
  }

  const tampered = []
  const missing = []
  const entries = Object.entries(manifest.files)
  // 最多校验 200 个文件，避免异常清单拖慢每次写操作。
  for (const [relative, expected] of entries.slice(0, 200)) {
    if (typeof expected !== 'string' || !expected) continue
    const file = path.join(pluginDir, relative)
    const actual = await fileSha256(file)
    if (actual === null) {
      missing.push(relative)
    } else if (actual !== expected) {
      tampered.push(relative)
    }
  }
  const ok = tampered.length === 0 && missing.length === 0
  const value = {
    ok,
    sealed: true,
    sealedAt: manifest.sealedAt ?? null,
    checkedCount: Math.min(entries.length, 200),
    tampered,
    missing,
    message: ok
      ? '核心代码校验通过。'
      : `核心代码自校验失败：被改动 ${tampered.length} 个、缺失 ${missing.length} 个。`
        + '为安全起见，已停止一切写系统操作，请重新安装插件。',
  }
  selfCheckCache = { at: now, value }
  return value
}

/** 清空自校验缓存（安装/更新后调用）。 */
export function clearSelfCheckCache() {
  selfCheckCache = { at: 0, value: null }
}

/**
 * 申请守护权限（Windows 上会弹 UAC）。
 *
 * @param {{
 *   platform: string,
 *   runElevatedProbe?: () => Promise<{ admin?: boolean } | null>,
 * }} options
 * @returns {Promise<{ ok: boolean, granted: boolean, level: string, message: string, admin?: boolean }>}
 */
export async function requestElevation({ platform, runElevatedProbe }) {
  if (platform !== 'windows') {
    return {
      ok: false,
      granted: false,
      level: 'unsupported',
      message: '当前系统不需要（或无法通过本插件）申请管理员权限；插件以当前用户权限运行。',
    }
  }
  if (typeof runElevatedProbe !== 'function') {
    return { ok: false, granted: false, level: 'error', message: '提权通道不可用（缺少提权执行器）。' }
  }
  try {
    const result = await runElevatedProbe()
    const admin = result && result.admin === true
    return {
      ok: admin,
      granted: admin,
      level: admin ? 'admin' : 'user',
      admin,
      message: admin
        ? '已获得管理员守护权限。该权限只用于保护系统。'
        : '未获得管理员权限：UAC 被取消或提权失败。',
    }
  } catch (error) {
    const code = error && error.code === 'elevation-cancelled' ? 'elevation-cancelled' : 'elevation-failed'
    return {
      ok: false,
      granted: false,
      level: 'user',
      message: code === 'elevation-cancelled'
        ? '你取消了 UAC 授权请求，守护权限未获得。'
        : `提权失败：${error && error.message ? error.message : String(error)}`,
    }
  }
}

/**
 * 生成 integrity.json 内容（发布前由构建脚本调用）。
 * @param {{ pluginDir: string }} options
 */
export async function buildIntegrityManifest({ pluginDir }) {
  const { readdir } = await import('node:fs/promises')
  const files = {}
  async function walk(dir, prefix) {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === 'test' || entry.name === '.git') continue
        await walk(path.join(dir, entry.name), relative)
      } else if (/\.(js|mjs|json|ps1)$/.test(entry.name) && entry.name !== 'integrity.json') {
        const hash = await fileSha256(path.join(dir, entry.name))
        if (hash) files[relative] = hash
      }
    }
  }
  await walk(pluginDir, '')
  return { version: 1, sealedAt: new Date().toISOString(), files }
}

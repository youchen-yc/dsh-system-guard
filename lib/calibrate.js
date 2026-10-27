/**
 * dsh-system-guard · 联网校准（平台无关，纯逻辑可注入测试）
 *
 * 作用：用 DSH Host 的 `ctx.web` 服务检索官方渠道，核对「当前系统版本的支持状态」与
 * 「官方推荐的系统文件完整性校验方式」，输出 CONTRACT §3 的 CalibrationReport。
 *
 * ⚠️ 诚实边界（必须与 README / UI 文案一致）：
 *   1) 官方站（微软 / 苹果 / Ubuntu 等）**不提供逐文件哈希清单**，本模块核对的是
 *      「版本信息 + 官方文档中的支持状态 / 完整性校验方式」，**不是逐文件下载比对**；
 *      逐文件完整性由本地 SHA-256 基线负责。
 *   2) 只读官方渠道：搜索结果会按平台官方域名白名单过滤，第三方站点一律丢弃；
 *      只抓取官方页面正文，且只取短摘要。
 *   3) 隐私（CONTRACT §1.5）：只把**系统版本信息**（osName/osBuild/osVersion）用于检索，
 *      **绝不**把核心文件路径清单、用户名、目录信息发给任何网站。
 *   4) 失败诚实：无 ctx.web / 无 key / 超时 / 403 / 搜索不到官方来源，一律返回
 *      { ok:false, error:{ code:'network', message } }，**绝不拼接或伪造 findings**。
 *   5) 搜索降级（本机实测需要）：不少机器的 Host 没有配置搜索凭据，
 *      `ctx.web.search` 会直接抛 WEB_PROVIDER_CREDENTIAL_MISSING，但 `ctx.web.fetch` 仍可用；
 *      此时本模块**改为直接读取 OFFICIAL_URLS 里预置的官方文档页面**（每平台 3~8 条候选，
 *      按本机 osBuild / osName 挑版本相关的页面，默认抓 3 篇、最多 5 篇），
 *      并在 findings 里如实写明「本次未使用搜索引擎」，sources 只记录实际抓到的 URL。
 *      如果 fetch 也失败，仍然返回 ok:false 并带上真实原因。
 *
 * DSH ctx.web 实际签名（已核对本机安装的 @deepseek-ai/dsh-web 源码）：
 *   - `ctx.web.search({ query, maxResults }, signal?)`
 *       → { content?: string, sources: [{ url, title?, snippet?, publishedAt? }], truncated: boolean }
 *   - `ctx.web.fetch({ url }, signal?)`
 *       → { url, statusCode, body: { kind: 'html'|'text', content }, truncated: boolean }
 *     失败会抛 WebError（扩展自 HarnessError），带可路由的 `error.code`。
 *
 * ⚠️ 本模块的「内置生命周期参考表」是离线知识（非本次抓取），可能在将来过时；
 * 对应 finding 里已明确标注来源是内置表，并建议用官方页面核对。
 * 验证状态（2026-10-27，开发机）：
 *   - 已用「fetch = 真实 Node fetch」的 fake web 直连验证：`calibrate()` 返回 ok:true，
 *     抓到 microsoft.com 官方页面（HTTP 200）；OFFICIAL_URLS 每个 URL 都逐个真实 GET 过。
 *   - 按版本挑页已用测试覆盖：build 19045 只挑 Windows 10 / 22H2 页面，不会抓 Windows 11 页面。
 *   - 仍**未**验证：Host 真实 `ctx.web`（search/fetch provider 注入）在目标机器上的行为；
 *     本机没有配置搜索凭据，因此 search 分支只有 fake 自测。
 */

// ---------------------------------------------------------------------------
// 官方域名白名单（只信任这些来源）
// ---------------------------------------------------------------------------

export const OFFICIAL_DOMAINS = Object.freeze({
  windows: Object.freeze([
    'microsoft.com',
    'learn.microsoft.com',
    'support.microsoft.com',
    'windows.com',
    'docs.microsoft.com',
  ]),
  macos: Object.freeze(['apple.com', 'developer.apple.com', 'support.apple.com']),
  linux: Object.freeze([
    'ubuntu.com',
    'debian.org',
    'fedoraproject.org',
    'archlinux.org',
    'kernel.org',
    'redhat.com',
    'suse.com',
    'opensuse.org',
  ]),
})

/** 「未收录平台」时的并集白名单。 */
const GENERIC_DOMAINS = Object.freeze([
  ...OFFICIAL_DOMAINS.windows,
  ...OFFICIAL_DOMAINS.macos,
  ...OFFICIAL_DOMAINS.linux,
])

/**
 * 预置官方文档页面（`web.search` 不可用 / 抛错时的直连降级目标）。
 *
 * 全部是官方域名，写死在这里便于维护与审计；运行时会再用 `isOfficialUrl()`
 * 校验一遍，防止将来维护时手滑写入第三方地址。
 *
 * `match` 用来按本机系统挑更相关的页面（例如 Windows 10 build 19045 优先读
 * 22H2 的 release health / known issues 页，Windows 11 读 23H2/24H2 页）；
 * 没有 `match` 的页面是通用页（如 sfc 命令文档），在相关页不够时补位。
 */
const freezePreset = (preset) => Object.freeze(preset)

export const OFFICIAL_URLS = Object.freeze({
  windows: Object.freeze([
    freezePreset({
      title: 'Windows 10 - release information | Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/windows/release-health/release-information',
      match: { osNameAny: ['windows 10'], osBuildMax: 21999 },
    }),
    freezePreset({
      title: 'Windows 11 - release information | Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information',
      match: { osNameAny: ['windows 11'], osBuildMin: 22000 },
    }),
    freezePreset({
      title: 'Windows Server release information | Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info',
      match: { osNameAny: ['server'] },
    }),
    freezePreset({
      title: 'Windows 10 Home and Pro - Microsoft Lifecycle',
      url: 'https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro',
      match: { osNameAny: ['windows 10'], osBuildMax: 21999 },
    }),
    freezePreset({
      title: 'Windows 11 Home and Pro - Microsoft Lifecycle',
      url: 'https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro',
      match: { osNameAny: ['windows 11'], osBuildMin: 22000 },
    }),
    freezePreset({
      title: 'Windows 10, version 22H2 known issues | Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2',
      match: { osNameAny: ['windows 10'], osBuildMin: 19045, osBuildMax: 19045 },
    }),
    freezePreset({
      title: "What's new in Windows 10, version 22H2 | Microsoft Learn",
      url: 'https://learn.microsoft.com/en-us/windows/whats-new/whats-new-windows-10-version-22h2',
      match: { osNameAny: ['windows 10'], osBuildMin: 19041, osBuildMax: 19045 },
    }),
    freezePreset({
      title: 'sfc - Windows commands | Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sfc',
    }),
  ]),
  macos: Object.freeze([
    freezePreset({ title: 'macOS - Apple Support', url: 'https://support.apple.com/macos' }),
    freezePreset({ title: 'macOS - Apple Developer', url: 'https://developer.apple.com/macos/' }),
    freezePreset({ title: 'macOS Release Notes | Apple Developer Documentation', url: 'https://developer.apple.com/documentation/macos-release-notes' }),
    freezePreset({ title: '磁盘工具使用手册 - Apple 支持', url: 'https://support.apple.com/guide/disk-utility/welcome/mac' }),
  ]),
  linux: Object.freeze([
    freezePreset({ title: 'Ubuntu release cycle', url: 'https://ubuntu.com/about/release-cycle' }),
    freezePreset({ title: 'Ubuntu release notes', url: 'https://documentation.ubuntu.com/release-notes/' }),
    freezePreset({ title: 'Debian releases', url: 'https://www.debian.org/releases/' }),
    freezePreset({ title: 'Fedora Linux', url: 'https://fedoraproject.org/' }),
    freezePreset({ title: 'The Linux Kernel Archives', url: 'https://www.kernel.org/' }),
  ]),
  generic: Object.freeze([
    freezePreset({ title: 'Microsoft Lifecycle', url: 'https://learn.microsoft.com/en-us/lifecycle/' }),
    freezePreset({ title: 'Ubuntu release cycle', url: 'https://ubuntu.com/about/release-cycle' }),
    freezePreset({ title: 'macOS - Apple Support', url: 'https://support.apple.com/macos' }),
    freezePreset({ title: 'The Linux Kernel Archives', url: 'https://www.kernel.org/' }),
  ]),
})

/** 校准方法说明（同时作为 report.note 与一条 finding）。 */
export const SUPPORT_BOUNDARY_NOTE = '校准方法：官方站（微软/苹果/Ubuntu 等）不提供逐文件哈希清单，本次校准核对的是版本信息与官方文档中的支持状态、完整性校验方式，不是逐文件下载比对；逐文件完整性由本地 SHA-256 基线负责。'

/** 默认检索条数与抓取页数（抓取 1~3 篇官方页面）。 */
const DEFAULT_MAX_RESULTS = 8
const DEFAULT_FETCH_PAGES = 2
/** 直连降级时最多抓几篇预置官方页面（OFFICIAL_URLS 每平台 3~8 条候选，按版本挑选，最多抓 5 篇）。 */
const DEFAULT_FALLBACK_PAGES = 3
const DEFAULT_TIMEOUT_MS = 20000
const MAX_SOURCES = 8
const MAX_FETCH_CHARS = 6000

// ---------------------------------------------------------------------------
// 内置生命周期参考表（离线知识，可能过时；findings 里会如实标注来源）
// ---------------------------------------------------------------------------

export const LIFECYCLE = Object.freeze({
  windows: Object.freeze({
    '19041': Object.freeze({ label: 'Windows 10 2004', supportEnds: '2021-12-14' }),
    '19042': Object.freeze({ label: 'Windows 10 20H2', supportEnds: '2023-05-09' }),
    '19043': Object.freeze({ label: 'Windows 10 21H1', supportEnds: '2022-12-13' }),
    '19044': Object.freeze({ label: 'Windows 10 21H2', supportEnds: '2023-06-13' }),
    '19045': Object.freeze({
      label: 'Windows 10 22H2',
      supportEnds: '2025-10-14',
      note: 'Windows 10 常规支持已结束，安全更新需 ESU（消费者扩展安全更新另计）',
    }),
    '22000': Object.freeze({ label: 'Windows 11 21H2', supportEnds: '2023-10-10' }),
    '22621': Object.freeze({ label: 'Windows 11 22H2', supportEnds: '2025-10-14' }),
    '22631': Object.freeze({ label: 'Windows 11 23H2', supportEnds: '2025-11-11' }),
    '26100': Object.freeze({ label: 'Windows 11 24H2', supportEnds: '2026-10-13', approximate: true }),
  }),
  linux: Object.freeze({
    '20.04': Object.freeze({
      label: 'Ubuntu 20.04 LTS',
      supportEnds: '2025-04-02',
      note: '标准支持已结束；Ubuntu Pro / ESM 可延长到 2030 年',
    }),
    '22.04': Object.freeze({ label: 'Ubuntu 22.04 LTS', supportEnds: '2027-04-01', note: '标准支持 5 年，ESM 可到 2032 年' }),
    '24.04': Object.freeze({ label: 'Ubuntu 24.04 LTS', supportEnds: '2029-04-01', note: '标准支持 5 年' }),
    '24.10': Object.freeze({ label: 'Ubuntu 24.10（非 LTS）', supportEnds: '2025-07-01', approximate: true }),
    '25.04': Object.freeze({ label: 'Ubuntu 25.04（非 LTS）', supportEnds: '2026-01-01', approximate: true }),
  }),
  macos: Object.freeze({
    '12': Object.freeze({ label: 'macOS 12 Monterey', supportEnds: '2024-09-16', approximate: true }),
    '13': Object.freeze({ label: 'macOS 13 Ventura', supportEnds: '2025-09-15', approximate: true }),
    '14': Object.freeze({ label: 'macOS 14 Sonoma', supportEnds: '2026-09-15', approximate: true }),
    '15': Object.freeze({ label: 'macOS 15 Sequoia', supportEnds: '2027-09-15', approximate: true }),
    '26': Object.freeze({ label: 'macOS 26 Tahoe', supportEnds: '2028-09-15', approximate: true }),
  }),
})

/** 各平台官方推荐的完整性校验方式（内置知识，非本次抓取）。 */
const INTEGRITY_GUIDE = Object.freeze({
  windows: Object.freeze({
    match: /sfc|dism|系统文件检查|system file checker|integrity/i,
    canonical: 'https://learn.microsoft.com/windows-server/administration/windows-commands/sfc',
    text: '官方推荐的系统文件完整性校验：先运行 sfc /scannow；若无法修复，再用 DISM /Online /Cleanup-Image /RestoreHealth。两者都是 Windows 自带命令，需要管理员权限。',
  }),
  macos: Object.freeze({
    match: /recovery|磁盘工具|disk utility|重新安装|reinstall|integrity|恢复模式/i,
    canonical: 'https://support.apple.com/macos',
    text: 'macOS 官方没有逐文件哈希校验命令；系统文件损坏时官方做法是进入恢复模式（Recovery），用「磁盘工具 - 急救」修复磁盘，必要时重新安装 macOS。',
  }),
  linux: Object.freeze({
    match: /debsums|rpm|pacman|package|软件包|完整性|integrity/i,
    canonical: 'https://ubuntu.com/server/docs',
    text: 'Linux 官方推荐用包管理器校验文件：Debian/Ubuntu 用 debsums（受损包用 apt-get install --reinstall 重装），RHEL/Fedora 用 rpm -Va，Arch 用 pacman -Qkk。',
  }),
  generic: Object.freeze({
    match: /integrity|完整性|校验/i,
    canonical: 'https://learn.microsoft.com/',
    text: '不同系统的官方完整性校验方式不同：Windows 用 sfc / DISM，macOS 用恢复模式，Linux 用包管理器（debsums / rpm -Va / pacman -Qkk）。',
  }),
})

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

/** 归一化平台名（只认 windows / macos / linux，其他归 generic）。 */
function normalizePlatform(platform) {
  const value = typeof platform === 'string' ? platform.toLowerCase() : ''
  if (value === 'windows' || value === 'macos' || value === 'linux') return value
  return 'generic'
}

/** 统一失败返回；message 会自动补「联网校准失败：」前缀。 */
function fail(code, reason) {
  const text = String(reason || '未知原因')
  return {
    ok: false,
    error: {
      code,
      message: text.startsWith('联网校准失败') ? text : `联网校准失败：${text}`,
    },
  }
}

/** 把 web 抛出的错误（WebError 带 code）描述成人能读的原因。 */
function describeWebError(error) {
  if (!error) return '未知错误'
  const code = typeof error.code === 'string' && error.code ? error.code : ''
  const message = error.message || String(error)
  return code ? `${code}: ${message}` : String(message)
}

/** 给 web 调用加超时，避免 Host 的 provider 卡死整次校准。 */
function withTimeout(promise, ms, label) {
  const timeoutMs = Math.max(1000, Number(ms) || DEFAULT_TIMEOUT_MS)
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} 超时（${timeoutMs}ms）`)), timeoutMs)
    promise.then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      (error) => {
        clearTimeout(timer)
        reject(error)
      },
    )
  })
}

/** 取 URL 的 hostname（用于 title 缺省）。 */
function hostnameOf(url) {
  try {
    return new URL(String(url)).hostname
  } catch {
    return String(url || '')
  }
}

/** 解析 decode 到文本的实体。 */
function decodeEntities(text) {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }
  return String(text || '').replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body) => {
    if (body[0] === '#') {
      const isHex = body[1] === 'x' || body[1] === 'X'
      const code = Number.parseInt(isHex ? body.slice(2) : body.slice(1), isHex ? 16 : 10)
      if (Number.isFinite(code) && code > 0 && code <= 0x10ffff) {
        try {
          return String.fromCodePoint(code)
        } catch {
          return whole
        }
      }
      return whole
    }
    return Object.prototype.hasOwnProperty.call(named, body) ? named[body] : whole
  })
}

/** 极简 HTML → 纯文本（够用于取摘要；不做完整 DOM 解析）。 */
function htmlToText(html) {
  let text = String(html || '')
  text = text.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
  text = text.replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
  text = text.replace(/<!--[\s\S]*?-->/g, ' ')
  text = text.replace(/<\s*(?:br|\/p|\/div|\/li|\/h[1-6]|\/tr)\b[^>]*>/gi, '\n')
  text = text.replace(/<[^>]+>/g, ' ')
  text = decodeEntities(text)
  return text
    .replace(/[ \t\f\v]+/g, ' ')
    .replace(/\r\n?/g, '\n')
    .replace(/\n\s*\n\s*\n+/g, '\n\n')
    .trim()
}

/**
 * 从抓取正文里挑一句可引用摘要。
 * 官方页面正文前部常有导航/Cookie/浏览器提示，先过滤这类噪声，
 * 再优先含日期或支持/版本/完整性关键词的句子；都挑不到就退回首句，不编造。
 */
function pickExcerpt(text, max = 180) {
  const source = String(text || '').replace(/\s+/g, ' ').trim()
  if (!source) return ''
  const navNoise = /skip to (main )?content|chat experience|browser is no longer supported|enable (javascript|cookies)|back to top|choose your language|privacy policy|terms of use|download microsoft edge|internet explorer|summarize this article|add to plans|read in english/i
  const sentences = source
    .split(/(?<=[。！？.!?])\s+|\n+/)
    .map((sentence) => sentence.trim())
    .filter((sentence) => sentence.length >= 12 && !navNoise.test(sentence))
  const dated = /(20\d\d|支持结束|end of support|support ends|lifecycle|生命周期|released?|版本)/i
  const keyword = /(支持|生命周期|结束|版本|升级|完整性|校验|修复|恢复|support|lifecycle|release|end of|integrity|version|recovery|repair|verify)/i
  const preferred = sentences.find((sentence) => dated.test(sentence))
    || sentences.find((sentence) => keyword.test(sentence))
    || sentences[0]
  const chosen = preferred || source
  return chosen.length > max ? `${chosen.slice(0, max)}…` : chosen
}

// ---------------------------------------------------------------------------
// 纯函数：查询构造 / 结果解析 / 官方来源过滤
// ---------------------------------------------------------------------------

/** 用 Facts 生成 2~3 条官方检索语句（只含系统版本信息，不含任何路径/用户信息）。 */
export function buildQueries(facts) {
  const safeFacts = facts && typeof facts === 'object' ? facts : {}
  const platform = normalizePlatform(safeFacts.platform)
  const osName = typeof safeFacts.osName === 'string' ? safeFacts.osName.trim() : ''
  const osVersion = typeof safeFacts.osVersion === 'string' ? safeFacts.osVersion.trim() : ''
  const osBuild = typeof safeFacts.osBuild === 'string' ? safeFacts.osBuild.trim() : ''
  const label = [osName, osVersion, osBuild ? `build ${osBuild}` : ''].filter(Boolean).join(' ').trim() || '未知系统'
  const queries = []
  if (platform === 'windows') {
    queries.push(`Windows ${osBuild || osVersion} 支持状态 生命周期 官方文档`)
    queries.push(`Windows ${osBuild || osVersion} release health lifecycle 官方文档`)
    queries.push('Windows 系统文件完整性检查 sfc DISM 官方文档')
  } else if (platform === 'macos') {
    queries.push(`macOS ${osVersion} 支持状态 官方文档`)
    queries.push('macOS 系统文件完整性 恢复模式 磁盘工具 官方文档')
  } else if (platform === 'linux') {
    queries.push(`${osName || 'Linux'} ${osVersion} 支持周期 LTS 官方文档`.trim())
    queries.push(`${osName || 'Linux'} 系统文件完整性校验 官方文档`.trim())
    queries.push('Ubuntu LTS 软件包完整性校验 debsums 官方文档')
  } else {
    queries.push(`${label} 系统支持状态 官方文档`)
    queries.push(`${label} 系统文件完整性校验 官方文档`)
  }
  return queries.map((query) => query.replace(/\s+/g, ' ').trim()).filter(Boolean).slice(0, 3)
}

/** 兼容不同实现/测试桩：把 search 结果规整成 { content, truncated, sources[] }。 */
export function parseSearchResult(raw) {
  const result = { content: '', truncated: false, sources: [] }
  if (!raw || typeof raw !== 'object') return result
  if (typeof raw.content === 'string') result.content = raw.content
  result.truncated = raw.truncated === true
  const list = Array.isArray(raw.sources) ? raw.sources : []
  for (const item of list) {
    if (!item || typeof item !== 'object') continue
    if (typeof item.url !== 'string' || item.url.length === 0) continue
    result.sources.push({
      url: item.url,
      title: typeof item.title === 'string' ? item.title : '',
      snippet: typeof item.snippet === 'string' ? item.snippet : '',
      publishedAt: typeof item.publishedAt === 'string' ? item.publishedAt : '',
    })
  }
  return result
}

/** 只允许官方域名（https/http，按平台白名单匹配子域）。 */
export function isOfficialUrl(url, platform) {
  let parsed
  try {
    parsed = new URL(String(url))
  } catch {
    return false
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '')
  const key = normalizePlatform(platform)
  const domains = key === 'generic' ? GENERIC_DOMAINS : (OFFICIAL_DOMAINS[key] || GENERIC_DOMAINS)
  return domains.some((domain) => host === domain || host.endsWith(`.${domain}`))
}

/**
 * 从 fetch 结果里取纯文本正文（兼容旧签名与测试桩）。
 * 只做文本化，不执行任何页面脚本。
 */
export function extractFetchText(raw) {
  if (!raw || typeof raw !== 'object') return ''
  let kind = ''
  let content = ''
  if (raw.body && typeof raw.body === 'object') {
    kind = raw.body.kind === 'html' ? 'html' : (raw.body.kind === 'text' ? 'text' : '')
    content = typeof raw.body.content === 'string' ? raw.body.content : ''
  }
  // 兼容：有些实现直接给 { content } 或 { text }。
  if (!content && typeof raw.content === 'string') content = raw.content
  if (!content && typeof raw.text === 'string') content = raw.text
  if (!content) return ''
  const text = kind === 'html' ? htmlToText(content) : content
  return text.replace(/\s+/g, ' ').trim().slice(0, MAX_FETCH_CHARS)
}

/** 从来源列表里挑第一个「标题或 URL 命中关键词」的官方来源。 */
function pickSource(sources, pattern) {
  for (const source of sources) {
    const haystack = `${source.title || ''} ${source.url || ''}`
    if (pattern.test(haystack)) return source
  }
  return null
}

/** 描述本机 OS，用于 findings / summary 文案。 */
function describeOsLabel(facts) {
  const safeFacts = facts && typeof facts === 'object' ? facts : {}
  const name = typeof safeFacts.osName === 'string' && safeFacts.osName.trim() ? safeFacts.osName.trim() : '未知系统'
  const build = typeof safeFacts.osBuild === 'string' && safeFacts.osBuild.trim() ? safeFacts.osBuild.trim() : ''
  return build ? `${name}（build ${build}）` : name
}

/** 查内置生命周期表；查不到返回 null。 */
function lookupLifecycle(platform, facts, now = Date.now()) {
  const key = normalizePlatform(platform)
  const table = LIFECYCLE[key]
  if (!table) return null
  const safeFacts = facts && typeof facts === 'object' ? facts : {}
  let matched = null
  if (key === 'windows') {
    const build = String(safeFacts.osBuild || '').trim()
    if (build && table[build]) matched = build
  } else if (key === 'linux') {
    const version = String(safeFacts.osVersion || '').trim()
    if (version) {
      const candidates = [version, version.split('.').slice(0, 2).join('.')]
      matched = candidates.find((candidate) => candidate && table[candidate]) || null
    }
  } else if (key === 'macos') {
    const major = String(safeFacts.osVersion || '').trim().split('.')[0]
    if (major && table[major]) matched = major
  }
  if (!matched) return null
  const entry = table[matched]
  const endsAt = entry.supportEnds ? Date.parse(entry.supportEnds) : NaN
  return {
    label: entry.label,
    supportEnds: entry.supportEnds || null,
    approximate: entry.approximate === true,
    note: entry.note || '',
    ended: Number.isFinite(endsAt) ? endsAt < now : null,
  }
}

/** 支持状态 finding（①：当前 OS 是否还在支持期 / 是否已知旧 build）。 */
export function buildSupportFinding({ platform, facts, sources = [], now = Date.now() }) {
  const key = normalizePlatform(platform)
  const lifecycle = lookupLifecycle(key, facts, now)
  const osLabel = describeOsLabel(facts)
  const officialSource = pickSource(sources, /lifecycle|release.?health|end.?of.?support|支持|生命周期/i)
  const sourceUrl = officialSource ? officialSource.url : (sources[0] ? sources[0].url : '')
  if (lifecycle && lifecycle.supportEnds) {
    const approximate = lifecycle.approximate ? '（近似值）' : ''
    const note = lifecycle.note ? `；${lifecycle.note}` : ''
    const verdict = lifecycle.ended
      ? '已过该日期：属于已知旧版本 / 已结束支持，建议升级到仍在支持的版本'
      : '仍在支持期内'
    return {
      level: lifecycle.ended ? 'warn' : 'info',
      text: `本机为 ${osLabel}（${lifecycle.label}）。插件内置参考表的支持结束日期为 ${lifecycle.supportEnds}${approximate}${note}；${verdict}。（该日期来自内置参考表而非本次抓取，可能过时，请用官方生命周期页面核对。）`,
      source: sourceUrl,
    }
  }
  if (lifecycle) {
    return {
      level: 'info',
      text: `本机为 ${osLabel}（${lifecycle.label}）；内置参考表未给出支持结束日期，请以官方生命周期页面为准。`,
      source: sourceUrl,
    }
  }
  return {
    level: 'info',
    text: `本机为 ${osLabel}；插件内置参考表未收录该版本，无法离线判断是否仍在支持期，请以官方生命周期页面（release health / lifecycle）为准。`,
    source: sourceUrl,
  }
}

/** 完整性校验方式 finding（②：官方推荐的完整性校验方式）。 */
export function buildIntegrityFinding({ platform, sources = [] }) {
  const key = normalizePlatform(platform)
  const guide = INTEGRITY_GUIDE[key] || INTEGRITY_GUIDE.generic
  const official = pickSource(sources, guide.match)
  const sourceUrl = official ? official.url : guide.canonical
  const suffix = official
    ? '（本次检索到对应官方页面，见 source）'
    : '（source 是官方文档入口；本次未检索到直接对应页面，建议用户点开确认）'
  return { level: 'info', text: `${guide.text}${suffix}`, source: sourceUrl }
}

/**
 * 纯函数：用「已收集到的官方来源 + 已抓取的官方页面 + 限制说明」拼装 CalibrationReport。
 * 抽成纯函数便于 selftest 在不联网的情况下验证结构与文案。
 */
export function buildCalibrationReport({
  facts,
  platform,
  sources = [],
  docs = [],
  warnings = [],
  now = Date.now(),
  fallbackNote = '',
} = {}) {
  const safeFacts = facts && typeof facts === 'object' ? facts : {}
  const key = normalizePlatform(platform || safeFacts.platform)
  const normalizedSources = (Array.isArray(sources) ? sources : [])
    .filter((source) => source && typeof source.url === 'string' && source.url)
    .slice(0, MAX_SOURCES)
    .map((source) => ({
      title: typeof source.title === 'string' && source.title ? source.title : hostnameOf(source.url),
      url: source.url,
    }))
  // findings 里逐篇列摘要：最多 5 篇，与降级抓取上限（5 篇）保持一致。
  // 之前这里写死 2，抓 3 篇时会出现「3 个来源、2 篇页面」的不一致。
  const safeDocs = (Array.isArray(docs) ? docs : [])
    .filter((doc) => doc && typeof doc.url === 'string' && doc.url)
    .slice(0, 5)
  const findings = []
  findings.push(buildSupportFinding({ platform: key, facts: safeFacts, sources: normalizedSources, now }))
  findings.push(buildIntegrityFinding({ platform: key, sources: normalizedSources }))
  const safeFallbackNote = typeof fallbackNote === 'string' ? fallbackNote.trim() : ''
  if (safeFallbackNote) {
    // 降级说明单独成一条 finding：本次没有走搜索引擎，而是直接读取官方文档页面。
    findings.push({ level: 'info', text: safeFallbackNote, source: '' })
  }
  findings.push({ level: 'info', text: SUPPORT_BOUNDARY_NOTE, source: '' })
  for (const doc of safeDocs) {
    const excerpt = pickExcerpt(doc.text)
    findings.push({
      level: 'info',
      text: `已抓取官方页面「${doc.title || hostnameOf(doc.url)}」（HTTP ${doc.statusCode ?? '未知'}）${excerpt ? `；摘要：${excerpt}` : '；正文未提取到可用摘要'}。`,
      source: doc.url,
    })
  }
  const safeWarnings = (Array.isArray(warnings) ? warnings : []).filter((item) => typeof item === 'string' && item)
  if (safeWarnings.length > 0) {
    findings.push({ level: 'warn', text: `本次校准的限制：${safeWarnings.join('；')}`, source: '' })
  }
  const lifecycle = lookupLifecycle(key, safeFacts, now)
  const status = lifecycle
    ? (lifecycle.supportEnds ? (lifecycle.ended ? '已结束支持（旧版本）' : '仍在支持期') : '支持状态需人工核对')
    : '支持状态需人工核对'
  const summaryBase = `本机 ${describeOsLabel(safeFacts)}：${status}（依据插件内置参考表）；本次核对到 ${normalizedSources.length} 个官方来源、抓取 ${safeDocs.length} 篇官方页面，完整性校验方式见 findings，未做逐文件下载比对。`
  const summary = safeFallbackNote
    ? `${summaryBase}本次未使用搜索引擎、直接读取官方文档页面（见 findings）。`
    : summaryBase
  return {
    ok: true,
    checkedAt: now,
    sources: normalizedSources,
    findings,
    summary,
    note: SUPPORT_BOUNDARY_NOTE,
  }
}

// ---------------------------------------------------------------------------
// 直连官方页面的降级抓取（web.search 不可用 / 抛错时使用）
// ---------------------------------------------------------------------------

/** 判断一条预置页面的 match 条件是否适用于本机（无 match 视为通用页）。
 *
 * 规则（全部同时满足才算命中）：
 *   - osNameAny：系统名称里必须出现其中至少一个关键词（如 ['windows 10']）；
 *   - osNameNone：系统名称里不能出现任何关键词（用于把 Server 从 Win10/Win11 里摘出去）；
 *   - osBuildMin / osBuildMax：build 号区间。
 *
 * 只看 build 不够：Windows Server 2025 的 build 26100 也 ≥ 22000，
 * 只看 build 会把它当成 Windows 11 去抓 Win11 页面；所以名称关键词是主判据。
 */
function matchPreset(match, { osBuild, osName }) {
  if (!match || typeof match !== 'object') return false
  const any = Array.isArray(match.osNameAny) ? match.osNameAny : []
  if (any.length > 0 && !any.some((needle) => osName.includes(String(needle).toLowerCase()))) return false
  const none = Array.isArray(match.osNameNone) ? match.osNameNone : []
  if (none.length > 0 && none.some((needle) => osName.includes(String(needle).toLowerCase()))) return false
  if (Number.isFinite(match.osBuildMin) && osBuild < match.osBuildMin) return false
  if (Number.isFinite(match.osBuildMax) && osBuild > match.osBuildMax) return false
  return true
}

/** build 号缺失（probe 取不到）时，按系统名称推断一个合理的 build，避免把 Win11 当成 Win10。 */
function inferBuildFromName(osName) {
  const name = String(osName || '').toLowerCase()
  if (name.includes('windows 11')) return 22631
  if (name.includes('windows 10')) return 19045
  if (name.includes('server')) return 20348
  return 0
}

/**
 * 按平台与本机版本挑预置官方页面：
 *   1. 版本相关的页面优先（Windows 10 build 19045 只读 Win10 / 22H2 页，不读 Win11 页）；
 *   2. 通用页（如 sfc 命令文档）补位；
 *   3. 仍然不够时不再凑数——少抓几篇比抓无关页面更好。
 *
 * 上限 5 篇（默认 3 篇），避免一次校准时流量和耗时过大。
 */
function presetUrlsFor(platform, limit, facts = null) {
  const key = normalizePlatform(platform)
  const pool = (OFFICIAL_URLS[key] || OFFICIAL_URLS.generic || [])
    .filter((item) => item && typeof item.url === 'string' && isOfficialUrl(item.url, key))
  const max = Math.max(1, Math.min(5, Number(limit) || DEFAULT_FALLBACK_PAGES))
  const osName = String((facts && facts.osName) || '').toLowerCase()
  const rawBuild = Number(facts && facts.osBuild)
  const osBuild = Number.isFinite(rawBuild) && rawBuild > 0 ? rawBuild : inferBuildFromName(osName)
  const matched = []
  const general = []
  for (const item of pool) {
    if (!item.match) {
      general.push(item)
    } else if (matchPreset(item.match, { osBuild, osName })) {
      matched.push(item)
    }
  }
  return [...matched, ...general].slice(0, max)
}

/**
 * 抓取预置官方页面，返回 { sources, docs, warnings, aborted }。
 * 只把「真正抓取成功且有正文」的 URL 记进 sources；失败原因写进 warnings，不伪造。
 */
async function fetchPresetOfficialPages({ web, platform, limit, timeoutMs, signal, facts = null, logger = {} } = {}) {
  const result = { sources: [], docs: [], warnings: [], aborted: false }
  const goal = Math.max(1, Math.min(5, Number(limit) || DEFAULT_FALLBACK_PAGES))
  // 候选比目标多取两条：某一篇官方页改版 / 临时 404 时，自动用后面的候选补上，
  // 而不是让校准结果只剩一两篇。
  const candidates = presetUrlsFor(platform, Math.min(5, goal + 2), facts)
  if (candidates.length === 0) {
    result.warnings.push('没有可用的预置官方页面（OFFICIAL_URLS 配置为空）。')
    return result
  }
  if (typeof web?.fetch !== 'function') {
    result.warnings.push('ctx.web 没有 fetch 能力，无法直接读取官方文档页面。')
    return result
  }
  for (const preset of candidates) {
    if (result.docs.length >= goal) break
    if (signal && signal.aborted) {
      result.aborted = true
      return result
    }
    try {
      const raw = await withTimeout(
        Promise.resolve().then(() => web.fetch({ url: preset.url })),
        timeoutMs,
        'web.fetch',
      )
      const statusCode = Number.isFinite(raw?.statusCode) ? raw.statusCode : null
      if (statusCode !== null && (statusCode < 200 || statusCode >= 400)) {
        result.warnings.push(`官方页面返回 HTTP ${statusCode}：${preset.url}`)
        continue
      }
      const text = extractFetchText(raw)
      if (!text) {
        result.warnings.push(`官方页面没有可读正文：${preset.url}`)
        continue
      }
      const finalUrl = typeof raw?.url === 'string' && raw.url ? raw.url : preset.url
      result.sources.push({ title: preset.title, url: finalUrl })
      result.docs.push({
        title: preset.title,
        url: finalUrl,
        statusCode,
        text,
        truncated: raw?.truncated === true,
      })
      logger.info?.(`[system-guard] 直连官方页面成功：${finalUrl}`)
    } catch (error) {
      result.warnings.push(`抓取官方页面失败（${preset.url}）：${describeWebError(error)}`)
      logger.warn?.(`[system-guard] 直连官方页面失败：${preset.url} → ${describeWebError(error)}`)
    }
  }
  return result
}

/** 降级说明文案：明说「本次没有用搜索引擎」以及原因。 */
function buildFallbackNote(reason) {
  return `本次未使用搜索引擎（${reason || '搜索不可用或搜索失败'}），改为直接读取官方文档页面；sources 为本次实际抓取成功的官方 URL，findings 中没有伪造的检索结果。`
}

/** 从失败原因里判断降级理由（凭据缺失是最常见的一种）。 */
function describeFallbackReason(web, warnings) {
  if (!web || typeof web.search !== 'function') return '宿主未提供 ctx.web.search 能力'
  const joined = (Array.isArray(warnings) ? warnings : []).join(' ')
  if (/CREDENTIAL|API[_ ]?KEY|no API key|missing (api )?key/i.test(joined)) return '宿主未配置搜索凭据'
  return '搜索不可用或搜索失败'
}

// ---------------------------------------------------------------------------
// 主入口
// ---------------------------------------------------------------------------

/**
 * 联网校准。
 *
 * @param {{
 *   facts?: object,                       // Facts（至少含 platform / osName / osVersion / osBuild）
 *   web?: { search?: Function, fetch?: Function }, // Host 的 ctx.web，可能为 undefined
 *   config?: object,                      // 插件设置（只读取可选的校准相关字段）
 *   log?: { info?: Function, warn?: Function },
 *   signal?: AbortSignal,
 * }} [input]
 * @returns {Promise<object>} CalibrationReport 或 { ok:false, error:{ code, message } }
 */
export async function calibrate({ facts, web, config, log, signal } = {}) {
  const settings = config && typeof config === 'object' ? config : {}
  const logger = log && typeof log === 'object' ? log : {}
  if (signal && signal.aborted) return fail('aborted', '联网校准已取消。')

  // 1) 输入与联网能力检查：不做任何伪造。
  //    注意：这里不能只看 search —— 宿主没配搜索凭据时 search 会抛错，
  //    但 fetch 通常仍可用（本机实测 learn.microsoft.com 等官方页面 200），
  //    所以 has search / has fetch 任一可用就继续，最后按真实结果返回。
  if (!facts || typeof facts !== 'object' || !facts.platform) {
    return fail('invalid-input', '缺少系统事实（facts.platform），无法校准。')
  }
  const canSearch = Boolean(web && typeof web === 'object' && typeof web.search === 'function')
  const canFetch = Boolean(web && typeof web === 'object' && typeof web.fetch === 'function')
  if (!canSearch && !canFetch) {
    return fail('network', web
      ? '当前 Host 的 ctx.web 既没有 search 也没有 fetch 能力（CLI / 精简 profile 下可能未启用联网），无法检索官方资料。'
      : '当前 Host 没有可用的 ctx.web 服务（CLI / 精简 profile 下可能未启用联网），无法检索官方资料。')
  }

  const platform = normalizePlatform(facts.platform)
  const timeoutMs = Number(settings.calibrateTimeoutMs) || DEFAULT_TIMEOUT_MS
  const warnings = []

  // 2) 优先走官方检索（只用系统版本信息做查询）。
  if (canSearch) {
    const queries = buildQueries(facts).slice(0, Math.max(1, Math.min(3, Number(settings.calibrateMaxQueries) || 3)))
    const maxResults = Math.max(1, Math.min(10, Number(settings.calibrateMaxResults) || DEFAULT_MAX_RESULTS))
    const fetchPages = Math.max(1, Math.min(3, Number(settings.calibrateFetchPages) || DEFAULT_FETCH_PAGES))
    const searchOutcomes = []
    for (const query of queries) {
      if (signal && signal.aborted) return fail('aborted', '联网校准已取消。')
      try {
        const raw = await withTimeout(
          Promise.resolve().then(() => web.search({ query, maxResults })),
          timeoutMs,
          'web.search',
        )
        const parsed = parseSearchResult(raw)
        searchOutcomes.push({ query, ...parsed })
        logger.info?.(`[system-guard] 校准检索完成：${query}（${parsed.sources.length} 条来源）`)
      } catch (error) {
        warnings.push(`检索失败（${query}）：${describeWebError(error)}`)
        logger.warn?.(`[system-guard] 校准检索失败：${query} → ${describeWebError(error)}`)
      }
    }
    if (searchOutcomes.length > 0) {
      // 只保留官方域名来源（第三方一律丢弃，且不抓取）。
      const seen = new Set()
      const officialSources = []
      let droppedThirdParty = 0
      for (const outcome of searchOutcomes) {
        for (const source of outcome.sources) {
          if (!isOfficialUrl(source.url, platform === 'generic' ? facts.platform : platform)) {
            droppedThirdParty += 1
            continue
          }
          if (seen.has(source.url)) continue
          seen.add(source.url)
          officialSources.push({
            url: source.url,
            title: source.title || hostnameOf(source.url),
            snippet: source.snippet || '',
          })
        }
      }
      if (officialSources.length > 0) {
        if (droppedThirdParty > 0) {
          warnings.push(`已丢弃 ${droppedThirdParty} 条非官方来源（只允许官方渠道）。`)
        }
        // 3) 抓取 1~3 篇官方页面取摘要（失败只写 warnings，不伪造）。
        const docs = []
        for (const source of officialSources.slice(0, fetchPages)) {
          if (signal && signal.aborted) return fail('aborted', '联网校准已取消。')
          try {
            const raw = await withTimeout(
              Promise.resolve().then(() => web.fetch({ url: source.url })),
              timeoutMs,
              'web.fetch',
            )
            const text = extractFetchText(raw)
            if (!text) {
              warnings.push(`官方页面没有可读正文：${source.url}`)
              continue
            }
            docs.push({
              title: source.title,
              url: typeof raw.url === 'string' && raw.url ? raw.url : source.url,
              statusCode: Number.isFinite(raw.statusCode) ? raw.statusCode : null,
              text,
              truncated: raw.truncated === true,
            })
          } catch (error) {
            warnings.push(`抓取官方页面失败（${source.url}）：${describeWebError(error)}`)
          }
        }
        const report = buildCalibrationReport({
          facts,
          platform: platform === 'generic' ? facts.platform : platform,
          sources: officialSources,
          docs,
          warnings,
          now: Date.now(),
        })
        logger.info?.(`[system-guard] 联网校准完成：${report.sources.length} 个官方来源，抓取 ${docs.length} 篇官方页面。`)
        return report
      }
      warnings.push(`搜索结果中没有可用的官方来源（已按官方域名白名单过滤，丢弃 ${droppedThirdParty} 条第三方来源）。`)
    }
  } else {
    warnings.push('宿主没有提供 ctx.web.search 能力。')
  }

  // 4) 降级：直接抓预置官方页面（search 不可用 / 抛错 / 无官方结果时）。
  //    只使用官方域名；抓不到就如实失败，绝不伪造 findings。
  if (!canFetch) {
    return fail('network', [...warnings, '宿主也没有提供 ctx.web.fetch 能力，无法直接读取官方文档页面。'].join('；'))
  }
  const fallbackLimit = Number(settings.calibrateFallbackPages) || DEFAULT_FALLBACK_PAGES
  const fallback = await fetchPresetOfficialPages({ web, platform, limit: fallbackLimit, timeoutMs, signal, facts, logger })
  if (fallback.aborted) return fail('aborted', '联网校准已取消。')
  for (const warning of fallback.warnings) {
    if (!warnings.includes(warning)) warnings.push(warning)
  }
  if (fallback.docs.length === 0) {
    return fail('network', [...warnings, '直接读取预置官方文档页面也失败（网络不可用或 fetch provider 不可用）。'].join('；'))
  }
  const fallbackNote = buildFallbackNote(describeFallbackReason(web, warnings))
  const report = buildCalibrationReport({
    facts,
    platform: platform === 'generic' ? facts.platform : platform,
    sources: fallback.sources,
    docs: fallback.docs,
    warnings,
    now: Date.now(),
    fallbackNote,
  })
  logger.info?.(`[system-guard] 联网校准降级完成（直接读取官方页面）：${report.sources.length} 个来源，${fallback.docs.length} 篇页面。`)
  return report
}

export default { calibrate }

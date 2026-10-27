/**
 * dsh-system-guard · 纯逻辑 / 契约自测（不联网、不依赖 POSIX 命令、只读）
 *
 * 运行：`node --test test/selftest.mjs`（Node ≥20）。
 *
 * 覆盖范围：
 *   1) calibrate 的联网行为：web 缺失 / search 抛错 / 正常 fake web /
 *      **只有 fetch 没有 search 时的直连官方页面降级** / fetch 也失败时的诚实失败；
 *   2) posix-backend 在 Windows 上被调用时的降级路径（不崩、结构合法）；
 *   3) CalibrationReport / Analysis / JunkReport / FileRef / Probe / PatrolReport /
 *      BackupInfo / Facts 的手写「JSON schema 风格」形状校验；
 *   4) CONTRACT §1.5 的两条硬约束：可中断（AbortSignal）与隐私（查询里不带文件路径）。
 *
 * 注意：这里**没有**真实 macOS/Linux 环境，POSIX 行为只验证了「声明清单 + 降级路径 + 纯逻辑」，
 * 真实系统上的扫描/备份/修复结果需要在目标机器上另行验证（报告里会注明「未验证」）。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  POSIX_CORE_FILES,
  POSIX_JUNK_GROUPS,
  createPosixBackend,
  detectPosixPlatform,
} from '../lib/posix-backend.js'
import {
  LIFECYCLE,
  OFFICIAL_DOMAINS,
  OFFICIAL_URLS,
  SUPPORT_BOUNDARY_NOTE,
  buildCalibrationReport,
  buildQueries,
  calibrate,
  extractFetchText,
  isOfficialUrl,
  parseSearchResult,
} from '../lib/calibrate.js'
import { computeSchedule } from '../lib/patrol.js'

// ---------------------------------------------------------------------------
// 测试数据
// ---------------------------------------------------------------------------

const WINDOWS_FACTS = {
  platform: 'windows',
  osName: 'Microsoft Windows 10 专业工作站版',
  osVersion: '10.0.19045',
  osBuild: '19045',
  arch: 'AMD64',
  files: [],
  warnings: [],
}

const SHA256_RE = /^[a-f0-9]{64}$/

// ---------------------------------------------------------------------------
// 手写形状校验（JSON schema 风格；不引第三方依赖）
// ---------------------------------------------------------------------------

function assertCalibrationReport(report) {
  assert.equal(typeof report, 'object')
  assert.equal(report.ok, true)
  assert.equal(typeof report.checkedAt, 'number')
  assert.ok(Array.isArray(report.sources))
  for (const source of report.sources) {
    assert.equal(typeof source.title, 'string')
    assert.ok(source.title.length > 0)
    assert.equal(typeof source.url, 'string')
    assert.match(source.url, /^https?:\/\//)
  }
  assert.ok(Array.isArray(report.findings))
  assert.ok(report.findings.length > 0)
  for (const finding of report.findings) {
    assert.ok(['info', 'warn', 'error'].includes(finding.level), `未知 finding level: ${finding.level}`)
    assert.equal(typeof finding.text, 'string')
    assert.ok(finding.text.length > 0)
    assert.equal(typeof finding.source, 'string')
  }
  assert.equal(typeof report.summary, 'string')
  assert.ok(report.summary.length > 0)
  assert.equal(typeof report.note, 'string')
  assert.ok(report.note.includes('逐文件'))
}

function assertFileRef(ref) {
  assert.equal(typeof ref, 'object')
  assert.equal(typeof ref.id, 'string', 'FileRef.id 必须是字符串')
  assert.ok(ref.id.length > 0)
  assert.equal(typeof ref.path, 'string')
  assert.ok(ref.path.length > 0)
  assert.ok(['core', 'support', 'memory', 'junk'].includes(ref.role), `未知 role: ${ref.role}`)
  assert.equal(typeof ref.group, 'string')
  assert.ok(ref.size === null || (typeof ref.size === 'number' && ref.size >= 0), 'FileRef.size 必须是 number|null')
  assert.ok(ref.sha256 === null || (typeof ref.sha256 === 'string' && SHA256_RE.test(ref.sha256)),
    'FileRef.sha256 必须是 64 位十六进制或 null')
  assert.ok(ref.version === null || typeof ref.version === 'string', 'FileRef.version 必须是 string|null')
  assert.equal(typeof ref.critical, 'boolean')
  assert.equal(typeof ref.exists, 'boolean')
}

function assertAnalysis(analysis) {
  assert.equal(typeof analysis.analyzedAt, 'number')
  assert.equal(typeof analysis.durationMs, 'number')
  assert.equal(typeof analysis.coreCount, 'number')
  assert.equal(typeof analysis.coreBytes, 'number')
  assert.equal(typeof analysis.supportCount, 'number')
  assert.equal(typeof analysis.supportBytes, 'number')
  assert.ok(Array.isArray(analysis.files))
  assert.ok(analysis.files.length <= 800, 'Analysis.files 最多 800 条')
  analysis.files.forEach(assertFileRef)
  assert.ok(Array.isArray(analysis.groups))
  analysis.groups.forEach(assertJunkGroup)
  assert.equal(typeof analysis.totalJunkBytes, 'number')
  assert.ok(['builtin', 'calibrated'].includes(analysis.baselineSource))
  assert.ok(analysis.calibratedAt === null || typeof analysis.calibratedAt === 'number')
  assert.ok(Array.isArray(analysis.warnings))
}

function assertJunkGroup(group) {
  assert.equal(typeof group.id, 'string')
  assert.ok(group.id.length > 0)
  assert.equal(typeof group.title, 'string')
  assert.ok(['junk', 'memory'].includes(group.kind), `未知 kind: ${group.kind}`)
  assert.equal(typeof group.note, 'string')
  assert.equal(typeof group.safeToDelete, 'boolean')
  assert.ok(Array.isArray(group.items))
  assert.ok(group.items.length <= 3000, 'JunkGroup.items 最多 3000 条')
  for (const item of group.items) {
    assert.equal(typeof item.id, 'string')
    assert.equal(typeof item.path, 'string')
    assert.ok(numberOrZero(item.size) >= 0)
    assert.equal(item.exists, true, '垃圾项必须是真实存在的路径')
  }
  assert.ok(numberOrZero(group.totalBytes) >= 0)
  assert.equal(typeof group.itemCount, 'number')
  assert.ok(group.itemCount >= group.items.length)
}

function numberOrZero(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function assertJunkReport(report) {
  assert.ok(Array.isArray(report.groups))
  report.groups.forEach(assertJunkGroup)
  assert.equal(typeof report.totalBytes, 'number')
  assert.ok(Array.isArray(report.warnings))
}

function assertProbe(probe) {
  assert.equal(typeof probe.platform, 'string')
  assert.equal(typeof probe.osName, 'string')
  assert.equal(typeof probe.osVersion, 'string')
  assert.equal(typeof probe.osBuild, 'string')
  assert.equal(typeof probe.arch, 'string')
  assert.equal(typeof probe.admin, 'boolean')
  assert.equal(typeof probe.systemRoot, 'string')
  assert.equal(typeof probe.systemDrive, 'string')
  assert.ok(Array.isArray(probe.volumes))
  for (const volume of probe.volumes) {
    assert.equal(typeof volume.id, 'string')
    assert.equal(typeof volume.label, 'string')
    assert.equal(typeof volume.fs, 'string')
    assert.equal(typeof volume.totalBytes, 'number')
    assert.equal(typeof volume.freeBytes, 'number')
    assert.equal(typeof volume.isSystem, 'boolean')
  }
  assert.equal(typeof probe.tools, 'object')
  assert.ok(probe.updateWindow === null || typeof probe.updateWindow === 'object')
  assert.ok(Array.isArray(probe.warnings))
}

function assertPatrolReport(report) {
  assert.equal(typeof report.checkedAt, 'number')
  assert.equal(typeof report.durationMs, 'number')
  assert.equal(typeof report.total, 'number')
  assert.equal(typeof report.unchanged, 'number')
  assert.ok(Array.isArray(report.changed))
  for (const change of report.changed) {
    assert.equal(typeof change.path, 'string')
    assert.equal(typeof change.expectedSha, 'string')
    assert.equal(typeof change.actualSha, 'string')
    assert.equal(typeof change.exempted, 'boolean')
    assert.equal(typeof change.reason, 'string')
  }
  assert.ok(Array.isArray(report.missing))
  assert.ok(report.missing.every((item) => typeof item === 'string'))
  assert.ok(['healthy', 'changed', 'damaged', 'unknown'].includes(report.verdict))
  assert.equal(typeof report.sfc.ran, 'boolean')
  assert.ok(report.sfc.passed === null || typeof report.sfc.passed === 'boolean')
  assert.equal(typeof report.sfc.detail, 'string')
  assert.equal(typeof report.backup.state, 'string')
  assert.ok(Array.isArray(report.warnings))
}

function assertBackupInfo(info) {
  assert.equal(typeof info.root, 'string')
  assert.equal(typeof info.hidden, 'boolean')
  assert.equal(typeof info.volume, 'string')
  assert.ok(info.createdAt === null || typeof info.createdAt === 'number')
  assert.equal(typeof info.fileCount, 'number')
  assert.equal(typeof info.totalBytes, 'number')
  assert.equal(typeof info.manifestPath, 'string')
  assert.ok(['ok', 'none', 'missing', 'partial'].includes(info.state), `未知 backup state: ${info.state}`)
  assert.ok(info.verifiedAt === null || typeof info.verifiedAt === 'number')
  assert.ok(Array.isArray(info.missingFiles))
  assert.ok(Array.isArray(info.corruptFiles))
}

function assertFacts(facts) {
  assert.equal(typeof facts.platform, 'string')
  assert.equal(typeof facts.osName, 'string')
  assert.equal(typeof facts.osVersion, 'string')
  assert.equal(typeof facts.osBuild, 'string')
  assert.equal(typeof facts.arch, 'string')
  assert.ok(Array.isArray(facts.files))
  for (const file of facts.files) {
    assert.equal(typeof file.path, 'string')
    assert.ok(file.version === null || typeof file.version === 'string')
    assert.equal(typeof file.sha256, 'string')
    assert.match(file.sha256, SHA256_RE)
  }
  assert.ok(Array.isArray(facts.warnings))
}

// ---------------------------------------------------------------------------
// calibrate：三种联网行为
// ---------------------------------------------------------------------------

test('calibrate：web 缺失 → ok:false + error.code 表示缺联网能力，且不抛错', async () => {
  const report = await calibrate({ facts: WINDOWS_FACTS })
  assert.equal(report.ok, false)
  assert.equal(typeof report.error, 'object')
  assert.equal(report.error.code, 'network')
  assert.match(report.error.message, /^联网校准失败：/)
  assert.match(report.error.message, /ctx\.web/)
})

test('calibrate：search 与 fetch 都失败 → ok:false，且把两边的真实原因都带上', async () => {
  const fakeWeb = {
    search: async () => {
      const error = new Error('no usable web provider is registered')
      error.code = 'WEB_PROVIDER_UNAVAILABLE'
      throw error
    },
    fetch: async () => {
      const error = new Error('fetch provider is not configured')
      error.code = 'WEB_PROVIDER_CREDENTIAL_MISSING'
      throw error
    },
  }
  const report = await calibrate({ facts: WINDOWS_FACTS, web: fakeWeb })
  assert.equal(report.ok, false)
  assert.equal(report.error.code, 'network')
  // 检索失败原因 + 直连官方页面失败原因都要如实带上，不能只剩一句「失败」。
  assert.match(report.error.message, /WEB_PROVIDER_UNAVAILABLE/)
  assert.match(report.error.message, /WEB_PROVIDER_CREDENTIAL_MISSING/)
  assert.match(report.error.message, /直接读取预置官方文档页面也失败/)
})

test('calibrate：只有 fetch 没有 search → 降级直连预置官方页面，ok:true + findings 含降级说明', async () => {
  const calls = []
  const fakeWeb = {
    // 故意不提供 search（模拟 CLI/精简 profile 或宿主没配搜索能力）
    fetch: async (request) => {
      calls.push(request)
      return {
        url: request.url,
        statusCode: 200,
        truncated: false,
        body: {
          kind: 'html',
          content: '<html><body><h1>Windows release information</h1>'
            + '<p>Windows 10 版本 22H2 的支持结束日期为 2025 年 10 月 14 日。</p></body></html>',
        },
      }
    },
  }
  const report = await calibrate({ facts: WINDOWS_FACTS, web: fakeWeb })
  assertCalibrationReport(report)
  // 预置列表每平台 2~3 条，默认全抓（3 条），sources 只保留真正抓到的 URL。
  assert.ok(report.sources.length >= 2, '应至少抓到 2 篇官方页面')
  assert.ok(report.sources.every((source) => isOfficialUrl(source.url, 'windows')))
  assert.ok(report.sources.some((source) => source.url.includes('release-information')))
  assert.ok(calls.length >= 2 && calls.length <= 3)
  assert.ok(calls.every((request) => isOfficialUrl(request.url, 'windows')), '只允许抓官方域名')
  // 必须如实写明本次没有用搜索引擎。
  assert.ok(report.findings.some((finding) => finding.text.includes('本次未使用搜索引擎')
    && finding.text.includes('改为直接读取官方文档页面')))
})

test('calibrate：search 抛凭据缺失 + fetch 正常 → 降级成功并写明「宿主未配置搜索凭据」', async () => {
  const fakeWeb = {
    search: async () => {
      const error = new Error('DeepSeek search has no API key for "DEEPSEEK_API_KEY"')
      error.code = 'WEB_PROVIDER_CREDENTIAL_MISSING'
      throw error
    },
    fetch: async (request) => ({
      url: request.url,
      statusCode: 200,
      truncated: false,
      body: { kind: 'text', content: 'Windows 10 Home and Pro - Microsoft Lifecycle. Support ended October 14, 2025.' },
    }),
  }
  const report = await calibrate({ facts: WINDOWS_FACTS, web: fakeWeb, config: { calibrateMaxQueries: 1 } })
  assertCalibrationReport(report)
  assert.ok(report.sources.length >= 2)
  assert.ok(report.sources.every((source) => isOfficialUrl(source.url, 'windows')))
  assert.ok(report.findings.some((finding) => finding.text.includes('宿主未配置搜索凭据')))
  assert.ok(report.findings.some((finding) => finding.text.includes('本次未使用搜索引擎')))
  // 限制说明里保留真实错误码，方便排查。
  assert.ok(report.findings.some((finding) => finding.level === 'warn'
    && finding.text.includes('WEB_PROVIDER_CREDENTIAL_MISSING')))
})

test('OFFICIAL_URLS：三平台各 3~8 条官方页面，URL 全部通过官方白名单', () => {
  for (const platform of ['windows', 'macos', 'linux']) {
    const list = OFFICIAL_URLS[platform]
    assert.ok(Array.isArray(list), `${platform} 缺少预置官方页面列表`)
    assert.ok(list.length >= 3 && list.length <= 8, `${platform} 预置页面应为 3~8 条，实际 ${list.length}`)
    const urls = new Set()
    for (const item of list) {
      assert.equal(typeof item.title, 'string')
      assert.ok(item.title.length > 0)
      assert.equal(typeof item.url, 'string')
      assert.ok(item.url.startsWith('https://'), `官方页面必须用 https：${item.url}`)
      assert.equal(isOfficialUrl(item.url, platform), true, `预置 URL 不在官方白名单内：${item.url}`)
      assert.ok(!urls.has(item.url), `预置 URL 重复：${item.url}`)
      urls.add(item.url)
      // match 是可选字段；写了就必须是对象，避免写成字符串后静默失效。
      assert.ok(item.match === undefined || (item.match && typeof item.match === 'object'),
        `match 必须是对象：${item.url}`)
    }
  }
  assert.ok(Array.isArray(OFFICIAL_URLS.generic) && OFFICIAL_URLS.generic.length > 0,
    '未知平台也要有兜底的官方页面')
})

test('calibrate 降级：build 19045 按版本挑页，不抓 Windows 11 页面', async () => {
  const fetched = []
  const fakeWeb = {
    fetch: async ({ url }) => {
      fetched.push(url)
      return {
        url,
        statusCode: 200,
        truncated: false,
        body: {
          kind: 'html',
          content: '<html><body><h1>Windows 10 release information</h1>'
            + '<p>On October 14, 2025, Windows 10 reached end of support.</p></body></html>',
        },
      }
    },
  }
  const report = await calibrate({ facts: WINDOWS_FACTS, web: fakeWeb, config: {} })
  assert.equal(report.ok, true)
  assert.ok(fetched.length >= 1 && fetched.length <= 5, `抓取页数应在 1~5，实际 ${fetched.length}`)
  assert.ok(fetched.every((url) => isOfficialUrl(url, 'windows')), '只能抓官方域名')
  assert.ok(fetched.every((url) => !url.includes('windows11')),
    `build 19045 不应抓 Windows 11 页面：${fetched.join(' ')}`)
  assert.ok(fetched.some((url) => url.includes('release-information')),
    `应优先抓 Windows 10 release information：${fetched.join(' ')}`)
  assert.ok(report.findings.some((finding) => finding.text.includes('未使用搜索引擎')))
  // 抓到的每一篇都要进 findings，且 summary 的数字与实际抓取篇数一致
  // （之前全局写死 slice(0,2)，抓 3 篇时会出现「3 来源 / 2 篇」的不一致）。
  const fetchedFindings = report.findings.filter((finding) => finding.text.includes('已抓取官方页面'))
  assert.equal(fetchedFindings.length, report.sources.length,
    `findings 篇数（${fetchedFindings.length}）应与 sources 数（${report.sources.length}）一致`)
  assert.ok(report.summary.includes(`抓取 ${report.sources.length} 篇`), report.summary)
})

test('calibrate 降级：Win11 / Server 不会误抓 Windows 10 页面', async () => {
  const run = async (facts) => {
    const fetched = []
    const web = {
      fetch: async ({ url }) => {
        fetched.push(url)
        return { url, statusCode: 200, body: { kind: 'html', content: '<p>release information support end of support</p>' } }
      },
    }
    const report = await calibrate({ facts, web, config: {} })
    assert.equal(report.ok, true, JSON.stringify(report.error || {}))
    return fetched
  }
  const isWin10Page = (url) => url.includes('/release-health/release-information')
    || url.includes('status-windows-10')
    || url.includes('windows-10-home-and-pro')
    || url.includes('whats-new-windows-10')

  const win11 = await run({ platform: 'windows', osName: 'Microsoft Windows 11 专业版', osVersion: '10.0.22631', osBuild: '22631', arch: 'AMD64', files: [], warnings: [] })
  assert.ok(win11.every((url) => !isWin10Page(url)), `Win11 抓到了 Win10 页面：${win11.join(' ')}`)
  assert.ok(win11.some((url) => url.includes('windows11-release-information')), `Win11 应抓 Win11 页面：${win11.join(' ')}`)

  // Server 2025 的 build 26100 也 ≥ 22000：只按 build 判断会把它误当成 Win11。
  const server = await run({ platform: 'windows', osName: 'Microsoft Windows Server 2025 Standard', osVersion: '10.0.26100', osBuild: '26100', arch: 'AMD64', files: [], warnings: [] })
  assert.ok(server.every((url) => !isWin10Page(url) && !url.includes('windows11')), `Server 抓到了 Win10/Win11 页面：${server.join(' ')}`)
  assert.ok(server.some((url) => url.includes('windows-server-release-info')), `Server 应抓 Server 页面：${server.join(' ')}`)

  // build 缺失时用系统名称兜底，仍然不能把 Win11 当 Win10。
  const noBuild = await run({ platform: 'windows', osName: 'Microsoft Windows 11 专业版', osVersion: '', osBuild: '', arch: 'AMD64', files: [], warnings: [] })
  assert.ok(noBuild.every((url) => !isWin10Page(url)), `Win11（无 build）抓到了 Win10 页面：${noBuild.join(' ')}`)
})

test('calibrate：正常 fake web → 合法 CalibrationReport，只保留官方来源并抓取官方页面', async () => {
  const calls = { search: [], fetch: [] }
  const fakeWeb = {
    search: async (request) => {
      calls.search.push(request)
      return {
        content: 'provider answer（可缺省）',
        truncated: false,
        sources: [
          {
            url: 'https://learn.microsoft.com/en-us/windows/release-health/',
            title: 'Windows release health',
            snippet: 'Windows 10 版本 22H2 支持结束日期',
          },
          { url: 'https://example.com/third-party', title: '第三方站点（应被丢弃）' },
          {
            url: 'https://support.microsoft.com/help/4026529',
            title: '使用系统文件检查器工具修复丢失或损坏的系统文件',
            snippet: 'sfc /scannow',
          },
        ],
      }
    },
    fetch: async (request) => {
      calls.fetch.push(request)
      return {
        url: request.url,
        statusCode: 200,
        truncated: false,
        body: {
          kind: 'html',
          content: '<html><body><h1>Windows release health</h1>'
            + '<p>Windows 10 版本 22H2 的支持结束日期为 2025 年 10 月 14 日。</p>'
            + '<script>alert(1)</script></body></html>',
        },
      }
    },
  }
  const report = await calibrate({ facts: WINDOWS_FACTS, web: fakeWeb, config: { calibrateFetchPages: 2 } })
  assertCalibrationReport(report)
  // 只保留官方域名，第三方被丢弃。
  assert.equal(report.sources.length, 2)
  assert.ok(report.sources.every((source) => isOfficialUrl(source.url, 'windows')))
  assert.ok(report.sources.some((source) => source.url.includes('learn.microsoft.com')))
  assert.ok(report.sources.every((source) => !source.url.includes('example.com')))
  // 检索与抓取只发生在官方来源上。
  assert.equal(calls.search.length, 3)
  assert.equal(calls.fetch.length, 2)
  assert.ok(calls.fetch.every((request) => isOfficialUrl(request.url, 'windows')))
  // ① 支持状态（内置表：19045 已结束支持）
  assert.ok(report.findings.some((finding) => finding.level === 'warn' && finding.text.includes('已结束支持')))
  // ② 官方完整性校验方式（sfc / DISM）
  assert.ok(report.findings.some((finding) => finding.text.includes('sfc /scannow')))
  // ③ 插件边界说明
  assert.ok(report.findings.some((finding) => finding.text.includes('逐文件哈希清单')))
  // 抓取到的官方页面进入 findings
  assert.ok(report.findings.some((finding) => finding.text.includes('已抓取官方页面')))
  // 摘要与 note
  assert.ok(report.summary.includes('未做逐文件下载比对'))
  assert.equal(report.note, SUPPORT_BOUNDARY_NOTE)
  // 隐私：查询里不能出现文件路径/用户信息
  const searchPayload = JSON.stringify(calls.search)
  for (const marker of ['/boot', '/etc/', 'System32', os.homedir()]) {
    assert.ok(!searchPayload.includes(marker), `检索参数泄露了本机信息：${marker}`)
  }
})

test('calibrate：搜索结果全是第三方 → 拒绝校准（不伪造 findings）', async () => {
  const fakeWeb = {
    search: async () => ({
      sources: [{ url: 'https://example.com/a', title: '第三方 A' }, { url: 'https://some-blog.net/b' }],
      truncated: false,
    }),
  }
  const report = await calibrate({ facts: WINDOWS_FACTS, web: fakeWeb })
  assert.equal(report.ok, false)
  assert.equal(report.error.code, 'network')
  assert.match(report.error.message, /官方来源/)
})

test('calibrate：搜索成功但抓取失败 → 仍然 ok:true，并把限制写进 warn finding（不伪造）', async () => {
  const fakeWeb = {
    search: async () => ({
      sources: [{ url: 'https://learn.microsoft.com/en-us/windows/release-health/', title: 'Windows release health' }],
      truncated: false,
    }),
    fetch: async () => {
      const error = new Error('server returned 403')
      error.code = 'WEB_PROVIDER_ERROR'
      throw error
    },
  }
  const report = await calibrate({ facts: WINDOWS_FACTS, web: fakeWeb })
  assertCalibrationReport(report)
  assert.ok(report.findings.some((finding) => finding.level === 'warn' && finding.text.includes('抓取官方页面失败')))
})

test('calibrate：facts 缺失 → ok:false + invalid-input', async () => {
  const report = await calibrate({ web: { search: async () => ({ sources: [] }) } })
  assert.equal(report.ok, false)
  assert.equal(report.error.code, 'invalid-input')
})

// ---------------------------------------------------------------------------
// 纯解析函数
// ---------------------------------------------------------------------------

test('parseSearchResult：规整/容错', () => {
  assert.deepEqual(parseSearchResult(null), { content: '', truncated: false, sources: [] })
  assert.deepEqual(parseSearchResult({}), { content: '', truncated: false, sources: [] })
  const parsed = parseSearchResult({
    content: '答案',
    truncated: true,
    sources: [
      { url: 'https://learn.microsoft.com/x', title: 'T', snippet: 'S', publishedAt: '2026-01-01' },
      { title: '没有 url' },
      { url: 123 },
      null,
    ],
  })
  assert.equal(parsed.content, '答案')
  assert.equal(parsed.truncated, true)
  assert.equal(parsed.sources.length, 1)
  assert.deepEqual(parsed.sources[0], {
    url: 'https://learn.microsoft.com/x',
    title: 'T',
    snippet: 'S',
    publishedAt: '2026-01-01',
  })
})

test('extractFetchText：html 去脚本/去标签/解码实体，text 原样保留', () => {
  const html = '<html><head><style>.a{}</style></head><body><h1>标题</h1>'
    + '<p>支持 &amp; 生命周期</p><script>evil()</script><div>尾部</div></body></html>'
  const text = extractFetchText({ body: { kind: 'html', content: html } })
  assert.ok(text.includes('标题'))
  assert.ok(text.includes('支持 & 生命周期'))
  assert.ok(!text.includes('evil()'))
  assert.ok(!text.includes('<'))
  const plain = extractFetchText({ body: { kind: 'text', content: '纯文本  内容' } })
  assert.equal(plain, '纯文本 内容')
  assert.equal(extractFetchText(null), '')
  assert.equal(extractFetchText({ body: { kind: 'html', content: '' } }), '')
})

test('isOfficialUrl：子域白名单，拒绝第三方/伪造/非 http(s)', () => {
  assert.equal(isOfficialUrl('https://learn.microsoft.com/en-us/windows/', 'windows'), true)
  assert.equal(isOfficialUrl('https://support.apple.com/zh-cn/guide', 'macos'), true)
  assert.equal(isOfficialUrl('https://ubuntu.com/server/docs', 'linux'), true)
  assert.equal(isOfficialUrl('https://debian.org/', 'linux'), true)
  assert.equal(isOfficialUrl('https://example.com/', 'windows'), false)
  assert.equal(isOfficialUrl('https://microsoft.com.evil.example/', 'windows'), false)
  assert.equal(isOfficialUrl('ftp://learn.microsoft.com/', 'windows'), false)
  assert.equal(isOfficialUrl('not a url', 'windows'), false)
  assert.equal(isOfficialUrl('https://apple.com/', 'windows'), false, '跨平台域名不应命中')
})

test('buildQueries：2~3 条、只含版本信息、不含路径/用户信息', () => {
  for (const facts of [
    WINDOWS_FACTS,
    { platform: 'linux', osName: 'Ubuntu', osVersion: '24.04', osBuild: '6.8.0-45-generic' },
    { platform: 'macos', osName: 'macOS', osVersion: '14.6.1', osBuild: '23G93' },
  ]) {
    const queries = buildQueries(facts)
    assert.ok(queries.length >= 2 && queries.length <= 3, '查询数量应在 2~3 条')
    assert.ok(queries.every((query) => typeof query === 'string' && query.trim().length > 0))
    const payload = queries.join(' ')
    for (const marker of ['/boot', '/etc/', 'System32', 'C:\\', os.homedir()]) {
      assert.ok(!payload.includes(marker), `查询里出现了本机路径：${marker}`)
    }
  }
})

test('buildCalibrationReport：纯函数拼装（sources 去重前由调用方负责；这里校验结构与文案）', () => {
  const report = buildCalibrationReport({
    facts: WINDOWS_FACTS,
    platform: 'windows',
    sources: [
      { title: 'Windows release health', url: 'https://learn.microsoft.com/en-us/windows/release-health/' },
      { title: '', url: 'https://support.microsoft.com/help/4026529' },
    ],
    docs: [
      {
        title: 'Windows release health',
        url: 'https://learn.microsoft.com/en-us/windows/release-health/',
        statusCode: 200,
        text: 'Windows 10 版本 22H2 的支持结束日期为 2025 年 10 月 14 日。',
      },
    ],
    warnings: [],
    now: Date.UTC(2026, 9, 27),
  })
  assertCalibrationReport(report)
  assert.equal(report.checkedAt, Date.UTC(2026, 9, 27))
  assert.equal(report.sources[1].title, 'support.microsoft.com', '缺 title 时用域名兜底')
  assert.ok(report.findings.some((finding) => finding.text.includes('2025-10-14')))
})

// ---------------------------------------------------------------------------
// 契约形状：FileRef / JunkReport / Analysis / Probe / PatrolReport / BackupInfo / Facts
// ---------------------------------------------------------------------------

test('POSIX 声明清单符合契约（核心文件与垃圾分组），且不碰用户文档目录', () => {
  for (const platform of ['linux', 'macos']) {
    const specs = POSIX_CORE_FILES[platform]
    assert.ok(Array.isArray(specs) && specs.length > 0)
    const ids = new Set()
    for (const spec of specs) {
      assert.equal(typeof spec.id, 'string')
      assert.ok(spec.id.length > 0)
      assert.ok(!ids.has(spec.id), `重复的核心文件 id：${spec.id}`)
      ids.add(spec.id)
      assert.equal(typeof spec.group, 'string')
      assert.equal(typeof spec.critical, 'boolean')
      assert.ok(Boolean(spec.path || spec.glob || (Array.isArray(spec.candidates) && spec.candidates.length > 0)))
      if (spec.path) assert.ok(spec.path.startsWith('/'), `核心文件路径必须是绝对路径：${spec.path}`)
      if (spec.candidates) {
        assert.ok(spec.candidates.every((candidate) => typeof candidate === 'string' && candidate.startsWith('/')))
      }
      if (spec.glob) {
        assert.ok(spec.glob.dir.startsWith('/'))
        assert.equal(typeof spec.glob.prefix, 'string')
      }
    }
    const groups = POSIX_JUNK_GROUPS[platform]
    assert.ok(Array.isArray(groups) && groups.length > 0)
    const groupIds = new Set()
    for (const group of groups) {
      assert.equal(typeof group.id, 'string')
      assert.ok(!groupIds.has(group.id), `重复的垃圾分组 id：${group.id}`)
      groupIds.add(group.id)
      assert.ok(['junk', 'memory'].includes(group.kind))
      assert.equal(typeof group.title, 'string')
      assert.equal(typeof group.note, 'string')
      assert.equal(typeof group.safeToDelete, 'boolean')
      assert.ok(Array.isArray(group.roots) && group.roots.length > 0)
      for (const root of group.roots) {
        assert.equal(typeof root, 'string')
        assert.ok(root.startsWith('/') || root.startsWith('~'), `垃圾根目录必须是绝对路径或 ~ 开头：${root}`)
        // CONTRACT §1.5：不递归扫描桌面/文档/下载等用户目录。
        assert.ok(!/(Desktop|Documents|Downloads|Pictures|Music|Videos|文档|下载|桌面)/i.test(root), `垃圾目录不应包含用户文档目录：${root}`)
      }
    }
  }
})

test('Windows 上 createPosixBackend 不崩：probe 返回降级结构（Lead 要求）', async () => {
  const backend = createPosixBackend()
  assert.equal(backend.platform, 'windows')
  assert.equal(detectPosixPlatform(), 'windows')
  const probe = await backend.probe()
  assertProbe(probe)
  assert.equal(probe.platform, 'windows')
  assert.ok(probe.warnings.length > 0)
  assert.ok(probe.warnings.some((warning) => warning.includes('posix 后端只做兜底')))
})

test('posix backend 在 Windows 上的降级方法都返回合法形状且不抛错', async () => {
  const dataDir = path.join(os.tmpdir(), `dsh-guard-selftest-${process.pid}-${Date.now()}`)
  const backend = createPosixBackend({ dataDir })

  const analysis = await backend.analyze({ files: [] })
  assertAnalysis(analysis)
  assert.equal(analysis.files.length, 0, 'Windows 上 posix backend 没有核心文件清单')
  assert.ok(analysis.warnings.length > 0)

  const junk = await backend.junkScan()
  assertJunkReport(junk)
  assert.equal(junk.groups.length, 0)
  assert.ok(junk.warnings.length > 0)

  const deleted = await backend.junkDelete({ items: [{ path: '/tmp/a' }, { path: '/tmp/b' }] })
  assert.equal(deleted.requested, 2)
  assert.deepEqual(deleted.deleted, [])
  assert.equal(deleted.freedBytes, 0)
  assert.equal(deleted.elevated, false)
  assert.equal(deleted.failed.length, 2)
  assert.ok(deleted.failed.every((entry) => entry.error === 'unsupported-on-platform'))

  const backup = await backend.backup({ files: [] })
  assertBackupInfo(backup)
  assert.equal(backup.state, 'none')
  assert.ok(backup.warnings.length > 0)
  // 降级路径不允许写任何文件（含 dataDir）。
  assert.equal(existsSync(dataDir), false, 'Windows 降级路径不应创建 dataDir')

  const backupStatus = await backend.backupStatus()
  assertBackupInfo(backupStatus)
  assert.equal(backupStatus.state, 'none')

  const patrol = await backend.patrol({ baseline: { files: [] }, opts: {} })
  assertPatrolReport(patrol)
  assert.equal(patrol.verdict, 'unknown')
  assert.equal(patrol.sfc.ran, false)

  const repair = await backend.repair({ mode: 'sfc', paths: [] })
  assert.equal(repair.ok, false)
  assert.equal(repair.error.code, 'unsupported-on-platform')

  const facts = await backend.calibrateFacts()
  assertFacts(facts)
  assert.equal(facts.platform, 'windows')
  assert.equal(facts.files.length, 0)
  assert.ok(facts.warnings.length > 0)

  const restorePoint = backend.restorePoint
  assert.equal(typeof restorePoint, 'undefined', 'POSIX 没有系统还原点，不导出 restorePoint（交给 core 返回 unsupported）')

  await backend.dispose()
})

test('注入 linux 平台时 analyze 产出合法 FileRef / Analysis（声明式降级检查，不执行命令）', async () => {
  const backend = createPosixBackend({
    platform: 'linux',
    config: { posixActionTimeoutMs: 30000, posixJunkScanTimeoutMs: 1500 },
  })
  assert.equal(backend.platform, 'linux')
  const analysis = await backend.analyze({ files: null })
  assertAnalysis(analysis)
  assert.ok(analysis.coreCount > 0, '声明式核心清单应至少产出若干 FileRef')
  const coreRefs = analysis.files.filter((file) => file.role === 'core')
  assert.ok(coreRefs.length > 0)
  assert.ok(coreRefs.some((file) => file.path.startsWith('/')))
  // 目录型 FileRef（如 /lib/modules）的 size/sha256 允许为 null。
  assert.ok(analysis.files.every((file) => file.size === null || typeof file.size === 'number'))
})

test('analyze 增量模式（传入上次基线）不重复计入 support，核心计数正确', async () => {
  const backend = createPosixBackend({
    platform: 'linux',
    config: { posixActionTimeoutMs: 30000, posixJunkScanTimeoutMs: 800 },
  })
  const first = await backend.analyze({ files: null })
  assertAnalysis(first)
  const second = await backend.analyze({ files: first.files })
  assertAnalysis(second)
  assert.equal(second.coreCount, first.coreCount, '增量分析的核心计数应保持一致')
  assert.equal(
    second.files.filter((file) => file.role === 'core').length,
    first.files.filter((file) => file.role === 'core').length,
  )
  const paths = second.files.map((file) => file.path)
  assert.equal(new Set(paths).size, paths.length, '增量分析不应重复同一路径')
  assert.ok(second.files.length <= 800)
})

test('posix backend 修复行为诚实：macOS 返回 manual-required，不假装成功', async () => {
  const backend = createPosixBackend({ platform: 'macos' })
  const report = await backend.repair({ mode: 'sfc' })
  assert.equal(report.ok, false)
  assert.equal(report.error.code, 'manual-required')
  assert.match(report.error.message, /恢复模式/)
  assert.equal(report.actions.length, 0)
})

test('patrol 语义：只核对可校验条目；缺失核心文件 → damaged；无哈希条目只查存在性', async () => {
  const backend = createPosixBackend({ platform: 'linux' })
  const existing = fileURLToPath(new URL('../lib/calibrate.js', import.meta.url))
  const missing = path.join(os.tmpdir(), `dsh-guard-missing-${process.pid}-${Date.now()}`)

  // 无哈希的核心条目：存在性检查通过，verdict 应为 healthy（不是 unknown）。
  const healthy = await backend.patrol({
    baseline: {
      files: [
        { path: existing, role: 'core', critical: true, sha256: null },
        { path: missing, role: 'support', critical: false, sha256: null },
      ],
    },
    opts: {},
  })
  assertPatrolReport(healthy)
  assert.equal(healthy.total, 1, 'support 无哈希条目不应计入 total')
  assert.equal(healthy.unchanged, 1)
  assert.equal(healthy.verdict, 'healthy')
  assert.ok(healthy.warnings.some((warning) => warning.includes('仅检查存在性')))

  // 有基线哈希的核心文件缺失 → missing + damaged。
  const damaged = await backend.patrol({
    baseline: { files: [{ path: missing, role: 'core', critical: true, sha256: 'a'.repeat(64) }] },
    opts: {},
  })
  assertPatrolReport(damaged)
  assert.equal(damaged.total, 1)
  assert.equal(damaged.verdict, 'damaged')
  assert.deepEqual(damaged.missing, [missing])
})

test('CONTRACT §1.5 可中断：已取消的 AbortSignal 会让长任务抛 code=aborted', async () => {
  const backend = createPosixBackend({ platform: 'linux', config: { posixActionTimeoutMs: 30000 } })
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(
    () => backend.analyze({ files: null, signal: controller.signal }),
    (error) => error && error.code === 'aborted',
  )
})

test('patrol.computeSchedule（Lead 模块）契约：巡查/校准排期可断言', () => {
  const dayMs = 24 * 60 * 60 * 1000
  const schedule = computeSchedule({
    settings: { patrolIntervalDays: 7, calibrateAskIntervalDays: 30 },
    persisted: { lastPatrolAt: 1_000, lastCalibrateAt: null, nextCalibrateAskAt: null },
    now: 1_000 + 8 * dayMs,
    dayMs,
  })
  assert.equal(schedule.patrol.intervalDays, 7)
  assert.equal(schedule.patrol.due, true)
  assert.equal(schedule.patrol.overdueDays, 1)
  assert.equal(typeof schedule.patrol.nextText, 'string')
  assert.equal(schedule.calibrate.intervalDays, 30)
  assert.equal(schedule.calibrate.due, false)
  assert.equal(schedule.calibrate.lastText, '从未校准')

  const fresh = computeSchedule({
    settings: {},
    persisted: {},
    now: 0,
    dayMs,
  })
  assert.equal(fresh.patrol.nextAt, null)
  assert.equal(fresh.patrol.nextText, '分析完成后开始计时')
  assert.equal(fresh.patrol.due, false)
  assert.equal(fresh.calibrate.nextAskAt, null)
})

test('官方域名白名单覆盖三平台（防止空表导致过滤失去意义）', () => {
  for (const platform of ['windows', 'macos', 'linux']) {
    assert.ok(Array.isArray(OFFICIAL_DOMAINS[platform]) && OFFICIAL_DOMAINS[platform].length > 0)
  }
  // 内置生命周期表也要有三平台条目（否则「已知旧 build」判断会全落空）。
  for (const platform of ['windows', 'macos', 'linux']) {
    assert.ok(Object.keys(LIFECYCLE[platform]).length > 0)
  }
})

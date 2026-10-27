#!/usr/bin/env node
/**
 * dsh-system-guard · Windows 真机只读验证（CONTRACT §9）
 *
 * 默认只跑「只读」动作，验证真实数值，不修改任何系统文件：
 *   - helper 脚本与 UTF-8 BOM 编码检查
 *   - 管理员权限检测
 *   - probe（系统事实）
 *   - analyze（核心文件清单 + 分类 + 垃圾扫描）
 *   - junk-scan（垃圾与系统记忆分类）
 *   - patrol（用 analyze 的清单当基线做完整性巡查）
 *   - calibrate-facts（校准输入，≤80 个核心文件）
 *   - backup-status（备份状态读取）
 *   - AbortSignal 中止（对 junk-scan 发中止信号，期望 code=aborted）
 *   - 提权包装脚本语法（只解析，不弹 UAC）
 *   - patrol 判定自测（用临时文件验证 healthy/changed/damaged/豁免）
 *   - 提权动作门控（非管理员时只返回 need-elevation，不弹 UAC）
 *   - 删除白名单拒绝（白名单外路径一律 not-allowed，不执行删除）
 *   - updateConfig 热更新
 *
 * 破坏性/提权动作（junk-delete 真删 / repair / restore / restore-point）永远不在这里跑。
 * 备份是安全写入（只复制系统文件到「剩余容量最大」的固定盘），需显式 --backup：
 *
 *   node test/win-live.mjs                  # 只读验证
 *   node test/win-live.mjs --backup         # 额外真跑一次备份并复查状态（保留目录供集成测试）
 *   node test/win-live.mjs --data-dir=D:\x  # 指定插件数据目录（默认系统临时目录）
 *
 * 环境变量 SG_VERBOSE=1 会打印后端日志。
 */

import { spawnSync } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'
import { promises as fsp } from 'node:fs'

import { createWindowsBackend } from '../lib/win-backend.js'
import { guardPath, guardExists, detectElevation, buildElevatedWrapper } from '../lib/ps.js'

const argv = process.argv.slice(2)
const wantBackup = argv.includes('--backup')
const dataDirArg = argv.find((item) => item.startsWith('--data-dir='))
const dataDir = dataDirArg
  ? path.resolve(dataDirArg.slice('--data-dir='.length))
  : path.join(os.tmpdir(), 'dsh-system-guard-test')

const verbose = process.env.SG_VERBOSE === '1'
const log = {
  info: (message) => {
    if (verbose) process.stdout.write(`      [info] ${message}\n`)
  },
  warn: (message) => process.stdout.write(`      [warn] ${message}\n`),
  error: (message) => process.stdout.write(`      [error] ${message}\n`),
}

const results = []

function fail(message) {
  const error = new Error(message)
  error.assertion = true
  throw error
}

function assert(condition, message) {
  if (!condition) fail(message)
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value)
}

function formatBytes(bytes) {
  const value = Number(bytes) || 0
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GiB`
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MiB`
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KiB`
  return `${value} B`
}

async function check(name, fn) {
  const startedAt = Date.now()
  process.stdout.write(`[ RUN  ] ${name}\n`)
  try {
    const detail = await fn()
    const durationMs = Date.now() - startedAt
    results.push({ name, status: 'PASS', durationMs, detail })
    process.stdout.write(`[ PASS ] ${name}  ${durationMs}ms  ${detail || ''}\n\n`)
    return true
  } catch (error) {
    const durationMs = Date.now() - startedAt
    const message = error && error.message ? error.message : String(error)
    const status = error && error.skip ? 'SKIP' : 'FAIL'
    results.push({ name, status, durationMs, detail: message })
    process.stdout.write(`[ ${status} ] ${name}  ${durationMs}ms  ${message}\n\n`)
    return status !== 'FAIL'
  }
}

const shared = {
  probe: null,
  analysis: null,
  junk: null,
  backupInfo: null,
}

async function main() {
  process.stdout.write('===== dsh-system-guard · Windows 真机只读验证 =====\n')
  process.stdout.write(`时间：${new Date().toISOString()}\n`)
  process.stdout.write(`平台：${process.platform} / ${os.arch()} / Node ${process.version}\n`)
  process.stdout.write(`数据目录：${dataDir}\n`)
  process.stdout.write(`备份实测：${wantBackup ? '开启（--backup，安全写入）' : '关闭（只读）'}\n\n`)

  await fsp.mkdir(dataDir, { recursive: true })

  if (process.platform !== 'win32') {
    process.stdout.write('不是 Windows 平台，无法运行本验证脚本。\n')
    process.exitCode = 2
    return
  }

  const backend = createWindowsBackend({ dataDir, config: {}, log })

  // 1) helper 脚本存在 + UTF-8 BOM（PowerShell 5.1 解析中文必需）
  await check('helper 脚本与 UTF-8 BOM', async () => {
    assert(guardExists(), `找不到 guard.ps1：${guardPath()}`)
    const buffer = await fsp.readFile(guardPath())
    const hasBom = buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf
    assert(hasBom, 'guard.ps1 缺少 UTF-8 BOM（PowerShell 5.1 会按 GBK 解析导致乱码/语法错误）')
    return `${guardPath()} ${(buffer.length / 1024).toFixed(0)} KiB，BOM 正常`
  })

  // 2) 管理员权限检测（真实检测，不是读配置）
  await check('detectElevation', async () => {
    const admin = await detectElevation({ refresh: true })
    shared.admin = admin
    assert(typeof admin === 'boolean', 'detectElevation 应返回布尔值')
    return `admin=${admin}${admin ? '' : '（普通权限，修复类动作会提示需要提权）'}`
  })

  // 3) probe
  await check('probe（系统事实）', async () => {
    const probe = await backend.probe()
    shared.probe = probe
    assert(probe && probe.platform === 'windows', 'probe.platform 应为 windows')
    assert(typeof probe.osName === 'string' && probe.osName.length > 0, 'probe.osName 缺失')
    assert(typeof probe.osVersion === 'string' && probe.osVersion.length > 0, 'probe.osVersion 缺失')
    assert(typeof probe.osBuild === 'string' && probe.osBuild.length > 0, 'probe.osBuild 缺失')
    assert(typeof probe.admin === 'boolean', 'probe.admin 应为布尔值')
    assert(typeof probe.systemRoot === 'string' && probe.systemRoot.length > 0, 'probe.systemRoot 缺失')
    assert(typeof probe.systemDrive === 'string', 'probe.systemDrive 缺失')
    assert(Array.isArray(probe.volumes), 'probe.volumes 应为数组')
    assert(probe.volumes.length > 0, '没有检测到固定磁盘')
    for (const volume of probe.volumes) {
      assert(typeof volume.id === 'string' && volume.id, 'volume.id 缺失')
      assert(typeof volume.fs === 'string' && volume.fs, `volume.fs 缺失（${volume.id}）`)
      assert(isFiniteNumber(volume.totalBytes) && volume.totalBytes > 0, `volume.totalBytes 异常（${volume.id}）`)
      assert(isFiniteNumber(volume.freeBytes) && volume.freeBytes >= 0, `volume.freeBytes 异常（${volume.id}）`)
      assert(typeof volume.isSystem === 'boolean', `volume.isSystem 缺失（${volume.id}）`)
    }
    const tools = probe.tools || {}
    for (const key of ['sfc', 'dism', 'wbadmin', 'vssadmin', 'bcdedit', 'checkpoint', 'takeown', 'icacls']) {
      assert(typeof tools[key] === 'boolean', `probe.tools.${key} 应为布尔值`)
    }
    const window = probe.updateWindow
    if (window !== null && window !== undefined) {
      assert(typeof window.from === 'string' && typeof window.to === 'string', 'probe.updateWindow.from/to 应为 ISO 字符串')
    }
    const biggest = probe.volumes.reduce((best, current) => (current.freeBytes > best.freeBytes ? current : best), probe.volumes[0])
    return `${probe.osName} ${probe.osVersion}（${probe.osBuild}）/${probe.arch} admin=${probe.admin} 盘=${probe.volumes.length} 最大剩余=${biggest.id} ${formatBytes(biggest.freeBytes)} 更新窗口=${window ? `${window.from} ~ ${window.to}` : 'null'} 工具=${Object.entries(tools).filter(([, v]) => v).length}/8`
  })

  // 4) analyze
  await check('analyze（核心清单 + 分类 + 垃圾）', async () => {
    const analysis = await backend.analyze({ files: null })
    shared.analysis = analysis
    assert(analysis && typeof analysis === 'object', 'analyze 无返回值')
    assert(isFiniteNumber(analysis.coreCount) && analysis.coreCount > 0, `coreCount 异常：${analysis.coreCount}`)
    assert(isFiniteNumber(analysis.coreBytes) && analysis.coreBytes > 0, `coreBytes 异常：${analysis.coreBytes}`)
    assert(Array.isArray(analysis.files), 'analysis.files 应为数组')
    assert(analysis.files.length > 0 && analysis.files.length <= 800, `analysis.files 数量异常：${analysis.files.length}`)
    assert(Array.isArray(analysis.groups) && analysis.groups.length >= 8, `垃圾分组数量异常：${analysis.groups ? analysis.groups.length : 'null'}`)
    assert(isFiniteNumber(analysis.totalJunkBytes), 'totalJunkBytes 应为数字')
    assert(analysis.baselineSource === 'builtin', `baselineSource 应为 builtin，实际 ${analysis.baselineSource}`)
    let hashedCore = 0
    for (const file of analysis.files) {
      assert(typeof file.path === 'string' && file.path, 'files[].path 缺失')
      assert(['core', 'support', 'memory', 'junk'].includes(file.role), `files[].role 非法：${file.role}`)
      assert(typeof file.exists === 'boolean', `files[].exists 应为布尔值（${file.path}）`)
      if (file.role === 'core' && file.exists && typeof file.sha256 === 'string' && /^[a-f0-9]{64}$/.test(file.sha256)) hashedCore += 1
      if (file.exists) assert(isFiniteNumber(file.size) && file.size >= 0, `files[].size 异常（${file.path}）`)
    }
    const missingCore = analysis.files.filter((file) => file.role === 'core' && !file.exists).length
    return `核心=${analysis.coreCount}（${hashedCore} 个已算 sha256，${formatBytes(analysis.coreBytes)}）support=${analysis.supportCount}（${formatBytes(analysis.supportBytes)}）files=${analysis.files.length} 分组=${analysis.groups.length} 垃圾=${formatBytes(analysis.totalJunkBytes)} 缺失核心=${missingCore} 耗时=${analysis.durationMs}ms`
  })

  // 5) junk-scan
  await check('junk-scan（垃圾与系统记忆分类）', async () => {
    const report = await backend.junkScan({})
    shared.junk = report
    assert(report && Array.isArray(report.groups), 'junkScan.groups 应为数组')
    assert(report.groups.length >= 8, `垃圾分组数量异常：${report.groups.length}`)
    assert(isFiniteNumber(report.totalBytes) && report.totalBytes >= 0, 'junkScan.totalBytes 应为数字')
    assert(isFiniteNumber(report.junkBytes) && isFiniteNumber(report.memoryBytes), 'junkBytes/memoryBytes 应存在')
    const ids = []
    for (const group of report.groups) {
      assert(typeof group.id === 'string' && group.id, 'group.id 缺失')
      assert(typeof group.title === 'string' && group.title, `group.title 缺失（${group.id}）`)
      assert(['junk', 'memory'].includes(group.kind), `group.kind 非法：${group.kind}`)
      assert(typeof group.note === 'string' && group.note.length > 0, `group.note 缺失（${group.id}）`)
      assert(typeof group.safeToDelete === 'boolean', `group.safeToDelete 应为布尔值（${group.id}）`)
      assert(isFiniteNumber(group.totalBytes) && group.totalBytes >= 0, `group.totalBytes 异常（${group.id}）`)
      assert(isFiniteNumber(group.itemCount) && group.itemCount >= 0, `group.itemCount 异常（${group.id}）`)
      assert(Array.isArray(group.items), `group.items 应为数组（${group.id}）`)
      assert(group.items.length <= 3000, `group.items 超过 3000 条（${group.id}: ${group.items.length}）`)
      if (group.kind === 'memory') {
        assert(group.safeToDelete === false, `系统记忆类必须 safeToDelete=false（${group.id}）`)
      }
      for (const item of group.items) {
        assert(typeof item.path === 'string' && item.path, `items[].path 缺失（${group.id}）`)
        assert(isFiniteNumber(item.size) && item.size >= 0, `items[].size 异常（${group.id}）`)
      }
      ids.push(`${group.id}:${group.itemCount}`)
    }
    const junkBytes = report.groups.filter((group) => group.kind === 'junk').reduce((sum, group) => sum + group.totalBytes, 0)
    assert(junkBytes === report.totalBytes, `totalBytes 应等于可清理垃圾合计（${report.totalBytes} vs ${junkBytes}）`)
    return `分组=${report.groups.length} 可清理=${formatBytes(report.junkBytes)} 系统记忆=${formatBytes(report.memoryBytes)} 明细=${ids.join(' ')}`
  })

  // 6) patrol（用 analyze 的清单当基线；只读）
  await check('patrol（完整性巡查）', async () => {
    assert(shared.analysis, '缺少 analyze 结果，无法巡查')
    const report = await backend.patrol({
      baseline: { files: shared.analysis.files },
      opts: { settings: { excludeUpdateWindowMinutes: 1440 }, updateWindowMinutes: 1440, sfc: false },
    })
    assert(report && typeof report === 'object', 'patrol 无返回值')
    assert(['healthy', 'changed', 'damaged', 'unknown'].includes(report.verdict), `verdict 非法：${report.verdict}`)
    assert(isFiniteNumber(report.total) && report.total > 0, `patrol.total 异常：${report.total}`)
    assert(Array.isArray(report.changed), 'patrol.changed 应为数组')
    assert(Array.isArray(report.missing), 'patrol.missing 应为数组')
    assert(report.sfc && report.sfc.ran === false, 'patrol 默认不应跑 sfc')
    for (const item of report.changed) {
      assert(typeof item.path === 'string', 'changed[].path 缺失')
      assert(typeof item.exempted === 'boolean', 'changed[].exempted 应为布尔值')
      if (item.exempted) assert(item.reason === 'windows-update-window', '豁免原因应为 windows-update-window')
    }
    return `核定=${report.total} 未变=${report.unchanged} 变化=${report.changed.length} 缺失=${report.missing.length} 结论=${report.verdict} 备份=${report.backup ? report.backup.state : 'null'} 耗时=${report.durationMs}ms`
  })

  // 7) calibrate-facts
  await check('calibrate-facts（校准输入）', async () => {
    const facts = await backend.calibrateFacts({})
    assert(facts && facts.platform === 'windows', 'facts.platform 应为 windows')
    assert(typeof facts.osName === 'string' && facts.osName, 'facts.osName 缺失')
    assert(Array.isArray(facts.files), 'facts.files 应为数组')
    assert(facts.files.length > 0 && facts.files.length <= 80, `facts.files 数量异常：${facts.files.length}`)
    for (const file of facts.files) {
      assert(typeof file.path === 'string' && file.path, 'facts.files[].path 缺失')
      assert(typeof file.sha256 === 'string' && /^[a-f0-9]{64}$/.test(file.sha256), `facts.files[].sha256 非法（${file.path}）`)
    }
    return `文件=${facts.files.length} 版本=${facts.osVersion} 首项=${path.basename(facts.files[0].path)}`
  })

  // 8) backup-status（只读）
  await check('backup-status（备份状态）', async () => {
    const status = await backend.backupStatus()
    assert(status && ['ok', 'none', 'missing', 'partial'].includes(status.state), `state 非法：${status && status.state}`)
    return `state=${status.state} root=${status.root || 'null'} 文件=${status.fileCount} 大小=${formatBytes(status.totalBytes)}`
  })

  // 9) AbortSignal 中止
  await check('AbortSignal 中止（junk-scan）', async () => {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 120)
    const startedAt = Date.now()
    try {
      const report = await backend.junkScan({ signal: controller.signal })
      // 机器极快、扫描在 abort 之前就完成：这不算失败，只是没验证到中止路径
      const error = new Error(`扫描在 abort 之前完成（${Date.now() - startedAt}ms，${report.groups.length} 组），本次未触发中止路径`)
      error.skip = true
      throw error
    } catch (error) {
      if (error.skip) throw error
      assert(error && error.code === 'aborted', `期望 code=aborted，实际 ${error && error.code}`)
      return `已在 ${Date.now() - startedAt}ms 中止，code=aborted`
    } finally {
      clearTimeout(timer)
    }
  })

  // 10) 提权包装脚本：只做语法校验，不真的弹 UAC
  await check('提权包装脚本语法（不弹 UAC）', async () => {
    const stamp = Date.now()
    const outFile = path.join(os.tmpdir(), `sg-elev-syntax-${stamp}.json`)
    const wrapperPath = path.join(os.tmpdir(), `sg-elev-syntax-${stamp}.ps1`)
    const wrapper = buildElevatedWrapper({ action: 'probe', outFile, paramsFile: '', timeoutSec: 0 })
    assert(/-Verb RunAs/.test(wrapper), '包装脚本缺少 -Verb RunAs')
    assert(/-Wait/.test(wrapper), '包装脚本缺少 -Wait（要等提权进程结束）')
    assert(/-WindowStyle Hidden/.test(wrapper), '包装脚本缺少隐藏窗口')
    assert(/Start-Process/.test(wrapper), '包装脚本没有用 Start-Process')
    // 带 BOM 落盘，再用 PowerShell 解析器校验语法（只解析，不执行）
    await fsp.writeFile(wrapperPath, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(wrapper, 'utf8')]))
    const parseScript = [
      '$err = $null; $tok = $null;',
      `[System.Management.Automation.Language.Parser]::ParseFile('${wrapperPath.replace(/'/g, "''")}', [ref]$tok, [ref]$err) | Out-Null;`,
      'if (@($err).Count -gt 0) { Write-Output $err[0].Message; exit 1 } else { Write-Output ok; exit 0 }',
    ].join(' ')
    const run = spawnSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', parseScript],
      { encoding: 'utf8', windowsHide: true, timeout: 30_000 },
    )
    await fsp.rm(wrapperPath, { force: true }).catch(() => {})
    assert(run.status === 0, `包装脚本语法错误：${(run.stdout || '').trim()} ${(run.stderr || '').trim()}`)
    return '语法通过，RunAs / -Wait / Hidden 齐全（真机 UAC 未执行）'
  })

  // 11) patrol 判定自测：用自己造的临时文件验证 healthy / changed / damaged / 豁免
  await check('patrol 判定自测（临时文件）', async () => {
    const { createHash } = await import('node:crypto')
    const dir = path.join(dataDir, 'patrol-selftest')
    await fsp.mkdir(dir, { recursive: true })
    const file = path.join(dir, 'sample.bin')
    const sha = (buffer) => createHash('sha256').update(buffer).digest('hex')
    const contentA = Buffer.alloc(100, 65)
    await fsp.writeFile(file, contentA)
    const baseline = [{ path: file, sha256: sha(contentA), size: 100, role: 'core' }]
    const opts = { settings: {}, updateWindowMinutes: 1440 }
    const same = await backend.patrol({ baseline, opts })
    await fsp.writeFile(file, Buffer.alloc(100, 66))
    const changed = await backend.patrol({ baseline, opts })
    await fsp.writeFile(file, Buffer.alloc(101, 66))
    const resized = await backend.patrol({ baseline, opts })
    await fsp.rm(file, { force: true })
    const missing = await backend.patrol({ baseline, opts })
    await fsp.writeFile(file, contentA)
    const now = new Date()
    await fsp.utimes(file, now, now)
    const window = {
      from: new Date(now.getTime() - 2 * 3600 * 1000).toISOString(),
      to: now.toISOString(),
    }
    const exempted = await backend.patrol({
      baseline: [{ path: file, sha256: '0'.repeat(64), size: 100, role: 'core' }],
      opts: { settings: {}, updateWindow: window },
    })
    await fsp.rm(dir, { recursive: true, force: true })
    assert(same.verdict === 'healthy' && same.unchanged === 1, `相同内容判定错误：${same.verdict}`)
    assert(changed.verdict === 'changed' && changed.changed.length === 1, `同大小改写应为 changed，实际 ${changed.verdict}`)
    assert(changed.changed[0].exempted === false, '非更新窗口内的变化不应豁免')
    assert(resized.verdict === 'damaged', `大小变化应为 damaged，实际 ${resized.verdict}`)
    assert(missing.verdict === 'damaged' && missing.missing.length === 1, `缺失应为 damaged，实际 ${missing.verdict}`)
    assert(exempted.verdict === 'healthy', `更新窗口内变化应豁免为 healthy，实际 ${exempted.verdict}`)
    assert(exempted.changed.length === 1 && exempted.changed[0].exempted === true, '豁免标记缺失')
    assert(exempted.changed[0].reason === 'windows-update-window', '豁免原因错误')
    return 'healthy / changed / damaged / missing / 豁免 均符合契约'
  })

  // 12) 提权动作门控：非管理员时必须立刻返回 need-elevation，且绝不偷偷弹 UAC
  await check('提权动作门控（不弹 UAC）', async () => {
    if (shared.admin) {
      const skip = new Error('当前进程已是管理员，跳过提权门控测试（避免真的执行 sfc/dism）')
      skip.skip = true
      throw skip
    }
    const results = [
      await backend.repair({ mode: 'sfc' }),
      await backend.repair({ mode: 'dism' }),
      await backend.repair({ mode: 'restore-point' }),
      await backend.restorePoint(),
      await backend.restore({ paths: ['C:\\Windows\\System32\\ntdll.dll'] }),
    ]
    for (const result of results) {
      assert(result.ok === false, '非管理员时提权动作必须失败')
      assert(
        result.error && result.error.code === 'need-elevation',
        `期望 need-elevation，实际 ${result.error && result.error.code}`,
      )
    }
    const invalid = await backend.repair({ mode: '不是模式' })
    assert(invalid.error && invalid.error.code === 'invalid-params', '未知修复模式应报 invalid-params')
    return 'sfc / dism / restore-point / restore / restorePoint 均返回 need-elevation，未弹 UAC'
  })

  // 13) 删除白名单：不在垃圾分类目录里的路径必须拒绝（不会真的删除）
  await check('删除白名单拒绝', async () => {
    const result = await backend.junkDelete({ items: [{ path: 'C:\\Windows\\System32\\ntoskrnl.exe' }] })
    assert(Array.isArray(result.deleted) && result.deleted.length === 0, '不该删除白名单外的路径')
    assert(Array.isArray(result.failed) && result.failed.length === 1, '应返回一条拒绝记录')
    assert(result.failed[0].error === 'not-allowed', `期望 not-allowed，实际 ${result.failed[0].error}`)
    return '系统目录路径被拒绝（not-allowed），未执行任何删除'
  })

  // 14) 配置热更新
  await check('updateConfig', async () => {
    assert(typeof backend.updateConfig === 'function', 'backend 缺少 updateConfig')
    const next = backend.updateConfig({ junkMaxItems: 500, keepQuarantineDays: 3, excludeUpdateWindowMinutes: 720 })
    assert(next.junkMaxItems === 500, `junkMaxItems 未生效：${next.junkMaxItems}`)
    assert(next.excludeUpdateWindowMinutes === 720, `excludeUpdateWindowMinutes 未生效：${next.excludeUpdateWindowMinutes}`)
    assert(next.keepQuarantineDays === 3, `keepQuarantineDays 未生效：${next.keepQuarantineDays}`)
    backend.updateConfig({ junkMaxItems: 3000, keepQuarantineDays: 7, excludeUpdateWindowMinutes: 1440 })
    return `热更新生效：junkMaxItems=${next.junkMaxItems} excludeUpdateWindowMinutes=${next.excludeUpdateWindowMinutes} keepQuarantineDays=${next.keepQuarantineDays}`
  })

  // 15) 备份实测（仅 --backup）
  if (wantBackup) {
    await check('backup（真实备份到最大剩余盘）', async () => {
      const info = await backend.backup({ files: shared.analysis ? shared.analysis.files : [] })
      shared.backupInfo = info
      assert(info && typeof info.root === 'string' && info.root, 'backup.root 缺失')
      assert(info.fileCount > 0, `备份文件数为 0：${info.fileCount}`)
      assert(info.totalBytes > 0, `备份大小异常：${info.totalBytes}`)
      assert(info.state === 'ok' || info.state === 'partial', `备份 state 异常：${info.state}`)
      assert(info.hidden === true, '备份目录应为隐藏目录')
      assert(typeof info.manifestPath === 'string' && info.manifestPath, 'manifestPath 缺失')
      const manifestText = await fsp.readFile(info.manifestPath, 'utf8')
      const manifest = JSON.parse(manifestText)
      assert(Array.isArray(manifest.files) && manifest.files.length === info.fileCount, 'manifest.files 数量与 fileCount 不一致')
      for (const file of manifest.files) {
        assert(/^[a-f0-9]{64}$/.test(file.sha256 || ''), `manifest 里 ${file.path} 的 sha256 非法`)
        assert(isFiniteNumber(file.size) && file.size >= 0, `manifest 里 ${file.path} 的 size 非法`)
        assert(typeof file.rel === 'string' && file.rel, `manifest 里 ${file.path} 缺少 rel`)
      }
      return `root=${info.root} 盘=${info.volume} 文件=${info.fileCount} 大小=${formatBytes(info.totalBytes)} 隐藏=${info.hidden} ACL=${info.aclProtected} 耗时=${info.durationMs}ms`
    })

    await check('backup-status（复查刚做的备份）', async () => {
      assert(shared.backupInfo, '没有备份结果可复查')
      const status = await backend.backupStatus()
      assert(status.state === 'ok', `刚备份完应为 ok，实际 ${status.state}`)
      assert(status.fileCount > 0, '备份文件数为 0')
      assert(Array.isArray(status.missingFiles) && status.missingFiles.length === 0, `备份里有缺失文件：${status.missingFiles}`)
      return `state=${status.state} root=${status.root} 文件=${status.fileCount} 大小=${formatBytes(status.totalBytes)} 校验哈希数=${status.hashChecked}`
    })

    await check('备份目录保留（供集成测试）', async () => {
      assert(shared.backupInfo, '没有备份结果')
      const stat = await fsp.stat(shared.backupInfo.root)
      assert(stat.isDirectory(), '备份目录不存在')
      return `保留路径：${shared.backupInfo.root}（本次不清理）`
    })
  }

  await backend.dispose()

  // 汇总
  const total = results.length
  const passed = results.filter((item) => item.status === 'PASS').length
  const skipped = results.filter((item) => item.status === 'SKIP').length
  const failed = results.filter((item) => item.status === 'FAIL')
  const totalMs = results.reduce((sum, item) => sum + item.durationMs, 0)
  process.stdout.write('===== 汇总 =====\n')
  process.stdout.write(`PASS ${passed} / FAIL ${failed.length} / SKIP ${skipped} / 共 ${total} 项，累计耗时 ${(totalMs / 1000).toFixed(1)}s\n`)
  if (failed.length > 0) {
    for (const item of failed) process.stdout.write(`  FAIL: ${item.name} — ${item.detail}\n`)
    process.exitCode = 1
  }
  if (shared.backupInfo) {
    process.stdout.write(`备份目录（已保留，可删）：${shared.backupInfo.root}\n`)
  }
  process.stdout.write('只读验证未执行：junk-delete / repair / restore-point（需要提权或会改动系统，按约定不在此脚本执行）\n')
}

main().catch((error) => {
  process.stdout.write(`\n验证脚本异常退出：${error && error.stack ? error.stack : String(error)}\n`)
  process.exitCode = 1
})

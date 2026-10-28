#!/usr/bin/env node
/**
 * 生成 CycloneDX 1.5 SBOM（零第三方依赖，纯 Node 内置模块，不联网）。
 *
 * 用途：满足《代码安全防御架构规则》F-04（每次发布必须生成并归档 SBOM）。
 * 本项目零第三方依赖：components 固定为空数组，metadata.component 记录本体与许可证；
 * files 属性记录随包发布的每个文件的 SHA-256，便于安装后逐文件核对。
 *
 * 用法：node scripts/build-sbom.mjs [输出路径]
 */

import { createHash } from 'node:crypto'
import { readFile, writeFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const PLUGIN_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const OUT = process.argv[2] || path.join(PLUGIN_DIR, 'sbom.cdx.json')

/** 递归收集仓库内发布相关文件（跳过 node_modules / .git / dist / 测试）。 */
async function walk(dir, prefix = '') {
  const result = []
  const entries = await readdir(dir, { withFileTypes: true })
  for (const entry of entries) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'dist', 'test'].includes(entry.name)) continue
      result.push(...(await walk(path.join(dir, entry.name), relative)))
    } else if (/\.(js|mjs|json|ps1|md|svg|yml)$/.test(entry.name)) {
      result.push(relative)
    }
  }
  return result.sort()
}

const files = await walk(PLUGIN_DIR)
const pkg = JSON.parse(await readFile(path.join(PLUGIN_DIR, 'package.json'), 'utf8'))
const properties = []
for (const file of files) {
  if (file === 'sbom.cdx.json') continue
  const buffer = await readFile(path.join(PLUGIN_DIR, file))
  const sha256 = createHash('sha256').update(buffer).digest('hex')
  properties.push({ name: `file:${file}`, value: sha256 })
}

const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [{ vendor: 'dsh-system-guard', name: 'build-sbom', version: pkg.version }],
    component: {
      type: 'application',
      name: pkg.name,
      version: pkg.version,
      description: typeof pkg.description === 'string' ? pkg.description.slice(0, 400) : '',
      licenses: [{ license: { id: 'MIT' } }],
      externalReferences: pkg.repository && pkg.repository.url
        ? [{ type: 'vcs', url: String(pkg.repository.url).replace(/^git\+/, '') }]
        : [],
    },
  },
  components: [],
  dependencies: [{ ref: `${pkg.name}@${pkg.version}`, dependsOn: [] }],
  properties,
}

await writeFile(OUT, `${JSON.stringify(sbom, null, 2)}\n`, 'utf8')
console.log(`SBOM 已生成：${OUT}（${files.length} 个文件，零第三方依赖）`)

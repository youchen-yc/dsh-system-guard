#!/usr/bin/env node
/**
 * 系统守护 · 封存脚本。
 *
 * 生成 `integrity.json`：记录插件核心文件（index.js / client.js / lib/*.js /
 * scripts/*.ps1 / package.json / locale/*.json）的 SHA-256。
 *
 * 运行时 lib/privilege.js 的 selfCheck() 会用它对核心代码做自校验：
 * 被改动或缺失就不允许执行任何写系统操作，并在面板上告警。
 *
 * 用法（在插件目录下）：node scripts/seal.mjs
 */

import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { writeFile } from 'node:fs/promises'

import { buildIntegrityManifest } from '../lib/privilege.js'

const pluginDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const manifest = await buildIntegrityManifest({ pluginDir })
const target = path.join(pluginDir, 'integrity.json')
await writeFile(target, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
const count = Object.keys(manifest.files).length
console.log(`已封存 ${count} 个核心文件 → ${target}`)

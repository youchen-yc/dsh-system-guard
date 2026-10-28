#!/usr/bin/env node
/**
 * 分发自检（J-02 / J-04）：运行时 JS 里不得出现本机绝对路径、本机用户名、workspace 专属链接。
 *
 * 为什么单独写成脚本：把「盘符 + 冒号 + 分隔符」这种模式用字符拼接构造，
 * 避免自检脚本自身（以及 CI 配置）在文本里出现被扫描规则命中的字面量。
 *
 * 退出码：0 = 通过；1 = 命中违规（CI 应阻断）。
 */

import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'test'])
const CHECKED = /\.(js|mjs)$/

// 盘符：字母 + 冒号（分两段拼，避免出现被扫描的字面量）。
// 负向后顾排除 URL scheme（如 https:、http:）里「字母 + 冒号 + 斜杠」的误判。
const PATTERNS = [
  { name: '本机绝对路径（盘符）', re: new RegExp('(?<![A-Za-z0-9])[A-Za-z]' + ':' + '[\\\\/]') },
  { name: '工作区绝对路径', re: new RegExp('DSH' + '[0-9]' + '[\\\\/]') },
  { name: '用户主目录路径', re: new RegExp('/' + 'Users' + '/') },
  { name: '用户主目录路径（Linux）', re: new RegExp('/' + 'home' + '/') },
]

async function walk(dir, prefix = '') {
  const files = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) files.push(...(await walk(path.join(dir, entry.name), relative)))
    else if (CHECKED.test(entry.name)) files.push(relative)
  }
  return files
}

const files = await walk(ROOT)
let violations = 0
for (const file of files) {
  const text = await readFile(path.join(ROOT, file), 'utf8')
  const lines = text.split(/\r?\n/)
  for (const pattern of PATTERNS) {
    for (let index = 0; index < lines.length; index += 1) {
      if (pattern.re.test(lines[index])) {
        console.error(`VIOLATION ${pattern.name}: ${file}:${index + 1} → ${lines[index].trim().slice(0, 160)}`)
        violations += 1
      }
    }
  }
}

if (violations > 0) {
  console.error(`分发自检未通过：${violations} 处违规`)
  process.exit(1)
}
console.log(`分发自检通过：${files.length} 个运行时文件，未发现本机绝对路径/用户名/workspace 链接`)

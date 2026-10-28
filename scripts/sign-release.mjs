#!/usr/bin/env node
/**
 * 发布产物签名（Ed25519，Node 内置 crypto，零依赖）。
 *
 * 用途：满足 F-03「发布产物必须签名，构建后与发布前分别校验签名一致」。
 * - 私钥保存在插件数据目录（`$DSH_HOME/system-guard/release-ed25519.pem`），
 *   **不入仓库、不进发布包**（密钥与产物分离）；
 * - 公钥导出到 `keys/release.pub`（随仓库发布，供用户验证）；
 * - 对 dist/*.tgz 生成 detached 签名 `<tgz>.sig`（base64），并打印验证命令。
 *
 * 用法：
 *   node scripts/sign-release.mjs                    # 首次自动生成密钥并签名 dist 下所有 tgz
 *   node scripts/sign-release.mjs --verify-only      # 只校验已有签名（CI 用）
 */

import { createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { readFile, writeFile, readdir, mkdir } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const PLUGIN_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const DIST_DIR = path.join(PLUGIN_DIR, 'dist')
const KEYS_DIR = path.join(PLUGIN_DIR, 'keys')
const PUB_PATH = path.join(KEYS_DIR, 'release.pub')
const dataDir = process.env.DSH_HOME
  ? path.join(process.env.DSH_HOME, 'system-guard')
  : path.join(os.homedir(), '.dsh', 'system-guard')
const PRIV_PATH = path.join(dataDir, 'release-ed25519.pem')
const verifyOnly = process.argv.includes('--verify-only')

async function ensureKeyPair() {
  await mkdir(dataDir, { recursive: true })
  await mkdir(KEYS_DIR, { recursive: true })
  try {
    const pem = await readFile(PRIV_PATH, 'utf8')
    const privateKey = createPrivateKey(pem)
    return { privateKey, publicKey: createPublicKey(privateKey) }
  } catch {
    if (verifyOnly) return null
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    await writeFile(PRIV_PATH, privateKey.export({ type: 'pkcs8', format: 'pem' }), { encoding: 'utf8', mode: 0o600 })
    await writeFile(PUB_PATH, publicKey.export({ type: 'spki', format: 'pem' }), 'utf8')
    console.log(`已生成发布密钥：私钥 ${PRIV_PATH}（不入库）· 公钥 ${PUB_PATH}`)
    return { privateKey, publicKey }
  }
}

const pair = await ensureKeyPair()
if (!pair) {
  console.log('未找到私钥，跳过签名（只做校验的环境属正常）')
  process.exit(0)
}

const entries = (await readdir(DIST_DIR).catch(() => [])).filter((name) => name.endsWith('.tgz')).sort()
if (entries.length === 0) {
  console.log('dist/ 下没有 tgz，先 npm pack 再签名')
  process.exit(0)
}

let failed = 0
for (const name of entries) {
  const filePath = path.join(DIST_DIR, name)
  const sigPath = `${filePath}.sig`
  const buffer = await readFile(filePath)
  if (verifyOnly) {
    let sig
    try {
      sig = await readFile(sigPath, 'utf8')
    } catch {
      console.warn(`缺少签名：${name}`)
      failed += 1
      continue
    }
    const ok = verify(null, buffer, pair.publicKey, Buffer.from(sig.trim(), 'base64'))
    console.log(`${ok ? 'PASS' : 'FAIL'} 签名校验 ${name}`)
    if (!ok) failed += 1
  } else {
    const signature = sign(null, buffer, pair.privateKey)
    await writeFile(sigPath, `${signature.toString('base64')}\n`, 'utf8')
    const sha256 = createHash('sha256').update(buffer).digest('hex')
    console.log(`已签名 ${name}`)
    console.log(`  sha256: ${sha256}`)
    console.log(`  签名:   ${sigPath}`)
  }
}

if (failed > 0) process.exit(1)
console.log(verifyOnly ? '全部签名校验通过' : '签名完成；验证命令：node scripts/sign-release.mjs --verify-only')

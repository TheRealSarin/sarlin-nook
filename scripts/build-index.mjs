import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

import { buildGatedIndex, formatHealth, formatMeta, formatQuarantine, parseApprovals, parseYanked } from './gate.mjs'
import { formatCatalogue, listRemoteVersions, parseIndex, readEntries } from './lib.mjs'
import { ROOT, loadPolicy } from './policy.mjs'
import { compileCheck, scanPackage } from './scan.mjs'

const run = promisify(execFile)

function option(name) {
  const position = process.argv.indexOf(name)
  return position === -1 ? undefined : process.argv[position + 1]
}

async function readOptional(path, fallback) {
  if (!path) return fallback
  try {
    return await readFile(path, 'utf8')
  } catch (error) {
    if (error.code === 'ENOENT') return fallback
    throw error
  }
}

async function readJson(path, fallback) {
  const text = await readOptional(path, null)
  if (text === null) return fallback
  try {
    return JSON.parse(text)
  } catch {
    return fallback
  }
}

async function compilerVersion(sarlinPath) {
  const { stdout } = await run(sarlinPath, ['--version'])
  return stdout.trim().split(/\s+/).at(-1)
}

const outputDirectory = option('--output') ?? join(ROOT, 'out')
const sarlinPath = option('--sarlin') ?? process.env.SARLIN_BIN
if (!sarlinPath) {
  console.error('error: pass --sarlin <path> or set SARLIN_BIN; new versions cannot be published without the security scan')
  process.exit(1)
}

const policy = await loadPolicy(option('--policy'))
const previous = parseIndex(await readOptional(option('--previous'), ''))
const previousQuarantine = await readJson(option('--previous-quarantine'), [])
const previousHealth = await readJson(option('--previous-health'), [])
const previousCatalogue = await readJson(option('--previous-catalogue'), [])
const previousMeta = await readJson(option('--previous-meta'), null)
const approvals = parseApprovals(await readOptional(option('--approvals') ?? join(ROOT, 'approvals.txt'), ''))
const yanked = parseYanked(await readOptional(option('--yanked') ?? join(ROOT, 'yanked.txt'), ''))

const { entries, problems } = await readEntries(option('--packages') ?? join(ROOT, 'packages'))
if (problems.length > 0) {
  for (const problem of problems) console.error(`error: ${problem}`)
  process.exit(1)
}

const compiler = await compilerVersion(sarlinPath)
const workDirectory = await mkdtemp(join(tmpdir(), 'nook-build-'))
try {
  const built = await buildGatedIndex({
    entries,
    previous,
    previousQuarantine,
    previousHealth,
    previousCatalogue,
    previousMeta,
    approvals,
    yanked,
    policy,
    compiler,
    resolveVersions: listRemoteVersions,
    scan: (options) => scanPackage({ ...options, sarlinPath, policy, workDir: workDirectory }),
    health: (options) => compileCheck({ ...options, sarlinPath, policy, workDir: workDirectory }),
  })
  for (const warning of built.warnings) console.warn(`warning: ${warning}`)
  for (const item of built.newlyQuarantined) console.warn(`quarantined ${item.name} ${item.version} (${item.severity})`)
  for (const item of built.overridden) console.log(`approved ${item.name} ${item.version}`)

  await mkdir(outputDirectory, { recursive: true })
  await writeFile(join(outputDirectory, 'index.txt'), built.indexText)
  await writeFile(join(outputDirectory, 'index.txt.sha256'), built.indexChecksum)
  await writeFile(join(outputDirectory, 'packages.json'), formatCatalogue(built.packages))
  await writeFile(join(outputDirectory, 'quarantine.json'), formatQuarantine(built.quarantine))
  await writeFile(join(outputDirectory, 'health.json'), formatHealth(built.health))
  await writeFile(join(outputDirectory, 'meta.json'), formatMeta(built.meta))
  await writeFile(join(outputDirectory, 'unavailable.json'), `${JSON.stringify(built.unavailableRepositories, null, 2)}\n`)
  console.log(`indexed ${built.meta.packages} package(s) with ${built.meta.versions} version(s), ${built.quarantine.length} held back (generation ${built.meta.generation})`)
} finally {
  await rm(workDirectory, { recursive: true, force: true })
}

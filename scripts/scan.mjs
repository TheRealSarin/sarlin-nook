import { execFile } from 'node:child_process'
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

import {
  analyzeSource,
  applyChecks,
  checkClones,
  checkDangerousRemovals,
  checkDependencyGraph,
  checkForeignCode,
  checkHiddenCharacters,
  checkHygiene,
  checkIdentifiers,
  checkLicense,
  checkObfuscation,
  checkPathNames,
  checkProject,
  checkRequires,
  checkSecrets,
  checkSensitiveStrings,
  collectCapabilities,
  finding,
  isSourcePath,
  listExternals,
  normalisedSourceHashes,
  parseCollisionOutput,
  parseProjectFile,
  repositoryOwner,
  sanitize,
} from './checks.mjs'
import {
  checkCapabilityEscalation,
  checkHistoryFacts,
  checkVersionSanity,
  git,
  gitEnvironment,
  inspectHistory,
  newestVersion,
  compareVersions,
} from './history.mjs'

const run = promisify(execFile)

const MAGIC = {
  png: [[0x89, 0x50, 0x4e, 0x47]],
  jpg: [[0xff, 0xd8, 0xff]],
  jpeg: [[0xff, 0xd8, 0xff]],
  gif: [[0x47, 0x49, 0x46, 0x38]],
  webp: [[0x52, 0x49, 0x46, 0x46]],
  ico: [[0, 0, 1, 0]],
  bmp: [[0x42, 0x4d]],
  ttf: [[0, 1, 0, 0], [0x74, 0x72, 0x75, 0x65]],
  otf: [[0x4f, 0x54, 0x54, 0x4f]],
  woff: [[0x77, 0x4f, 0x46, 0x46]],
  woff2: [[0x77, 0x4f, 0x46, 0x32]],
}

const LICENSE_FILE = /^(LICEN[SC]E|COPYING)(\.[A-Za-z]+)?$/i
const MAIN_FUNCTION = /^\s*func\s+main\s*\(/m
const MAXIMUM_TEXT_BYTES = 4 * 1024 * 1024

export async function runSarlin(sarlinPath, args, { cwd, env, policy }) {
  const timeout = (policy.sarlinTimeoutSeconds ?? 60) * 1000
  try {
    const { stdout, stderr } = await run(sarlinPath, args, {
      cwd,
      env,
      timeout,
      killSignal: 'SIGKILL',
      maxBuffer: policy.sarlinOutputCapBytes ?? 262144,
    })
    return { code: 0, output: `${stdout}${stderr}`, timedOut: false }
  } catch (error) {
    const output = `${error.stdout ?? ''}${error.stderr ?? ''}`
    if (error.code === 'ENOENT') throw new Error(`the sarlin binary '${sarlinPath}' was not found`)
    const truncated = error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
    return {
      code: typeof error.code === 'number' ? error.code : -1,
      output: truncated ? `${output}\n(output truncated)` : output,
      timedOut: error.killed === true && !truncated,
    }
  }
}

export async function createNook(directory, lines) {
  await mkdir(directory, { recursive: true })
  await git(['init', '--quiet', '-b', 'index'], { cwd: directory })
  await writeFile(join(directory, 'index.txt'), `nook-index 1\n${lines.join('\n')}\n`)
  await git(['add', 'index.txt'], { cwd: directory })
  const committed = await git(
    ['-c', 'user.name=nook', '-c', 'user.email=nook@invalid.test', 'commit', '--quiet', '-m', 'index'],
    { cwd: directory },
  )
  if (!committed.ok) throw new Error(`could not create the temporary index: ${committed.stderr}`)
}

export function indexLines(listedPackages, extra = []) {
  const lines = []
  const skip = new Set(extra.map((item) => item.name))
  for (const item of listedPackages) {
    if (skip.has(item.name)) continue
    for (const { version, commit } of item.versions ?? []) {
      lines.push(`${item.name} ${version} ${item.repository} ${commit}`)
    }
  }
  for (const item of extra) lines.push(`${item.name} ${item.version} ${item.repository} ${item.commit}`)
  return lines
}

export function packageDirectory(home, name, version, commit) {
  return join(home, 'packages', `${name}-${version}-${commit.slice(0, 12)}`)
}

export function checkEntries(entries, policy) {
  const findings = []
  const files = entries.filter((item) => item.type === 'file')
  for (const item of entries) {
    if (item.type === 'symlink') findings.push(finding('symlink', `${JSON.stringify(item.path)} is a symbolic link`))
    if (item.type === 'submodule') findings.push(finding('submodule', `${JSON.stringify(item.path)} is a git submodule`))
  }
  if (files.length > policy.maximumFileCount) {
    findings.push(finding('file-count', `the package has ${files.length} files; the limit is ${policy.maximumFileCount}`))
  }
  const bytes = files.reduce((sum, item) => sum + item.size, 0)
  if (bytes > policy.maximumPackageBytes) {
    findings.push(finding('package-size', `the package is ${bytes} bytes; the limit is ${policy.maximumPackageBytes}`))
  }
  findings.push(...checkPathNames(entries.map((item) => item.path)))
  return findings
}

export function checkBinary({ path, size, bytes, policy }) {
  const extension = path.includes('.') ? path.split('.').pop().toLowerCase() : ''
  const allowed = policy.allowedBinaryExtensions.includes(extension)
  const head = bytes.subarray(0, 8192)
  const binary = head.includes(0)
  if (allowed) {
    const signatures = MAGIC[extension] ?? []
    const matches = signatures.some((signature) => signature.every((value, index) => head[index] === value))
    if (!matches) return [finding('binary-file', `${JSON.stringify(path)} does not look like a .${extension} file`)]
    if (size > policy.maximumBinaryBytes) {
      return [finding('binary-file', `${JSON.stringify(path)} is ${size} bytes; binary files may be at most ${policy.maximumBinaryBytes}`)]
    }
    return []
  }
  if (binary) return [finding('binary-file', `${JSON.stringify(path)} is a binary file that is not an image or font`)]
  return []
}

async function walkDirectory(root) {
  const entries = []
  const visit = async (relative) => {
    const names = await readdir(join(root, relative))
    for (const name of names.sort()) {
      if (relative === '' && name === '.git') continue
      const path = relative === '' ? name : `${relative}/${name}`
      const info = await lstat(join(root, path))
      if (info.isSymbolicLink()) {
        entries.push({ path, type: 'symlink', size: 0 })
      } else if (info.isDirectory()) {
        entries.push({ path: `${path}/`, type: 'dir', size: 0 })
        if (entries.length > 20000) return
        await visit(path)
      } else if (info.isFile()) {
        entries.push({ path, type: 'file', size: info.size })
      } else {
        entries.push({ path, type: 'symlink', size: 0 })
      }
    }
  }
  await visit('')
  return entries
}

function countLines(files) {
  return files.filter((file) => isSourcePath(file.path)).reduce((sum, file) => sum + file.text.split('\n').length, 0)
}

async function readPackage(root, entries, policy) {
  const blocked = []
  const files = []
  const regular = entries.filter((item) => item.type === 'file')
  const bytes = regular.reduce((sum, item) => sum + item.size, 0)
  const tooBig = regular.length > policy.maximumFileCount || bytes > policy.maximumPackageBytes
  if (tooBig) return { files, blocked }
  for (const item of regular) {
    const buffer = await readFile(join(root, item.path))
    const binaryFindings = checkBinary({ path: item.path, size: item.size, bytes: buffer, policy })
    blocked.push(...binaryFindings)
    const isBinary = buffer.subarray(0, 8192).includes(0)
    files.push({ path: item.path, text: isBinary || buffer.length > MAXIMUM_TEXT_BYTES ? null : buffer.toString('utf8') })
  }
  return { files, blocked }
}

function firstLines(output, count = 4) {
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, count)
    .map((line) => sanitize(line, 240))
    .join(' / ')
}

async function readDependencies(directory) {
  try {
    return parseProjectFile(await readFile(join(directory, 'sarlin.project'), 'utf8')).requires
  } catch {
    return null
  }
}

async function readHashes(directory) {
  const hashes = new Set()
  const entries = await walkDirectory(directory).catch(() => [])
  const files = []
  for (const item of entries) {
    if (item.type !== 'file' || !isSourcePath(item.path) || item.size > MAXIMUM_TEXT_BYTES) continue
    files.push({ path: item.path, text: await readFile(join(directory, item.path), 'utf8') })
  }
  for (const hash of normalisedSourceHashes(files)) hashes.add(hash)
  return hashes
}

async function crossPackageChecks({ entry, version, commit, listedPackages, sarlinPath, policy, environment, scratch, home }) {
  const result = { findings: [], incompatibleWith: [], graph: new Map(), newest: new Map(), others: [] }
  const others = listedPackages.filter((item) => item.name !== entry.name && item.versions?.length > 0)
  for (const item of listedPackages) {
    if (item.versions?.length > 0) result.newest.set(item.name, newestVersion(item.versions.map((v) => v.version)))
  }
  if (others.length === 0) return result
  const newestOf = (item) => item.versions.find((v) => v.version === result.newest.get(item.name))
  const nook = join(scratch, 'nook-all')
  await createNook(nook, indexLines(listedPackages, [{ name: entry.name, version, repository: entry.repository, commit }]))
  const project = join(scratch, 'project-all')
  await mkdir(join(project, 'source'), { recursive: true })
  const requires = [`require: ${entry.name} ${version}`, ...others.map((item) => `require: ${item.name} ${newestOf(item).version}`)]
  await writeFile(join(project, 'sarlin.project'), `name: nook_scan_all\nentry: source/main.sar\nlanguage: 1\n${requires.join('\n')}\n`)
  await writeFile(join(project, 'source', 'main.sar'), 'func main() {\n}\n')
  const env = { ...environment, SARLIN_NOOK_INDEX: nook }
  const collisions = await runSarlin(sarlinPath, ['collisions', project], { cwd: scratch, env, policy })
  const found = parseCollisionOutput(collisions.output, `${entry.name} ${version}`)
  const comprehensible = /no collisions found|collision/.test(collisions.output)
  if (collisions.timedOut || !comprehensible) {
    result.findings.push(
      finding('collision-check-skipped', `the collision check against other listed packages could not run: ${firstLines(collisions.output, 2) || 'no output'}`),
    )
  }
  const conflicting = new Map()
  for (const item of found) {
    for (const label of item.labels) {
      const name = label.split(' ')[0]
      if (!conflicting.has(name)) conflicting.set(name, [])
      conflicting.get(name).push(item.name)
    }
  }
  for (const [name, names] of conflicting) {
    result.incompatibleWith.push(name)
    result.findings.push(finding('collision', `it defines ${[...new Set(names)].map((n) => `'${n}'`).join(', ')}, which ${name} also defines`))
  }
  if (result.incompatibleWith.length > 0) {
    result.findings.push(finding('incompatible-with', `it cannot be combined with: ${result.incompatibleWith.join(', ')}`))
  }
  for (const item of others) {
    const latest = newestOf(item)
    const directory = packageDirectory(home, item.name, latest.version, latest.commit)
    const requiresOf = await readDependencies(directory)
    if (requiresOf) result.graph.set(item.name, requiresOf)
    const owner = repositoryOwner(item.repository)?.owner ?? ''
    result.others.push({ name: item.name, owner, version: latest.version, commit: latest.commit, directory })
  }
  return result
}

export async function scanPackage({
  entry,
  version,
  commit,
  sarlinPath,
  policy,
  listedPackages = [],
  workDir,
  published = [],
  previousScan = null,
  unavailable = new Set(),
  mode = 'full',
}) {
  const created = workDir === undefined
  const base = created ? await mkdtemp(join(tmpdir(), 'nook-scan-')) : workDir
  await mkdir(base, { recursive: true })
  const scratch = await mkdtemp(join(base, 'scan-'))
  try {
    return await scanInScratch({ entry, version, commit, sarlinPath, policy, listedPackages, scratch, published, previousScan, unavailable, mode })
  } finally {
    if (created) await rm(base, { recursive: true, force: true })
    else await rm(scratch, { recursive: true, force: true })
  }
}

async function scanInScratch({ entry, version, commit, sarlinPath, policy, listedPackages, scratch, published, previousScan, unavailable, mode }) {
  const findings = []
  const home = join(scratch, 'home')
  const environment = gitEnvironment({ HOME: scratch, SARLIN_NOOK_HOME: home })
  const nook = join(scratch, 'nook')
  await createNook(nook, indexLines(listedPackages, [{ name: entry.name, version, repository: entry.repository, commit }]))
  const project = join(scratch, 'project')
  await mkdir(join(project, 'source'), { recursive: true })
  await writeFile(join(project, 'sarlin.project'), `name: nook_scan\nentry: source/main.sar\nlanguage: 1\nrequire: ${entry.name} ${version}\n`)
  await writeFile(join(project, 'source', 'main.sar'), 'func main() {\n}\n')

  const env = { ...environment, SARLIN_NOOK_INDEX: nook }
  const check = await runSarlin(sarlinPath, ['check', project], { cwd: scratch, env, policy })
  const directory = packageDirectory(home, entry.name, version, commit)

  let entries = null
  let history = null
  const previousPublished = published
    .filter((item) => compareVersions(item.version, version) < 0)
    .sort((left, right) => compareVersions(right.version, left.version))[0]
  if (mode === 'full') {
    history = await inspectHistory({
      repository: entry.repository,
      version,
      commit,
      previousCommit: previousPublished?.commit,
      directory: join(scratch, 'history.git'),
    })
  }

  let files = []
  let statistics = { files: 0, bytes: 0, lines: 0 }
  let packageRead = false
  try {
    entries = await walkDirectory(directory)
    packageRead = true
  } catch {
    entries = history?.cloned ? history.tree : null
  }
  if (history?.cloned && packageRead) {
    const seen = new Set()
    for (const item of checkEntries(history.tree, policy).filter((found) => found.id === 'symlink' || found.id === 'submodule')) {
      if (!seen.has(item.message)) findings.push(item)
      seen.add(item.message)
    }
  }
  if (entries) {
    findings.push(...checkEntries(entries, policy).filter((item) => !(packageRead && history?.cloned && (item.id === 'symlink' || item.id === 'submodule'))))
    findings.push(...checkHygiene(entries.map((item) => item.path)))
  }

  const mainFiles = []
  if (packageRead) {
    const blockedBySize = findings.some((item) => item.id === 'file-count' || item.id === 'package-size')
    const read = blockedBySize ? { files: [], blocked: [] } : await readPackage(directory, entries, policy)
    files = read.files
    findings.push(...read.blocked)
    const regular = entries.filter((item) => item.type === 'file')
    statistics = { files: regular.length, bytes: regular.reduce((sum, item) => sum + item.size, 0), lines: countLines(files) }
    const sources = files.filter((file) => isSourcePath(file.path) && file.text !== null)
    for (const file of sources) if (MAIN_FUNCTION.test(analyzeSource(file.text).code)) mainFiles.push(file.path)
    const project_ = files.find((file) => file.path === 'sarlin.project')
    if (!project_) {
      findings.push(finding('no-project', 'the package has no sarlin.project'))
    } else {
      findings.push(...checkProject({ projectText: project_.text, entryName: entry.name, paths: entries.map((item) => item.path), policy }))
    }
    findings.push(...checkHiddenCharacters(files, entries.map((item) => item.path)))
    findings.push(...checkSecrets(files, policy))
    findings.push(...checkIdentifiers(files))
    findings.push(...checkSensitiveStrings(files, policy))
    findings.push(...checkObfuscation(files, policy))
    findings.push(...checkDangerousRemovals(files))
  } else if (entries) {
    statistics = { files: entries.filter((item) => item.type === 'file').length, bytes: entries.reduce((sum, item) => sum + item.size, 0), lines: 0 }
  }
  for (const path of mainFiles) findings.push(finding('main-defined', `${path} defines func main; packages must not define a program entry point`))

  if (check.timedOut) {
    findings.push(finding('check-failed', `sarlin check did not finish within ${policy.sarlinTimeoutSeconds} seconds`))
  } else if (check.code !== 0) {
    const mentionsMain = /func main|entry point/.test(check.output)
    if (!(mentionsMain && mainFiles.length > 0)) {
      findings.push(finding('check-failed', `sarlin check failed: ${firstLines(check.output)}`))
    }
  }

  const sourceFiles = files.filter((file) => isSourcePath(file.path) && file.text !== null)
  const capabilities = collectCapabilities(sourceFiles)
  const externals = listExternals(sourceFiles)
  findings.push(...checkForeignCode(externals, capabilities, policy))

  const licenseFile = files.find((file) => LICENSE_FILE.test(file.path) && file.text !== null)
  if (packageRead) {
    findings.push(...checkLicense({ licenseText: licenseFile?.text ?? null, declared: entry.license, policy }))
  } else if (entry.license && !policy.allowedLicenses.includes(entry.license)) {
    findings.push(finding('license-not-allowed', `the license '${entry.license}' is not in the allowed list`))
  }

  const projectFile = files.find((file) => file.path === 'sarlin.project')
  const requires = projectFile ? parseProjectFile(projectFile.text).requires : []
  findings.push(...checkRequires(requires, listedPackages))

  let cross = { findings: [], incompatibleWith: [], graph: new Map(), newest: new Map(), others: [] }
  if (mode === 'full' && packageRead) {
    cross = await crossPackageChecks({ entry, version, commit, listedPackages, sarlinPath, policy, environment, scratch, home })
    findings.push(...cross.findings)
    const owner = repositoryOwner(entry.repository)?.owner ?? ''
    const others = []
    for (const other of cross.others) {
      others.push({ name: other.name, owner: other.owner, hashes: await readHashes(other.directory) })
    }
    findings.push(...checkClones({ hashes: normalisedSourceHashes(files), owner, others, policy }))
    const graph = new Map(cross.graph)
    graph.set(entry.name, requires)
    findings.push(...checkDependencyGraph({ name: entry.name, graph, newest: cross.newest, unavailable, policy }))
  }

  if (history?.cloned) {
    findings.push(...checkHistoryFacts({ reachable: history.reachable, descends: history.descends, previousVersion: previousPublished?.version, previousKnown: history.previousKnown }))
    findings.push(...checkVersionSanity({ version, published: published.map((item) => item.version), tagDate: history.tagDate, previousCommitDate: history.previousCommitDate, policy }))
    if (history.signed) findings.push(finding('signed', 'the commit or tag carries a signature'))
  }

  let breaksDependents = []
  if (mode === 'full' && packageRead) {
    const { dependentsImpact } = await import('./dependents.mjs')
    const impact = await dependentsImpact({ entry, version, commit, listedPackages, sarlinPath, policy, environment, scratch })
    findings.push(...impact.findings)
    breaksDependents = impact.breaks.map((item) => item.name)
  }

  let previous = previousScan
  if (mode === 'full' && !previous && previousPublished && packageRead) {
    previous = await scanPackage({
      entry,
      version: previousPublished.version,
      commit: previousPublished.commit,
      sarlinPath,
      policy,
      listedPackages,
      workDir: scratch,
      mode: 'quick',
    })
  }
  const current = { capabilities, files: statistics.files, bytes: statistics.bytes }
  findings.push(...checkCapabilityEscalation({ current, previous, policy }))

  findings.push(finding('capabilities', capabilities.length > 0 ? `capabilities used: ${capabilities.join(', ')}` : 'no notable capabilities used'))
  findings.push(finding('statistics', `${statistics.files} files, ${statistics.bytes} bytes, ${statistics.lines} lines of Sarlin`))
  if (requires.length > 0) {
    findings.push(finding('dependencies', `requires: ${requires.map((item) => `${item.name} ${item.version}`).join(', ')}`))
  }

  return {
    findings: applyChecks(findings, policy),
    capabilities,
    files: statistics.files,
    bytes: statistics.bytes,
    lines: statistics.lines,
    dependencies: requires,
    incompatibleWith: cross.incompatibleWith,
    breaksDependents,
    signed: history?.signed ?? false,
    commitDate: history?.commitDate ?? null,
    scanned: packageRead,
  }
}

export async function scanVersionRange({ entry, versions, previous, ...options }) {
  const known = previous?.get(entry.name)
  const sameRepository = known !== undefined && known.repository === entry.repository
  const published = sameRepository ? [...known.versions].map(([version, commit]) => ({ version, commit })) : []
  const fresh = versions.filter(({ version }) => !published.some((item) => item.version === version))
  fresh.sort((left, right) => compareVersions(left.version, right.version))
  const results = []
  let history = [...published]
  for (const { version, commit } of fresh) {
    const scan = await scanPackage({ entry, version, commit, published: history, ...options })
    results.push({ version, commit, scan })
    history = [...history, { version, commit }]
  }
  return results
}

export function newVersions(entry, remote, previous) {
  const known = previous?.get(entry.name)
  const pinned = known !== undefined && known.repository === entry.repository ? known.versions : new Map()
  return [...remote]
    .filter(([version]) => !pinned.has(version))
    .map(([version, commit]) => ({ version, commit }))
}

export async function compileCheck({ entry, version, commit, listedPackages, sarlinPath, policy, workDir }) {
  const scratch = await mkdtemp(join(workDir, 'health-'))
  try {
    const home = join(scratch, 'home')
    const nook = join(scratch, 'nook')
    await createNook(nook, indexLines(listedPackages, [{ name: entry.name, version, repository: entry.repository, commit }]))
    const project = join(scratch, 'project')
    await mkdir(join(project, 'source'), { recursive: true })
    await writeFile(join(project, 'sarlin.project'), `name: nook_health\nentry: source/main.sar\nlanguage: 1\nrequire: ${entry.name} ${version}\n`)
    await writeFile(join(project, 'source', 'main.sar'), 'func main() {\n}\n')
    const env = { ...gitEnvironment({ HOME: scratch, SARLIN_NOOK_HOME: home }), SARLIN_NOOK_INDEX: nook }
    const check = await runSarlin(sarlinPath, ['check', project], { cwd: scratch, env, policy })
    return { ok: check.code === 0 && !check.timedOut, output: check.output, timedOut: check.timedOut }
  } finally {
    await rm(scratch, { recursive: true, force: true })
  }
}

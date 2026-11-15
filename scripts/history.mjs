import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

import { finding } from './checks.mjs'

const run = promisify(execFile)

export function gitEnvironment(extra = {}) {
  return {
    ...process.env,
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    ...extra,
  }
}

export async function git(args, { cwd, timeout = 120000, env } = {}) {
  try {
    const { stdout } = await run('git', args, {
      cwd,
      timeout,
      killSignal: 'SIGKILL',
      env: gitEnvironment(env),
      maxBuffer: 64 * 1024 * 1024,
    })
    return { ok: true, code: 0, stdout }
  } catch (error) {
    return { ok: false, code: typeof error.code === 'number' ? error.code : -1, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }
  }
}

export function parseVersion(version) {
  const [major, minor, patch] = version.split('.').map(Number)
  return { major, minor, patch }
}

export function compareVersions(left, right) {
  const a = parseVersion(left)
  const b = parseVersion(right)
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch
}

export function newestVersion(versions) {
  return [...versions].sort(compareVersions).at(-1)
}

export function checkVersionSanity({ version, published, tagDate, previousCommitDate, policy }) {
  const findings = []
  if (published.length === 0) return findings
  const latest = newestVersion(published)
  const current = parseVersion(version)
  const old = parseVersion(latest)
  if (compareVersions(version, latest) <= 0) {
    findings.push(finding('back-dated-tag', `${version} is not newer than the published version ${latest}`))
    if (tagDate && previousCommitDate && new Date(tagDate) < new Date(previousCommitDate)) {
      findings.push(finding('back-dated-commit', `the tag for ${version} is older than the commit of ${latest}`))
    }
    return findings
  }
  const majorJump = current.major - old.major
  const minorJump = majorJump === 0 ? current.minor - old.minor : 0
  if (majorJump > policy.maximumMajorJump || minorJump > policy.maximumMinorJump) {
    findings.push(finding('version-jump', `${version} jumps too far from the published version ${latest}`))
  }
  return findings
}

const ESCALATING = ['foreign_code', 'network', 'file', 'directory']

export function checkCapabilityEscalation({ current, previous, policy }) {
  const findings = []
  if (!previous) return findings
  const added = ESCALATING.filter(
    (capability) => current.capabilities.includes(capability) && !previous.capabilities.includes(capability),
  )
  if (added.length > 0) {
    findings.push(finding('capability-escalation', `this version newly uses: ${added.join(', ')}`))
  }
  const byteGrowth =
    previous.bytes > 0 &&
    current.bytes > previous.bytes * policy.growthFactor &&
    current.bytes - previous.bytes > policy.growthMinimumBytes
  const fileGrowth =
    previous.files > 0 &&
    current.files > previous.files * policy.growthFactor &&
    current.files - previous.files > policy.growthMinimumFiles
  if (byteGrowth || fileGrowth) {
    findings.push(
      finding(
        'size-growth',
        `the package grew from ${previous.files} files and ${previous.bytes} bytes to ${current.files} files and ${current.bytes} bytes`,
      ),
    )
  }
  return findings
}

export function checkHistoryFacts({ reachable, descends, previousVersion, previousKnown }) {
  const findings = []
  if (reachable === false) {
    findings.push(finding('tag-unreachable', 'the tagged commit is not reachable from the default branch'))
  }
  if (previousVersion && descends === false) {
    const reason = previousKnown === false ? 'no longer exists in the repository' : 'is not an ancestor of this commit'
    findings.push(finding('history-rewrite', `the commit of the published ${previousVersion} ${reason}`))
  }
  return findings
}

export function isSigned(objectText) {
  return /^gpgsig /m.test(objectText) || /-----BEGIN (?:PGP|SSH) SIGNATURE-----/.test(objectText)
}

export async function inspectHistory({ repository, version, commit, previousCommit, directory }) {
  const clone = await git(['clone', '--bare', '--quiet', '--', repository, directory])
  if (!clone.ok) return { cloned: false, error: (clone.stderr ?? '').split('\n')[0] }
  const reachable = (await git(['merge-base', '--is-ancestor', commit, 'HEAD'], { cwd: directory })).code === 0
  let descends = null
  let previousKnown = null
  let previousCommitDate = null
  if (previousCommit) {
    previousKnown = (await git(['cat-file', '-e', `${previousCommit}^{commit}`], { cwd: directory })).ok
    descends = previousKnown
      ? (await git(['merge-base', '--is-ancestor', previousCommit, commit], { cwd: directory })).code === 0
      : false
    if (previousKnown) {
      previousCommitDate = (await git(['log', '-1', '--format=%cI', previousCommit], { cwd: directory })).stdout.trim() || null
    }
  }
  const tagDate =
    (await git(['for-each-ref', '--format=%(creatordate:iso-strict)', `refs/tags/v${version}`], { cwd: directory })).stdout.trim() ||
    null
  const commitText = (await git(['cat-file', 'commit', commit], { cwd: directory })).stdout
  const tagText = (await git(['cat-file', '-p', `refs/tags/v${version}`], { cwd: directory })).stdout
  const treeResult = await git(['ls-tree', '-r', '-t', '-z', '--long', commit], { cwd: directory })
  const tree = []
  for (const record of treeResult.stdout.split('\0')) {
    const match = /^(\d+) (blob|tree|commit)\s+([0-9a-f]+|-)\s+(\S+)\t([\s\S]+)$/.exec(record)
    if (!match) continue
    const [, mode, type, , size, path] = match
    tree.push({
      path: type === 'tree' ? `${path}/` : path,
      type: mode === '120000' ? 'symlink' : type === 'commit' ? 'submodule' : type === 'tree' ? 'dir' : 'file',
      size: size === '-' ? 0 : Number(size),
    })
  }
  return {
    cloned: true,
    reachable,
    descends,
    previousKnown,
    previousCommitDate,
    tagDate,
    signed: isSigned(commitText) || isSigned(tagText),
    tree,
  }
}

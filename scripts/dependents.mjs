import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

import { finding, parseCollisionOutput, parseProjectFile, sanitize } from './checks.mjs'
import { git, newestVersion, parseVersion } from './history.mjs'
import { createNook, indexLines, runSarlin } from './scan.mjs'

export function claimsCompatibility(newVersion, requiredVersion) {
  const current = parseVersion(newVersion)
  const required = parseVersion(requiredVersion)
  if (current.major !== required.major) return false
  if (current.major === 0 && current.minor !== required.minor) return false
  return current.minor > required.minor || (current.minor === required.minor && current.patch >= required.patch)
}

export function rewriteRequire(projectText, name, version) {
  let changed = false
  const lines = projectText.split('\n').map((line) => {
    const match = /^(\s*require\s*:\s*)(\S+)(\s+)(\S+)(.*)$/.exec(line)
    if (match && match[2] === name) {
      changed = true
      return `${match[1]}${match[2]}${match[3]}${version}${match[5]}`
    }
    return line
  })
  return { text: lines.join('\n'), changed }
}

export function checkDependentImpact({ version, breaks }) {
  const findings = []
  for (const item of breaks) {
    const id = claimsCompatibility(version, item.requires) ? 'dependents-break-compatible' : 'dependents-break'
    findings.push(finding(id, `${item.name} ${item.version} (requires ${item.requires}) would fail with ${version}: ${item.problem}`))
  }
  return findings
}

async function fetchCommit(repository, commit, directory) {
  await mkdir(directory, { recursive: true })
  await git(['init', '--quiet', '-b', 'work'], { cwd: directory })
  const fetched = await git(['fetch', '--quiet', '--depth', '1', '--', repository, commit], { cwd: directory })
  if (!fetched.ok) return false
  return (await git(['checkout', '--quiet', 'FETCH_HEAD'], { cwd: directory })).ok
}

function problemOf(output) {
  const lines = output.split('\n').map((line) => line.trim()).filter(Boolean)
  const errors = lines.filter((line) => /error|warning:/.test(line))
  return sanitize((errors.length > 0 ? errors : lines).slice(0, 3).join(' / '), 300) || 'no output'
}

export async function dependentsImpact({ entry, version, commit, listedPackages, sarlinPath, policy, environment, scratch }) {
  const breaks = []
  const checked = []
  for (const other of listedPackages) {
    if (other.name === entry.name || !other.versions?.length) continue
    const latest = other.versions.find((item) => item.version === newestVersion(other.versions.map((v) => v.version)))
    const work = await mkdtemp(join(scratch, 'dependent-'))
    const source = join(work, 'source-repo')
    if (!(await fetchCommit(other.repository, latest.commit, source))) continue
    const projectText = await readFile(join(source, 'sarlin.project'), 'utf8').catch(() => '')
    const requires = parseProjectFile(projectText).requires.find((item) => item.name === entry.name)
    if (!requires) continue
    checked.push(other.name)
    const rewritten = rewriteRequire(projectText, entry.name, version)
    await writeFile(join(source, 'sarlin.project'), rewritten.text)
    await git(['add', '-A'], { cwd: source })
    await git(['-c', 'user.name=nook', '-c', 'user.email=nook@invalid.test', 'commit', '--quiet', '-m', 'substitute'], { cwd: source })
    const substituted = (await git(['rev-parse', 'HEAD'], { cwd: source })).stdout.trim()
    const nook = join(work, 'nook')
    const lines = indexLines(
      listedPackages.filter((item) => item.name !== other.name),
      [
        { name: entry.name, version, repository: entry.repository, commit },
        { name: other.name, version: latest.version, repository: source, commit: substituted },
      ],
    )
    await createNook(nook, lines)
    const project = join(work, 'project')
    await mkdir(join(project, 'source'), { recursive: true })
    await writeFile(join(project, 'sarlin.project'), `name: nook_dependents\nentry: source/main.sar\nlanguage: 1\nrequire: ${other.name} ${latest.version}\n`)
    await writeFile(join(project, 'source', 'main.sar'), 'func main() {\n}\n')
    const env = { ...environment, SARLIN_NOOK_INDEX: nook }
    const check = await runSarlin(sarlinPath, ['check', project], { cwd: work, env, policy })
    const collisions = await runSarlin(sarlinPath, ['collisions', project], { cwd: work, env, policy })
    const names = parseCollisionOutput(collisions.output, `${other.name} ${latest.version}`).map((item) => item.name)
    if (check.code !== 0 || check.timedOut || names.length > 0) {
      breaks.push({
        name: other.name,
        version: latest.version,
        requires: requires.version,
        problem: check.timedOut ? 'sarlin check timed out' : check.code !== 0 ? problemOf(check.output) : `it defines the same names: ${names.join(', ')}`,
      })
    }
  }
  return { breaks, checked, findings: checkDependentImpact({ version, breaks }) }
}

import { execFile } from 'node:child_process'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { promisify } from 'node:util'

import { repositoryOwner, sanitize } from './checks.mjs'
import { newestVersion } from './history.mjs'
import { ENTRY_EXTENSION, listRemoteVersions, parseIndex, validateEntry } from './lib.mjs'
import { ROOT, damerauLevenshtein, isTrusted, loadPolicy } from './policy.mjs'
import { scanPackage } from './scan.mjs'

const run = promisify(execFile)

export const MARKER = '<!-- nook-triage -->'

export const LABELS = {
  approve: { name: 'auto-approved', color: '0e8a16', description: 'Passed every automatic check and was merged by the triage workflow' },
  review: { name: 'needs-manual-review', color: 'fbca04', description: 'A maintainer must review this before it can be merged' },
  reject: { name: 'rejected-by-checks', color: 'd73a4a', description: 'Failed a blocking automatic check; fix it and push again' },
}

const PACKAGE_PATH = /^packages\/[^/]+\.package$/
const DAY = 24 * 60 * 60 * 1000

const result = (title, status, message, details = []) => ({ title, status, message, details })

export function worstStatus(statuses) {
  if (statuses.includes('block')) return 'block'
  if (statuses.includes('review')) return 'review'
  return 'pass'
}

export function decide(checks) {
  const worst = worstStatus(checks.map((check) => check.status))
  return worst === 'block' ? 'reject' : worst === 'review' ? 'review' : 'approve'
}

export function checkScope(files) {
  if (files.length === 0) return result('Scope', 'review', 'The pull request changes no files')
  const outside = files.filter((file) => !PACKAGE_PATH.test(file.filename) || !['added', 'modified'].includes(file.status))
  if (outside.length === 0) return result('Scope', 'pass', 'Only package entries are added or modified')
  const names = outside.slice(0, 5).map((file) => `${file.filename} (${file.status})`)
  return result('Scope', 'review', `Changes outside packages/<name>.package or deletions need a maintainer: ${names.join(', ')}`)
}

export function checkEntryChange({ fileName, text, baseText }) {
  const { entry, problems } = validateEntry(fileName, text ?? '')
  if (problems.length > 0) return { outcome: result('Entry', 'block', problems.map((problem) => sanitize(problem, 160)).join('; ')), entry: null }
  if (baseText !== null && baseText !== undefined) {
    const before = validateEntry(fileName, baseText).entry
    if (before.repository && before.repository.toLowerCase() !== entry.repository.toLowerCase()) {
      return {
        outcome: result('Entry', 'review', `The repository changed from ${sanitize(before.repository)} to ${sanitize(entry.repository)}; changing where a name points needs a maintainer`),
        entry,
      }
    }
  }
  return { outcome: result('Entry', 'pass', `${entry.name} is a valid entry`), entry }
}

export function checkIdentity({ author, entry, policy }) {
  const owner = repositoryOwner(entry.repository)?.owner
  if (owner && owner.toLowerCase() === author.toLowerCase()) return result('Author identity', 'pass', `${author} owns the repository`)
  if (isTrusted(policy, author)) return result('Author identity', 'pass', `${author} is a trusted user`)
  return result('Author identity', 'review', `The package repository is owned by ${sanitize(owner ?? 'someone else')}, not by ${author}`)
}

export function checkAccount({ author, user, priorMerged, association, policy, now }) {
  const ageDays = user?.created_at ? Math.floor((now - new Date(user.created_at).getTime()) / DAY) : null
  const facts = `account age ${ageDays ?? 'unknown'} days, ${priorMerged} earlier merged pull request(s), association ${sanitize(association ?? 'NONE', 30)}`
  if (isTrusted(policy, author)) return result('Author account', 'info', `${author} is a trusted user (${facts})`)
  const problems = []
  if (ageDays === null || ageDays < policy.minimumAccountAgeDays) problems.push(`the account is younger than ${policy.minimumAccountAgeDays} days`)
  if (priorMerged < policy.minimumPriorMergedPullRequests) problems.push('this is a first contribution')
  if (problems.length > 0) return result('Author account', 'review', `${problems.join(' and ')} (${facts})`)
  return result('Author account', 'pass', facts)
}

export function checkRepository({ entry, repo, policy, now }) {
  if (!repo) return result('Package repository', 'block', 'The repository does not exist or is not public')
  if (repo.private) return result('Package repository', 'block', 'The repository is private')
  const problems = []
  if (repo.archived) problems.push('the repository is archived')
  if (repo.fork) problems.push('the repository is a fork')
  const ageDays = Math.floor((now - new Date(repo.created_at).getTime()) / DAY)
  if (!(ageDays >= policy.minimumRepositoryAgeDays)) problems.push(`the repository is younger than ${policy.minimumRepositoryAgeDays} days`)
  const detected = repo.license?.spdx_id && repo.license.spdx_id !== 'NOASSERTION' ? repo.license.spdx_id : null
  const license = detected ?? entry.license ?? null
  if (!license) problems.push('no license was detected or stated')
  else {
    for (const candidate of [detected, entry.license].filter(Boolean)) {
      if (!policy.allowedLicenses.includes(candidate)) problems.push(`the license ${sanitize(candidate, 40)} is not in the allowed list`)
    }
  }
  if (problems.length > 0) return result('Package repository', 'review', `${problems.join('; ')}`)
  return result('Package repository', 'pass', `Public, ${ageDays} days old, license ${license}`)
}

export function checkRepositoryIdentity({ entry, repo }) {
  const wanted = repositoryOwner(entry.repository)
  if (!repo || !wanted) return result('Repository identity', 'info', 'Not checked')
  const canonical = String(repo.full_name ?? '').toLowerCase()
  const type = repo.owner?.type ?? 'unknown'
  if (canonical !== `${wanted.owner}/${wanted.name}`.toLowerCase()) {
    return result('Repository identity', 'review', `${wanted.owner}/${wanted.name} now lives at ${sanitize(repo.full_name)}; the repository was renamed or transferred`)
  }
  return result('Repository identity', 'info', `Owner type: ${sanitize(type, 20)}`)
}

function normalisedName(name) {
  return name.replace(/_/g, '')
}

export function checkNames({ entry, listedNames, policy }) {
  const name = entry.name
  if (policy.reservedNames.includes(name)) return result('Name safety', 'block', `'${name}' is a reserved name`)
  const others = listedNames.filter((other) => other !== name)
  const same = others.find((other) => normalisedName(other) === normalisedName(name))
  if (same) return result('Name safety', 'block', `'${name}' differs from the existing package '${same}' only by punctuation`)
  const close = []
  for (const other of [...others, ...policy.reservedNames]) {
    const limit = Math.min(policy.typosquatDistance, Math.floor(Math.min(other.length, name.length) / 3))
    if (limit > 0 && damerauLevenshtein(name, other) <= limit) close.push(other)
  }
  if (close.length > 0) return result('Name safety', 'review', `'${name}' is very close to ${[...new Set(close)].slice(0, 5).map((value) => `'${value}'`).join(', ')}`)
  return result('Name safety', 'pass', `'${name}' is not reserved and not close to another name`)
}

export function checkDuplicate({ entry, listed }) {
  const clash = listed.find((other) => other.name !== entry.name && other.repository.toLowerCase() === entry.repository.toLowerCase())
  if (clash) return result('Duplicate repository', 'block', `${sanitize(entry.repository)} is already listed as '${clash.name}'`)
  return result('Duplicate repository', 'pass', 'The repository is not listed under another name')
}

export function checkScanResult({ name, version, scan }) {
  const worst = scan.findings.some((item) => item.severity === 'block') ? 'block' : scan.findings.some((item) => item.severity === 'review') ? 'review' : 'pass'
  const blocks = scan.findings.filter((item) => item.severity === 'block').length
  const reviews = scan.findings.filter((item) => item.severity === 'review').length
  const message = worst === 'pass' ? `${name} ${version} is clean` : `${name} ${version}: ${blocks} blocking and ${reviews} review finding(s)`
  return result('Package scan', worst, message, scan.findings)
}

export function checkRates({ author, pulls, number, filesAdded, user, policy, now }) {
  if (isTrusted(policy, author)) return result('Rate limits', 'pass', 'Trusted user')
  const problems = []
  const own = pulls.filter((pull) => pull.user?.login?.toLowerCase() === author.toLowerCase() && pull.number !== number)
  const open = own.filter((pull) => pull.state === 'open').length
  if (open > policy.maximumOpenPullRequests) problems.push(`${open} other pull requests are open`)
  const ageDays = user?.created_at ? Math.floor((now - new Date(user.created_at).getTime()) / DAY) : 0
  const recent = own.filter((pull) => now - new Date(pull.created_at).getTime() < DAY).length + 1
  if (ageDays < policy.minimumAccountAgeDays && recent > policy.maximumRecentListings) problems.push(`${recent} listings in 24 hours from a young account`)
  if (filesAdded > policy.maximumEntriesPerPullRequest) problems.push(`the pull request adds ${filesAdded} entries`)
  return problems.length > 0 ? result('Rate limits', 'review', problems.join('; ')) : result('Rate limits', 'pass', 'Within the limits')
}

export function checkDraft(pull) {
  return pull.draft ? result('Draft', 'review', 'The pull request is a draft; mark it ready for review to continue') : result('Draft', 'pass', 'Ready for review')
}

function applyPolicyToChecks(checks, policy) {
  const ids = { 'Repository identity': 'repository-moved', 'Rate limits': 'listing-rate' }
  return checks.map((check) => {
    const id = ids[check.title]
    const setting = id ? policy.checks?.[id] : undefined
    if (setting?.enabled === false) return { ...check, status: check.status === 'info' ? 'info' : 'pass' }
    return check
  })
}

export function verdictText(decision) {
  if (decision === 'approve') return 'All checks passed. This pull request is merged automatically.'
  if (decision === 'review') return 'A maintainer needs to look at this pull request before it can be merged.'
  return 'Blocking problems were found. This pull request will not be merged until they are fixed.'
}

export function nextSteps(decision, merged = true) {
  if (decision === 'approve') {
    return merged
      ? ['Nothing to do. The index workflow publishes the package within a few minutes.']
      : ['The automatic merge did not go through. A maintainer will merge it.']
  }
  if (decision === 'review') {
    return [
      'Nothing is wrong yet. The maintainer has been asked to review and will merge or comment.',
      'Pushing new commits reruns these checks.',
      'Review findings are not errors: they mark things a human must approve, such as external native code, network use or a first contribution.',
    ]
  }
  return [
    'Fix every item marked block in the table above, then push to this branch. The checks rerun by themselves.',
    'Findings are listed with a file and line where possible. Secret values are never printed.',
  ]
}

function cell(text) {
  return sanitize(text, 400)
}

export function renderComment({ decision, checks, sha, merged = true, notes = [] }) {
  const lines = [MARKER, `## Nook triage: ${decision === 'approve' ? 'approved' : decision === 'review' ? 'needs manual review' : 'rejected'}`, '', verdictText(decision), '', '| Check | Result | Details |', '| --- | --- | --- |']
  for (const check of checks) lines.push(`| ${check.title} | ${check.status} | ${cell(check.message)} |`)
  const findings = checks.flatMap((check) => check.details.filter((item) => item.severity !== 'info'))
  const infos = checks.flatMap((check) => check.details.filter((item) => item.severity === 'info'))
  if (findings.length > 0) {
    lines.push('', '### Scan findings', '')
    for (const item of findings.slice(0, 40)) lines.push(`- ${item.severity}: ${item.id}: ${cell(item.message)}`)
    if (findings.length > 40) lines.push(`- and ${findings.length - 40} more`)
  }
  if (infos.length > 0) {
    lines.push('', '### Information', '')
    for (const item of infos.slice(0, 20)) lines.push(`- ${item.id}: ${cell(item.message)}`)
  }
  for (const note of notes) lines.push('', cell(note))
  lines.push('', '### What you can do next', '')
  for (const step of nextSteps(decision, merged)) lines.push(`- ${step}`)
  lines.push('', `Checked commit ${sha.slice(0, 7)}.`, '')
  return lines.join('\n')
}

async function ensureLabels(api, repo) {
  const existing = new Set((await api('GET', `repos/${repo}/labels`, { paginate: true })).map((label) => label.name))
  for (const label of Object.values(LABELS)) {
    if (!existing.has(label.name)) await api('POST', `repos/${repo}/labels`, { body: { name: label.name, color: label.color, description: label.description } })
  }
}

async function setDecisionLabel(api, repo, number, decision) {
  const current = new Set((await api('GET', `repos/${repo}/issues/${number}/labels`, { paginate: true })).map((label) => label.name))
  for (const [key, label] of Object.entries(LABELS)) {
    if (key !== decision && current.has(label.name)) await api('DELETE', `repos/${repo}/issues/${number}/labels/${encodeURIComponent(label.name)}`)
  }
  if (!current.has(LABELS[decision].name)) await api('POST', `repos/${repo}/issues/${number}/labels`, { body: { labels: [LABELS[decision].name] } })
}

async function upsertComment(api, repo, number, body) {
  const comments = await api('GET', `repos/${repo}/issues/${number}/comments`, { paginate: true })
  const existing = comments.find((comment) => comment.body?.startsWith(MARKER))
  if (!existing) return api('POST', `repos/${repo}/issues/${number}/comments`, { body: { body } })
  if (existing.body !== body) await api('PATCH', `repos/${repo}/issues/comments/${existing.id}`, { body: { body } })
  return existing
}

async function readHeadFile(api, pull, path) {
  const source = pull.head?.repo?.full_name
  if (!source) return null
  try {
    const found = await api('GET', `repos/${source}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${pull.head.sha}`)
    if (!found || found.encoding !== 'base64' || typeof found.content !== 'string') return null
    return Buffer.from(found.content, 'base64').toString('utf8')
  } catch {
    return null
  }
}

export async function runTriage({ api, repo, number, expectedSha, policy, deps, now = Date.now() }) {
  const pull = await api('GET', `repos/${repo}/pulls/${number}`)
  if (pull.state !== 'open') return { skipped: 'the pull request is not open' }
  if (expectedSha && pull.head.sha !== expectedSha) return { skipped: 'the pull request head moved; a newer run will check it' }
  const author = pull.user.login
  const files = await api('GET', `repos/${repo}/pulls/${number}/files`, { paginate: true })
  const listed = await deps.listBaseEntries()
  const checks = [checkDraft(pull), checkScope(files)]
  const packageFiles = files.filter((file) => PACKAGE_PATH.test(file.filename) && ['added', 'modified'].includes(file.status)).slice(0, 10)

  const user = await api('GET', `users/${author}`).catch(() => null)
  const pulls = await api('GET', `repos/${repo}/pulls?state=all`, { paginate: true })
  const priorMerged = pulls.filter((item) => item.user?.login?.toLowerCase() === author.toLowerCase() && item.merged_at && item.number !== number).length
  checks.push(checkRates({ author, pulls, number, filesAdded: files.filter((file) => file.status === 'added' && PACKAGE_PATH.test(file.filename)).length, user, policy, now }))
  checks.push(checkAccount({ author, user, priorMerged, association: pull.author_association, policy, now }))

  const listedNames = listed.map((item) => item.name)
  const perFile = []
  for (const file of packageFiles) {
    const fileName = file.filename.slice('packages/'.length)
    const text = await readHeadFile(api, pull, file.filename)
    const base = listed.find((item) => item.fileName === fileName)
    const { outcome, entry } = checkEntryChange({ fileName, text, baseText: file.status === 'modified' ? base?.text ?? null : null })
    const rows = [outcome]
    if (entry) {
      rows.push(checkIdentity({ author, entry, policy }))
      const owner = repositoryOwner(entry.repository)
      let repoInfo = null
      if (owner) repoInfo = await api('GET', `repos/${owner.owner}/${owner.name}`).catch(() => null)
      rows.push(checkRepository({ entry, repo: repoInfo, policy, now }))
      rows.push(checkRepositoryIdentity({ entry, repo: repoInfo }))
      rows.push(checkNames({ entry, listedNames, policy }))
      rows.push(checkDuplicate({ entry, listed }))
      if (repoInfo && outcome.status !== 'block') rows.push(await scanNewest({ entry, listed, deps }))
    }
    perFile.push({ fileName, rows })
  }
  const order = ['Entry', 'Author identity', 'Package repository', 'Repository identity', 'Name safety', 'Duplicate repository', 'Package scan']
  for (const title of order) {
    const matching = perFile.flatMap(({ fileName, rows }) => rows.filter((row) => row.title === title).map((row) => ({ fileName, row })))
    if (matching.length === 0) continue
    const status = matching.some(({ row }) => row.status === 'block') ? 'block' : matching.some(({ row }) => row.status === 'review') ? 'review' : matching.some(({ row }) => row.status === 'pass') ? 'pass' : 'info'
    const message = matching.length === 1 ? matching[0].row.message : matching.map(({ fileName, row }) => `${fileName}: ${row.message}`).join('; ')
    checks.push({ title, status, message, details: matching.flatMap(({ row }) => row.details) })
  }
  const finalChecks = applyPolicyToChecks(checks, policy)
  let decision = decide(finalChecks)

  await ensureLabels(api, repo)
  let merged = false
  const notes = []
  if (decision === 'approve') {
    const fresh = await api('GET', `repos/${repo}/pulls/${number}`)
    if (fresh.head.sha !== pull.head.sha) {
      decision = 'review'
      notes.push('The branch changed while the checks were running, so it was not merged.')
    } else {
      try {
        await deps.merge({ number, sha: pull.head.sha })
        merged = true
      } catch (error) {
        decision = 'review'
        notes.push(`The automatic merge failed: ${error.message.split('\n')[0]}`)
      }
    }
  }
  await setDecisionLabel(api, repo, number, decision)
  await upsertComment(api, repo, number, renderComment({ decision, checks: finalChecks, sha: pull.head.sha, merged, notes }))
  if (merged) await deps.dispatchIndex()
  return { decision, merged, checks: finalChecks }
}

async function scanNewest({ entry, listed, deps }) {
  let remote
  try {
    remote = await deps.listVersions(entry.repository)
  } catch (error) {
    return result('Package scan', 'block', `Could not read tags from ${sanitize(entry.repository)}: ${sanitize(error.message, 100)}`)
  }
  if (remote.size === 0) return result('Package scan', 'block', 'The repository has no version tag; tag a release such as v0.1.0')
  const version = newestVersion([...remote.keys()])
  const commit = remote.get(version)
  const scan = await deps.scan({ entry, version, commit, listedPackages: listed.map((item) => ({ name: item.name, repository: item.repository, versions: item.versions ?? [] })).filter((item) => item.name !== entry.name) })
  return checkScanResult({ name: entry.name, version, scan })
}

export function ghApi(token) {
  return async (method, path, { body, paginate } = {}) => {
    const args = ['api', '--method', method, path]
    if (paginate) args.push('--paginate', '--slurp')
    const options = { env: { ...process.env, GH_TOKEN: token ?? process.env.GH_TOKEN }, maxBuffer: 64 * 1024 * 1024 }
    if (body !== undefined) {
      args.push('--input', '-')
    }
    try {
      const child = run('gh', args, options)
      if (body !== undefined) {
        child.child.stdin.end(JSON.stringify(body))
      }
      const { stdout } = await child
      if (stdout.trim() === '') return null
      const parsed = JSON.parse(stdout)
      return paginate ? parsed.flat() : parsed
    } catch (error) {
      const failure = new Error(`gh api ${method} ${path} failed: ${(error.stderr ?? error.message).split('\n')[0]}`)
      failure.status = /404/.test(error.stderr ?? '') ? 404 : 0
      throw failure
    }
  }
}

async function readBaseEntries(directory, previousIndex) {
  const names = (await readdir(directory)).filter((name) => name.endsWith(ENTRY_EXTENSION)).sort()
  const entries = []
  for (const fileName of names) {
    const text = await readFile(join(directory, fileName), 'utf8')
    const { entry } = validateEntry(fileName, text)
    if (!entry.name || !entry.repository) continue
    const known = previousIndex.get(entry.name)
    const versions = known ? [...known.versions].map(([version, commit]) => ({ version, commit })) : []
    entries.push({ ...entry, fileName, text, versions })
  }
  return entries
}

async function main() {
  const repo = process.env.GITHUB_REPOSITORY
  const number = Number(process.env.PR_NUMBER)
  const expectedSha = process.env.PR_HEAD_SHA
  const sarlinPath = process.env.SARLIN_BIN
  if (!repo || !Number.isInteger(number) || !sarlinPath) {
    console.error('error: GITHUB_REPOSITORY, PR_NUMBER and SARLIN_BIN must be set')
    process.exit(2)
  }
  const indexPath = process.argv.includes('--index') ? process.argv[process.argv.indexOf('--index') + 1] : null
  let previousIndex = new Map()
  if (indexPath) previousIndex = parseIndex(await readFile(indexPath, 'utf8').catch(() => ''))
  const policy = await loadPolicy()
  const api = ghApi()
  const deps = {
    listBaseEntries: () => readBaseEntries(join(ROOT, 'packages'), previousIndex),
    listVersions: listRemoteVersions,
    scan: (options) => scanPackage({ ...options, sarlinPath, policy }),
    merge: async ({ number: pullNumber, sha }) => {
      await run('gh', ['pr', 'merge', String(pullNumber), '--repo', repo, '--squash', '--delete-branch', '--match-head-commit', sha])
    },
    dispatchIndex: async () => {
      await run('gh', ['workflow', 'run', 'index.yml', '--repo', repo])
    },
  }
  const outcome = await runTriage({ api, repo, number, expectedSha, policy, deps })
  console.log(outcome.skipped ? `skipped: ${outcome.skipped}` : `decision: ${outcome.decision}${outcome.merged ? ' (merged)' : ''}`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`error: ${error.message}`)
    process.exit(1)
  })
}

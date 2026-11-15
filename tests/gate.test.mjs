import assert from 'node:assert/strict'
import { readFileSync, rmSync } from 'node:fs'
import { after, test } from 'node:test'

import { buildGatedIndex, decideVersion, formatHealth, parseApprovals, parseYanked, policyFingerprint, reuseHealth } from '../scripts/gate.mjs'
import { ISSUE_LABEL, applyPlan, issueBody, issueTitle, planIssues } from '../scripts/issues.mjs'
import { listRemoteVersions, parseIndex } from '../scripts/lib.mjs'
import { compileCheck, scanPackage } from '../scripts/scan.mjs'
import { CLEAN_SOURCE, SARLIN_BIN, SKIP_COMPILER, addRelease, entryFor, makeRepository, packageFiles, tempDirectory } from './helpers.mjs'

const policy = JSON.parse(readFileSync(new URL('../policy.json', import.meta.url), 'utf8'))
const NOW = new Date('2026-06-01T00:00:00Z')
const A = 'a'.repeat(40)
const B = 'b'.repeat(40)
const C = 'c'.repeat(40)
const entry = { name: 'widgets', repository: 'https://github.com/o/widgets', description: 'W', license: 'MIT' }
const finding = (severity, id = 'x') => ({ id, severity, message: `${id} message` })

function harness({ remote, findings = [], previousText = '', ...rest } = {}) {
  const calls = { scan: [], health: [] }
  const options = {
    entries: [entry],
    previous: parseIndex(previousText),
    policy,
    compiler: '0.1.4',
    now: NOW,
    resolveVersions: async () => remote,
    scan: async (request) => {
      calls.scan.push(request.version)
      return { findings: typeof findings === 'function' ? findings(request) : findings, incompatibleWith: [], breaksDependents: [] }
    },
    health: async (request) => {
      calls.health.push(request.version)
      return { ok: true }
    },
    ...rest,
  }
  return { calls, build: (extra = {}) => buildGatedIndex({ ...options, ...extra }) }
}

test('approvals and yanked files ignore comments and malformed lines', () => {
  const approvals = parseApprovals(`# header\nwidgets 0.1.0 ${A} # reviewed\nbad line\nwidgets 0.2.0 short\n\n`)
  assert.deepEqual([...approvals], [`widgets 0.1.0 ${A}`])
  const yanked = parseYanked('# c\nwidgets 0.1.0 leaked a key\nwidgets 0.2.0\n')
  assert.equal(yanked.get('widgets 0.1.0'), 'leaked a key')
  assert.equal(yanked.get('widgets 0.2.0'), 'no reason given')
})

test('decideVersion never overrides a block and only overrides review when approved', () => {
  assert.deepEqual(decideVersion({ findings: [finding('info')], approved: false }), { publish: true, hold: null, overridden: false })
  assert.equal(decideVersion({ findings: [finding('review')], approved: false }).hold, 'review')
  assert.equal(decideVersion({ findings: [finding('review')], approved: true }).overridden, true)
  assert.equal(decideVersion({ findings: [finding('block'), finding('review')], approved: true }).publish, false)
})

test('a clean new version is published', async () => {
  const { build, calls } = harness({ remote: new Map([['0.1.0', A]]), findings: [finding('info')] })
  const result = await build()
  assert.equal(result.indexText, `nook-index 1\nwidgets 0.1.0 ${entry.repository} ${A}\n`)
  assert.deepEqual(result.quarantine, [])
  assert.deepEqual(calls.scan, ['0.1.0'])
})

test('a version with review findings is quarantined and not published', async () => {
  const { build } = harness({ remote: new Map([['0.1.0', A]]), findings: [finding('review', 'external-code')] })
  const result = await build()
  assert.equal(result.indexText, 'nook-index 1\n')
  assert.equal(result.quarantine.length, 1)
  assert.deepEqual({ name: result.quarantine[0].name, version: result.quarantine[0].version, commit: result.quarantine[0].commit, severity: result.quarantine[0].severity }, { name: 'widgets', version: '0.1.0', commit: A, severity: 'review' })
  assert.equal(result.quarantine[0].findings[0].id, 'external-code')
  assert.equal(result.newlyQuarantined.length, 1)
  assert.equal(result.packages[0].versions.length, 0)
})

test('an approval releases a review hold but never a block', async () => {
  const approvals = new Set([`widgets 0.1.0 ${A}`])
  const held = harness({ remote: new Map([['0.1.0', A]]), findings: [finding('review')] })
  const released = await held.build({ approvals })
  assert.match(released.indexText, /widgets 0.1.0/)
  assert.equal(released.overridden.length, 1)
  const blocked = harness({ remote: new Map([['0.1.0', A]]), findings: [finding('block'), finding('review')] })
  const stuck = await blocked.build({ approvals })
  assert.equal(stuck.indexText, 'nook-index 1\n')
  assert.equal(stuck.quarantine[0].severity, 'block')
  const wrongCommit = await held.build({ approvals: new Set([`widgets 0.1.0 ${B}`]) })
  assert.equal(wrongCommit.quarantine.length, 1)
})

test('published versions are grandfathered: never rescanned, never removed, never repointed', async () => {
  const previousText = `nook-index 1\nwidgets 0.1.0 ${entry.repository} ${A}\n`
  const { build, calls } = harness({ remote: new Map([['0.1.0', B], ['0.2.0', C]]), previousText, findings: [finding('block')] })
  const result = await build()
  assert.deepEqual(calls.scan, ['0.2.0'])
  assert.match(result.indexText, new RegExp(`widgets 0.1.0 ${entry.repository} ${A}`))
  assert.ok(result.warnings.some((warning) => warning.includes('stays at')))
  const gone = harness({ remote: new Map(), previousText })
  const kept = await gone.build()
  assert.match(kept.indexText, /widgets 0.1.0/)
  assert.deepEqual(gone.calls.scan, [])
})

test('an unreachable repository keeps its versions and is recorded as unavailable', async () => {
  const previousText = `nook-index 1\nwidgets 0.1.0 ${entry.repository} ${A}\n`
  const failing = harness({ remote: null, previousText })
  const options = { resolveVersions: async () => { throw new Error('offline') } }
  const first = await failing.build(options)
  assert.match(first.indexText, /widgets 0.1.0/)
  assert.equal(first.health[0].status, 'unavailable')
  assert.equal(first.health[0].since, NOW.toISOString())
  assert.deepEqual(first.unavailableRepositories, [])
  const later = new Date(NOW.getTime() + 8 * 86400000)
  const second = await failing.build({ ...options, previousHealth: first.health, now: later })
  assert.equal(second.health[0].since, NOW.toISOString())
  assert.equal(second.unavailableRepositories[0].name, 'widgets')
  assert.match(second.indexText, /widgets 0.1.0/)
})

test('quarantine decisions are reused until the policy or commit changes', async () => {
  const { build, calls } = harness({ remote: new Map([['0.1.0', A]]), findings: [finding('review')] })
  const first = await build()
  const later = new Date(NOW.getTime() + 3600000)
  const second = await build({ previousQuarantine: first.quarantine, now: later })
  assert.deepEqual(calls.scan, ['0.1.0'])
  assert.equal(second.quarantine[0].firstSeen, NOW.toISOString())
  assert.equal(second.newlyQuarantined.length, 0)
  await build({ previousQuarantine: first.quarantine, policy: { ...policy, minimumAccountAgeDays: 1 } })
  assert.equal(calls.scan.length, 2)
  assert.notEqual(policyFingerprint(policy), policyFingerprint({ ...policy, minimumAccountAgeDays: 1 }))
})

test('later versions are scanned against the published history only', async () => {
  const seen = []
  const { build } = harness({
    remote: new Map([['0.1.0', A], ['0.2.0', B]]),
    findings: (request) => {
      seen.push(request.published.map((item) => item.version))
      return request.version === '0.1.0' ? [finding('review')] : []
    },
  })
  const result = await build()
  assert.deepEqual(seen, [[], []])
  assert.match(result.indexText, /0.2.0/)
  assert.ok(!/0.1.0/.test(result.indexText))
})

test('health is reused for the same version and compiler and refreshed otherwise', async () => {
  const previousText = `nook-index 1\nwidgets 0.1.0 ${entry.repository} ${A}\n`
  const { build, calls } = harness({ remote: new Map([['0.1.0', A]]), previousText })
  const first = await build()
  assert.deepEqual(calls.health, ['0.1.0'])
  assert.deepEqual(first.health, [{ name: 'widgets', version: '0.1.0', compiler: '0.1.4', status: 'ok', checkedAt: NOW.toISOString() }])
  assert.equal(first.packages[0].compatible, true)
  assert.equal(first.packages[0].compiler, '0.1.4')
  await build({ previousHealth: first.health })
  assert.deepEqual(calls.health, ['0.1.0'])
  await build({ previousHealth: first.health, compiler: '0.1.5' })
  assert.equal(calls.health.length, 2)
  assert.ok(reuseHealth(first.health, 'widgets', '0.1.0', '0.1.4'))
  assert.equal(reuseHealth(first.health, 'widgets', '0.2.0', '0.1.4'), null)
  assert.match(formatHealth(first.health), /"status": "ok"/)
  const failing = await harness({ remote: new Map([['0.1.0', A]]), previousText, health: async () => ({ ok: false }) }).build()
  assert.equal(failing.health[0].status, 'failing')
  assert.equal(failing.packages[0].compatible, false)
})

test('yanked versions leave index.txt, stay in the catalogue and are not rescanned', async () => {
  const previousText = `nook-index 1\nwidgets 0.1.0 ${entry.repository} ${A}\nwidgets 0.2.0 ${entry.repository} ${B}\n`
  const yanked = parseYanked('widgets 0.2.0 leaked a key\n')
  const { build, calls } = harness({ remote: new Map([['0.1.0', A], ['0.2.0', B]]), previousText })
  const first = await build({ yanked })
  assert.ok(!first.indexText.includes('0.2.0'))
  assert.match(first.indexText, /0.1.0/)
  const record = first.packages[0].versions.find((item) => item.version === '0.2.0')
  assert.deepEqual({ yanked: record.yanked, reason: record.reason, commit: record.commit }, { yanked: true, reason: 'leaked a key', commit: B })
  const second = await build({ yanked, previous: parseIndex(first.indexText) })
  assert.deepEqual(calls.scan, [])
  assert.ok(!second.indexText.includes('0.2.0'))
  assert.equal(second.health[0].version, '0.1.0')
})

test('meta.json carries a generation that only moves when the index changes', async () => {
  const { build } = harness({ remote: new Map([['0.1.0', A]]) })
  const first = await build()
  assert.equal(first.meta.generation, 1)
  assert.match(first.indexChecksum, /^[0-9a-f]{64} {2}index.txt\n$/)
  const same = await build({ previousMeta: first.meta, now: new Date(NOW.getTime() + 86400000) })
  assert.deepEqual(same.meta, first.meta)
  const changed = harness({ remote: new Map([['0.1.0', A], ['0.2.0', B]]) })
  const next = await changed.build({ previousMeta: first.meta, previous: parseIndex(first.indexText), now: new Date(NOW.getTime() + 86400000) })
  assert.equal(next.meta.generation, 2)
  assert.equal(next.meta.versions, 2)
})

test('packages.json gains compatibility and per-version impact fields', async () => {
  const { build } = harness({
    remote: new Map([['0.1.0', A]]),
    findings: [finding('info')],
    scan: async () => ({ findings: [], incompatibleWith: ['gadgets'], breaksDependents: ['users'] }),
  })
  const result = await build()
  assert.deepEqual(result.packages[0].versions[0].incompatibleWith, ['gadgets'])
  assert.deepEqual(result.packages[0].versions[0].breaksDependents, ['users'])
  const again = await build({ previous: parseIndex(result.indexText), previousCatalogue: JSON.parse(JSON.stringify(result.packages)) })
  assert.deepEqual(again.packages[0].versions[0].incompatibleWith, ['gadgets'])
})

test('issue text names the findings and the exact approval line', () => {
  const record = { name: 'widgets', version: '0.1.0', commit: A, severity: 'review', firstSeen: NOW.toISOString(), findings: [finding('review', 'external-code')], breaksDependents: ['users'] }
  assert.equal(issueTitle(record), 'Needs review: widgets 0.1.0')
  const body = issueBody(record)
  assert.match(body, /\| review \| external-code \|/)
  assert.ok(body.includes(`    widgets 0.1.0 ${A}`))
  assert.match(body, /approvals.txt/)
  assert.match(body, /users/)
  const blocked = issueBody({ ...record, severity: 'block' })
  assert.match(blocked, /can never be approved/)
  assert.ok(!blocked.includes(`    widgets 0.1.0 ${A}`))
})

test('issues are opened once and closed when the version is no longer held back', async () => {
  const record = { name: 'widgets', version: '0.1.0', commit: A, severity: 'review', firstSeen: NOW.toISOString(), findings: [] }
  const first = planIssues({ quarantine: [record], allIssues: [], openIssues: [] })
  assert.equal(first.create.length, 1)
  assert.equal(first.create[0].label, ISSUE_LABEL)
  const existing = [{ number: 5, title: 'Needs review: widgets 0.1.0' }]
  assert.deepEqual(planIssues({ quarantine: [record], allIssues: existing, openIssues: existing }), { create: [], close: [] })
  const closed = planIssues({ quarantine: [], allIssues: existing, openIssues: existing })
  assert.equal(closed.close[0].number, 5)
  const unavailable = planIssues({ quarantine: [], allIssues: [], openIssues: [], unavailable: [{ name: 'gone', repository: 'https://github.com/o/gone', since: 'x' }] })
  assert.equal(unavailable.create[0].title, 'Repository unavailable: gone')
  const calls = []
  await applyPlan({ plan: { create: first.create, close: closed.close }, gh: async (args, input) => calls.push({ args, input }) })
  assert.equal(calls[0].args[0], 'issue')
  assert.ok(calls[0].input.includes('approvals.txt'))
  assert.equal(calls[1].args[2], '5')
})

const roots = []
after(() => roots.forEach((path) => rmSync(path, { recursive: true, force: true })))

test('end to end with the real compiler: clean publishes, external is held, approval releases', { skip: SKIP_COMPILER }, async () => {
  const root = tempDirectory()
  roots.push(root)
  const clean = makeRepository(root, 'cleanpkg', packageFiles('cleanpkg', CLEAN_SOURCE))
  const risky = makeRepository(root, 'riskypkg', packageFiles('riskypkg', `${CLEAN_SOURCE.replace('clean_double', 'risky_double')}\nexternal C func risky_call(a int32) int32\n    return a;\nend external\n`))
  const entries = [entryFor('cleanpkg', clean.directory), entryFor('riskypkg', risky.directory)]
  const run = (extra = {}) =>
    buildGatedIndex({
      entries,
      previous: new Map(),
      policy,
      compiler: '0.1.4',
      resolveVersions: listRemoteVersions,
      scan: (options) => scanPackage({ ...options, sarlinPath: SARLIN_BIN, policy, workDir: root }),
      health: (options) => compileCheck({ ...options, sarlinPath: SARLIN_BIN, policy, workDir: root }),
      ...extra,
    })
  const first = await run()
  assert.match(first.indexText, /cleanpkg 0.1.0/)
  assert.ok(!first.indexText.includes('riskypkg'))
  assert.equal(first.quarantine[0].name, 'riskypkg')
  assert.ok(first.quarantine[0].findings.some((item) => item.id === 'external-code'))
  assert.equal(first.health[0].status, 'ok')
  const second = await run({ approvals: new Set([`riskypkg 0.1.0 ${risky.commit}`]), previous: parseIndex(first.indexText) })
  assert.match(second.indexText, /riskypkg 0.1.0/)
  assert.deepEqual(second.quarantine, [])
  const third = await run({ previous: parseIndex(second.indexText) })
  assert.equal(third.indexText, second.indexText)
  addRelease(clean.directory, { 'README.md': '# v2\n' }, 'v0.1.1')
  const fourth = await run({ previous: parseIndex(second.indexText) })
  assert.match(fourth.indexText, /cleanpkg 0.1.1/, JSON.stringify(fourth.quarantine))
})

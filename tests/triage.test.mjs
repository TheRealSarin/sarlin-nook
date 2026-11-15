import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  LABELS,
  MARKER,
  checkAccount,
  checkDraft,
  checkDuplicate,
  checkEntryChange,
  checkIdentity,
  checkNames,
  checkRates,
  checkRepository,
  checkRepositoryIdentity,
  checkScanResult,
  checkScope,
  decide,
  renderComment,
  runTriage,
} from '../scripts/triage.mjs'
import { createFakeGitHub } from './fake-github.mjs'

const policy = JSON.parse(readFileSync(new URL('../policy.json', import.meta.url), 'utf8'))
const NOW = Date.parse('2026-06-01T00:00:00Z')
const SHA = 'a'.repeat(40)
const COMMIT = 'c'.repeat(40)

const entryText = (name, owner, extra = '') => `name: ${name}\nrepository: https://github.com/${owner}/${name}\ndescription: A test package\nlicense: MIT\n${extra}`
const status = (checks, title) => checks.find((check) => check.title === title)?.status

function setup({ author = 'alice', name = 'widgets', repoOwner = author, accountDays = 400, prior = 1, repoDays = 100, repoExtra = {}, filesOverride, texts, association = 'CONTRIBUTOR', versions, scan, listed = [], extraPulls = [] } = {}) {
  const fake = createFakeGitHub()
  fake.addUser(author, accountDays, NOW)
  fake.addRepository(`${repoOwner}/${name}`, { now: NOW, daysOld: repoDays, ...repoExtra })
  const path = `packages/${name}.package`
  fake.addPull(7, {
    author,
    sha: SHA,
    association,
    files: filesOverride ?? [{ filename: path, status: 'added' }],
    texts: texts ?? { [path]: entryText(name, repoOwner) },
  })
  for (let index = 0; index < prior; index += 1) {
    fake.state.pulls.set(100 + index, { number: 100 + index, state: 'closed', summary: { number: 100 + index, state: 'closed', user: { login: author }, created_at: '2026-01-01T00:00:00Z', merged_at: '2026-01-02T00:00:00Z' } })
  }
  for (const [index, pull] of extraPulls.entries()) fake.state.pulls.set(200 + index, { number: 200 + index, summary: pull })
  const deps = fake.deps({ listed, versions: versions ?? new Map([['0.1.0', COMMIT]]), scan })
  return { fake, deps, run: () => runTriage({ api: fake.api, repo: fake.state.repo, number: 7, expectedSha: SHA, policy, deps, now: NOW }) }
}

const labelsOf = (fake) => [...(fake.state.issueLabels.get(7) ?? [])]
const bodyOf = (fake) => fake.state.comments.get(7)[0].body

test('scope passes only for added or modified package entries', () => {
  assert.equal(checkScope([{ filename: 'packages/a_b.package', status: 'added' }]).status, 'pass')
  for (const file of [
    { filename: '.github/workflows/index.yml', status: 'modified' },
    { filename: 'scripts/lib.mjs', status: 'modified' },
    { filename: 'policy.json', status: 'modified' },
    { filename: 'approvals.txt', status: 'modified' },
    { filename: 'yanked.txt', status: 'added' },
    { filename: 'packages/a.package', status: 'removed' },
    { filename: 'packages/a.package', status: 'renamed' },
    { filename: 'packages/sub/a.package', status: 'added' },
    { filename: 'packages/a.txt', status: 'added' },
  ]) {
    assert.equal(checkScope([file]).status, 'review', JSON.stringify(file))
  }
  assert.equal(checkScope([]).status, 'review')
})

test('entry validity blocks bad entries and reviews a changed repository', () => {
  const good = entryText('widgets', 'alice')
  assert.equal(checkEntryChange({ fileName: 'widgets.package', text: good, baseText: null }).outcome.status, 'pass')
  assert.equal(checkEntryChange({ fileName: 'other.package', text: good, baseText: null }).outcome.status, 'block')
  assert.equal(checkEntryChange({ fileName: 'widgets.package', text: 'junk', baseText: null }).outcome.status, 'block')
  assert.equal(checkEntryChange({ fileName: 'widgets.package', text: null, baseText: null }).outcome.status, 'block')
  const hijack = checkEntryChange({ fileName: 'widgets.package', text: entryText('widgets', 'mallory'), baseText: good })
  assert.equal(hijack.outcome.status, 'review')
  assert.match(hijack.outcome.message, /changing where a name points/)
  assert.equal(checkEntryChange({ fileName: 'widgets.package', text: good.replace('A test', 'Another'), baseText: good }).outcome.status, 'pass')
})

test('author identity compares the author with the repository owner', () => {
  const entry = { repository: 'https://github.com/Alice/widgets' }
  assert.equal(checkIdentity({ author: 'alice', entry, policy }).status, 'pass')
  assert.equal(checkIdentity({ author: 'bob', entry, policy }).status, 'review')
  assert.equal(checkIdentity({ author: 'TheRealSarin', entry, policy }).status, 'pass')
})

test('author account needs age and a prior merged pull request unless trusted', () => {
  const old = { created_at: new Date(NOW - 400 * 86400000).toISOString() }
  const young = { created_at: new Date(NOW - 10 * 86400000).toISOString() }
  const base = { author: 'alice', association: 'NONE', policy, now: NOW }
  assert.equal(checkAccount({ ...base, user: old, priorMerged: 1 }).status, 'pass')
  assert.equal(checkAccount({ ...base, user: young, priorMerged: 1 }).status, 'review')
  const first = checkAccount({ ...base, user: old, priorMerged: 0 })
  assert.equal(first.status, 'review')
  assert.match(first.message, /first contribution/)
  const trusted = checkAccount({ ...base, author: 'TheRealSarin', user: young, priorMerged: 0 })
  assert.equal(trusted.status, 'info')
})

test('package repository checks existence, visibility, archive, fork, age and license', () => {
  const entry = { license: 'MIT' }
  const repo = { private: false, archived: false, fork: false, created_at: new Date(NOW - 30 * 86400000).toISOString(), license: { spdx_id: 'MIT' } }
  const check = (changes, entryChanges = {}) => checkRepository({ entry: { ...entry, ...entryChanges }, repo: changes === null ? null : { ...repo, ...changes }, policy, now: NOW })
  assert.equal(check({}).status, 'pass')
  assert.equal(check(null).status, 'block')
  assert.equal(check({ private: true }).status, 'block')
  assert.equal(check({ archived: true }).status, 'review')
  assert.equal(check({ fork: true }).status, 'review')
  assert.equal(check({ created_at: new Date(NOW - 2 * 86400000).toISOString() }).status, 'review')
  assert.equal(check({ license: null }, { license: undefined }).status, 'review')
  assert.equal(check({ license: null }, { license: 'MIT' }).status, 'pass')
  assert.equal(check({ license: { spdx_id: 'GPL-3.0' } }).status, 'review')
  assert.equal(check({ license: { spdx_id: 'NOASSERTION' } }, { license: undefined }).status, 'review')
})

test('repository identity reviews a renamed or transferred repository', () => {
  const entry = { repository: 'https://github.com/alice/widgets' }
  assert.equal(checkRepositoryIdentity({ entry, repo: { full_name: 'Alice/Widgets', owner: { type: 'Organization' } } }).status, 'info')
  assert.equal(checkRepositoryIdentity({ entry, repo: { full_name: 'bob/widgets' } }).status, 'review')
})

test('name safety blocks reserved names and punctuation twins, reviews close names', () => {
  const run = (name, listedNames = []) => checkNames({ entry: { name }, listedNames, policy })
  assert.equal(run('csv', ['svg']).status, 'pass')
  assert.equal(run('std').status, 'block')
  assert.equal(run('sarlin_lang').status, 'block')
  assert.equal(run('my_widget', ['mywidget']).status, 'block')
  assert.equal(run('widgetz', ['widgets']).status, 'review')
  assert.equal(run('widgest', ['widgets']).status, 'review')
  assert.equal(run('stdlibs').status, 'review')
  assert.equal(run('widgets', ['widgets']).status, 'pass')
  assert.equal(run('totally_new').status, 'pass')
})

test('a trusted user may claim a reserved name and nobody else may', () => {
  const run = (author) => checkNames({ entry: { name: 'acras' }, listedNames: [], policy, author })
  assert.equal(run('TheRealSarin').status, 'info')
  assert.equal(run('thereal sarin').status, 'block')
  assert.equal(run('mallory').status, 'block')
  assert.equal(run('').status, 'block')
})

test('duplicate repositories under another name are blocked', () => {
  const listed = [{ name: 'first', repository: 'https://github.com/o/first' }]
  assert.equal(checkDuplicate({ entry: { name: 'second', repository: 'https://github.com/O/First' }, listed }).status, 'block')
  assert.equal(checkDuplicate({ entry: { name: 'first', repository: 'https://github.com/o/first' }, listed }).status, 'pass')
})

test('scan results map to block, review and pass', () => {
  const make = (...severities) => ({ findings: severities.map((severity) => ({ id: 'x', severity, message: 'm' })) })
  assert.equal(checkScanResult({ name: 'a', version: '1.0.0', scan: make('info') }).status, 'pass')
  assert.equal(checkScanResult({ name: 'a', version: '1.0.0', scan: make('info', 'review') }).status, 'review')
  assert.equal(checkScanResult({ name: 'a', version: '1.0.0', scan: make('review', 'block') }).status, 'block')
})

test('rate limits cover open pull requests, young accounts and many entries', () => {
  const open = Array.from({ length: 4 }, (_, index) => ({ number: 50 + index, state: 'open', user: { login: 'bob' }, created_at: new Date(NOW - 10 * 86400000).toISOString() }))
  const user = { created_at: new Date(NOW - 400 * 86400000).toISOString() }
  const base = { author: 'bob', number: 1, filesAdded: 1, user, policy, now: NOW }
  assert.equal(checkRates({ ...base, pulls: open }).status, 'review')
  assert.equal(checkRates({ ...base, pulls: open.slice(0, 3) }).status, 'pass')
  assert.equal(checkRates({ ...base, pulls: [], filesAdded: 3 }).status, 'review')
  const recent = Array.from({ length: 3 }, (_, index) => ({ number: 60 + index, state: 'closed', user: { login: 'bob' }, created_at: new Date(NOW - 3600000).toISOString() }))
  assert.equal(checkRates({ ...base, pulls: recent, user: { created_at: new Date(NOW - 5 * 86400000).toISOString() } }).status, 'review')
  assert.equal(checkRates({ ...base, pulls: recent }).status, 'pass')
  assert.equal(checkRates({ ...base, author: 'TheRealSarin', pulls: open, filesAdded: 9 }).status, 'pass')
})

test('draft pull requests are not merged and decisions follow the worst check', () => {
  assert.equal(checkDraft({ draft: true }).status, 'review')
  assert.equal(decide([{ status: 'pass' }, { status: 'info' }]), 'approve')
  assert.equal(decide([{ status: 'pass' }, { status: 'review' }]), 'review')
  assert.equal(decide([{ status: 'review' }, { status: 'block' }]), 'reject')
})

test('a trusted owner with a clean package is approved, merged and the index dispatched', async () => {
  const { fake, run } = setup({ author: 'TheRealSarin', name: 'gadgets', accountDays: 900, prior: 0, association: 'OWNER' })
  const outcome = await run()
  assert.equal(outcome.decision, 'approve')
  assert.deepEqual(fake.state.merged, [{ number: 7, sha: SHA }])
  assert.equal(fake.state.dispatched, 1)
  assert.deepEqual(labelsOf(fake), [LABELS.approve.name])
  assert.ok(bodyOf(fake).startsWith(MARKER))
  assert.match(bodyOf(fake), /merged automatically/)
})

test('an established author with their own clean package is approved', async () => {
  const { fake, run } = setup()
  assert.equal((await run()).decision, 'approve')
  assert.equal(fake.state.merged.length, 1)
})

test('a first contribution needs manual review and is not merged', async () => {
  const { fake, run } = setup({ prior: 0 })
  const outcome = await run()
  assert.equal(outcome.decision, 'review')
  assert.equal(fake.state.merged.length, 0)
  assert.equal(fake.state.dispatched, 0)
  assert.deepEqual(labelsOf(fake), [LABELS.review.name])
  assert.match(bodyOf(fake), /first contribution/)
})

test('a young account needs manual review', async () => {
  const { run } = setup({ accountDays: 5 })
  const outcome = await run()
  assert.equal(outcome.decision, 'review')
  assert.equal(status(outcome.checks, 'Author account'), 'review')
})

test('a package owned by someone else needs manual review', async () => {
  const { run, fake } = setup({ repoOwner: 'carol' })
  const outcome = await run()
  assert.equal(outcome.decision, 'review')
  assert.equal(status(outcome.checks, 'Author identity'), 'review')
  assert.equal(fake.state.merged.length, 0)
})

test('a fork needs manual review', async () => {
  const { run } = setup({ repoExtra: { fork: true } })
  const outcome = await run()
  assert.equal(outcome.decision, 'review')
  assert.equal(status(outcome.checks, 'Package repository'), 'review')
})

test('a young repository needs manual review', async () => {
  const { run } = setup({ repoDays: 2 })
  assert.equal((await run()).decision, 'review')
})

test('a typosquat of an existing package needs manual review', async () => {
  const listed = [{ name: 'widgets', repository: 'https://github.com/zed/widgets', fileName: 'widgets.package', text: '' }]
  const { run } = setup({ name: 'widgetz', listed })
  const outcome = await run()
  assert.equal(outcome.decision, 'review')
  assert.equal(status(outcome.checks, 'Name safety'), 'review')
})

test('a reserved name is rejected', async () => {
  const { run, fake } = setup({ name: 'stdlib' })
  const outcome = await run()
  assert.equal(outcome.decision, 'reject')
  assert.deepEqual(labelsOf(fake), [LABELS.reject.name])
})

test('changing the repository of an existing entry is a hijack attempt and needs review', async () => {
  const listed = [{ name: 'widgets', fileName: 'widgets.package', repository: 'https://github.com/alice/widgets', text: entryText('widgets', 'alice') }]
  const path = 'packages/widgets.package'
  const { run, fake } = setup({
    filesOverride: [{ filename: path, status: 'modified' }],
    texts: { [path]: entryText('widgets', 'mallory') },
    listed,
    repoOwner: 'mallory',
    author: 'mallory',
  })
  const outcome = await run()
  assert.equal(outcome.decision, 'review')
  assert.equal(status(outcome.checks, 'Entry'), 'review')
  assert.equal(fake.state.merged.length, 0)
})

test('files outside packages need review even for the trusted owner', async () => {
  const { run, fake } = setup({
    author: 'TheRealSarin',
    name: 'gadgets',
    filesOverride: [{ filename: 'packages/gadgets.package', status: 'added' }, { filename: '.github/workflows/index.yml', status: 'modified' }],
  })
  const outcome = await run()
  assert.equal(outcome.decision, 'review')
  assert.equal(status(outcome.checks, 'Scope'), 'review')
  assert.equal(fake.state.merged.length, 0)
})

test('an invalid entry is rejected', async () => {
  const path = 'packages/widgets.package'
  const { run } = setup({ texts: { [path]: 'name: widgets\nrepository: not-a-url\n' } })
  const outcome = await run()
  assert.equal(outcome.decision, 'reject')
  assert.equal(status(outcome.checks, 'Entry'), 'block')
})

test('a blocking scan finding rejects the pull request', async () => {
  const scan = async () => ({ findings: [{ id: 'secret', severity: 'block', message: 'a.txt:1 looks like a secret' }] })
  const { run, fake } = setup({ scan })
  const outcome = await run()
  assert.equal(outcome.decision, 'reject')
  assert.match(bodyOf(fake), /block: secret/)
  assert.equal(fake.state.merged.length, 0)
})

test('a review scan finding needs manual review', async () => {
  const scan = async () => ({ findings: [{ id: 'external-code', severity: 'review', message: 'native code' }] })
  const { run } = setup({ scan })
  assert.equal((await run()).decision, 'review')
})

test('a repository without version tags is rejected and unreadable tags are reported', async () => {
  const none = setup({ versions: new Map() })
  assert.equal((await none.run()).decision, 'reject')
  const fake = createFakeGitHub()
  const broken = setup()
  broken.deps.listVersions = async () => {
    throw new Error('network down')
  }
  assert.equal((await broken.run()).decision, 'reject')
  assert.ok(fake)
})

test('the same repository under another name is rejected', async () => {
  const listed = [{ name: 'other', repository: 'https://github.com/alice/widgets', fileName: 'other.package', text: '' }]
  const { run } = setup({ listed })
  const outcome = await run()
  assert.equal(outcome.decision, 'reject')
  assert.equal(status(outcome.checks, 'Duplicate repository'), 'block')
})

test('a missing package repository is rejected', async () => {
  const { run, fake } = setup()
  fake.state.repos.clear()
  assert.equal((await run()).decision, 'reject')
})

test('the sticky comment is updated in place and not rewritten when unchanged', async () => {
  const { run, fake } = setup({ prior: 0 })
  await run()
  await run()
  const comments = fake.state.comments.get(7)
  assert.equal(comments.length, 1)
  assert.equal(fake.state.calls.filter((call) => call.startsWith('PATCH')).length, 0)
  fake.state.comments.get(7)[0].body = `${MARKER}\nold`
  await run()
  assert.equal(fake.state.comments.get(7).length, 1)
  assert.equal(fake.state.calls.filter((call) => call.startsWith('PATCH')).length, 1)
  assert.match(fake.state.comments.get(7)[0].body, /Nook triage/)
})

test('labels are created when missing and swapped when the decision changes', async () => {
  const { run, fake } = setup({ prior: 0 })
  await run()
  assert.deepEqual([...fake.state.labels.keys()].sort(), ['auto-approved', 'needs-manual-review', 'rejected-by-checks'])
  assert.equal(fake.state.labels.get('needs-manual-review').color, 'fbca04')
  const posts = fake.state.calls.filter((call) => call.startsWith('POST') && call.endsWith('/labels')).length
  await run()
  assert.equal(fake.state.calls.filter((call) => call.startsWith('POST') && call.endsWith('/labels')).length, posts)
  fake.state.issueLabels.set(7, new Set(['rejected-by-checks']))
  await run()
  assert.deepEqual(labelsOf(fake), ['needs-manual-review'])
})

test('a failed merge becomes a manual review', async () => {
  const { run, fake } = setup()
  fake.state.mergeError = 'conflicts'
  const outcome = await run()
  assert.equal(outcome.decision, 'review')
  assert.equal(fake.state.dispatched, 0)
  assert.match(bodyOf(fake), /automatic merge failed: conflicts/)
})

test('a moved head or a closed pull request is skipped without changes', async () => {
  const { fake, deps } = setup()
  const moved = await runTriage({ api: fake.api, repo: fake.state.repo, number: 7, expectedSha: 'b'.repeat(40), policy, deps, now: NOW })
  assert.match(moved.skipped, /head moved/)
  fake.state.pulls.get(7).state = 'closed'
  const closed = await runTriage({ api: fake.api, repo: fake.state.repo, number: 7, expectedSha: SHA, policy, deps, now: NOW })
  assert.match(closed.skipped, /not open/)
  assert.equal(fake.state.comments.size, 0)
})

test('a draft pull request is never merged', async () => {
  const { run, fake } = setup()
  fake.state.pulls.get(7).draft = true
  const outcome = await run()
  assert.equal(outcome.decision, 'review')
  assert.equal(fake.state.merged.length, 0)
})

test('hostile text is neutralised and the comment is plain ASCII', () => {
  const checks = [{ title: 'Scope', status: 'review', message: 'bad @everyone <script>|`x`‮ café', details: [{ id: 'x', severity: 'review', message: '@admin | pipe' }] }]
  const body = renderComment({ decision: 'review', checks, sha: SHA })
  assert.ok(/^[\x20-\x7e\n]*$/.test(body))
  assert.ok(!body.includes('@everyone') && !body.includes('<script>'))
  assert.ok(body.startsWith(MARKER))
  for (const decision of ['approve', 'review', 'reject']) {
    assert.match(renderComment({ decision, checks, sha: SHA }), /What you can do next/)
  }
})

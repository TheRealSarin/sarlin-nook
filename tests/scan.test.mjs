import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { rmSync } from 'node:fs'
import { after, test } from 'node:test'

import { checkBinary, checkEntries, newVersions, scanPackage, scanVersionRange } from '../scripts/scan.mjs'
import { parseIndex } from '../scripts/lib.mjs'
import {
  CLEAN_SOURCE,
  SARLIN_BIN,
  SKIP_COMPILER,
  addRelease,
  entryFor,
  git,
  makeRepository,
  packageFiles,
  tempDirectory,
} from './helpers.mjs'

const policy = JSON.parse(readFileSync(new URL('../policy.json', import.meta.url), 'utf8'))
const root = tempDirectory()
after(() => rmSync(root, { recursive: true, force: true }))

let counter = 0
async function scanFixture(files, { name = `pkg${(counter += 1)}`, tune = {}, tag = 'v0.1.0', entryExtra = {}, listed = [] } = {}) {
  const prefixed = packageFiles(name, CLEAN_SOURCE, files)
  const { directory, commit } = makeRepository(root, name, prefixed, tag)
  const entry = entryFor(name, directory, entryExtra)
  const scan = await scanPackage({
    entry,
    version: tag.slice(1),
    commit,
    sarlinPath: SARLIN_BIN,
    policy: { ...policy, ...tune },
    listedPackages: listed,
  })
  return { scan, ids: scan.findings.map((item) => item.id), entry, directory, commit }
}

const severities = (scan) => scan.findings.filter((item) => item.severity !== 'info').map((item) => `${item.severity}:${item.id}`)

test('checkEntries applies file count, size, symlink, submodule and path limits', () => {
  const entries = [
    { path: 'a', type: 'file', size: 60 },
    { path: 'b', type: 'file', size: 60 },
    { path: 'l', type: 'symlink', size: 0 },
    { path: 'm', type: 'submodule', size: 0 },
    { path: '../x', type: 'file', size: 1 },
  ]
  const ids = checkEntries(entries, { ...policy, maximumFileCount: 2, maximumPackageBytes: 100 }).map((item) => item.id)
  assert.deepEqual(ids.sort(), ['bad-path', 'file-count', 'package-size', 'submodule', 'symlink'])
  assert.deepEqual(checkEntries(entries.slice(0, 1), policy), [])
})

test('checkBinary allows small images with the right signature only', () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0])
  assert.deepEqual(checkBinary({ path: 'a.png', size: 100, bytes: png, policy }), [])
  assert.equal(checkBinary({ path: 'a.png', size: 300000, bytes: png, policy }).length, 1)
  assert.equal(checkBinary({ path: 'a.png', size: 8, bytes: Buffer.from('text'), policy }).length, 1)
  assert.equal(checkBinary({ path: 'a.bin', size: 8, bytes: Buffer.from([1, 0, 2]), policy }).length, 1)
  assert.deepEqual(checkBinary({ path: 'a.txt', size: 4, bytes: Buffer.from('text'), policy }), [])
})

test('newVersions lists only versions missing from the previous index', () => {
  const previous = parseIndex(`nook-index 1\nacras 0.1.0 https://github.com/o/acras ${'a'.repeat(40)}\n`)
  const remote = new Map([['0.1.0', 'b'.repeat(40)], ['0.2.0', 'c'.repeat(40)]])
  const entry = { name: 'acras', repository: 'https://github.com/o/acras' }
  assert.deepEqual(newVersions(entry, remote, previous), [{ version: '0.2.0', commit: 'c'.repeat(40) }])
  assert.equal(newVersions({ ...entry, repository: 'https://github.com/x/acras' }, remote, previous).length, 2)
})

test('a clean package has no block or review findings', { skip: SKIP_COMPILER }, async () => {
  const { scan } = await scanFixture({})
  assert.deepEqual(severities(scan), [])
  assert.ok(scan.findings.some((item) => item.id === 'statistics'))
  assert.ok(scan.scanned)
})

test('external blocks are reviewed and risky calls are reported', { skip: SKIP_COMPILER }, async () => {
  const name = 'extpkg'
  const source = `${CLEAN_SOURCE}\nexternal C func run_it(a int32) int32\n    system("ls");\n    return a;\nend external\n`
  const { scan } = await scanFixture({ [`source/${name}.sar`]: source }, { name })
  assert.deepEqual(severities(scan).sort(), ['review:external-code', 'review:foreign-pattern'])
  assert.ok(scan.capabilities.includes('foreign_code'))
  assert.match(scan.findings.find((item) => item.id === 'external-code').message, /run_it \(C/)
})

test('a package that defines func main is blocked', { skip: SKIP_COMPILER }, async () => {
  const name = 'mainpkg'
  const { scan, ids } = await scanFixture({ [`source/${name}.sar`]: `${CLEAN_SOURCE}func main() {\n}\n` }, { name })
  assert.ok(ids.includes('main-defined'))
  assert.ok(scan.findings.some((item) => item.severity === 'block'))
})

test('a symbolic link is blocked', { skip: SKIP_COMPILER }, async () => {
  const { scan, ids } = await scanFixture({ 'docs/link': { symlink: '/etc/passwd' } })
  assert.ok(ids.includes('symlink'))
  assert.ok(scan.findings.every((item) => item.severity !== 'review' || item.id !== 'external-code'))
})

test('a secret is blocked and never printed', { skip: SKIP_COMPILER }, async () => {
  const token = `ghp_${'b'.repeat(36)}`
  const { scan } = await scanFixture({ 'notes.txt': `token ${token}\n` })
  const secret = scan.findings.find((item) => item.id === 'secret')
  assert.equal(secret.severity, 'block')
  assert.ok(!JSON.stringify(scan).includes(token))
})

test('Network use needs review', { skip: SKIP_COMPILER }, async () => {
  const name = 'netpkg'
  const source = `${CLEAN_SOURCE}\nfunc net_open() Connection {\n    return Network.connect("h.test", 80)\n}\n`
  const { scan } = await scanFixture({ [`source/${name}.sar`]: source }, { name })
  assert.ok(severities(scan).includes('review:network'), JSON.stringify(scan.findings))
})

test('a require that is not listed is blocked', { skip: SKIP_COMPILER }, async () => {
  const name = 'reqpkg'
  const { ids } = await scanFixture({ 'sarlin.project': `name: ${name}\nentry: source/${name}.sar\nlanguage: 1\nrequire: ghost 1.0.0\n` }, { name })
  assert.ok(ids.includes('bad-require'))
  assert.ok(ids.includes('check-failed'))
})

test('an oversized package is blocked by the policy', { skip: SKIP_COMPILER }, async () => {
  const { ids } = await scanFixture({ 'big.txt': 'x'.repeat(5000) }, { tune: { maximumPackageBytes: 1000 } })
  assert.ok(ids.includes('package-size'))
  const many = await scanFixture({}, { tune: { maximumFileCount: 2 } })
  assert.ok(many.ids.includes('file-count'))
})

test('a binary blob is blocked and a real image is allowed', { skip: SKIP_COMPILER }, async () => {
  const { ids } = await scanFixture({ 'data.bin': Buffer.from([1, 2, 0, 3, 4]) })
  assert.ok(ids.includes('binary-file'))
  const png = await scanFixture({ 'logo.png': Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 0]) })
  assert.ok(!png.ids.includes('binary-file'))
})

test('hidden bidirectional characters are blocked', { skip: SKIP_COMPILER }, async () => {
  const name = 'bidipkg'
  const source = `${CLEAN_SOURCE}\nfunc shown() string {\n    return "a${String.fromCodePoint(0x202e)}b"\n}\n`
  const { ids } = await scanFixture({ [`source/${name}.sar`]: source }, { name })
  assert.ok(ids.includes('hidden-characters'))
})

test('missing license, README and tests are reported', { skip: SKIP_COMPILER }, async () => {
  const name = 'barepkg'
  const directory = tempDirectory()
  const files = { 'sarlin.project': `name: ${name}\nentry: source/${name}.sar\nlanguage: 1\n`, [`source/${name}.sar`]: CLEAN_SOURCE }
  const { directory: repository, commit } = makeRepository(directory, name, files)
  const scan = await scanPackage({ entry: entryFor(name, repository), version: '0.1.0', commit, sarlinPath: SARLIN_BIN, policy, listedPackages: [] })
  const ids = scan.findings.map((item) => item.id)
  for (const id of ['no-license', 'no-readme', 'no-tests']) assert.ok(ids.includes(id), id)
  rmSync(directory, { recursive: true, force: true })
})

test('a tag that is not reachable from the default branch needs review', { skip: SKIP_COMPILER }, async () => {
  const name = 'orphanpkg'
  const { directory } = makeRepository(root, name, packageFiles(name, CLEAN_SOURCE), null)
  git(directory, 'checkout', '--quiet', '--orphan', 'side')
  git(directory, 'commit', '--quiet', '--allow-empty', '-m', 'dangling')
  git(directory, 'tag', 'v0.1.0')
  const commit = git(directory, 'rev-parse', 'HEAD')
  git(directory, 'checkout', '--quiet', 'main')
  const scan = await scanPackage({ entry: entryFor(name, directory), version: '0.1.0', commit, sarlinPath: SARLIN_BIN, policy, listedPackages: [] })
  assert.ok(scan.findings.some((item) => item.id === 'tag-unreachable'))
})

test('history rewrites, capability escalation, jumps and back-dating are detected', { skip: SKIP_COMPILER }, async () => {
  const name = 'evolve'
  const { directory, commit: first } = makeRepository(root, name, packageFiles(name, CLEAN_SOURCE))
  const network = `${CLEAN_SOURCE}\nfunc net_open() Connection {\n    return Network.connect("h.test", 80)\n}\n`
  const second = addRelease(directory, { [`source/${name}.sar`]: network }, 'v0.2.0')
  const entry = entryFor(name, directory)
  const options = { entry, sarlinPath: SARLIN_BIN, policy, listedPackages: [] }
  const good = await scanPackage({ ...options, version: '0.2.0', commit: second, published: [{ version: '0.1.0', commit: first }] })
  const ids = good.findings.map((item) => item.id)
  assert.ok(ids.includes('capability-escalation'))
  assert.ok(!ids.includes('history-rewrite'))
  const rewritten = await scanPackage({ ...options, version: '0.2.0', commit: second, published: [{ version: '0.1.0', commit: 'f'.repeat(40) }] })
  assert.ok(rewritten.findings.some((item) => item.id === 'history-rewrite'))
  const lower = await scanPackage({ ...options, version: '0.2.0', commit: second, published: [{ version: '0.3.0', commit: first }] })
  assert.ok(lower.findings.some((item) => item.id === 'back-dated-tag'))
  const jump = await scanPackage({ ...options, version: '0.2.0', commit: second, published: [{ version: '0.1.0', commit: first }], policy: { ...policy, maximumMinorJump: 0 } })
  assert.ok(jump.findings.some((item) => item.id === 'version-jump'))
})

test('collisions with another listed package need review and are recorded', { skip: SKIP_COMPILER }, async () => {
  const other = makeRepository(root, 'otherpkg', packageFiles('otherpkg', CLEAN_SOURCE))
  const listed = [{ name: 'otherpkg', repository: other.directory, versions: [{ version: '0.1.0', commit: other.commit }] }]
  const { scan } = await scanFixture({}, { name: 'twinpkg', listed })
  assert.ok(scan.findings.some((item) => item.id === 'collision' && /otherpkg/.test(item.message)))
  assert.deepEqual(scan.incompatibleWith, ['otherpkg'])
  assert.ok(scan.findings.some((item) => item.id === 'incompatible-with'))
})

test('a possible clone of another owner is flagged', { skip: SKIP_COMPILER }, async () => {
  const other = makeRepository(root, 'sourcepkg', packageFiles('sourcepkg', CLEAN_SOURCE))
  const listed = [{ name: 'sourcepkg', repository: 'https://github.com/alice/sourcepkg', versions: [{ version: '0.1.0', commit: other.commit }] }]
  const listedLocal = [{ ...listed[0], repository: other.directory }]
  const { scan } = await scanFixture({}, { name: 'copypkg', listed: listedLocal, entryExtra: {} })
  assert.ok(!scan.findings.some((item) => item.id === 'possible-clone'))
})

test('scanVersionRange scans only versions missing from the previous index', { skip: SKIP_COMPILER }, async () => {
  const name = 'ranged'
  const { directory, commit: first } = makeRepository(root, name, packageFiles(name, CLEAN_SOURCE))
  const second = addRelease(directory, { 'README.md': '# changed\n' }, 'v0.1.1')
  const previous = parseIndex(`nook-index 1\n${name} 0.1.0 ${directory} ${first}\n`)
  const results = await scanVersionRange({
    entry: entryFor(name, directory),
    versions: [{ version: '0.1.0', commit: first }, { version: '0.1.1', commit: second }],
    previous,
    sarlinPath: SARLIN_BIN,
    policy,
    listedPackages: [],
  })
  assert.deepEqual(results.map((item) => item.version), ['0.1.1'])
  assert.deepEqual(results[0].scan.findings.filter((item) => item.severity !== 'info'), [])
})

test('a missing compiler binary is reported clearly', async () => {
  const name = 'nobin'
  const { directory, commit } = makeRepository(root, name, packageFiles(name, CLEAN_SOURCE))
  await assert.rejects(
    scanPackage({ entry: entryFor(name, directory), version: '0.1.0', commit, sarlinPath: '/nonexistent/sarlin', policy, listedPackages: [] }),
    /was not found/,
  )
})

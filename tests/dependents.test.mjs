import assert from 'node:assert/strict'
import { readFileSync, rmSync } from 'node:fs'
import { after, test } from 'node:test'

import { checkDependentImpact, claimsCompatibility, rewriteRequire } from '../scripts/dependents.mjs'
import { scanPackage } from '../scripts/scan.mjs'
import { SARLIN_BIN, SKIP_COMPILER, addRelease, entryFor, makeRepository, packageFiles, tempDirectory } from './helpers.mjs'

const policy = JSON.parse(readFileSync(new URL('../policy.json', import.meta.url), 'utf8'))
const roots = []
after(() => roots.forEach((path) => rmSync(path, { recursive: true, force: true })))

test('compatibility is claimed for same-major bumps, and for patch bumps below 1.0.0', () => {
  assert.ok(claimsCompatibility('1.2.0', '1.1.0'))
  assert.ok(claimsCompatibility('1.0.1', '1.0.0'))
  assert.ok(!claimsCompatibility('2.0.0', '1.9.0'))
  assert.ok(claimsCompatibility('0.1.1', '0.1.0'))
  assert.ok(!claimsCompatibility('0.2.0', '0.1.0'))
  assert.ok(!claimsCompatibility('1.0.0', '1.1.0'))
})

test('rewriteRequire substitutes only the named package', () => {
  const text = 'name: u\nrequire: base 0.1.0\nrequire: other 1.0.0 https://github.com/o/other\n'
  const result = rewriteRequire(text, 'base', '0.2.0')
  assert.ok(result.changed)
  assert.equal(result.text, 'name: u\nrequire: base 0.2.0\nrequire: other 1.0.0 https://github.com/o/other\n')
  assert.ok(!rewriteRequire(text, 'missing', '1.0.0').changed)
})

test('breaking a dependent is review for a compatible bump and info otherwise', () => {
  const breaks = [{ name: 'users', version: '1.0.0', requires: '0.1.0', problem: 'function gone' }]
  const compatible = checkDependentImpact({ version: '0.1.1', breaks })
  assert.equal(compatible[0].id, 'dependents-break-compatible')
  assert.equal(compatible[0].severity, 'review')
  const major = checkDependentImpact({ version: '0.2.0', breaks })
  assert.equal(major[0].id, 'dependents-break')
  assert.equal(major[0].severity, 'info')
  assert.deepEqual(checkDependentImpact({ version: '0.1.1', breaks: [] }), [])
})

test('a new dependency version that breaks a dependent is reported with the real compiler', { skip: SKIP_COMPILER }, async () => {
  const root = tempDirectory()
  roots.push(root)
  const base = makeRepository(root, 'basepkg', packageFiles('basepkg', 'func base_value(value float64) float64 {\n    return value + 1.0\n}\n'))
  const userFiles = packageFiles('userpkg', 'func user_value() float64 {\n    return base_value(1.0)\n}\n', {
    'sarlin.project': 'name: userpkg\nentry: source/userpkg.sar\nlanguage: 1\nrequire: basepkg 0.1.0\n',
  })
  const user = makeRepository(root, 'userpkg', userFiles)
  const next = addRelease(base.directory, { 'source/basepkg.sar': 'func base_renamed(value float64) float64 {\n    return value + 1.0\n}\n' }, 'v0.1.1')
  const listed = [
    { name: 'basepkg', repository: base.directory, versions: [{ version: '0.1.0', commit: base.commit }] },
    { name: 'userpkg', repository: user.directory, versions: [{ version: '0.1.0', commit: user.commit }] },
  ]
  const scan = await scanPackage({
    entry: entryFor('basepkg', base.directory),
    version: '0.1.1',
    commit: next,
    sarlinPath: SARLIN_BIN,
    policy,
    listedPackages: listed,
    published: [{ version: '0.1.0', commit: base.commit }],
  })
  const broken = scan.findings.find((item) => item.id === 'dependents-break-compatible')
  assert.ok(broken, JSON.stringify(scan.findings))
  assert.match(broken.message, /userpkg 0.1.0/)
  assert.deepEqual(scan.breaksDependents, ['userpkg'])
})

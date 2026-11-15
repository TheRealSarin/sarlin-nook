import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  checkCapabilityEscalation,
  checkHistoryFacts,
  checkVersionSanity,
  compareVersions,
  isSigned,
  newestVersion,
} from '../scripts/history.mjs'

const policy = JSON.parse(readFileSync(new URL('../policy.json', import.meta.url), 'utf8'))
const ids = (findings) => findings.map((item) => item.id)
const published = (...versions) => versions.map((version) => ({ version, commit: 'a'.repeat(40) }))

test('versions compare numerically', () => {
  assert.ok(compareVersions('0.10.0', '0.9.0') > 0)
  assert.equal(newestVersion(['0.1.0', '0.10.0', '0.2.0']), '0.10.0')
})

test('version sanity accepts normal bumps and the first version', () => {
  const base = { published: [], policy }
  assert.deepEqual(checkVersionSanity({ ...base, version: '1.0.0' }), [])
  assert.deepEqual(checkVersionSanity({ ...base, version: '0.2.0', published: ['0.1.0'] }), [])
})

test('a lower version is back-dated and a tag older than the previous commit needs review', () => {
  const lower = checkVersionSanity({ version: '0.1.0', published: ['0.2.0'], policy })
  assert.deepEqual(ids(lower), ['back-dated-tag'])
  assert.equal(lower[0].severity, 'info')
  const old = checkVersionSanity({
    version: '0.1.5',
    published: ['0.2.0'],
    tagDate: '2025-01-01T00:00:00Z',
    previousCommitDate: '2026-01-01T00:00:00Z',
    policy,
  })
  assert.deepEqual(ids(old), ['back-dated-tag', 'back-dated-commit'])
  assert.equal(old[1].severity, 'review')
})

test('big major and minor jumps need review', () => {
  assert.deepEqual(ids(checkVersionSanity({ version: '3.0.0', published: ['1.0.0'], policy })), ['version-jump'])
  assert.deepEqual(ids(checkVersionSanity({ version: '1.60.0', published: ['1.1.0'], policy })), ['version-jump'])
  assert.deepEqual(checkVersionSanity({ version: '2.0.0', published: ['1.9.0'], policy }), [])
  assert.deepEqual(checkVersionSanity({ version: '1.50.0', published: ['1.0.0'], policy }), [])
})

test('capability escalation names only capabilities that were absent before', () => {
  const previous = { capabilities: ['file'], files: 10, bytes: 1000 }
  const current = { capabilities: ['file', 'network', 'foreign_code', 'json'], files: 10, bytes: 1000 }
  const found = checkCapabilityEscalation({ current, previous, policy })
  assert.deepEqual(ids(found), ['capability-escalation'])
  assert.match(found[0].message, /foreign_code, network/)
  assert.deepEqual(checkCapabilityEscalation({ current, previous: null, policy }), [])
  assert.deepEqual(checkCapabilityEscalation({ current: previous, previous, policy }), [])
})

test('growth needs both the factor and the minimum', () => {
  const previous = { capabilities: [], files: 10, bytes: 10000 }
  assert.deepEqual(ids(checkCapabilityEscalation({ current: { capabilities: [], files: 10, bytes: 400000 }, previous, policy })), ['size-growth'])
  assert.deepEqual(checkCapabilityEscalation({ current: { capabilities: [], files: 10, bytes: 100000 }, previous, policy }), [])
  assert.deepEqual(checkCapabilityEscalation({ current: { capabilities: [], files: 10, bytes: 60000 }, previous, policy }), [])
  assert.deepEqual(ids(checkCapabilityEscalation({ current: { capabilities: [], files: 200, bytes: 10000 }, previous, policy })), ['size-growth'])
})

test('history facts report unreachable tags and rewritten history', () => {
  assert.deepEqual(checkHistoryFacts({ reachable: true, descends: true, previousVersion: '0.1.0', previousKnown: true }), [])
  assert.deepEqual(ids(checkHistoryFacts({ reachable: false })), ['tag-unreachable'])
  const gone = checkHistoryFacts({ reachable: true, descends: false, previousVersion: '0.1.0', previousKnown: false })
  assert.match(gone[0].message, /no longer exists/)
  assert.deepEqual(checkHistoryFacts({ reachable: true, descends: false, previousVersion: null }), [])
})

test('signatures are recognised in commit and tag objects', () => {
  assert.ok(isSigned('tree x\ngpgsig -----BEGIN PGP SIGNATURE-----\n'))
  assert.ok(isSigned('object x\n-----BEGIN SSH SIGNATURE-----\n'))
  assert.ok(!isSigned('tree x\nauthor a\n\nmessage gpgsig'))
})

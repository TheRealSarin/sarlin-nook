import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { CHECKS } from '../scripts/checks.mjs'

const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')

test('the README documents every check and uses plain ASCII', () => {
  for (const [id, { severity }] of Object.entries(CHECKS)) {
    assert.ok(readme.includes(`| \`${id}\` |`) && readme.includes(`| ${severity} |`), id)
  }
  assert.ok(/^[\x09\x0a\x20-\x7e]*$/.test(readme))
  for (const file of ['policy.json', 'approvals.txt', 'yanked.txt', 'quarantine.json', 'health.json', 'packages.txt', 'meta.json']) {
    assert.ok(readme.includes(file), file)
  }
})

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  buildIndex,
  compareVersionsDescending,
  formatCatalogue,
  formatIndex,
  listRemoteVersions,
  parseIndex,
  parseTagListing,
  parseVersionTag,
  validateEntry,
} from '../scripts/lib.mjs'

const VALID = `name: acras
repository: https://github.com/TheRealSarin/acras
description: A 2D game engine for Sarlin
license: MIT OR Apache-2.0
`
const COMMIT_A = 'a'.repeat(40)
const COMMIT_B = 'b'.repeat(40)
const COMMIT_C = 'c'.repeat(40)

test('accepts a complete entry', () => {
  const { entry, problems } = validateEntry('acras.package', VALID)
  assert.deepEqual(problems, [])
  assert.equal(entry.name, 'acras')
})

test('ignores comments and blank lines', () => {
  const { problems } = validateEntry('acras.package', `# the engine\n\n${VALID}`)
  assert.deepEqual(problems, [])
})

test('rejects a file name that does not match the name', () => {
  const { problems } = validateEntry('engine.package', VALID)
  assert.equal(problems.length, 1)
  assert.match(problems[0], /must be named 'acras.package'/)
})

test('rejects missing, unknown, repeated and malformed fields', () => {
  const { problems } = validateEntry(
    'acras.package',
    'name: acras\nname: acras\nhomepage: https://sarlin-lang.org\nbroken line\n',
  )
  assert.ok(problems.some((problem) => problem.includes("field 'name' is given twice")))
  assert.ok(problems.some((problem) => problem.includes("unknown field 'homepage'")))
  assert.ok(problems.some((problem) => problem.includes("expected 'key: value'")))
  assert.ok(problems.some((problem) => problem.includes("missing required field 'repository'")))
  assert.ok(problems.some((problem) => problem.includes("missing required field 'description'")))
})

test('rejects names and repositories outside the allowed shapes', () => {
  for (const name of ['Acras', '1acras', 'a', 'acras-engine', 'acras engine']) {
    const { problems } = validateEntry(`${name}.package`, VALID.replace('name: acras', `name: ${name}`))
    assert.ok(problems.some((problem) => problem.includes('must be 2 to 40 characters')), name)
  }
  for (const repository of [
    'http://github.com/TheRealSarin/acras',
    'https://gitlab.com/TheRealSarin/acras',
    'https://github.com/TheRealSarin/acras/tree/main',
    'https://github.com/TheRealSarin/acras; rm -rf /',
    '--upload-pack=touch /tmp/x',
    'file:///etc/passwd',
  ]) {
    const { problems } = validateEntry(
      'acras.package',
      VALID.replace('https://github.com/TheRealSarin/acras', repository),
    )
    assert.ok(problems.some((problem) => problem.includes('must be a GitHub address')), repository)
  }
})

test('reads only strict version tags', () => {
  assert.equal(parseVersionTag('v1.2.3').text, '1.2.3')
  for (const tag of ['1.2.3', 'v1.2', 'v1.2.3-beta', 'v01.2.3', 'release-1.2.3', 'v1.2.3.4']) {
    assert.equal(parseVersionTag(tag), null, tag)
  }
})

test('orders versions newest first by number, not by text', () => {
  const sorted = ['0.9.0', '0.10.0', '1.0.0', '0.2.11', '0.2.9'].sort(compareVersionsDescending)
  assert.deepEqual(sorted, ['1.0.0', '0.10.0', '0.9.0', '0.2.11', '0.2.9'])
})

test('prefers the commit behind an annotated tag', () => {
  const versions = parseTagListing(
    [
      `${COMMIT_A}\trefs/tags/v1.0.0`,
      `${COMMIT_B}\trefs/tags/v1.1.0`,
      `${COMMIT_C}\trefs/tags/v1.1.0^{}`,
      `${COMMIT_A}\trefs/tags/nightly`,
      `${COMMIT_A}\trefs/heads/main`,
      'garbage',
    ].join('\n'),
  )
  assert.deepEqual([...versions], [
    ['1.0.0', COMMIT_A],
    ['1.1.0', COMMIT_C],
  ])
})

test('builds a sorted index and round-trips it', async () => {
  const entries = [
    { name: 'zeta', repository: 'https://github.com/o/zeta', description: 'z' },
    { name: 'acras', repository: 'https://github.com/o/acras', description: 'a', license: 'MIT' },
  ]
  const remote = {
    'https://github.com/o/zeta': new Map([['0.1.0', COMMIT_A]]),
    'https://github.com/o/acras': new Map([
      ['0.2.0', COMMIT_B],
      ['0.10.0', COMMIT_C],
    ]),
  }
  const { packages, warnings } = await buildIndex(entries, new Map(), async (repository) => remote[repository])
  assert.deepEqual(warnings, [])
  const index = formatIndex(packages)
  assert.equal(
    index,
    [
      'nook-index 1',
      `acras 0.10.0 https://github.com/o/acras ${COMMIT_C}`,
      `acras 0.2.0 https://github.com/o/acras ${COMMIT_B}`,
      `zeta 0.1.0 https://github.com/o/zeta ${COMMIT_A}`,
      '',
    ].join('\n'),
  )
  const parsed = parseIndex(index)
  assert.equal(parsed.get('acras').versions.get('0.10.0'), COMMIT_C)
  const catalogue = JSON.parse(formatCatalogue(packages))
  assert.equal(catalogue[0].name, 'acras')
  assert.equal(catalogue[1].license, null)
})

test('never repoints a published version and keeps versions when a repository is unreachable', async () => {
  const entries = [
    { name: 'acras', repository: 'https://github.com/o/acras', description: 'a' },
    { name: 'gone', repository: 'https://github.com/o/gone', description: 'g' },
  ]
  const previous = parseIndex(
    [
      'nook-index 1',
      `acras 0.1.0 https://github.com/o/acras ${COMMIT_A}`,
      `gone 1.0.0 https://github.com/o/gone ${COMMIT_B}`,
      '',
    ].join('\n'),
  )
  const { packages, warnings } = await buildIndex(entries, previous, async (repository) => {
    if (repository.endsWith('/gone')) throw new Error('repository not found')
    return new Map([
      ['0.1.0', COMMIT_C],
      ['0.2.0', COMMIT_C],
    ])
  })
  const acras = packages.find((entry) => entry.name === 'acras')
  assert.deepEqual(acras.versions, [
    { version: '0.2.0', commit: COMMIT_C },
    { version: '0.1.0', commit: COMMIT_A },
  ])
  assert.deepEqual(packages.find((entry) => entry.name === 'gone').versions, [{ version: '1.0.0', commit: COMMIT_B }])
  assert.equal(warnings.length, 2)
})

test('drops pinned versions when a package moves to a different repository', async () => {
  const previous = parseIndex(`nook-index 1\nacras 0.1.0 https://github.com/o/old ${COMMIT_A}\n`)
  const { packages } = await buildIndex(
    [{ name: 'acras', repository: 'https://github.com/o/new', description: 'a' }],
    previous,
    async () => new Map([['0.1.0', COMMIT_B]]),
  )
  assert.deepEqual(packages[0].versions, [{ version: '0.1.0', commit: COMMIT_B }])
})

test('reads version tags from a real git repository', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'nook-test-'))
  const git = (...args) =>
    execFileSync('git', args, {
      cwd: directory,
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: 'Nook Test',
        GIT_AUTHOR_EMAIL: 'nook@test.invalid',
        GIT_COMMITTER_NAME: 'Nook Test',
        GIT_COMMITTER_EMAIL: 'nook@test.invalid',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_CONFIG_SYSTEM: '/dev/null',
      },
    })
      .toString()
      .trim()
  try {
    git('init', '-q', '-b', 'main')
    writeFileSync(join(directory, 'sarlin.project'), 'name: Sample\nentry: source/main.sar\n')
    git('add', '.')
    git('commit', '-q', '-m', 'First version')
    const first = git('rev-parse', 'HEAD')
    git('tag', 'v0.1.0')
    writeFileSync(join(directory, 'notes.txt'), 'second\n')
    git('add', '.')
    git('commit', '-q', '-m', 'Second version')
    const second = git('rev-parse', 'HEAD')
    git('tag', '-a', 'v0.2.0', '-m', 'Annotated release')
    git('tag', 'experimental')
    const versions = await listRemoteVersions(directory)
    assert.deepEqual([...versions].sort(), [
      ['0.1.0', first],
      ['0.2.0', second],
    ])
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

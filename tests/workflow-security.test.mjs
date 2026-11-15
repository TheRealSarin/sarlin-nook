import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'

const directory = new URL('../.github/workflows/', import.meta.url).pathname
const TRUSTED = new Set([
  'github.event.pull_request.number',
  'github.event.pull_request.head.sha',
  'github.repository',
  'secrets.GITHUB_TOKEN',
  'github.run_id',
])

export function analyseWorkflow(text) {
  const problems = []
  const lines = text.split('\n')
  const privileged = /^\s{2}pull_request_target:/m.test(text)
  const handlesPullRequests = /^\s{2}pull_request(_target)?:/m.test(text)
  if (!/^permissions:/m.test(text)) problems.push('permissions are missing at the top level')
  if (/^permissions:\s*write-all/m.test(text)) problems.push('permissions are write-all')
  let runIndent = null
  lines.forEach((line, index) => {
    const where = `line ${index + 1}`
    if (/\t/.test(line)) problems.push(`${where}: tab character`)
    if (/^\s*#/.test(line)) problems.push(`${where}: comment`)
    const indent = line.length - line.trimStart().length
    const blockStart = /^\s*(?:- )?run:\s*[|>][+-]?\s*$/.exec(line)
    if (runIndent !== null && line.trim() !== '' && indent <= runIndent) runIndent = null
    const inRun = runIndent !== null || /^\s*(?:- )?run:\s*\S/.test(line)
    if (blockStart) runIndent = indent
    for (const match of line.matchAll(/\$\{\{\s*([^}]*?)\s*\}\}/g)) {
      const expression = match[1]
      if (inRun) problems.push(`${where}: expression '${expression}' is interpolated into a run script`)
      else if (!TRUSTED.has(expression)) problems.push(`${where}: untrusted or unknown expression '${expression}'`)
      if (/github\.event\.[\w.]*(title|body|head_ref|name|label|ref|message|email)\b/.test(expression) || /github\.head_ref/.test(expression)) {
        problems.push(`${where}: attacker-controlled context '${expression}'`)
      }
    }
    const uses = /^\s*(?:- )?uses:\s*(\S+)/.exec(line)
    if (uses) {
      const reference = uses[1]
      const pinned = /@[0-9a-f]{40}$/.test(reference)
      const official = /^actions\/[\w.-]+@v\d+$/.test(reference)
      if (!reference.startsWith('./') && !pinned && !official) problems.push(`${where}: unpinned action ${reference}`)
    }
    if (privileged && /^\s*(ref|repository):/.test(line) && /(pull_request\.head|head_ref|head\.sha|head\.ref|head\.repo)/.test(line)) {
      problems.push(`${where}: a pull_request_target workflow checks out pull request head code`)
    }
    if (handlesPullRequests && /secrets\.(?!GITHUB_TOKEN\b)/.test(line)) problems.push(`${where}: a secret other than GITHUB_TOKEN`)
  })
  if (privileged && /(npm (test|install|ci)|npx |node [^\n]*(head|pr)[\w/.-]*\.m?js)/.test(text.replace(/scripts\/triage\.mjs/g, ''))) {
    problems.push('a pull_request_target workflow runs package manager commands')
  }
  return problems
}

const files = readdirSync(directory).filter((name) => name.endsWith('.yml'))

test('there are workflows to check', () => {
  assert.ok(files.includes('triage.yml') && files.includes('index.yml') && files.includes('validate.yml'))
})

for (const name of files) {
  test(`${name} passes the workflow security rules`, () => {
    assert.deepEqual(analyseWorkflow(readFileSync(join(directory, name), 'utf8')), [])
  })
}

test('triage.yml is a pull_request_target workflow with the documented permissions', () => {
  const text = readFileSync(join(directory, 'triage.yml'), 'utf8')
  assert.match(text, /pull_request_target:\n\s+types: \[opened, synchronize, reopened, ready_for_review\]/)
  for (const permission of ['contents: write', 'pull-requests: write', 'issues: write', 'actions: write']) assert.ok(text.includes(permission))
  assert.ok(text.includes('persist-credentials: false'))
  assert.ok(!/\bref:/.test(text))
})

test('index.yml keeps the cron, push and manual triggers', () => {
  const text = readFileSync(join(directory, 'index.yml'), 'utf8')
  assert.ok(text.includes("cron: '17 * * * *'"))
  assert.ok(text.includes('branches: [main]'))
  assert.ok(text.includes('workflow_dispatch:'))
})

test('the analyser detects each class of unsafe workflow', () => {
  const header = 'name: x\non:\n  pull_request_target:\n    types: [opened]\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n'
  const bad = [
    ['checks out head code', `${header}      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`],
    ['interpolates a title', `${header}      - run: echo "\${{ github.event.pull_request.title }}"\n`],
    ['interpolates into a block', `${header}      - run: |\n          echo \${{ github.repository }}\n`],
    ['unknown expression in env', `${header}      - run: true\n        env:\n          X: \${{ github.event.issue.body }}\n`],
    ['unpinned action', `${header}      - uses: someone/action@main\n`],
    ['other secret', `${header}      - run: true\n        env:\n          X: \${{ secrets.DEPLOY_KEY }}\n`],
    ['no permissions', 'name: x\non:\n  push:\n    branches: [main]\njobs: {}\n'],
    ['tab', `${header}\t- run: true\n`],
  ]
  for (const [label, text] of bad) assert.ok(analyseWorkflow(text).length > 0, label)
  const good = `${header}      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n      - run: node scripts/triage.mjs\n        env:\n          N: \${{ github.event.pull_request.number }}\n`
  assert.deepEqual(analyseWorkflow(good), [])
  assert.deepEqual(analyseWorkflow(`${header}      - uses: someone/action@${'a'.repeat(40)}\n`), [])
})

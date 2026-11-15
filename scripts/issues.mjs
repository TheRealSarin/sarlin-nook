import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

import { sanitize } from './checks.mjs'
import { parseIndex } from './lib.mjs'

export const ISSUE_LABEL = 'needs-manual-review'
const QUARANTINE_TITLE = /^Needs review: (\S+) (\S+)$/
const UNAVAILABLE_TITLE = /^Repository unavailable: (\S+)$/

export const issueTitle = (record) => `Needs review: ${record.name} ${record.version}`
export const unavailableTitle = (name) => `Repository unavailable: ${name}`

export function issueBody(record) {
  const lines = [
    `${record.name} ${record.version} was held back from the published index by the automatic security scan.`,
    '',
    `Commit: ${record.commit}`,
    `Held for: ${record.severity === 'block' ? 'a blocking problem' : 'manual review'}`,
    `First seen: ${record.firstSeen}`,
    '',
    '| Severity | Check | Details |',
    '| --- | --- | --- |',
  ]
  for (const item of record.findings) lines.push(`| ${item.severity} | ${item.id} | ${sanitize(item.message, 400)} |`)
  if (record.breaksDependents?.length > 0) lines.push('', `Packages that would break with this version: ${record.breaksDependents.join(', ')}`)
  if (record.incompatibleWith?.length > 0) lines.push('', `Cannot be combined with: ${record.incompatibleWith.join(', ')}`)
  lines.push('')
  if (record.severity === 'block') {
    lines.push(
      'How to fix: blocking findings can never be approved. Release a fixed version (a new tag such as the next patch version) in the package repository. It is scanned automatically within the hour.',
    )
  } else {
    lines.push(
      'How to approve: add the following line to approvals.txt in a pull request, and merge it after reading the findings above.',
      '',
      '    ' + `${record.name} ${record.version} ${record.commit}`,
      '',
      'The next index run publishes the version and this issue is closed automatically. The approval is tied to this exact commit.',
    )
  }
  return `${lines.join('\n')}\n`
}

export function unavailableBody(item) {
  return `${item.repository} has been unreachable since ${item.since}.\n\nPublished versions stay in the index and are never removed automatically. Check whether the repository was deleted, renamed or made private, and update or remove packages/${item.name}.package in a pull request if it is gone.\n`
}

export function planIssues({ quarantine, allIssues, openIssues, unavailable = [] }) {
  const create = []
  const close = []
  const titles = new Set(allIssues.map((issue) => issue.title))
  const heldKeys = new Set(quarantine.map((record) => `${record.name} ${record.version}`))
  for (const record of quarantine) {
    if (!titles.has(issueTitle(record))) create.push({ title: issueTitle(record), body: issueBody(record), label: ISSUE_LABEL })
  }
  const unavailableNames = new Set(unavailable.map((item) => item.name))
  for (const item of unavailable) {
    if (!titles.has(unavailableTitle(item.name))) create.push({ title: unavailableTitle(item.name), body: unavailableBody(item), label: ISSUE_LABEL })
  }
  for (const issue of openIssues) {
    const held = QUARANTINE_TITLE.exec(issue.title)
    if (held && !heldKeys.has(`${held[1]} ${held[2]}`)) {
      close.push({ number: issue.number, comment: `${held[1]} ${held[2]} is no longer held back, so this issue is closed.` })
    }
    const gone = UNAVAILABLE_TITLE.exec(issue.title)
    if (gone && !unavailableNames.has(gone[1])) {
      close.push({ number: issue.number, comment: `${gone[1]} is reachable again, so this issue is closed.` })
    }
  }
  return { create, close }
}

export async function applyPlan({ plan, gh }) {
  for (const issue of plan.create) {
    await gh(['issue', 'create', '--title', issue.title, '--label', issue.label, '--body-file', '-'], issue.body)
  }
  for (const issue of plan.close) {
    await gh(['issue', 'close', String(issue.number), '--comment', issue.comment])
  }
}

export function ghRunner(repo) {
  return (args, input) =>
    new Promise((resolve, reject) => {
      const child = execFile('gh', [...args, '--repo', repo], { maxBuffer: 32 * 1024 * 1024 }, (error, stdout) =>
        error ? reject(error) : resolve(stdout),
      )
      if (input !== undefined) child.stdin.end(input)
    })
}

async function main() {
  const directory = process.argv[process.argv.indexOf('--output') + 1]
  const repo = process.env.GITHUB_REPOSITORY
  if (!directory || !repo) {
    console.error('error: pass --output <dir> and set GITHUB_REPOSITORY')
    process.exit(2)
  }
  const quarantine = JSON.parse(await readFile(join(directory, 'quarantine.json'), 'utf8'))
  const health = JSON.parse(await readFile(join(directory, 'health.json'), 'utf8').catch(() => '[]'))
  const meta = JSON.parse(await readFile(join(directory, 'unavailable.json'), 'utf8').catch(() => '[]'))
  const published = parseIndex(await readFile(join(directory, 'index.txt'), 'utf8'))
  const gh = ghRunner(repo)
  const list = async (state) => JSON.parse(await gh(['issue', 'list', '--state', state, '--limit', '1000', '--json', 'number,title']))
  const plan = planIssues({ quarantine, allIssues: await list('all'), openIssues: await list('open'), unavailable: meta })
  await applyPlan({ plan, gh })
  console.log(`opened ${plan.create.length} issue(s), closed ${plan.close.length}; ${published.size} package(s) published, ${health.length} health record(s)`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`error: ${error.message}`)
    process.exit(1)
  })
}

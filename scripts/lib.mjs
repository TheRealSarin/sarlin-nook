import { execFile } from 'node:child_process'
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { promisify } from 'node:util'

const run = promisify(execFile)

export const INDEX_HEADER = 'nook-index 1'
export const ENTRY_EXTENSION = '.package'

const NAME_PATTERN = /^[a-z][a-z0-9_]{1,39}$/
const REPOSITORY_PATTERN = /^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/
const VERSION_TAG_PATTERN = /^v(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/
const COMMIT_PATTERN = /^[0-9a-f]{40}$/
const REQUIRED_FIELDS = ['name', 'repository', 'description']
const KNOWN_FIELDS = new Set([...REQUIRED_FIELDS, 'license'])
const MAXIMUM_FIELD_LENGTH = 200
const LS_REMOTE_TIMEOUT_MILLISECONDS = 30000

export function parseEntry(text) {
  const fields = {}
  const problems = []
  text.split('\n').forEach((rawLine, position) => {
    const line = rawLine.trim()
    if (line === '' || line.startsWith('#')) return
    const separator = line.indexOf(':')
    if (separator === -1) {
      problems.push(`line ${position + 1}: expected 'key: value'`)
      return
    }
    const key = line.slice(0, separator).trim()
    const value = line.slice(separator + 1).trim()
    if (!KNOWN_FIELDS.has(key)) {
      problems.push(`line ${position + 1}: unknown field '${key}'`)
    } else if (key in fields) {
      problems.push(`line ${position + 1}: field '${key}' is given twice`)
    } else if (value === '') {
      problems.push(`line ${position + 1}: field '${key}' has no value`)
    } else if (value.length > MAXIMUM_FIELD_LENGTH) {
      problems.push(`line ${position + 1}: field '${key}' is longer than ${MAXIMUM_FIELD_LENGTH} characters`)
    } else {
      fields[key] = value
    }
  })
  return { fields, problems }
}

export function validateEntry(fileName, text) {
  const { fields, problems } = parseEntry(text)
  for (const field of REQUIRED_FIELDS) {
    if (!(field in fields)) problems.push(`missing required field '${field}'`)
  }
  if ('name' in fields) {
    if (!NAME_PATTERN.test(fields.name)) {
      problems.push(
        `name '${fields.name}' must be 2 to 40 characters: lower case letters, digits and underscores, starting with a letter`,
      )
    }
    if (fileName !== `${fields.name}${ENTRY_EXTENSION}`) {
      problems.push(`file must be named '${fields.name}${ENTRY_EXTENSION}' to match its name field`)
    }
  }
  if ('repository' in fields && !REPOSITORY_PATTERN.test(fields.repository)) {
    problems.push(
      `repository '${fields.repository}' must be a GitHub address of the form https://github.com/owner/name`,
    )
  }
  return { entry: fields, problems }
}

export function parseVersionTag(tag) {
  const match = VERSION_TAG_PATTERN.exec(tag)
  if (!match) return null
  return { text: `${match[1]}.${match[2]}.${match[3]}` }
}

export function compareVersionsDescending(left, right) {
  const leftParts = left.split('.').map(Number)
  const rightParts = right.split('.').map(Number)
  for (let position = 0; position < 3; position += 1) {
    if (leftParts[position] !== rightParts[position]) return rightParts[position] - leftParts[position]
  }
  return 0
}

export function parseTagListing(listing) {
  const direct = new Map()
  const peeled = new Map()
  for (const line of listing.split('\n')) {
    const [commit, reference] = line.trim().split(/\s+/)
    if (!commit || !reference || !COMMIT_PATTERN.test(commit) || !reference.startsWith('refs/tags/')) continue
    const tag = reference.slice('refs/tags/'.length)
    if (tag.endsWith('^{}')) {
      peeled.set(tag.slice(0, -3), commit)
    } else {
      direct.set(tag, commit)
    }
  }
  const versions = new Map()
  for (const [tag, commit] of direct) {
    const version = parseVersionTag(tag)
    if (version) versions.set(version.text, peeled.get(tag) ?? commit)
  }
  return versions
}

export async function listRemoteVersions(repository) {
  const { stdout } = await run('git', ['ls-remote', '--tags', '--', repository], {
    timeout: LS_REMOTE_TIMEOUT_MILLISECONDS,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
    maxBuffer: 16 * 1024 * 1024,
  })
  return parseTagListing(stdout)
}

export async function readEntries(directory) {
  const names = (await readdir(directory)).filter((name) => name.endsWith(ENTRY_EXTENSION)).sort()
  const entries = []
  const problems = []
  const seen = new Set()
  for (const fileName of names) {
    const result = validateEntry(fileName, await readFile(join(directory, fileName), 'utf8'))
    for (const problem of result.problems) problems.push(`${fileName}: ${problem}`)
    if (result.problems.length === 0) {
      const repositoryKey = result.entry.repository.toLowerCase()
      if (seen.has(repositoryKey)) {
        problems.push(`${fileName}: repository ${result.entry.repository} is already listed by another package`)
      } else {
        seen.add(repositoryKey)
        entries.push(result.entry)
      }
    }
  }
  return { entries, problems }
}

export function parseIndex(text) {
  const pinned = new Map()
  const lines = text.split('\n').filter((line) => line.trim() !== '')
  if (lines[0] !== INDEX_HEADER) return pinned
  for (const line of lines.slice(1)) {
    const [name, version, repository, commit] = line.split(' ')
    if (!name || !version || !repository || !COMMIT_PATTERN.test(commit ?? '')) continue
    if (!pinned.has(name)) pinned.set(name, { repository, versions: new Map() })
    pinned.get(name).versions.set(version, commit)
  }
  return pinned
}

export async function buildIndex(entries, previous, resolveVersions = listRemoteVersions) {
  const packages = []
  const warnings = []
  for (const entry of [...entries].sort((left, right) => left.name.localeCompare(right.name))) {
    const earlier = previous.get(entry.name)
    const sameRepository = earlier !== undefined && earlier.repository === entry.repository
    const versions = new Map(sameRepository ? earlier.versions : [])
    try {
      const remote = await resolveVersions(entry.repository)
      for (const [version, commit] of remote) {
        const pinned = versions.get(version)
        if (pinned === undefined) {
          versions.set(version, commit)
        } else if (pinned !== commit) {
          warnings.push(
            `${entry.name} ${version}: the tag now points at ${commit}, but the published version stays at ${pinned}`,
          )
        }
      }
    } catch (error) {
      warnings.push(`${entry.name}: could not read tags from ${entry.repository}: ${error.message.split('\n')[0]}`)
    }
    packages.push({
      ...entry,
      versions: [...versions.keys()]
        .sort(compareVersionsDescending)
        .map((version) => ({ version, commit: versions.get(version) })),
    })
  }
  return { packages, warnings }
}

export function formatIndex(packages) {
  const lines = [INDEX_HEADER]
  for (const entry of packages) {
    for (const { version, commit } of entry.versions) {
      lines.push(`${entry.name} ${version} ${entry.repository} ${commit}`)
    }
  }
  return `${lines.join('\n')}\n`
}

export function formatCatalogue(packages) {
  const catalogue = packages.map((entry) => ({
    name: entry.name,
    description: entry.description,
    license: entry.license ?? null,
    repository: entry.repository,
    versions: entry.versions,
  }))
  return `${JSON.stringify(catalogue, null, 2)}\n`
}

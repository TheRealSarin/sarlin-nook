import { createHash } from 'node:crypto'

import { compareVersionsDescending, formatIndex } from './lib.mjs'
import { compareVersions, newestVersion } from './history.mjs'

export function parseApprovals(text) {
  const approved = new Set()
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim()
    if (line === '') continue
    const [name, version, commit] = line.split(/\s+/)
    if (name && version && /^[0-9a-f]{40}$/.test(commit ?? '')) approved.add(`${name} ${version} ${commit}`)
  }
  return approved
}

export function parseYanked(text) {
  const yanked = new Map()
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#')) continue
    const match = /^(\S+)\s+(\S+)(?:\s+(.*))?$/.exec(line)
    if (match) yanked.set(`${match[1]} ${match[2]}`, match[3]?.trim() || 'no reason given')
  }
  return yanked
}

export function policyFingerprint(policy) {
  return createHash('sha256').update(JSON.stringify(policy)).digest('hex').slice(0, 16)
}

export function decideVersion({ findings, approved }) {
  if (findings.some((item) => item.severity === 'block')) return { publish: false, hold: 'block', overridden: false }
  if (findings.some((item) => item.severity === 'review')) {
    return approved ? { publish: true, hold: null, overridden: true } : { publish: false, hold: 'review', overridden: false }
  }
  return { publish: true, hold: null, overridden: false }
}

export function reuseHealth(previousHealth, name, version, compiler) {
  const earlier = previousHealth.find((item) => item.name === name)
  if (earlier && earlier.version === version && earlier.compiler === compiler && ['ok', 'failing'].includes(earlier.status)) return earlier
  return null
}

function nextMeta({ previousMeta, indexText, compiler, packages, versions, now }) {
  const indexSha256 = createHash('sha256').update(indexText).digest('hex')
  const unchanged = previousMeta && previousMeta.indexSha256 === indexSha256
  return {
    generation: unchanged ? previousMeta.generation : (previousMeta?.generation ?? 0) + 1,
    generatedAt: unchanged ? previousMeta.generatedAt : now.toISOString(),
    indexSha256,
    compiler: compiler ?? null,
    packages,
    versions,
  }
}

export async function buildGatedIndex({
  entries,
  previous,
  previousQuarantine = [],
  previousHealth = [],
  previousCatalogue = [],
  previousMeta = null,
  approvals = new Set(),
  yanked = new Map(),
  policy,
  resolveVersions,
  scan,
  health = null,
  compiler = null,
  now = new Date(),
}) {
  const warnings = []
  const sorted = [...entries].sort((left, right) => left.name.localeCompare(right.name))
  const fingerprint = policyFingerprint(policy)
  const state = new Map()
  for (const entry of sorted) {
    const earlier = previous.get(entry.name)
    const published = new Map(earlier && earlier.repository === entry.repository ? earlier.versions : [])
    let remote = new Map()
    let unavailable = false
    try {
      remote = await resolveVersions(entry.repository)
    } catch (error) {
      unavailable = true
      warnings.push(`${entry.name}: could not read tags from ${entry.repository}: ${error.message.split('\n')[0]}`)
    }
    for (const [version, commit] of remote) {
      const pinned = published.get(version)
      if (pinned !== undefined && pinned !== commit) {
        warnings.push(`${entry.name} ${version}: the tag now points at ${commit}, but the published version stays at ${pinned}`)
      }
    }
    state.set(entry.name, { entry, published, remote, unavailable, extra: new Map() })
  }

  const listed = () =>
    sorted.map((entry) => ({
      name: entry.name,
      repository: entry.repository,
      versions: [...state.get(entry.name).published].map(([version, commit]) => ({ version, commit })),
    }))
  const catalogueMeta = (name, version) =>
    previousCatalogue.find((item) => item.name === name)?.versions?.find((item) => item.version === version) ?? {}

  const quarantine = []
  const newlyQuarantined = []
  const overridden = []
  const yankedKeys = new Set(yanked.keys())
  for (const item of state.values()) {
    const { entry, published, remote } = item
    for (const [version, commit] of published) {
      const meta = catalogueMeta(entry.name, version)
      item.extra.set(version, { incompatibleWith: meta.incompatibleWith, breaksDependents: meta.breaksDependents })
    }
    const fresh = [...remote]
      .filter(([version]) => !published.has(version) && !yankedKeys.has(`${entry.name} ${version}`))
      .map(([version, commit]) => ({ version, commit }))
      .sort((left, right) => compareVersions(left.version, right.version))
    for (const { version, commit } of fresh) {
      const record = previousQuarantine.find(
        (old) => old.name === entry.name && old.version === version && old.commit === commit && old.policyHash === fingerprint,
      )
      const listedPackages = listed()
      const dependencyIndexHash = createHash('sha256')
        .update(formatIndex(listedPackages.map((pkg) => ({
          ...pkg,
          versions: [...pkg.versions].sort((left, right) => compareVersionsDescending(left.version, right.version)),
        }))))
        .digest('hex')
      let findings
      let extras
      if (record && (!record.findings.some((finding) => finding.id === 'bad-require') || record.dependencyIndexHash === dependencyIndexHash)) {
        findings = record.findings
        extras = { incompatibleWith: record.incompatibleWith, breaksDependents: record.breaksDependents }
      } else {
        const unavailableVersions = new Set(
          quarantine.map((q) => `${q.name} ${q.version}`).concat([...yankedKeys]),
        )
        const result = await scan({
          entry,
          version,
          commit,
          published: [...published].map(([v, c]) => ({ version: v, commit: c })),
          listedPackages,
          unavailable: unavailableVersions,
        })
        findings = result.findings
        extras = { incompatibleWith: result.incompatibleWith ?? [], breaksDependents: result.breaksDependents ?? [] }
      }
      const verdict = decideVersion({ findings, approved: approvals.has(`${entry.name} ${version} ${commit}`) })
      if (verdict.publish) {
        published.set(version, commit)
        item.extra.set(version, extras)
        if (verdict.overridden) overridden.push({ name: entry.name, version, commit })
      } else {
        const entryRecord = {
          name: entry.name,
          version,
          commit,
          severity: verdict.hold,
          firstSeen: record?.firstSeen ?? now.toISOString(),
          policyHash: fingerprint,
          findings,
          ...(findings.some((finding) => finding.id === 'bad-require') ? { dependencyIndexHash } : {}),
          ...extras,
        }
        quarantine.push(entryRecord)
        if (!record) newlyQuarantined.push(entryRecord)
      }
    }
  }

  const packages = []
  const publishedPackages = []
  const healthRecords = []
  const unavailableRepositories = []
  for (const item of state.values()) {
    const { entry, published, remote } = item
    const versions = new Map(published)
    for (const [key, reason] of yanked) {
      const [name, version] = key.split(' ')
      if (name === entry.name && !versions.has(version)) versions.set(version, remote.get(version) ?? '-')
    }
    const list = [...versions.keys()].sort(compareVersionsDescending).map((version) => {
      const reason = yanked.get(`${entry.name} ${version}`)
      const extra = item.extra.get(version) ?? {}
      const record = { version, commit: versions.get(version) }
      if (reason !== undefined) {
        record.yanked = true
        record.reason = reason
      }
      if (extra.incompatibleWith?.length > 0) record.incompatibleWith = extra.incompatibleWith
      if (extra.breaksDependents?.length > 0) record.breaksDependents = extra.breaksDependents
      return record
    })
    const live = list.filter((version) => !version.yanked)
    const newest = live.length > 0 ? newestVersion(live.map((version) => version.version)) : null
    let record = null
    if (item.unavailable) {
      const earlier = previousHealth.find((old) => old.name === entry.name)
      const since = earlier?.status === 'unavailable' ? earlier.since : now.toISOString()
      record = { name: entry.name, version: newest, compiler: earlier?.compiler ?? compiler, status: 'unavailable', since, checkedAt: now.toISOString() }
      const days = (now.getTime() - new Date(since).getTime()) / 86400000
      if (days >= policy.unavailableDaysBeforeIssue) unavailableRepositories.push({ name: entry.name, repository: entry.repository, since })
    } else if (newest && compiler) {
      record = reuseHealth(previousHealth, entry.name, newest, compiler)
      if (!record && health) {
        const commit = versions.get(newest)
        const outcome = await health({ entry, version: newest, commit, listedPackages: listed() })
        record = { name: entry.name, version: newest, compiler, status: outcome.ok ? 'ok' : 'failing', checkedAt: now.toISOString() }
      }
    }
    if (record) healthRecords.push(record)
    const compatible = record?.status === 'ok' ? true : record?.status === 'failing' ? false : null
    packages.push({ ...entry, versions: list, compatible, compiler: record?.compiler ?? null })
    if (live.length > 0) publishedPackages.push({ ...entry, versions: live })
  }

  const indexText = formatIndex(publishedPackages)
  const versionCount = publishedPackages.reduce((sum, item) => sum + item.versions.length, 0)
  const meta = nextMeta({ previousMeta, indexText, compiler, packages: publishedPackages.length, versions: versionCount, now })
  return {
    indexText,
    indexChecksum: `${meta.indexSha256}  index.txt\n`,
    packages,
    publishedPackages,
    quarantine,
    health: healthRecords,
    meta,
    warnings,
    newlyQuarantined,
    overridden,
    unavailableRepositories,
  }
}

export function formatQuarantine(quarantine) {
  return `${JSON.stringify(quarantine, null, 2)}\n`
}

export function formatHealth(health) {
  return `${JSON.stringify(health, null, 2)}\n`
}

export function formatMeta(meta) {
  return `${JSON.stringify(meta, null, 2)}\n`
}

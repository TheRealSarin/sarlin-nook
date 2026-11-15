import { createHash } from 'node:crypto'

const CATALOGUE = [
  ['check-failed', 'block', 'sarlin check rejects the package, or a sarlin command timed out'],
  ['main-defined', 'block', 'a package source file defines func main'],
  ['symlink', 'block', 'the package contains a symbolic link'],
  ['file-count', 'block', 'the package has more files than the policy allows'],
  ['package-size', 'block', 'the package is larger than the policy allows'],
  ['binary-file', 'block', 'a binary file outside the image and font allowlist, over the size limit, or not matching its extension'],
  ['bad-path', 'block', 'a path with .., a backslash, an absolute form or control characters'],
  ['secret', 'block', 'a private key, access key, token or long credential assignment'],
  ['no-project', 'block', 'the package has no sarlin.project'],
  ['bad-require', 'block', 'a require line that does not resolve to a listed package or a GitHub address'],
  ['hidden-characters', 'block', 'bidirectional, zero-width or control characters in sources, project file, README or file names'],
  ['project-language', 'block', 'sarlin.project names an unsupported language number'],
  ['no-source', 'block', 'source/ holds no .sar file'],
  ['git-folder', 'block', 'the package contains a .git folder'],
  ['submodule', 'block', 'the package uses git submodules'],
  ['dependency-cycle', 'block', 'the requires of the package form a cycle'],
  ['external-code', 'review', 'external C, Cpp or Rust blocks (native code compiled into the user program)'],
  ['foreign-pattern', 'review', 'a risky native call inside an external block'],
  ['native-deep', 'review', 'assembly, executable memory, environment access, ptrace, Rust fs or net or libc inside an external block'],
  ['network', 'review', 'use of the Network built-in'],
  ['capability-review', 'review', 'use of another capability that the policy marks for review'],
  ['no-license', 'review', 'no LICENSE file'],
  ['license-not-allowed', 'review', 'the stated license is not in the allowed list'],
  ['license-mismatch', 'review', 'the LICENSE text does not match the license in the entry'],
  ['copyleft-license', 'review', 'a GPL, AGPL or LGPL license'],
  ['collision', 'review', 'a top-level name that another listed package also defines'],
  ['non-ascii-identifier', 'review', 'non-ASCII or mixed-script identifiers'],
  ['sensitive-path', 'review', 'a string or external block that names credential or browser data locations'],
  ['raw-ip-url', 'review', 'a URL with a raw IP address'],
  ['unlisted-host', 'review', 'a URL whose host is not in the allowed hosts'],
  ['long-line', 'review', 'a line longer than the policy allows'],
  ['encoded-blob', 'review', 'a long base64-like or hexadecimal blob'],
  ['escaped-ratio', 'review', 'a very high ratio of escaped characters in string literals'],
  ['dangerous-removal', 'review', 'file.remove or directory.remove of a bare root, home, dot or absolute literal'],
  ['project-name-mismatch', 'review', 'the name in sarlin.project differs from the Nook entry name'],
  ['entry-missing', 'review', 'the entry file in sarlin.project does not exist'],
  ['build-output', 'review', 'committed build output, archives, executables or node_modules'],
  ['nested-project', 'review', 'a nested sarlin.project file'],
  ['possible-clone', 'review', 'most source files are identical to another package from a different owner'],
  ['dependency-depth', 'review', 'the dependency chain is deeper than the policy allows'],
  ['dependency-yanked', 'review', 'a requirement on a yanked or quarantined version'],
  ['tag-unreachable', 'review', 'the version commit is not reachable from the default branch'],
  ['history-rewrite', 'review', 'the version commit does not descend from the previous published version'],
  ['capability-escalation', 'review', 'a capability the previous version did not use'],
  ['size-growth', 'review', 'size or file count grew by more than the configured factor'],
  ['back-dated-tag', 'info', 'the version is lower than a published version'],
  ['back-dated-commit', 'review', 'the tag is older than the commit of the previous version'],
  ['version-jump', 'review', 'the version jumps more than the allowed major or minor steps'],
  ['dependents-break', 'info', 'dependents that fail with this version'],
  ['dependents-break-compatible', 'review', 'dependents that fail although the bump claims compatibility'],
  ['dependency-outdated', 'info', 'a requirement pinned below the newest published version'],
  ['incompatible-with', 'info', 'listed packages this version cannot be combined with'],
  ['collision-check-skipped', 'info', 'the cross-package collision check could not run'],
  ['no-readme', 'info', 'no README'],
  ['no-tests', 'info', 'no tests folder'],
  ['capabilities', 'info', 'capabilities used by the package'],
  ['statistics', 'info', 'file, byte and line counts'],
  ['dependencies', 'info', 'packages required by this package'],
  ['signed', 'info', 'the commit or tag carries a signature'],
  ['repository-moved', 'review', 'the repository was renamed, transferred or redirected'],
  ['owner-type', 'info', 'the owner is a user or an organization'],
  ['too-many-open-pulls', 'review', 'the author has too many open pull requests'],
  ['listing-rate', 'review', 'a young account lists too many packages in a day'],
  ['too-many-entries', 'review', 'one pull request adds too many entries'],
  ['repository-unavailable', 'review', 'a listed repository stayed unreachable for several days'],
]

export const CHECKS = Object.fromEntries(
  CATALOGUE.map(([id, severity, description]) => [id, { severity, description }]),
)

export function finding(id, message) {
  const check = CHECKS[id]
  if (!check) throw new Error(`unknown check '${id}'`)
  return { id, severity: check.severity, message }
}

export function defaultCheckSettings() {
  return Object.fromEntries(
    Object.entries(CHECKS).map(([id, { severity }]) => [id, { enabled: true, severity }]),
  )
}

export function applyChecks(findings, policy) {
  const settings = policy.checks ?? {}
  const result = []
  for (const item of findings) {
    const setting = settings[item.id]
    if (setting?.enabled === false) continue
    result.push(setting?.severity ? { ...item, severity: setting.severity } : item)
  }
  return result
}

export function worstSeverity(findings) {
  if (findings.some((item) => item.severity === 'block')) return 'block'
  if (findings.some((item) => item.severity === 'review')) return 'review'
  return 'pass'
}

export function compilePatterns(patterns) {
  return patterns.map((item) => ({ id: item.id, regex: new RegExp(item.pattern, item.flags ?? '') }))
}

const EXTERNAL_START = /^\s*external\s+(C|Cpp|Rust)\s+func\s+([A-Za-z_][A-Za-z0-9_]*)/
const EXTERNAL_END = /^\s*end\s+external\b/

export function maskSource(text) {
  let code = ''
  let kept = ''
  const strings = []
  let line = 1
  let position = 0
  const length = text.length
  const blank = (segment) => segment.replace(/[^\n]/g, ' ')
  while (position < length) {
    const character = text[position]
    if (character === '#') {
      const lineEnd = text.indexOf('\n', position)
      const endOfLine = lineEnd === -1 ? length : lineEnd
      let end = endOfLine
      if (text.startsWith('###', position) && /^[ \t\r]*$/.test(text.slice(position + 3, endOfLine))) {
        const closing = /\n[ \t]*###[ \t\r]*(?=\n|$)/g
        closing.lastIndex = endOfLine
        const found = closing.exec(text)
        end = found ? found.index + found[0].length : length
      }
      const segment = text.slice(position, end)
      code += blank(segment)
      kept += blank(segment)
      line += segment.split('\n').length - 1
      position = end
    } else if (character === '"') {
      let cursor = position + 1
      while (cursor < length && text[cursor] !== '"' && text[cursor] !== '\n') {
        cursor += text[cursor] === '\\' && text[cursor + 1] !== '\n' ? 2 : 1
      }
      const closed = text[cursor] === '"'
      const stop = Math.min(cursor, length)
      const value = text.slice(position + 1, stop)
      strings.push({ line, value })
      code += `"${blank(value)}${closed ? '"' : ''}`
      kept += text.slice(position, closed ? stop + 1 : stop)
      position = closed ? stop + 1 : stop
    } else {
      code += character
      kept += character
      if (character === '\n') line += 1
      position += 1
    }
  }
  return { code, kept, strings }
}

export function analyzeSource(text) {
  const externals = []
  const rest = []
  let current = null
  text.split('\n').forEach((line, index) => {
    if (current) {
      if (EXTERNAL_END.test(line)) {
        current.endLine = index + 1
        externals.push(current)
        current = null
      } else {
        current.body.push({ line: index + 1, text: line })
      }
      rest.push('')
      return
    }
    const start = EXTERNAL_START.exec(line)
    if (start) {
      current = { language: start[1], name: start[2], startLine: index + 1, endLine: index + 1, body: [] }
      rest.push('')
      return
    }
    rest.push(line)
  })
  if (current) externals.push(current)
  return { externals, ...maskSource(rest.join('\n')) }
}

function linesMatching(text, predicate) {
  const lines = []
  text.split('\n').forEach((line, index) => {
    if (predicate(line)) lines.push(index + 1)
  })
  return lines
}

export function isSourcePath(path) {
  return path.startsWith('source/') && path.endsWith('.sar')
}

export function checkPathNames(paths) {
  const findings = []
  for (const path of paths) {
    const segments = path.replace(/[/]$/, '').split('/')
    const reasons = []
    if (path.startsWith('/')) reasons.push('is absolute')
    if (segments.includes('..')) reasons.push("contains '..'")
    if (path.includes('\\')) reasons.push('contains a backslash')
    if ([...path].some((character) => character.charCodeAt(0) < 0x20 || character.charCodeAt(0) === 0x7f)) {
      reasons.push('contains control characters')
    }
    if (reasons.length > 0) {
      findings.push(finding('bad-path', `path ${JSON.stringify(path)} ${reasons.join(' and ')}`))
    }
  }
  return findings
}

export function hiddenCharacter(text, allowLeadingMark = false, strict = false) {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index)
    const bidirectional = (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069)
    const zeroWidth =
      (code >= 0x200b && code <= 0x200f) || code === 0x2060 || (code === 0xfeff && !(allowLeadingMark && index === 0))
    const tolerated = !strict && (code === 0x09 || code === 0x0a || code === 0x0d)
    const control = (code < 0x20 && !tolerated) || code === 0x7f
    if (bidirectional || zeroWidth || control) return code
  }
  return null
}

function codePointLabel(code) {
  return `U+${code.toString(16).toUpperCase().padStart(4, '0')}`
}

export function checkHiddenCharacters(files, paths = []) {
  const findings = []
  for (const path of paths) {
    const code = hiddenCharacter(path, false, true)
    if (code !== null) {
      findings.push(finding('hidden-characters', `a file name contains the hidden character ${codePointLabel(code)}`))
    }
  }
  for (const file of files) {
    const name = file.path.split('/').pop()
    const relevant = file.path.endsWith('.sar') || file.path === 'sarlin.project' || /^README/i.test(name)
    if (!relevant || file.text === null) continue
    file.text.split('\n').forEach((line, index) => {
      const code = hiddenCharacter(line, index === 0)
      if (code !== null) {
        findings.push(
          finding('hidden-characters', `${file.path}:${index + 1} contains the hidden character ${codePointLabel(code)}`),
        )
      }
    })
  }
  return findings
}

function scriptOf(character) {
  if (/\p{Script=Latin}/u.test(character)) return 'Latin'
  if (/\p{Script=Cyrillic}/u.test(character)) return 'Cyrillic'
  if (/\p{Script=Greek}/u.test(character)) return 'Greek'
  if (/\p{N}|_/u.test(character)) return 'Common'
  return 'Other'
}

export function checkIdentifiers(files) {
  const findings = []
  for (const file of files) {
    if (!file.path.endsWith('.sar') || file.text === null) continue
    const { code } = analyzeSource(file.text)
    code.split('\n').forEach((line, index) => {
      for (const token of line.match(/[\p{L}\p{N}_]+/gu) ?? []) {
        if (/^[\x00-\x7f]+$/.test(token)) continue
        const scripts = new Set([...token].map(scriptOf).filter((script) => script !== 'Common'))
        const kind = scripts.size > 1 ? 'mixed-script' : 'non-ASCII'
        findings.push(finding('non-ascii-identifier', `${file.path}:${index + 1} has a ${kind} identifier`))
      }
    })
  }
  return findings
}

export function checkSecrets(files, policy) {
  const patterns = compilePatterns(policy.secretPatterns)
  const findings = []
  for (const file of files) {
    if (file.text === null) continue
    file.text.split('\n').forEach((line, index) => {
      for (const { id, regex } of patterns) {
        if (regex.test(line)) {
          findings.push(finding('secret', `${file.path}:${index + 1} looks like a secret (${id}); the value is not shown`))
        }
      }
    })
  }
  return findings
}

export function collectCapabilities(sourceFiles) {
  const found = new Set()
  const rules = [
    ['file', /\bfile\.[a-z_]+/],
    ['directory', /\bdirectory\.[a-z_]+/],
    ['path', /\bpath\.[a-z_]+/],
    ['time', /\bTime\.[a-z_]+/],
    ['json', /\bJSON\.[a-z_]+/],
    ['csv', /\bCSV\.[a-z_]+/],
    ['network', /\bNetwork\.[a-z_]+/],
  ]
  for (const file of sourceFiles) {
    const { externals, code } = analyzeSource(file.text)
    if (externals.length > 0) found.add('foreign_code')
    for (const [name, regex] of rules) if (regex.test(code)) found.add(name)
  }
  return [...found].sort()
}

export function listExternals(sourceFiles) {
  const result = []
  for (const file of sourceFiles) {
    for (const block of analyzeSource(file.text).externals) result.push({ ...block, path: file.path })
  }
  return result
}

export function checkForeignCode(externals, capabilities, policy) {
  const findings = []
  const foreignPatterns = compilePatterns(policy.blockedForeignPatterns)
  const deepPatterns = compilePatterns(policy.deepNativePatterns ?? [])
  if (externals.length > 0) {
    const list = externals.map((block) => `${block.name} (${block.language}, ${block.path}:${block.startLine})`)
    findings.push(
      finding('external-code', `external native code is compiled into the user's program: ${list.join(', ')}`),
    )
  }
  for (const block of externals) {
    for (const entry of block.body) {
      for (const { id, regex } of foreignPatterns) {
        if (regex.test(entry.text)) {
          findings.push(finding('foreign-pattern', `${block.path}:${entry.line} in '${block.name}' matches ${id}`))
        }
      }
      for (const { id, regex } of deepPatterns) {
        if (regex.test(entry.text)) {
          findings.push(finding('native-deep', `${block.path}:${entry.line} in '${block.name}' matches ${id}`))
        }
      }
    }
  }
  for (const capability of policy.reviewCapabilities) {
    if (!capabilities.includes(capability) || capability === 'foreign_code') continue
    if (capability === 'network') {
      findings.push(finding('network', 'the package uses the Network built-in'))
    } else {
      findings.push(finding('capability-review', `the package uses '${capability}', which the policy marks for review`))
    }
  }
  return findings
}

function hostAllowed(host, allowed) {
  const lower = host.toLowerCase()
  return allowed.some((entry) => lower === entry || lower.endsWith(`.${entry}`))
}

export function checkSensitiveStrings(files, policy) {
  const findings = []
  const sensitive = compilePatterns(policy.sensitivePathPatterns ?? [])
  const scan = (path, line, text) => {
    for (const { id, regex } of sensitive) {
      if (regex.test(text)) {
        findings.push(finding('sensitive-path', `${path}:${line} refers to a sensitive location (${id})`))
      }
    }
    for (const match of text.matchAll(/https?:\/\/([^\s/:"'<>\\]+)/gi)) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(match[1]) || match[1].startsWith('[')) {
        findings.push(finding('raw-ip-url', `${path}:${line} has a URL with a raw IP address`))
      } else if (!hostAllowed(match[1], policy.allowedHosts ?? [])) {
        findings.push(
          finding('unlisted-host', `${path}:${line} has a URL for ${match[1].toLowerCase()}, which is not an allowed host`),
        )
      }
    }
  }
  for (const file of files) {
    if (!file.path.endsWith('.sar') || file.text === null) continue
    const { strings, externals } = analyzeSource(file.text)
    for (const item of strings) scan(file.path, item.line, item.value)
    for (const block of externals) for (const entry of block.body) scan(file.path, entry.line, entry.text)
  }
  return findings
}

export function checkObfuscation(files, policy) {
  const findings = []
  const length = policy.maximumEncodedBlobLength
  const blob = new RegExp(`[A-Za-z0-9+/=]{${length},}|[0-9a-fA-F]{${length},}`)
  for (const file of files) {
    if (file.text === null) continue
    file.text.split('\n').forEach((line, index) => {
      if (line.length > policy.maximumLineLength) {
        findings.push(finding('long-line', `${file.path}:${index + 1} is ${line.length} characters long`))
      }
      if (file.path.endsWith('.sar') && blob.test(line)) {
        findings.push(finding('encoded-blob', `${file.path}:${index + 1} holds a long encoded blob`))
      }
    })
    if (file.path.endsWith('.sar')) {
      const { strings } = analyzeSource(file.text)
      const total = strings.reduce((sum, item) => sum + item.value.length, 0)
      const escapes = /\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-7]{3})/g
      const escaped = strings.reduce((sum, item) => sum + (item.value.match(escapes) ?? []).length * 4, 0)
      if (total > 200 && escaped / total > policy.maximumEscapedRatio) {
        findings.push(finding('escaped-ratio', `${file.path} is mostly escape sequences inside string literals`))
      }
    }
  }
  return findings
}

export function checkDangerousRemovals(files) {
  const findings = []
  const risky = /\b(?:directory|file)\.remove\s*\(\s*"(?:[/][^"]*|~[^"]*|\.|\.\.)"\s*[,)]/
  for (const file of files) {
    if (!file.path.endsWith('.sar') || file.text === null) continue
    const { kept } = analyzeSource(file.text)
    for (const line of linesMatching(kept, (text) => risky.test(text))) {
      findings.push(finding('dangerous-removal', `${file.path}:${line} removes a root, home, dot or absolute path literal`))
    }
  }
  return findings
}

export function detectLicense(text) {
  const flat = text.replace(/\s+/g, ' ')
  if (/GNU AFFERO GENERAL PUBLIC LICENSE/i.test(flat)) return 'AGPL-3.0'
  if (/GNU LESSER GENERAL PUBLIC LICENSE/i.test(flat)) return /Version 2\.1/i.test(flat) ? 'LGPL-2.1' : 'LGPL-3.0'
  if (/GNU GENERAL PUBLIC LICENSE/i.test(flat)) return /Version 2,/i.test(flat) ? 'GPL-2.0' : 'GPL-3.0'
  if (/Mozilla Public License/i.test(flat)) return 'MPL-2.0'
  if (/Apache License/i.test(flat) && /Version 2\.0/i.test(flat)) return 'Apache-2.0'
  if (/This is free and unencumbered software/i.test(flat)) return 'Unlicense'
  if (/Permission is hereby granted, free of charge/i.test(flat)) return 'MIT'
  if (/Redistribution and use in source and binary forms/i.test(flat)) {
    return /Neither the name of/i.test(flat) ? 'BSD-3-Clause' : 'BSD-2-Clause'
  }
  if (/Permission to use, copy, modify, and\/or distribute this software for any purpose with or without fee/i.test(flat)) {
    return /provided that the above copyright notice/i.test(flat) ? 'ISC' : '0BSD'
  }
  if (/Altered source versions must be plainly marked/i.test(flat)) return 'Zlib'
  return null
}

function declaredIdentifiers(declared) {
  return declared
    .split(/\s+(?:OR|AND|WITH)\s+|[/]/i)
    .map((part) => part.trim())
    .filter(Boolean)
}

export function checkLicense({ licenseText, declared, policy }) {
  const findings = []
  if (licenseText === null || licenseText === undefined) {
    findings.push(finding('no-license', 'the package has no LICENSE file'))
  }
  if (declared && !policy.allowedLicenses.includes(declared)) {
    findings.push(finding('license-not-allowed', `the license '${declared}' is not in the allowed list`))
  }
  const detected = licenseText ? detectLicense(licenseText) : null
  const copyleft = /^(?:A|L)?GPL/i
  if (detected && copyleft.test(detected)) {
    findings.push(finding('copyleft-license', `the LICENSE file is ${detected}, a copyleft license`))
  } else if (declared && declaredIdentifiers(declared).some((part) => copyleft.test(part))) {
    findings.push(finding('copyleft-license', `the declared license '${declared}' is a copyleft license`))
  }
  if (detected && declared && !declaredIdentifiers(declared).includes(detected)) {
    findings.push(finding('license-mismatch', `the LICENSE file looks like ${detected} but the entry says '${declared}'`))
  }
  return findings
}

export function parseProjectFile(text) {
  const fields = {}
  const requires = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#')) continue
    const separator = line.indexOf(':')
    if (separator === -1) continue
    const key = line.slice(0, separator).trim()
    const value = line.slice(separator + 1).trim()
    if (key === 'require') {
      const [name, version, repository] = value.split(/\s+/)
      requires.push({ name, version, repository })
    } else if (!(key in fields)) {
      fields[key] = value
    }
  }
  return { fields, requires }
}

export function normaliseName(name) {
  return name.toLowerCase().replace(/[\s-]+/g, '_')
}

export function checkProject({ projectText, entryName, paths, policy }) {
  const findings = []
  const { fields } = parseProjectFile(projectText)
  const language = Number(fields.language)
  if (!Number.isInteger(language) || !policy.supportedLanguages.includes(language)) {
    findings.push(
      finding(
        'project-language',
        `sarlin.project language '${fields.language ?? ''}' is not supported (supported: ${policy.supportedLanguages.join(', ')})`,
      ),
    )
  }
  if (fields.name !== undefined && normaliseName(fields.name) !== entryName) {
    findings.push(
      finding('project-name-mismatch', `sarlin.project name '${fields.name}' does not match the Nook name '${entryName}'`),
    )
  }
  if (fields.entry !== undefined && !paths.includes(fields.entry)) {
    findings.push(finding('entry-missing', `the entry file '${fields.entry}' does not exist`))
  }
  return findings
}

export function checkHygiene(paths) {
  const findings = []
  const files = paths.filter((path) => !path.endsWith('/'))
  if (!files.some((path) => /^README(\.[A-Za-z]+)?$/i.test(path))) {
    findings.push(finding('no-readme', 'the package has no README'))
  }
  if (!paths.some((path) => path === 'tests/' || path.startsWith('tests/'))) {
    findings.push(finding('no-tests', 'the package has no tests folder'))
  }
  if (!files.some(isSourcePath)) findings.push(finding('no-source', 'source/ holds no .sar file'))
  if (paths.some((path) => path === '.git/' || path.startsWith('.git/'))) {
    findings.push(finding('git-folder', 'the package contains a .git folder'))
  }
  if (files.includes('.gitmodules')) findings.push(finding('submodule', 'the package uses git submodules'))
  const nested = files.filter((path) => path.endsWith('/sarlin.project'))
  if (nested.length > 0) {
    findings.push(finding('nested-project', `nested sarlin.project files: ${nested.slice(0, 5).join(', ')}`))
  }
  const built = paths.filter(
    (path) =>
      /(^|[/])(output|node_modules)[/]/.test(path) || /\.(exe|so|dll|dylib|zip|tar|gz|tgz|7z|rar)$/i.test(path),
  )
  if (built.length > 0) {
    findings.push(finding('build-output', `committed build output or archives: ${built.slice(0, 5).join(', ')}`))
  }
  return findings
}

const GITHUB_ADDRESS = /^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/

export function checkRequires(requires, listedPackages) {
  const findings = []
  const listed = new Map(listedPackages.map((item) => [item.name, item]))
  for (const require of requires) {
    const text = `${require.name} ${require.version}`
    if (require.repository !== undefined) {
      if (!GITHUB_ADDRESS.test(require.repository)) {
        findings.push(finding('bad-require', `require '${text}' has an address that is not on github.com`))
      }
      continue
    }
    const target = listed.get(require.name)
    if (!target) {
      findings.push(finding('bad-require', `require '${text}' is not a listed Nook package`))
    } else if (target.versions?.length > 0 && !target.versions.some((item) => item.version === require.version)) {
      findings.push(finding('bad-require', `require '${text}' names a version the Nook has not published`))
    }
  }
  return findings
}

export function checkDependencyGraph({ name, graph, newest, unavailable = new Set(), policy }) {
  const findings = []
  let cycle = null
  let deepest = 0
  const visit = (current, trail) => {
    if (cycle) return
    if (trail.includes(current)) {
      cycle = [...trail.slice(trail.indexOf(current)), current]
      return
    }
    deepest = Math.max(deepest, trail.length)
    for (const dependency of graph.get(current) ?? []) visit(dependency.name, [...trail, current])
  }
  visit(name, [])
  if (cycle) findings.push(finding('dependency-cycle', `the requires form a cycle: ${cycle.join(' -> ')}`))
  if (deepest > policy.maximumDependencyDepth) {
    findings.push(
      finding('dependency-depth', `the dependency chain is ${deepest} deep; the limit is ${policy.maximumDependencyDepth}`),
    )
  }
  for (const dependency of graph.get(name) ?? []) {
    if (unavailable.has(`${dependency.name} ${dependency.version}`)) {
      findings.push(finding('dependency-yanked', `requires ${dependency.name} ${dependency.version}, which is yanked or quarantined`))
    }
    const latest = newest.get(dependency.name)
    if (latest && latest !== dependency.version) {
      findings.push(finding('dependency-outdated', `requires ${dependency.name} ${dependency.version}, but ${latest} is the newest`))
    }
  }
  return findings
}

export function normalisedSourceHashes(files) {
  const hashes = new Set()
  for (const file of files) {
    if (!isSourcePath(file.path) || file.text === null) continue
    hashes.add(createHash('sha256').update(file.text.replace(/\s+/g, '')).digest('hex'))
  }
  return hashes
}

export function checkClones({ hashes, owner, others, policy }) {
  const findings = []
  if (hashes.size === 0) return findings
  for (const other of others) {
    if (other.owner.toLowerCase() === owner.toLowerCase()) continue
    let shared = 0
    for (const hash of hashes) if (other.hashes.has(hash)) shared += 1
    if (shared / hashes.size > policy.cloneThreshold) {
      findings.push(
        finding('possible-clone', `${shared} of ${hashes.size} source files are identical to ${other.name}, which has a different owner`),
      )
    }
  }
  return findings
}

export function repositoryOwner(repository) {
  const match = /^https:\/\/github\.com\/([^/]+)\/([^/]+)$/i.exec(repository)
  return match ? { owner: match[1], name: match[2] } : null
}

export function parseCollisionOutput(output, label) {
  const lines = []
  for (const line of output.split('\n')) {
    const match = /^warning: '([^']+)' is defined by (.+)$/.exec(line.trim())
    if (!match || !line.includes(label)) continue
    const labels = [...match[2].matchAll(/([a-z][a-z0-9_]*) (\d+\.\d+\.\d+)|your project/g)].map((item) => item[0])
    lines.push({ name: match[1], labels: labels.filter((item) => item !== label) })
  }
  return lines
}

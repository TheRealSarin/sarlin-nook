import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  CHECKS,
  analyzeSource,
  applyChecks,
  checkClones,
  checkDangerousRemovals,
  checkDependencyGraph,
  checkForeignCode,
  checkHiddenCharacters,
  checkHygiene,
  checkIdentifiers,
  checkLicense,
  checkObfuscation,
  checkPathNames,
  checkProject,
  checkRequires,
  checkSecrets,
  checkSensitiveStrings,
  collectCapabilities,
  defaultCheckSettings,
  detectLicense,
  finding,
  listExternals,
  maskSource,
  normalisedSourceHashes,
  parseCollisionOutput,
  parseProjectFile,
  worstSeverity,
} from '../scripts/checks.mjs'
import { damerauLevenshtein, isTrusted } from '../scripts/policy.mjs'

const policy = JSON.parse(readFileSync(new URL('../policy.json', import.meta.url), 'utf8'))
const ids = (findings) => findings.map((item) => item.id)
const sar = (text, path = 'source/main.sar') => [{ path, text }]
const char = (code) => String.fromCodePoint(code)

test('policy.json carries a switch for every check and nothing else', () => {
  assert.deepEqual(Object.keys(policy.checks).sort(), Object.keys(CHECKS).sort())
  for (const setting of Object.values(policy.checks)) {
    assert.equal(setting.enabled, true)
    assert.ok(['block', 'review', 'info'].includes(setting.severity))
  }
  assert.deepEqual(policy.checks, defaultCheckSettings())
  assert.ok(!policy.reservedNames.includes('csv'))
})

test('applyChecks switches checks off and changes severity', () => {
  const findings = [finding('no-readme', 'x'), finding('no-license', 'y')]
  const tuned = { checks: { 'no-readme': { enabled: false }, 'no-license': { severity: 'block' } } }
  const result = applyChecks(findings, tuned)
  assert.deepEqual(ids(result), ['no-license'])
  assert.equal(result[0].severity, 'block')
  assert.equal(applyChecks(findings, {}).length, 2)
  assert.equal(worstSeverity(result), 'block')
  assert.equal(worstSeverity([finding('no-readme', 'x')]), 'pass')
  assert.equal(worstSeverity([finding('no-license', 'x')]), 'review')
  assert.throws(() => finding('nope', 'x'))
})

test('damerau levenshtein counts transpositions as one edit', () => {
  assert.equal(damerauLevenshtein('csv', 'csv'), 0)
  assert.equal(damerauLevenshtein('csv', 'cvs'), 1)
  assert.equal(damerauLevenshtein('acras', 'acres'), 1)
  assert.equal(damerauLevenshtein('abc', ''), 3)
  assert.ok(isTrusted(policy, 'therealsarin'))
  assert.ok(!isTrusted(policy, 'mallory'))
})

test('maskSource blanks comments and string contents and keeps line numbers', () => {
  const text = 'func a() {\n    # note Network.get\n    print("file.read")\n}\n###\nNetwork.x\n###\nfile.y\n'
  const { code, strings, kept } = maskSource(text)
  assert.equal(code.split('\n').length, text.split('\n').length)
  assert.ok(!code.includes('Network'))
  assert.ok(!code.includes('file.read'))
  assert.ok(code.includes('file.y'))
  assert.deepEqual(strings, [{ line: 3, value: 'file.read' }])
  assert.ok(kept.includes('"file.read"'))
})

test('analyzeSource extracts external blocks and hides their bodies', () => {
  const text = 'external C func add(a int32) int32\n    #include <stdio.h>\n    return a;\nend external\nfunc main() {\n}\n'
  const { externals, code } = analyzeSource(text)
  assert.equal(externals.length, 1)
  assert.equal(externals[0].language, 'C')
  assert.equal(externals[0].name, 'add')
  assert.equal(externals[0].body[0].line, 2)
  assert.ok(!code.includes('include'))
  assert.ok(code.includes('func main'))
})

test('path names with traversal, backslashes, absolute and control characters are blocked', () => {
  assert.deepEqual(checkPathNames(['source/a.sar', 'docs/']), [])
  for (const bad of ['../x', 'a/../b', '/etc/x', 'a\\b', `a${char(7)}b`]) {
    assert.deepEqual(ids(checkPathNames([bad])), ['bad-path'], bad)
  }
})

test('hidden characters are blocked in sources, project files, READMEs and names', () => {
  for (const code of [0x202e, 0x2066, 0x200b, 0x2060, 0x0007]) {
    const result = checkHiddenCharacters(sar(`func a() {\n    print("x${char(code)}y")\n}\n`))
    assert.deepEqual(ids(result), ['hidden-characters'])
    assert.match(result[0].message, /source\/main.sar:2/)
  }
  assert.deepEqual(checkHiddenCharacters(sar(`${char(0xfeff)}func a() {\n}\n`)), [])
  assert.equal(checkHiddenCharacters(sar(`func a() {\n}\n${char(0xfeff)}`)).length, 1)
  assert.equal(checkHiddenCharacters([{ path: 'README.md', text: `hi${char(0x200d)}` }]).length, 1)
  assert.equal(checkHiddenCharacters([{ path: 'sarlin.project', text: `name: a${char(0x202a)}` }]).length, 1)
  assert.equal(checkHiddenCharacters([], [`source/a${char(0x202e)}.sar`]).length, 1)
  assert.deepEqual(checkHiddenCharacters([{ path: 'notes.txt', text: char(0x200b) }]), [])
})

test('non-ASCII and mixed-script identifiers need review but strings and comments do not', () => {
  assert.deepEqual(checkIdentifiers(sar('func café() {\n}\n')).length, 1)
  const mixed = checkIdentifiers(sar(`func p${char(0x0430)}ss() {\n}\n`))
  assert.match(mixed[0].message, /mixed-script/)
  assert.deepEqual(checkIdentifiers(sar('func a() {\n    print("café")\n    # café\n}\n')), [])
})

test('secrets are reported by file and line without the value', () => {
  const token = `ghp_${'a'.repeat(36)}`
  const text = `ok\nkey: AKIA${'A'.repeat(16)}\nx = "${token}"\n-----BEGIN RSA PRIVATE KEY-----\napi_key = "abcdefghijklmnopqrstuvwxyz"\n`
  const result = checkSecrets([{ path: 'a.txt', text }], policy)
  assert.equal(result.length, 4)
  assert.ok(result.every((item) => item.severity === 'block'))
  assert.ok(result.every((item) => !item.message.includes(token) && !item.message.includes('abcdefgh')))
  assert.ok(result[0].message.startsWith('a.txt:2'))
  assert.deepEqual(checkSecrets([{ path: 'a.txt', text: 'token = "short"\npassword: hello\n' }], policy), [])
  assert.deepEqual(checkSecrets([{ path: 'logo.png', text: null }], policy), [])
})

test('capabilities are read from code, not from comments or strings', () => {
  const text = 'func a() {\n    # Network.get\n    print("Time.now")\n    file.read("x")\n    directory.list("y")\n    JSON.parse("{}")\n    local var n = Network.connect("h", 1)\n}\n'
  assert.deepEqual(collectCapabilities(sar(text)), ['directory', 'file', 'json', 'network'])
  assert.deepEqual(collectCapabilities(sar('external C func f()\n    return;\nend external\n')), ['foreign_code'])
  assert.deepEqual(collectCapabilities(sar('func a() {\n}\n')), [])
})

test('external blocks always need review and risky calls are listed with file and line', () => {
  const text = 'external C func run(a int32)\n    system("ls");\n    void *h = dlopen("x", 1);\nend external\nexternal Rust func r()\n    unsafe { }\n    std::process::Command::new("x");\nend external\n'
  const externals = listExternals(sar(text))
  const result = checkForeignCode(externals, ['foreign_code'], policy)
  assert.equal(result.filter((item) => item.id === 'external-code').length, 1)
  assert.match(result[0].message, /run \(C, source\/main.sar:1\)/)
  const patterns = result.filter((item) => item.id === 'foreign-pattern').map((item) => item.message)
  assert.ok(patterns.some((message) => message.includes('main.sar:2') && message.includes('system-call')))
  assert.ok(patterns.some((message) => message.includes('dlopen-call')))
  assert.ok(patterns.some((message) => message.includes('rust-unsafe')))
  assert.ok(patterns.some((message) => message.includes('rust-process-command')))
  assert.ok(result.every((item) => item.severity === 'review'))
})

test('deep native patterns catch assembly, environment reads and Rust fs and net', () => {
  const text = 'external Cpp func a()\n    __asm__("nop");\n    getenv("HOME");\n    mmap(0, 1, PROT_READ | PROT_EXEC, 0, 0, 0);\n    ptrace(0, 0, 0, 0);\nend external\nexternal Rust func b()\n    std::fs::read("x");\n    std::net::TcpStream::connect("x");\n    libc::getpid();\nend external\n'
  const result = checkForeignCode(listExternals(sar(text)), ['foreign_code'], policy)
  const deep = result.filter((item) => item.id === 'native-deep').map((item) => item.message).join('\n')
  for (const id of ['inline-assembly', 'environment-read', 'executable-memory', 'ptrace-call', 'rust-filesystem', 'rust-network', 'libc-call']) {
    assert.ok(deep.includes(id), id)
  }
})

test('capabilities in reviewCapabilities need review', () => {
  assert.deepEqual(ids(checkForeignCode([], ['network', 'file'], policy)), ['network'])
  const tuned = { ...policy, reviewCapabilities: ['file'] }
  assert.deepEqual(ids(checkForeignCode([], ['network', 'file'], tuned)), ['capability-review'])
})

test('sensitive paths, raw IP URLs and unlisted hosts are reported without the string', () => {
  const text = 'func a() {\n    file.read("/home/u/.ssh/id_rsa")\n    print("http://10.0.0.1/x")\n    print("https://evil.test/x")\n    print("https://raw.githubusercontent.com/a/b")\n    print("https://docs.github.com/x")\n}\nexternal C func c()\n    f = fopen("/etc/passwd", "r");\nend external\n'
  const result = checkSensitiveStrings(sar(text), policy)
  assert.deepEqual(ids(result).sort(), ['raw-ip-url', 'sensitive-path', 'sensitive-path', 'unlisted-host'])
  assert.ok(result.every((item) => !item.message.includes('id_rsa') || item.message.includes('ssh-keys')))
})

test('obfuscation heuristics flag long lines, blobs and escape-heavy strings', () => {
  const blob = 'A'.repeat(500)
  assert.deepEqual(ids(checkObfuscation(sar(`func a() {\n    print("${blob}")\n}\n`), policy)), ['encoded-blob'])
  assert.deepEqual(ids(checkObfuscation([{ path: 'README.md', text: 'x'.repeat(2500) }], policy)), ['long-line'])
  const escapes = '\\x41'.repeat(100)
  assert.ok(ids(checkObfuscation(sar(`func a() {\n    print("${escapes}")\n}\n`), policy)).includes('escaped-ratio'))
  assert.deepEqual(checkObfuscation(sar('func a() {\n    print("hello")\n}\n'), policy), [])
})

test('dangerous removals need a bare literal of root, home, dot or an absolute path', () => {
  for (const argument of ['"/"', '"~"', '"."', '".."', '"/home/user"']) {
    assert.equal(checkDangerousRemovals(sar(`func a() {\n    directory.remove(${argument})\n}\n`)).length, 1, argument)
  }
  assert.equal(checkDangerousRemovals(sar('func a() {\n    file.remove("/tmp/x")\n}\n')).length, 1)
  assert.deepEqual(checkDangerousRemovals(sar('func a(p string) {\n    file.remove(p)\n    file.remove("cache.txt")\n}\n')), [])
})

test('license detection recognises distinctive texts', () => {
  const mit = 'MIT License\n\nPermission is hereby granted, free of charge, to any person'
  assert.equal(detectLicense(mit), 'MIT')
  assert.equal(detectLicense('Apache License\nVersion 2.0, January 2004'), 'Apache-2.0')
  assert.equal(detectLicense('GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007'), 'GPL-3.0')
  assert.equal(detectLicense('GNU AFFERO GENERAL PUBLIC LICENSE'), 'AGPL-3.0')
  assert.equal(detectLicense('GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'), 'LGPL-2.1')
  assert.equal(detectLicense('Mozilla Public License Version 2.0'), 'MPL-2.0')
  assert.equal(detectLicense('This is free and unencumbered software released into the public domain.'), 'Unlicense')
  assert.equal(detectLicense('Redistribution and use in source and binary forms, with or without. Neither the name of X'), 'BSD-3-Clause')
  assert.equal(detectLicense('Redistribution and use in source and binary forms, with or without'), 'BSD-2-Clause')
  assert.equal(detectLicense('Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice'), 'ISC')
  assert.equal(detectLicense('hello'), null)
})

test('license checks cover missing, disallowed, mismatched and copyleft licenses', () => {
  const mit = 'Permission is hereby granted, free of charge'
  assert.deepEqual(checkLicense({ licenseText: mit, declared: 'MIT', policy }), [])
  assert.deepEqual(checkLicense({ licenseText: mit, declared: 'MIT OR Apache-2.0', policy }), [])
  assert.deepEqual(ids(checkLicense({ licenseText: null, declared: undefined, policy })), ['no-license'])
  assert.deepEqual(ids(checkLicense({ licenseText: mit, declared: 'Apache-2.0', policy })), ['license-mismatch'])
  assert.deepEqual(ids(checkLicense({ licenseText: mit, declared: 'WTFPL', policy })).sort(), ['license-mismatch', 'license-not-allowed'])
  const gpl = ids(checkLicense({ licenseText: 'GNU GENERAL PUBLIC LICENSE Version 3,', declared: 'GPL-3.0', policy }))
  assert.ok(gpl.includes('copyleft-license') && gpl.includes('license-not-allowed'))
})

test('sarlin.project checks language, name and entry', () => {
  const paths = ['source/csv.sar', 'sarlin.project']
  const good = 'name: csv\nentry: source/csv.sar\nlanguage: 1\n'
  assert.deepEqual(checkProject({ projectText: good, entryName: 'csv', paths, policy }), [])
  assert.deepEqual(ids(checkProject({ projectText: good.replace('language: 1', 'language: 2'), entryName: 'csv', paths, policy })), ['project-language'])
  assert.deepEqual(ids(checkProject({ projectText: 'name: csv\n', entryName: 'csv', paths, policy })), ['project-language'])
  assert.deepEqual(ids(checkProject({ projectText: good.replace('name: csv', 'name: Other-Name'), entryName: 'csv', paths, policy })), ['project-name-mismatch'])
  assert.deepEqual(checkProject({ projectText: good.replace('name: csv', 'name: My Pkg'), entryName: 'my_pkg', paths, policy }), [])
  assert.deepEqual(ids(checkProject({ projectText: good.replace('csv.sar', 'gone.sar'), entryName: 'csv', paths, policy })), ['entry-missing'])
  const parsed = parseProjectFile('name: a\nrequire: b 1.0.0\nrequire: c 1.0.0 https://github.com/o/c\n')
  assert.equal(parsed.requires.length, 2)
  assert.equal(parsed.requires[1].repository, 'https://github.com/o/c')
})

test('hygiene reports missing pieces, git folders, submodules, nested projects and build output', () => {
  const clean = ['README.md', 'LICENSE', 'sarlin.project', 'source/', 'source/a.sar', 'tests/', 'tests/main.sar']
  assert.deepEqual(checkHygiene(clean), [])
  assert.deepEqual(ids(checkHygiene(['sarlin.project', 'source/a.sar'])).sort(), ['no-readme', 'no-tests'])
  assert.deepEqual(ids(checkHygiene([...clean, 'source/x/sarlin.project', '.gitmodules', '.git/', '.git/config', 'output/a.bin', 'tool.exe'])).sort(), ['build-output', 'git-folder', 'nested-project', 'submodule'])
  assert.ok(ids(checkHygiene(['README.md', 'tests/', 'notes.txt'])).includes('no-source'))
  assert.ok(ids(checkHygiene([...clean, 'lib.zip'])).includes('build-output'))
})

test('requires must resolve to listed packages or GitHub addresses', () => {
  const listed = [{ name: 'csv', versions: [{ version: '0.1.0' }] }]
  assert.deepEqual(checkRequires([{ name: 'csv', version: '0.1.0' }], listed), [])
  assert.deepEqual(ids(checkRequires([{ name: 'ghost', version: '1.0.0' }], listed)), ['bad-require'])
  assert.deepEqual(ids(checkRequires([{ name: 'csv', version: '9.0.0' }], listed)), ['bad-require'])
  assert.deepEqual(checkRequires([{ name: 'x', version: '1.0.0', repository: 'https://github.com/o/x' }], listed), [])
  assert.deepEqual(ids(checkRequires([{ name: 'x', version: '1.0.0', repository: 'https://evil.test/o/x' }], listed)), ['bad-require'])
})

test('dependency graph reports cycles, depth, yanked and outdated requirements', () => {
  const dep = (name, version = '1.0.0') => ({ name, version })
  const run = (graph, extra = {}) =>
    checkDependencyGraph({ name: 'a', graph: new Map(Object.entries(graph)), newest: new Map(), policy, ...extra })
  assert.deepEqual(run({ a: [dep('b')], b: [] }), []) 
  assert.deepEqual(ids(run({ a: [dep('b')], b: [dep('a')] })), ['dependency-cycle'])
  const chain = Object.fromEntries(Array.from({ length: 10 }, (_, index) => [index === 0 ? 'a' : `n${index}`, [dep(`n${index + 1}`)]]))
  assert.ok(ids(run(chain)).includes('dependency-depth'))
  assert.deepEqual(ids(run({ a: [dep('b')] }, { unavailable: new Set(['b 1.0.0']) })), ['dependency-yanked'])
  assert.deepEqual(ids(run({ a: [dep('b')] }, { newest: new Map([['b', '1.2.0']]) })), ['dependency-outdated'])
})

test('clone detection compares normalised sources across different owners only', () => {
  const files = [
    { path: 'source/a.sar', text: 'func a() {\n}\n' },
    { path: 'source/b.sar', text: 'func   b()   {   }' },
  ]
  const hashes = normalisedSourceHashes(files)
  assert.equal(hashes.size, 2)
  const same = normalisedSourceHashes([{ path: 'source/z.sar', text: 'func a(){}' }, { path: 'source/y.sar', text: 'func b(){}' }])
  const others = [{ name: 'copy', owner: 'Mallory', hashes: same }]
  assert.deepEqual(ids(checkClones({ hashes, owner: 'alice', others, policy })), ['possible-clone'])
  assert.deepEqual(checkClones({ hashes, owner: 'MALLORY', others, policy }), [])
  assert.deepEqual(checkClones({ hashes: new Set(), owner: 'a', others, policy }), [])
})

test('collision output is parsed for the scanned package label', () => {
  const output = "warning: 'csv_parse' is defined by csv 0.1.1 (source/csv.sar:60) and by other 1.0.0 (source/o.sar:3)\nwarning: 'x' is defined by a 1.0.0 (s:1) and by b 1.0.0 (s:2)\n1 collision found.\n"
  assert.deepEqual(parseCollisionOutput(output, 'csv 0.1.1'), [{ name: 'csv_parse', labels: ['other 1.0.0'] }])
  assert.deepEqual(parseCollisionOutput(output, 'zzz 9.9.9'), [])
})

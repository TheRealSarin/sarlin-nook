import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

export const SARLIN_BIN =
  process.env.SARLIN_BIN ?? '/mnt/Company/sarlin-compiler-and-files/sarlin-compiler/target/release/sarlin'
export const SKIP_COMPILER = existsSync(SARLIN_BIN) ? false : 'the sarlin compiler binary is not available'

export const MIT_TEXT = 'MIT License\n\nCopyright (c) 2026 Test\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n'

export function tempDirectory(prefix = 'nook-test-') {
  return mkdtempSync(join(tmpdir(), prefix))
}

export function git(directory, ...args) {
  return execFileSync('git', args, {
    cwd: directory,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'Test',
      GIT_AUTHOR_EMAIL: 'test@example.invalid',
      GIT_COMMITTER_NAME: 'Test',
      GIT_COMMITTER_EMAIL: 'test@example.invalid',
      GIT_AUTHOR_DATE: process.env.TEST_DATE ?? '2026-01-01T00:00:00Z',
      GIT_COMMITTER_DATE: process.env.TEST_DATE ?? '2026-01-01T00:00:00Z',
    },
  }).trim()
}

export function writeFiles(directory, files) {
  for (const [path, content] of Object.entries(files)) {
    const target = join(directory, path)
    mkdirSync(dirname(target), { recursive: true })
    if (content !== null && typeof content === 'object' && 'symlink' in content) symlinkSync(content.symlink, target)
    else writeFileSync(target, content)
  }
}

export function packageFiles(name, source, extra = {}) {
  return {
    'sarlin.project': `name: ${name}\nentry: source/${name}.sar\nlanguage: 1\n`,
    [`source/${name}.sar`]: source,
    LICENSE: MIT_TEXT,
    'README.md': `# ${name}\n`,
    'tests/main.sar': 'func main() {\n}\n',
    ...extra,
  }
}

export const CLEAN_SOURCE = 'func clean_double(value float64) float64 {\n    return value * 2.0\n}\n'

export function makeRepository(parent, name, files, tag = 'v0.1.0') {
  const directory = join(parent, `${name}-repo`)
  mkdirSync(directory, { recursive: true })
  git(directory, 'init', '--quiet', '-b', 'main')
  writeFiles(directory, files)
  git(directory, 'add', '-A')
  git(directory, 'commit', '--quiet', '-m', 'initial')
  if (tag) git(directory, 'tag', tag)
  return { directory, commit: git(directory, 'rev-parse', 'HEAD') }
}

export function addRelease(directory, files, tag, removals = []) {
  writeFiles(directory, files)
  git(directory, 'add', '-A')
  git(directory, 'commit', '--quiet', '-m', `release ${tag}`)
  git(directory, 'tag', tag)
  return git(directory, 'rev-parse', 'HEAD')
}

export function entryFor(name, repository, extra = {}) {
  return { name, repository, description: `${name} package`, license: 'MIT', ...extra }
}

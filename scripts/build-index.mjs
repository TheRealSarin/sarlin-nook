import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildIndex, formatCatalogue, formatIndex, parseIndex, readEntries } from './lib.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function option(name) {
  const position = process.argv.indexOf(name)
  return position === -1 ? undefined : process.argv[position + 1]
}

const outputDirectory = option('--output') ?? join(root, 'out')
const previousPath = option('--previous')

let previous = new Map()
if (previousPath) {
  try {
    previous = parseIndex(await readFile(previousPath, 'utf8'))
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
}

const { entries, problems } = await readEntries(join(root, 'packages'))
if (problems.length > 0) {
  for (const problem of problems) console.error(`error: ${problem}`)
  process.exit(1)
}

const { packages, warnings } = await buildIndex(entries, previous)
for (const warning of warnings) console.warn(`warning: ${warning}`)

await mkdir(outputDirectory, { recursive: true })
await writeFile(join(outputDirectory, 'index.txt'), formatIndex(packages))
await writeFile(join(outputDirectory, 'packages.json'), formatCatalogue(packages))

const versionCount = packages.reduce((total, entry) => total + entry.versions.length, 0)
console.log(`indexed ${packages.length} package(s) with ${versionCount} version(s)`)

import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { listRemoteVersions, readEntries } from './lib.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const offline = process.argv.includes('--offline')

const { entries, problems } = await readEntries(join(root, 'packages'))

if (!offline) {
  for (const entry of entries) {
    try {
      const versions = await listRemoteVersions(entry.repository)
      if (versions.size === 0) {
        problems.push(
          `${entry.name}: ${entry.repository} has no version tag; tag a release as v1.2.3 before listing it`,
        )
      }
    } catch (error) {
      problems.push(`${entry.name}: could not read ${entry.repository}: ${error.message.split('\n')[0]}`)
    }
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`error: ${problem}`)
  process.exit(1)
}
console.log(`${entries.length} package(s) are valid`)

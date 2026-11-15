import assert from 'node:assert/strict'
import { test } from 'node:test'

import { PACKAGE_LIST_HEADER, cleanListText, formatPackageList } from '../scripts/lib.mjs'

const version = [{ version: '0.1.0', commit: 'a'.repeat(40) }]
const pkg = (name, description, license, versions = version) => ({ name, description, license, versions })

function parse(text) {
  assert.ok(text.endsWith('\n'))
  const [header, ...lines] = text.slice(0, -1).split('\n')
  assert.equal(header, PACKAGE_LIST_HEADER)
  return lines.map((line) => {
    const fields = line.split('\t')
    assert.equal(fields.length, 3, line)
    return { name: fields[0], license: fields[1], description: fields[2] }
  })
}

test('lines are sorted by name with a header and a trailing newline', () => {
  const text = formatPackageList([pkg('svg', 'Vector graphics', 'MIT'), pkg('csv', 'Tables', 'MIT')])
  assert.equal(text, 'nook-catalogue 1\ncsv\tMIT\tTables\nsvg\tMIT\tVector graphics\n')
})

test('a missing license is written as a dash', () => {
  assert.deepEqual(parse(formatPackageList([pkg('csv', 'Tables', undefined), pkg('svg', 'x', '  ')])).map((row) => row.license), ['-', '-'])
})

test('packages without published, non-yanked versions are omitted', () => {
  const text = formatPackageList([
    pkg('none', 'x', 'MIT', []),
    pkg('yanked', 'x', 'MIT', [{ version: '0.1.0', commit: 'a'.repeat(40), yanked: true }]),
    pkg('live', 'x', 'MIT', [{ version: '0.1.0', commit: 'a'.repeat(40), yanked: true }, ...version]),
  ])
  assert.deepEqual(parse(text).map((row) => row.name), ['live'])
  assert.equal(formatPackageList([]), 'nook-catalogue 1\n')
})

test('control characters, tabs, escape sequences and invisible characters become single spaces', () => {
  const dirty = `a\tb\r\nc${String.fromCharCode(27)}[31md${String.fromCodePoint(0x202e)}e${String.fromCodePoint(0x200b)}f${String.fromCodePoint(0xfeff)}g${String.fromCharCode(0)}h${String.fromCodePoint(0x85)}i`
  assert.equal(cleanListText(dirty), 'a b c [31md e f g h i')
  const rows = parse(formatPackageList([pkg('csv', `  ${dirty}  `, 'MIT')]))
  assert.equal(rows[0].description, 'a b c [31md e f g h i')
  assert.ok(!/[\u0000-\u001f]/.test(rows[0].description))
})

test('tabs in the license cannot add fields and long descriptions are cut to 200 characters', () => {
  const rows = parse(formatPackageList([pkg('csv', 'x'.repeat(500), 'MIT\tOR\tApache-2.0')]))
  assert.equal(rows[0].license, 'MIT OR Apache-2.0')
  assert.equal(rows[0].description.length, 200)
  assert.equal(cleanListText(`${'a'.repeat(199)} b`), 'a'.repeat(199))
})

test('an empty description still produces three fields', () => {
  assert.deepEqual(parse(formatPackageList([pkg('csv', '', 'MIT')])), [{ name: 'csv', license: 'MIT', description: '' }])
})

import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

export async function loadPolicy(path = join(ROOT, 'policy.json')) {
  return JSON.parse(await readFile(path, 'utf8'))
}

export function damerauLevenshtein(left, right) {
  const rows = left.length + 1
  const columns = right.length + 1
  const table = Array.from({ length: rows }, () => new Array(columns).fill(0))
  for (let row = 0; row < rows; row += 1) table[row][0] = row
  for (let column = 0; column < columns; column += 1) table[0][column] = column
  for (let row = 1; row < rows; row += 1) {
    for (let column = 1; column < columns; column += 1) {
      const cost = left[row - 1] === right[column - 1] ? 0 : 1
      table[row][column] = Math.min(
        table[row - 1][column] + 1,
        table[row][column - 1] + 1,
        table[row - 1][column - 1] + cost,
      )
      if (row > 1 && column > 1 && left[row - 1] === right[column - 2] && left[row - 2] === right[column - 1]) {
        table[row][column] = Math.min(table[row][column], table[row - 2][column - 2] + 1)
      }
    }
  }
  return table[rows - 1][columns - 1]
}

export function isTrusted(policy, login) {
  return policy.trustedUsers.some((user) => user.toLowerCase() === String(login).toLowerCase())
}

export function createFakeGitHub({ repo = 'TheRealSarin/sarlin-nook' } = {}) {
  const state = {
    repo,
    users: new Map(),
    repos: new Map(),
    pulls: new Map(),
    files: new Map(),
    contents: new Map(),
    labels: new Map(),
    issueLabels: new Map(),
    comments: new Map(),
    nextCommentId: 1,
    calls: [],
    merged: [],
    dispatched: 0,
    mergeError: null,
  }

  const notFound = (path) => Object.assign(new Error(`not found: ${path}`), { status: 404 })

  const api = async (method, path, { body } = {}) => {
    state.calls.push(`${method} ${path}`)
    const [route] = path.split('?')
    let match
    if ((match = /^users\/([^/]+)$/.exec(route)) && method === 'GET') {
      const user = state.users.get(match[1].toLowerCase())
      if (!user) throw notFound(path)
      return user
    }
    if ((match = /^repos\/([^/]+\/[^/]+)\/labels$/.exec(route))) {
      if (method === 'GET') return [...state.labels.values()]
      state.labels.set(body.name, { ...body })
      return body
    }
    if ((match = /^repos\/([^/]+\/[^/]+)\/pulls$/.exec(route)) && method === 'GET') return [...state.pulls.values()].map((pull) => pull.summary ?? pull)
    if ((match = /^repos\/([^/]+\/[^/]+)\/pulls\/(\d+)\/files$/.exec(route))) return state.files.get(Number(match[2])) ?? []
    if ((match = /^repos\/([^/]+\/[^/]+)\/pulls\/(\d+)$/.exec(route))) {
      const pull = state.pulls.get(Number(match[2]))
      if (!pull) throw notFound(path)
      return pull
    }
    if ((match = /^repos\/([^/]+\/[^/]+)\/contents\/(.+)$/.exec(route))) {
      const key = `${match[1]}:${decodeURIComponent(match[2])}:${path.split('ref=')[1]}`
      const text = state.contents.get(key)
      if (text === undefined) throw notFound(path)
      return { encoding: 'base64', content: Buffer.from(text).toString('base64') }
    }
    if ((match = /^repos\/([^/]+\/[^/]+)\/issues\/(\d+)\/labels$/.exec(route))) {
      const number = Number(match[2])
      const current = state.issueLabels.get(number) ?? new Set()
      if (method === 'GET') return [...current].map((name) => ({ name }))
      for (const name of body.labels) current.add(name)
      state.issueLabels.set(number, current)
      return [...current].map((name) => ({ name }))
    }
    if ((match = /^repos\/([^/]+\/[^/]+)\/issues\/(\d+)\/labels\/(.+)$/.exec(route)) && method === 'DELETE') {
      state.issueLabels.get(Number(match[2]))?.delete(decodeURIComponent(match[3]))
      return null
    }
    if ((match = /^repos\/([^/]+\/[^/]+)\/issues\/(\d+)\/comments$/.exec(route))) {
      const number = Number(match[2])
      const list = state.comments.get(number) ?? []
      if (method === 'GET') return list
      const comment = { id: state.nextCommentId++, body: body.body }
      list.push(comment)
      state.comments.set(number, list)
      return comment
    }
    if ((match = /^repos\/([^/]+\/[^/]+)\/issues\/comments\/(\d+)$/.exec(route)) && method === 'PATCH') {
      for (const list of state.comments.values()) {
        const found = list.find((comment) => comment.id === Number(match[2]))
        if (found) found.body = body.body
      }
      return null
    }
    if ((match = /^repos\/([^/]+\/[^/]+)$/.exec(route)) && method === 'GET') {
      const found = state.repos.get(match[1].toLowerCase())
      if (!found) throw notFound(path)
      return found
    }
    throw new Error(`the fake GitHub does not handle ${method} ${path}`)
  }

  return {
    state,
    api,
    addUser(login, daysOld, now) {
      state.users.set(login.toLowerCase(), { login, created_at: new Date(now - daysOld * 86400000).toISOString() })
    },
    addRepository(fullName, { daysOld = 100, now, ...rest } = {}) {
      state.repos.set(fullName.toLowerCase(), {
        full_name: fullName,
        private: false,
        archived: false,
        fork: false,
        created_at: new Date(now - daysOld * 86400000).toISOString(),
        license: { spdx_id: 'MIT' },
        owner: { type: 'User' },
        ...rest,
      })
    },
    addPull(number, { author, sha = 'a'.repeat(40), files, texts = {}, draft = false, association = 'NONE', summary }) {
      state.pulls.set(number, {
        number,
        state: 'open',
        draft,
        user: { login: author },
        author_association: association,
        head: { sha, repo: { full_name: `${author}/sarlin-nook` } },
        summary: summary ?? { number, state: 'open', user: { login: author }, created_at: new Date().toISOString(), merged_at: null },
      })
      state.files.set(number, files)
      for (const [path, text] of Object.entries(texts)) state.contents.set(`${author}/sarlin-nook:${path}:${sha}`, text)
    },
    deps({ listed = [], versions = new Map(), scan, listVersionsError } = {}) {
      return {
        listBaseEntries: async () => listed,
        listVersions: async () => {
          if (listVersionsError) throw new Error(listVersionsError)
          return versions
        },
        scan: scan ?? (async () => ({ findings: [], capabilities: [], files: 1, bytes: 1 })),
        merge: async ({ number, sha }) => {
          if (state.mergeError) throw new Error(state.mergeError)
          state.merged.push({ number, sha })
        },
        dispatchIndex: async () => {
          state.dispatched += 1
        },
      }
    },
  }
}

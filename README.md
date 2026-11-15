# The Nook

The Nook is the package list for the [Sarlin](https://sarlin-lang.org/) programming language. Starlings nest in enclosed spaces, and this is where Sarlin packages live.

This repository does not hold any package code. Each package stays in its own GitHub repository; the Nook records which packages exist and which versions they have published.

## How it works

- `packages/` holds one small file per package, named `<name>.package`.
- A version of a package is a git tag in the package's own repository, written `v1.2.3`.
- Pull requests are checked and merged by the triage workflow (see below).
- Once an hour, and after every change here, a workflow reads the tags of every listed package, scans every new version, and publishes the result to the [`index` branch](https://github.com/TheRealSarin/sarlin-nook/tree/index):
  - `index.txt` has one line per published version: `name version repository commit`, sorted by name, newest version first. `index.txt.sha256` holds its checksum.
  - `packages.json` has the same information with descriptions, for the website. Each package has `compatible` (true, false or null) and `compiler` (the compiler version the newest version was checked with). A version can carry `yanked`, `reason`, `incompatibleWith` and `breaksDependents`.
  - `packages.txt` is the plain text catalogue for the compiler. The first line is `nook-catalogue 1`, then one line per listed package that has a published, non-yanked version, sorted by name: `name<TAB>license<TAB>description`. The license is `-` when the entry has none. Control characters in descriptions are replaced by spaces and descriptions are cut to 200 characters. The versions stay in `index.txt`.
  - `quarantine.json` lists new versions that were held back, with their findings.
  - `health.json` says whether the newest version of every package passes `sarlin check` with the newest released compiler: `{name, version, compiler, status, checkedAt}` where status is `ok`, `failing` or `unavailable` (the repository could not be reached; `since` gives the first day). An entry is reused while the name, version and compiler stay the same.
  - `meta.json` has a `generation` number that only grows when `index.txt` changes, plus `generatedAt` and the checksum, so tools can detect a stale or rolled-back index.
- A published version is pinned to the commit it had when it was first seen. Moving a tag afterwards does not change the published version; release a new version instead.
- Versions that are already in the published index are never scanned again for gating and never removed.

## Listing a package

1. Put the package in a public GitHub repository and tag a release, for example `v0.1.0`.
2. Add `packages/<name>.package` in a pull request:

   ```text
   name: acras
   repository: https://github.com/TheRealSarin/acras
   description: A 2D game engine for Sarlin
   license: MIT OR Apache-2.0
   ```

   - `name` is 2 to 40 characters: lower case letters, digits and underscores, starting with a letter. The file name must match it.
   - `repository` must have the form `https://github.com/owner/name`.
   - `description` is one line. `license` is optional.
   - Lines starting with `#` are ignored.
3. The triage workflow checks the pull request, posts one sticky comment with a table of every check, and either merges it, asks the maintainer to review it, or lists what to fix.

After the pull request is merged, new versions need no further changes here: tag a new release in the package repository and, if the scan passes, it is published within the hour. A package is a Sarlin project (`sarlin.project` and `source/**/*.sar`) that does not define `func main`.

## How triage decides

`.github/workflows/triage.yml` runs on `pull_request_target` (opened, synchronize, reopened, ready_for_review) with write permissions for contents, pull requests, issues and actions. It checks out only the base branch, reads the changed files through the GitHub API at the head commit, and runs only scripts from the base branch. Pull request titles, branch names, file names and descriptions never reach a shell: the workflow passes only the pull request number and head commit through environment variables.

Each check returns pass, review, block or info:

| Check | Rule |
| --- | --- |
| Scope | Every changed file must be an added or modified `packages/<name>.package`. Anything else (workflows, scripts, policy, approvals, yanked.txt, deletions, renames) is review, even for a trusted user. |
| Entry | The entry must pass validation (block). The file name must match the name. Changing the repository of an existing entry is review (it would change where a name points). |
| Author identity | The author must own the package repository (case-insensitive) or be a trusted user, otherwise review. |
| Author account | The account must be at least `minimumAccountAgeDays` old and have at least `minimumPriorMergedPullRequests` merged pull requests here, otherwise review. Trusted users skip the thresholds and are reported as info. |
| Package repository | Must exist, be public (block), not archived, not a fork, at least `minimumRepositoryAgeDays` old, have a license that is in `allowedLicenses` (review). |
| Repository identity | A renamed or transferred repository is review. The owner type is info. |
| Name safety | A reserved name is block. A name that differs from an existing one only by underscores is block. A name within `typosquatDistance` (Damerau-Levenshtein, scaled down for very short names) of an existing or reserved name is review. |
| Duplicate repository | The same repository under another name is block. |
| Package scan | The scan of the newest version tag (see below). Any block finding is block, any review finding is review. |
| Rate limits | More than 3 other open pull requests from the author, more than 3 listings in 24 hours from a young account, or more than 2 entries in one pull request is review. |
| Draft | A draft pull request is never merged. |

The decision is `reject` when any check blocks, `review` when any check asks for review, and `approve` otherwise.

| Decision | Label | What happens |
| --- | --- | --- |
| approve | `auto-approved` | The head commit is re-checked, the pull request is squash merged with `gh pr merge --squash --delete-branch --match-head-commit`, and the index workflow is started (merges made with the workflow token do not trigger push workflows). |
| review | `needs-manual-review` | A comment explains why. Nothing is merged. |
| reject | `rejected-by-checks` | A comment lists the blockers. Push a fix and the checks rerun. |

Missing labels are created on the first run. The comment is identified by the hidden marker `<!-- nook-triage -->` and updated in place on every run; it is not rewritten when nothing changed.

## The package scan

The scan gets the source through the real fetch path: a temporary local index, a temporary project that requires the package, and `sarlin check` plus `sarlin collisions`. It then reads the fetched files as data. Nothing from a package is ever executed: `sarlin check` type checks without compiling or running anything, and package tests are never run. `external C`, `external Cpp` and `external Rust` blocks and `Network.` always need a human.

Every `sarlin` call has a timeout (`sarlinTimeoutSeconds`) and an output cap; a timeout is a block.

### Checks

Every check has an id, a default severity and an entry under `checks` in `policy.json`. Set `"enabled": false` to switch a check off or change its `severity`. Thresholds, lists and patterns live in the same file.

| Id | What it detects | Default |
| --- | --- | --- |
| `check-failed` | sarlin check rejects the package, or a sarlin command timed out | block |
| `main-defined` | a package source file defines func main | block |
| `symlink` | the package contains a symbolic link | block |
| `file-count` | the package has more files than the policy allows | block |
| `package-size` | the package is larger than the policy allows | block |
| `binary-file` | a binary file outside the image and font allowlist, over the size limit, or not matching its extension | block |
| `bad-path` | a path with .., a backslash, an absolute form or control characters | block |
| `secret` | a private key, access key, token or long credential assignment | block |
| `no-project` | the package has no sarlin.project | block |
| `bad-require` | a require line that does not resolve to a listed package or a GitHub address | block |
| `hidden-characters` | bidirectional, zero-width or control characters in sources, project file, README or file names | block |
| `project-language` | sarlin.project names an unsupported language number | block |
| `no-source` | source/ holds no .sar file | block |
| `git-folder` | the package contains a .git folder | block |
| `submodule` | the package uses git submodules | block |
| `dependency-cycle` | the requires of the package form a cycle | block |
| `external-code` | external C, Cpp or Rust blocks (native code compiled into the user program) | review |
| `foreign-pattern` | a risky native call inside an external block | review |
| `native-deep` | assembly, executable memory, environment access, ptrace, Rust fs or net or libc inside an external block | review |
| `network` | use of the Network built-in | review |
| `capability-review` | use of another capability that the policy marks for review | review |
| `no-license` | no LICENSE file | review |
| `license-not-allowed` | the stated license is not in the allowed list | review |
| `license-mismatch` | the LICENSE text does not match the license in the entry | review |
| `copyleft-license` | a GPL, AGPL or LGPL license | review |
| `collision` | a top-level name that another listed package also defines | review |
| `non-ascii-identifier` | non-ASCII or mixed-script identifiers | review |
| `sensitive-path` | a string or external block that names credential or browser data locations | review |
| `raw-ip-url` | a URL with a raw IP address | review |
| `unlisted-host` | a URL whose host is not in the allowed hosts | review |
| `long-line` | a line longer than the policy allows | review |
| `encoded-blob` | a long base64-like or hexadecimal blob | review |
| `escaped-ratio` | a very high ratio of escaped characters in string literals | review |
| `dangerous-removal` | file.remove or directory.remove of a bare root, home, dot or absolute literal | review |
| `project-name-mismatch` | the name in sarlin.project differs from the Nook entry name | review |
| `entry-missing` | the entry file in sarlin.project does not exist | review |
| `build-output` | committed build output, archives, executables or node_modules | review |
| `nested-project` | a nested sarlin.project file | review |
| `possible-clone` | most source files are identical to another package from a different owner | review |
| `dependency-depth` | the dependency chain is deeper than the policy allows | review |
| `dependency-yanked` | a requirement on a yanked or quarantined version | review |
| `tag-unreachable` | the version commit is not reachable from the default branch | review |
| `history-rewrite` | the version commit does not descend from the previous published version | review |
| `capability-escalation` | a capability the previous version did not use | review |
| `size-growth` | size or file count grew by more than the configured factor | review |
| `back-dated-tag` | the version is lower than a published version | info |
| `back-dated-commit` | the tag is older than the commit of the previous version | review |
| `version-jump` | the version jumps more than the allowed major or minor steps | review |
| `dependents-break` | dependents that fail with this version | info |
| `dependents-break-compatible` | dependents that fail although the bump claims compatibility | review |
| `dependency-outdated` | a requirement pinned below the newest published version | info |
| `incompatible-with` | listed packages this version cannot be combined with | info |
| `collision-check-skipped` | the cross-package collision check could not run | info |
| `no-readme` | no README | info |
| `no-tests` | no tests folder | info |
| `capabilities` | capabilities used by the package | info |
| `statistics` | file, byte and line counts | info |
| `dependencies` | packages required by this package | info |
| `signed` | the commit or tag carries a signature | info |
| `repository-moved` | the repository was renamed, transferred or redirected | review |
| `owner-type` | the owner is a user or an organization | info |
| `too-many-open-pulls` | the author has too many open pull requests | review |
| `listing-rate` | a young account lists too many packages in a day | review |
| `too-many-entries` | one pull request adds too many entries | review |
| `repository-unavailable` | a listed repository stayed unreachable for several days | review |

## Gated index

- Every new version is scanned. No block and no review findings: published. Any block or review finding: not published, written to `quarantine.json` instead.
- A review hold is released by a line `name version commit` in `approvals.txt` (`#` starts a comment). A block can never be approved; release a fixed version.
- For each newly held version one issue titled `Needs review: <name> <version>` is opened with the findings and the exact line to add to `approvals.txt`. Duplicates are not opened, and the issue is closed when the version is no longer held back. A repository that stays unreachable for `unavailableDaysBeforeIssue` days gets a `Repository unavailable: <name>` issue; versions are never removed automatically.
- The scan of a held version is reused until the commit or `policy.json` changes.

### Yanking a version

Add `name version reason` to `yanked.txt` in a pull request (a maintainer merges it, as it is not a package file). The version disappears from `index.txt`, so `sarlin add` and fresh resolution skip it. Projects with an existing `sarlin.lock` keep working because the lock pins a repository and a commit. `packages.json` keeps the version with `"yanked": true` and the reason. See `SECURITY.md`.

## Policy and approvals

- `policy.json` holds every threshold: trusted users, age limits, size limits, reserved names, allowed licenses, patterns for risky native calls and secrets, allowed hosts, and the per-check switches.
- `approvals.txt` releases review holds (one line per version and commit).
- `yanked.txt` pulls versions from the index.
- `CODEOWNERS` asks the owner to review every change.

## Security model

- The triage workflow never checks out or runs pull request code. It uses the API to read files and treats all package repository content as hostile data.
- Untrusted values reach scripts only through environment variables, never through expressions interpolated into shell. `tests/workflow-security.test.mjs` enforces this for every workflow.
- Secret values found in packages are never printed; findings give a file and line.
- Comment text from packages (compiler output, file names) is stripped of markup and mentions before it is posted.
- `external` native code and `Network.` always need a human; so do first contributions, young accounts, forks, new capabilities and history rewrites.

### Pinned actions

The workflows use the official `actions/checkout@v4` and `actions/setup-node@v4` by major tag, checked by the workflow test. They are not yet pinned by commit SHA because the SHAs could not be resolved without network access; Dependabot proposes updates weekly. Pin them with `gh api repos/actions/checkout/git/ref/tags/<tag>` (dereference annotated tags) and record the table here.

## Checking a change locally

```sh
npm test
npm run validate
npm run build-index -- --sarlin /path/to/sarlin
```

`npm run validate -- --offline` checks the files without contacting GitHub. Tests that need the compiler use `SARLIN_BIN` and skip when it is not available. The scripts need Node 22 or newer and Git, and have no other dependencies.

## License

The Nook's scripts and package list are available under your choice of the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE): `MIT OR Apache-2.0`. Each listed package has its own license.


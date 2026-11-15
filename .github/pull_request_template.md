## Package listing checklist

- [ ] The package repository is public and has a tagged release such as `v0.1.0`
- [ ] The package has a LICENSE file and the entry names the same license
- [ ] The package does not define `func main`
- [ ] The package contains no `external` native code, unless it is really needed (it always needs a manual review)
- [ ] The package does not use `Network.` unless it is really needed (it needs a manual review)
- [ ] The package has no committed secrets, binaries, build output or symbolic links
- [ ] This pull request only adds or changes files in `packages/`

The triage workflow checks all of this automatically and merges the pull request when everything is clean.

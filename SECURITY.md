# Security policy

## What the Nook protects

The Nook lists packages that Sarlin programs compile into their own executables. A malicious package can therefore run code on the machine of everyone who uses it. For that reason the Nook never executes anything from a package: it fetches the source at a pinned commit, type checks it with `sarlin check` and reads the files as data. Packages with `external` native code, network use or anything unusual always wait for a human.

## Reporting a malicious or broken package

- For a suspected malicious package or a leaked secret, use GitHub's private vulnerability reporting on this repository (Security tab, Report a vulnerability). Do not open a public issue with exploit details.
- For a broken package or a license problem, open an issue with the "Report a malicious or broken package" template.
- Say which package and version you mean, and where in the code you saw the problem.

## What happens next

- You get a first answer within 3 days. A confirmed malicious package is yanked as soon as the maintainer can act, normally within 24 hours.
- The package entry is removed or the version is yanked, and the owner is asked to release a fixed version.

## Yanking a version

A version is yanked by adding a line `name version reason` to `yanked.txt` in a pull request. The file is not a package file, so a maintainer always merges it by hand.

- Yanked versions are removed from `index.txt`, so `sarlin add` and fresh dependency resolution skip them.
- Projects with an existing `sarlin.lock` keep working, because the lock pins a repository and a commit.
- `packages.json` still lists the version with `"yanked": true` and the reason.
- Versions are never removed automatically.

## Supported versions

Only the latest published index is supported.

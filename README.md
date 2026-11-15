# The Nook

The Nook is the package list for the [Sarlin](https://sarlin-lang.org/) programming language. Starlings nest in enclosed spaces, and this is where Sarlin packages live.

This repository does not hold any package code. Each package stays in its own GitHub repository; the Nook records which packages exist and which versions they have published.

## How it works

- `packages/` holds one small file per package, named `<name>.package`.
- A version of a package is a git tag in the package's own repository, written `v1.2.3`.
- Once an hour, and after every change here, a workflow reads the tags of every listed package and publishes the result to the [`index` branch](https://github.com/TheRealSarin/sarlin-nook/tree/index):
  - `index.txt` has one line per published version: `name version repository commit`, sorted by name, newest version first.
  - `packages.json` has the same information with descriptions, for the website.
- A published version is pinned to the commit it had when it was first seen. Moving a tag afterwards does not change the published version; release a new version instead.

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
3. The pull request check confirms the file is well formed, the repository can be read, and it has at least one version tag.

After the pull request is merged, new versions need no further changes here: tag a new release in the package repository and it is picked up within the hour.

## Checking a change locally

```sh
npm test
npm run validate
npm run build-index
```

`npm run validate -- --offline` checks the files without contacting GitHub. The scripts need Node 22 or newer and Git, and have no other dependencies.

## License

The Nook's scripts and package list are available under your choice of the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE): `MIT OR Apache-2.0`. Each listed package has its own license.

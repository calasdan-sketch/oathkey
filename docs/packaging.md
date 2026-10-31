# Packaging: oathkey.pyz, winget and npx

None of these is published yet. This page says how to build each one and how
to submit it. PyPI stays the main way in (`pipx install oathkey`).

## oathkey.pyz (one file, any Python 3.10+)

```
python scripts/build_pyz.py            # writes dist/oathkey.pyz and dist/oathkey-<version>-windows.zip
python dist/oathkey.pyz doctor
```

The release workflow builds both files on every `v*` tag, attaches them to
the GitHub release, lists them in `SHA256SUMS` and gives them a build
provenance attestation. They are not uploaded to PyPI.

On its first run the `.pyz` unpacks itself once into
`~/.oathkey/pyz/<hash>/` (oathkey reads its recipes and `SKILL.md` as files).
`install`, `setup-agent`, `wrap` and `scan-git --install-hook` write
`python -P <path to oathkey.pyz> ...`, so keep the file where it is. It refuses
`hook install`: the Claude Code hook needs the pip install.

## winget (Windows)

winget wants an installer (exe, msi, msix or zip), and a Python program is
none of those, so the package is a **portable zip**: `oathkey.pyz` plus
`oathkey.cmd`, a launcher that runs it with `py -3` (or `python`). The
manifest lists `Python.Python.3.12` as a dependency, so winget installs Python
first. `ArchiveBinariesDependOnPath: true` puts the folder on PATH; a
`PortableCommandAlias` is not used because winget names a link to a `.cmd`
`oathkey.exe`, which then does not start
([winget-cli #3807](https://github.com/microsoft/winget-cli/issues/3807)).

The manifests (schema 1.10.0) are in
`packaging/winget/manifests/c/CalasAutomations/oathkey/0.9.0/`.

To submit a release:

1. Push the tag and wait for the GitHub release.
2. In `CalasAutomations.oathkey.installer.yaml`, replace
   `REPLACE_WITH_THE_SHA256_OF_THE_ZIP_FROM_SHA256SUMS` with the line for
   `oathkey-<version>-windows.zip` in the release's `SHA256SUMS`. For a new
   version, also change `0.9.0` in all three files, the folder name and the URL.
3. Check it on a Windows PC:
   `winget validate --manifest <folder>`, then
   `winget install --manifest <folder>` (turn on local manifests first:
   `winget settings --enable LocalManifestFiles`, as admin), then open a new
   window and run `oathkey doctor`.
4. Fork https://github.com/microsoft/winget-pkgs, copy the folder to the same
   path under `manifests/`, and open a pull request. `wingetcreate submit
   <folder>` does the fork and the pull request for you.

Without winget, `packaging/winget/install-oathkey.cmd` installs from PyPI
with pipx if it is there, else `py -m pip install --user oathkey`.

## npx (Node.js)

`packaging/npm/` is a package called `oathkey` with no dependencies.
`bin/oathkey.js` finds Python 3.10+ (`py -3`, `python` or `python3`) and runs
the `oathkey.pyz` shipped next to it, or `python -m oathkey` when there is
none. Without Python it says: "Install Python 3.10+ from python.org, then run
again."

To publish:

```
python scripts/build_pyz.py packaging/npm      # puts oathkey.pyz in the package
cd packaging/npm
# set "version" in package.json to the release version
npm pack --dry-run                             # check the list: bin/oathkey.js, oathkey.pyz, README.md, package.json
npm publish
```

`packaging/npm/oathkey.pyz` is git-ignored; build it fresh each time.

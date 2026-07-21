# npm adversary

Reviews npm projects for dangerous lifecycle scripts, mutable dependencies, and missing lockfiles.

## Checks

- **npm lifecycle downloads and executes remote code:** Vendor or checksum installer inputs.
- **npm dependency uses a mutable version:** Use reviewed versions and commit the lockfile.
- **npm project has no lockfile:** Commit a package lockfile.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects the npm adversary when changes include `package.json` or `**/package.json`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.

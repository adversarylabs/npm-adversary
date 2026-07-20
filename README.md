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

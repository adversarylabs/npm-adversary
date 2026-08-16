# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `npm.auto-update-no-cooldown` | High | Dependency auto-merge is enabled with no release-age cooldown |
| `npm.direct-dependency-lock-drift` | High | A package manifest's direct dependency map differs from its npm v2/v3 lockfile package entry |
| `npm.git-dependency` | Medium | Production dependency is a mutable git URL (branch) |
| `npm.lifecycle-download` | Critical | Lifecycle script fetches artifacts without integrity pin |
| `npm.lifecycle-obfuscated` | Critical | Lifecycle script contains obfuscated or encoded execution |
| `npm.lifecycle-remote-exec` | Critical | Lifecycle script downloads and executes remote code |
| `npm.missing-lockfile` | Medium | `package.json` exists without `package-lock.json` or `npm-shrinkwrap.json` |
| `npm.publish-config-insecure-registry` | High | `.npmrc` or `publishConfig` points publish/registry to HTTP (non-TLS) |
| `npm.script-curl-pipe` | High | Any package script (not only install) pipes remote content to a shell |
| `npm.unbounded-dependency` | Medium | Dependency range is unbounded (`*`, `latest`, or `>=0.0.0`) on production deps |

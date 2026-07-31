> **Shipped in 0.0.4:** , , , , , , , , 
>
> Rules documented below that are not in that list are deferred (not yet in `src/spec.ts`).

# Checks — what npm detects

This file is the **public audit list** of detectors for the **npm** adversary. Product surface for Node package supply-chain issues that are high-confidence from static `package.json` / lockfile review—not a full malware scanner of `node_modules`.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `.npmrc`; plus update-automation config for the npm ecosystem only (`renovate.json` / `.github/renovate.json5`, `.github/dependabot.yml`). Do not deep-scan installed tarballs.

**Precision stance:** Lifecycle scripts that download/execute remote code fire. Harmless local `tsc`/`node` scripts stay quiet. Unbounded ranges fire only when lockfile is also missing or ignored.

Public grounding: historical npm supply-chain incidents (**event-stream** 2018, **ua-parser-js** 2021, **node-ipc** protestware, **chalk/debug** takeover and **Shai-Hulud** worm 2025, recurring `preinstall`/`postinstall` malware campaigns), npm docs on lifecycle scripts, lockfile integrity practices, and release-age cooldown adoption (Renovate/Dependabot/pnpm/Bun `minimumReleaseAge`).

---

## Critical

### `npm.lifecycle-remote-exec`

| | |
| --- | --- |
| **What** | Lifecycle script downloads and executes remote code |
| **Why** | Primary npm malware delivery path (`postinstall` curl-bash, `node -e` fetch) |
| **Looks for** | `scripts.preinstall|install|postinstall|prepare|prepublishOnly` containing `curl`, `wget`, `fetch(`, `http.get`, `bash -c`, `curl \| sh`, `curl \| bash`, or piping to `node` |
| **Stays quiet when** | Scripts only run local bin paths (`tsc`, `husky install`, `node ./scripts/…` without network fetch) |
| **Public examples** | [event-stream incident](https://github.com/dominictarr/event-stream/issues/116); ua-parser-js compromise via poisoned publish; endless postinstall miners |
| **Remediation** | Remove network install scripts; vendor binaries with checksums; use `ignore-scripts` in CI for untrusted deps |

### `npm.lifecycle-download`

| | |
| --- | --- |
| **What** | Lifecycle script fetches artifacts without integrity pin |
| **Why** | Even “legitimate” installers are MITM/supply-chain pivots if unpinned |
| **Looks for** | install scripts with URL downloads lacking sha256 verification |
| **Stays quiet when** | Download is paired with checksum verification in-script, or uses package `optionalDependencies` binary packages from the registry |
| **Public examples** | Same class as remote-exec; many native addon installers historically curl unpinned |
| **Remediation** | Vendor or checksum installer inputs; prefer prebuilds from npm with integrity |

### `npm.lifecycle-obfuscated`

| | |
| --- | --- |
| **What** | Lifecycle script contains obfuscated or encoded execution |
| **Why** | Dominant pattern in real npm malware: `postinstall` decoding and executing a payload |
| **Looks for** | `scripts.preinstall\|install\|postinstall\|prepare` containing `eval(`, `Buffer.from(…, 'base64')`, `atob(`, long base64/hex literals, or `node -e` with encoded payloads |
| **Stays quiet when** | Plain readable build tooling; short `node -e` one-liners without decode-then-execute |
| **Public examples** | event-stream payload staging; recurring registry malware campaigns using encoded postinstall droppers |
| **Remediation** | Lifecycle scripts must be short and readable; anything encoded is rewrite-or-remove |

---

## High

### `npm.script-curl-pipe`

| | |
| --- | --- |
| **What** | Any package script (not only install) pipes remote content to a shell |
| **Why** | `npm run` is often trusted in CI; pipe-to-shell is still RCE |
| **Looks for** | `scripts.*` matching `curl … \| … sh/bash` or `wget … \| …` |
| **Stays quiet when** | No pipe-to-shell patterns |
| **Public examples** | Install docs that recommend `curl | bash` copied into package scripts |
| **Remediation** | Download to file, verify checksum, then execute |

### `npm.publish-config-insecure-registry`

| | |
| --- | --- |
| **What** | `.npmrc` or `publishConfig` points publish/registry to HTTP (non-TLS) |
| **Why** | Credential and tarball interception |
| **Looks for** | `registry=http://` or `publishConfig.registry` http URL |
| **Stays quiet when** | HTTPS registries only |
| **Public examples** | npm registry security requirements; corporate mirror misconfigs |
| **Remediation** | Use HTTPS registries only |

### `npm.auto-update-no-cooldown`

| | |
| --- | --- |
| **What** | Dependency auto-merge is enabled with no release-age cooldown |
| **Why** | Compromised versions are typically detected within hours-to-days of publish (chalk/debug takeover and Shai-Hulud worm, Sept 2025); auto-merging a patch published hours ago pulls malware in with zero human latency. A cooldown window means detection happens before you install |
| **Looks for** | Renovate config (`renovate.json` / `.github/renovate.json5`) with `automerge: true` (globally or in packageRules covering prod deps) and no `minimumReleaseAge`; `.github/dependabot.yml` npm ecosystem entries with auto-merge workflows and no `cooldown:` block |
| **Stays quiet when** | `minimumReleaseAge` / `cooldown` configured (any value ≥ 3 days); automerge disabled (human review provides the latency); automerge scoped to devDependencies only (downgrade to medium) |
| **Public examples** | Renovate `minimumReleaseAge` docs; Dependabot cooldown config; pnpm ≥ 10.16 / Bun `minimumReleaseAge`; Sept 2025 npm compromises where week-delayed installs were never exposed |
| **Remediation** | Set `minimumReleaseAge: "7 days"` (Renovate) or a Dependabot `cooldown`; plain npm has no native equivalent (`before=` in `.npmrc` is a blunt workaround) — pin exact versions and update deliberately. Fast-track genuinely urgent security patches manually. Note the trade-off honestly: cooldown delays security-fix uptake in exchange for not being patient zero |

---

## Medium

### `npm.unbounded-dependency`

| | |
| --- | --- |
| **What** | Dependency range is unbounded (`*`, `latest`, or `>=0.0.0`) on production deps |
| **Why** | Automatic major jumps pull unreviewed code |
| **Looks for** | `dependencies` / `optionalDependencies` versions that are `*`, `latest`, or `>=` without upper bound |
| **Stays quiet when** | Semver ranges with upper bounds (`^`, `~`, exact); devDependencies alone may be lower severity—still report `*` on deps. A committed lockfile downgrades to low (per stance: ranges fire hard only when the lockfile is missing or ignored) |
| **Public examples** | Lockfile vs range debates; surprise major bumps in CI |
| **Remediation** | Use reviewed versions and commit the lockfile |

### `npm.missing-lockfile`

| | |
| --- | --- |
| **What** | `package.json` exists without `package-lock.json` or `npm-shrinkwrap.json` |
| **Why** | Installs are non-reproducible across machines/CI |
| **Looks for** | package.json present; no npm lock/shrinkwrap (do not require yarn.lock/pnpm—owned by those adversaries) |
| **Stays quiet when** | Lockfile present. Libraries (published surface via `main`/`exports`, `private` unset) downgrade to low — lockfiles don’t ship with publishes; apps and anything with CI deploy signals fire at medium |
| **Public examples** | npm docs on package-lock; “works on my machine” install drift |
| **Remediation** | Commit `package-lock.json` from `npm install` / `npm ci` |

### `npm.scripts-prepublish-network`

| | |
| --- | --- |
| **What** | `prepublish` / `prepublishOnly` / `prepare` performs network install beyond local build |
| **Why** | Publish-time and consumer-install-time surprise execution |
| **Looks for** | Those script names with network fetch indicators |
| **Stays quiet when** | `prepare` only runs `tsc` / `npm run build` locally |
| **Public examples** | Lifecycle script malware; accidental network in prepare |
| **Remediation** | Keep prepare local; never download at publish/install |

### `npm.git-dependency`

| | |
| --- | --- |
| **What** | Production dependency is a mutable git URL (branch) |
| **Why** | Branch HEADs move; integrity field may be weak |
| **Looks for** | `dependencies` values like `git+https://…#main` / `#master` without commit SHA |
| **Stays quiet when** | Git URL pins full commit SHA |
| **Public examples** | npm git dependency docs; supply-chain via branch force-push |
| **Remediation** | Pin commit SHAs or publish to the registry |

---

## Out of scope

| Concern | Owner |
| --- | --- |
| Yarn / pnpm lock semantics | `yarn` / `pnpm` adversaries |
| TypeScript type-safety / React patterns | `typescript` / `react` |
| Generic secret scanning | `security/secrets` |
| Dockerfile Node base images | `container/dockerfile` |

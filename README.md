# npm

**npm** reviews Node package metadata for **dangerous lifecycle scripts, auto-update cooldowns, registry TLS, and lockfile integrity**.

It is a **package supply-chain reviewer**, not a malware scanner of node_modules. When it reports, install or auto-update paths can execute or pull untrusted code.

## What it does

1. **Discovers** package.json, lockfiles, .npmrc, and Renovate/Dependabot config.
2. **Runs deterministic detectors** for lifecycle scripts, ranges, lockfiles, and cooldowns.
3. **Synthesizes a review** with file:line evidence.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)**.

Highlights:

| Area | Examples |
| --- | --- |
| Lifecycle | curl|bash postinstall; obfuscated eval/base64 scripts |
| Automation | Renovate/Dependabot automerge without release-age cooldown |
| Integrity | Missing or stale lockfile; * ranges; mutable git deps |
| Registry | HTTP registry URLs |

### Ownership boundaries

| Concern | Owned by |
| --- | --- |
| Yarn / pnpm lock semantics | `yarn` / `pnpm` adversaries |
| Generic secret scanning | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |
| Dockerfile Node bases | [`container/dockerfile`](https://github.com/adversarylabs/dockerfile-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire.
- Prefer missing a weak signal over a false positive on normal production code.

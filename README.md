# npm adversary

Reviews npm projects for dangerous lifecycle scripts, auto-update cooldowns, and lockfile integrity.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates npm manifests, lockfiles, lifecycle scripts, registry configuration, dependency sources, integrity, and automated update policy.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns this dependency manager's configuration and resolution inputs. Package source code and other ecosystem concerns remain with language and security specialists.

export const spec = {
    "id": "npm",
    "displayName": "npm",
    "description": "Reviews npm projects for dangerous lifecycle scripts, auto-update cooldowns, and lockfile integrity.",
    "files": [
        "package.json",
        "**/package.json",
        "package-lock.json",
        "**/package-lock.json",
        "npm-shrinkwrap.json",
        "**/npm-shrinkwrap.json",
        ".npmrc",
        "**/.npmrc",
        "renovate.json",
        ".github/renovate.json5",
        ".github/dependabot.yml"
    ],
    "rules": [
        {
            "id": "npm.lifecycle-remote-exec",
            "title": "Lifecycle script downloads and executes remote code",
            "summary": "Lifecycle script downloads and executes remote code",
            "category": "supply-chain",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Primary npm malware delivery path via postinstall curl-bash.",
            "impact": "Install-time remote code execution as the developer or CI identity.",
            "recommendation": "Remove network install scripts; vendor binaries with checksums.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "lifecycle"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json"
                ],
                "pattern": {
                    "pattern": "[\\\"'](?:preinstall|install|postinstall|prepare|prepublishOnly)[\\\"']\\s*:\\s*[\\\"'][^\\\"']*(?:curl|wget)\\s+[^\\\"']*(?:\\|\\s*(?:ba)?sh|bash\\s+-c)",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "npm.lifecycle-download",
            "title": "Lifecycle script fetches remote artifacts without integrity",
            "summary": "Lifecycle script fetches remote artifacts without integrity",
            "category": "supply-chain",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Unpinned install-time downloads are supply-chain pivots.",
            "impact": "MITM or malicious artifact substitution at install.",
            "recommendation": "Vendor or checksum installer inputs.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "download"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json"
                ],
                "pattern": {
                    "pattern": "[\\\"'](?:preinstall|install|postinstall|prepare)[\\\"']\\s*:\\s*[\\\"'][^\\\"']*(?:curl|wget)\\s+https?://",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "npm.lifecycle-obfuscated",
            "title": "Lifecycle script uses obfuscated or encoded execution",
            "summary": "Lifecycle script uses obfuscated or encoded execution",
            "category": "supply-chain",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Dominant pattern in real npm malware: decode-then-execute postinstall.",
            "impact": "Hidden payload execution during npm install.",
            "recommendation": "Lifecycle scripts must be short and readable.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "obfuscation"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json"
                ],
                "pattern": {
                    "pattern": "[\\\"'](?:preinstall|install|postinstall|prepare)[\\\"']\\s*:\\s*[\\\"'][^\\\"']*(?:eval\\(|Buffer\\.from|atob\\(|node -e )",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "npm.script-curl-pipe",
            "title": "Package script pipes remote content to a shell",
            "summary": "Package script pipes remote content to a shell",
            "category": "supply-chain",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "npm run is trusted in CI; pipe-to-shell is still RCE.",
            "impact": "Remote code execution via a project script.",
            "recommendation": "Download to file, verify checksum, then execute.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "curl-pipe"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json"
                ],
                "pattern": {
                    "pattern": "[\\\"'][^\\\"']+[\\\"']\\s*:\\s*[\\\"'][^\\\"']*(?:curl|wget)[^\\\"']*\\|\\s*(?:ba)?sh",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "npm.publish-config-insecure-registry",
            "title": "Registry or publishConfig uses HTTP",
            "summary": "Registry or publishConfig uses HTTP",
            "category": "supply-chain",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Non-TLS registries enable credential and tarball interception.",
            "impact": "Token theft or package substitution.",
            "recommendation": "Use HTTPS registries only.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "registry"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json",
                    ".npmrc",
                    "**/.npmrc"
                ],
                "pattern": {
                    "pattern": "(?:registry\\s*=\\s*http://|\\\"registry\\\"\\s*:\\s*\\\"http://)",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "npm.auto-update-no-cooldown",
            "title": "Auto-merge enabled without release-age cooldown",
            "summary": "Auto-merge enabled without release-age cooldown",
            "category": "supply-chain",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Compromised versions are often detected within days; auto-merge without age pulls malware immediately.",
            "impact": "Zero human latency to a poisoned publish.",
            "recommendation": "Set minimumReleaseAge or Dependabot cooldown (e.g. 7 days).",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "cooldown"
            ],
            "match": {
                "kind": "missing-content",
                "files": [
                    "renovate.json",
                    ".github/renovate.json5",
                    ".github/dependabot.yml",
                    "**/renovate.json"
                ],
                "trigger": {
                    "pattern": "automerge[\\\"']?\\s*:\\s*true",
                    "flags": "i"
                },
                "required": {
                    "pattern": "minimumReleaseAge|cooldown\\s*:",
                    "flags": "i"
                }
            }
        },
        {
            "id": "npm.direct-dependency-lock-drift",
            "title": "Direct dependency metadata differs from npm lockfile",
            "summary": "Direct dependency metadata differs from npm lockfile",
            "category": "dependency-integrity",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "npm ci requires package manifests and lockfile package entries to describe the same direct dependency contract.",
            "impact": "Clean installs can fail, or install metadata that does not represent the reviewed manifest.",
            "recommendation": "Regenerate and commit the npm lockfile with npm install --package-lock-only.",
            "complexity": "trivial",
            "tags": ["npm", "lockfile", "reproducibility"],
            "match": {
                "kind": "direct-dependency-drift",
                "files": ["package.json", "**/package.json", "package-lock.json", "**/package-lock.json", "npm-shrinkwrap.json", "**/npm-shrinkwrap.json"]
            }
        },
        {
            "id": "npm.unbounded-dependency",
            "title": "Production dependency uses unbounded range",
            "summary": "Production dependency uses unbounded range",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Automatic major jumps pull unreviewed code.",
            "impact": "Surprise breaking or malicious major versions.",
            "recommendation": "Use reviewed versions and commit the lockfile.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "range"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json"
                ],
                "pattern": {
                    "pattern": "\\\"dependencies\\\"\\s*:\\s*\\{[^}]{0,800}\\\"[^\\\"]+\\\"\\s*:\\s*\\\"(?:\\*|latest|>=0\\.0\\.0)\\\"",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "npm.missing-lockfile",
            "title": "package.json without npm lockfile",
            "summary": "package.json without npm lockfile",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Installs are non-reproducible across machines and CI.",
            "impact": "Different dependency trees on each install.",
            "recommendation": "Commit package-lock.json from npm install / npm ci.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "lockfile"
            ],
            "match": {
                "kind": "missing-file",
                "triggerFiles": [
                    "package.json"
                ],
                "requiredFiles": [
                    "package-lock.json",
                    "npm-shrinkwrap.json"
                ]
            }
        },
        {
            "id": "npm.git-dependency",
            "title": "Production dependency tracks a mutable git branch",
            "summary": "Production dependency tracks a mutable git branch",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Branch HEADs move under you.",
            "impact": "Non-reproducible installs and force-push risk.",
            "recommendation": "Pin git dependencies to full commit SHAs.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "git"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json"
                ],
                "pattern": {
                    "pattern": "\\\"dependencies\\\"\\s*:\\s*\\{[^}]*git(?:\\+https?)?:[^\\\"']+#(?:main|master)[\\\"']",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};

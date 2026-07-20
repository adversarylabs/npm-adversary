export const spec = {
    "id": "npm",
    "displayName": "npm",
    "description": "Reviews npm projects for dangerous lifecycle scripts, mutable dependencies, and missing lockfiles.",
    "files": [
        "package.json",
        "**/package.json",
        "package-lock.json",
        "**/package-lock.json",
        ".npmrc",
        "**/.npmrc"
    ],
    "rules": [
        {
            "id": "npm.lifecycle-download",
            "title": "npm lifecycle downloads and executes remote code",
            "summary": "npm lifecycle downloads and executes remote code",
            "category": "supply-chain",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "npm lifecycle downloads and executes remote code weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Vendor or checksum installer inputs.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "lifecycle-download"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json"
                ],
                "pattern": {
                    "pattern": "[\"'](?:preinstall|install|postinstall)[\"']\\s*:\\s*[\"'][^\"']*(?:curl|wget)[^\"']*\\|\\s*(?:ba)?sh",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "npm.unbounded-dependency",
            "title": "npm dependency uses a mutable version",
            "summary": "npm dependency uses a mutable version",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "npm dependency uses a mutable version weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Use reviewed versions and commit the lockfile.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "unbounded-dependency"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json"
                ],
                "pattern": {
                    "pattern": "[\"'][\\w@_./-]+[\"']\\s*:\\s*[\"'](?:\\*|latest|next)[\"']",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "npm.missing-lockfile",
            "title": "npm project has no lockfile",
            "summary": "npm project has no lockfile",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "npm project has no lockfile weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Commit a package lockfile.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "missing-lockfile"
            ],
            "match": {
                "kind": "missing-file",
                "triggerFiles": [
                    "package.json",
                    "**/package.json"
                ],
                "requiredFiles": [
                    "package-lock.json",
                    "npm-shrinkwrap.json",
                    "**/package-lock.json"
                ]
            }
        }
    ]
};

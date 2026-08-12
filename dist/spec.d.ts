import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
interface DirectDependencyDriftMatch {
    kind: "direct-dependency-drift";
    files: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch | DirectDependencyDriftMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "npm";
    readonly displayName: "npm";
    readonly description: "Reviews npm projects for dangerous lifecycle scripts, auto-update cooldowns, and lockfile integrity.";
    readonly files: ["package.json", "**/package.json", "package-lock.json", "**/package-lock.json", "npm-shrinkwrap.json", "**/npm-shrinkwrap.json", ".npmrc", "**/.npmrc", "renovate.json", ".github/renovate.json5", ".github/dependabot.yml"];
    readonly rules: [{
        readonly id: "npm.lifecycle-remote-exec";
        readonly title: "Lifecycle script downloads and executes remote code";
        readonly summary: "Lifecycle script downloads and executes remote code";
        readonly category: "supply-chain";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Primary npm malware delivery path via postinstall curl-bash.";
        readonly impact: "Install-time remote code execution as the developer or CI identity.";
        readonly recommendation: "Remove network install scripts; vendor binaries with checksums.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "lifecycle"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json"];
            readonly pattern: {
                readonly pattern: "[\\\"'](?:preinstall|install|postinstall|prepare|prepublishOnly)[\\\"']\\s*:\\s*[\\\"'][^\\\"']*(?:curl|wget)\\s+[^\\\"']*(?:\\|\\s*(?:ba)?sh|bash\\s+-c)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "npm.lifecycle-download";
        readonly title: "Lifecycle script fetches remote artifacts without integrity";
        readonly summary: "Lifecycle script fetches remote artifacts without integrity";
        readonly category: "supply-chain";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Unpinned install-time downloads are supply-chain pivots.";
        readonly impact: "MITM or malicious artifact substitution at install.";
        readonly recommendation: "Vendor or checksum installer inputs.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "download"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json"];
            readonly pattern: {
                readonly pattern: "[\\\"'](?:preinstall|install|postinstall|prepare)[\\\"']\\s*:\\s*[\\\"'][^\\\"']*(?:curl|wget)\\s+https?://";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "npm.lifecycle-obfuscated";
        readonly title: "Lifecycle script uses obfuscated or encoded execution";
        readonly summary: "Lifecycle script uses obfuscated or encoded execution";
        readonly category: "supply-chain";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Dominant pattern in real npm malware: decode-then-execute postinstall.";
        readonly impact: "Hidden payload execution during npm install.";
        readonly recommendation: "Lifecycle scripts must be short and readable.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "obfuscation"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json"];
            readonly pattern: {
                readonly pattern: "[\\\"'](?:preinstall|install|postinstall|prepare)[\\\"']\\s*:\\s*[\\\"'][^\\\"']*(?:eval\\(|Buffer\\.from|atob\\(|node -e )";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "npm.script-curl-pipe";
        readonly title: "Package script pipes remote content to a shell";
        readonly summary: "Package script pipes remote content to a shell";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "npm run is trusted in CI; pipe-to-shell is still RCE.";
        readonly impact: "Remote code execution via a project script.";
        readonly recommendation: "Download to file, verify checksum, then execute.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "curl-pipe"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json"];
            readonly pattern: {
                readonly pattern: "[\\\"'][^\\\"']+[\\\"']\\s*:\\s*[\\\"'][^\\\"']*(?:curl|wget)[^\\\"']*\\|\\s*(?:ba)?sh";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "npm.publish-config-insecure-registry";
        readonly title: "Registry or publishConfig uses HTTP";
        readonly summary: "Registry or publishConfig uses HTTP";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Non-TLS registries enable credential and tarball interception.";
        readonly impact: "Token theft or package substitution.";
        readonly recommendation: "Use HTTPS registries only.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "registry"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json", ".npmrc", "**/.npmrc"];
            readonly pattern: {
                readonly pattern: "(?:registry\\s*=\\s*http://|\\\"registry\\\"\\s*:\\s*\\\"http://)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "npm.auto-update-no-cooldown";
        readonly title: "Auto-merge enabled without release-age cooldown";
        readonly summary: "Auto-merge enabled without release-age cooldown";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Compromised versions are often detected within days; auto-merge without age pulls malware immediately.";
        readonly impact: "Zero human latency to a poisoned publish.";
        readonly recommendation: "Set minimumReleaseAge or Dependabot cooldown (e.g. 7 days).";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "cooldown"];
        readonly match: {
            readonly kind: "missing-content";
            readonly files: ["renovate.json", ".github/renovate.json5", ".github/dependabot.yml", "**/renovate.json"];
            readonly trigger: {
                readonly pattern: "automerge[\\\"']?\\s*:\\s*true";
                readonly flags: "i";
            };
            readonly required: {
                readonly pattern: "minimumReleaseAge|cooldown\\s*:";
                readonly flags: "i";
            };
        };
    }, {
        readonly id: "npm.direct-dependency-lock-drift";
        readonly title: "Direct dependency metadata differs from npm lockfile";
        readonly summary: "Direct dependency metadata differs from npm lockfile";
        readonly category: "dependency-integrity";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "npm ci requires package manifests and lockfile package entries to describe the same direct dependency contract.";
        readonly impact: "Clean installs can fail, or install metadata that does not represent the reviewed manifest.";
        readonly recommendation: "Regenerate and commit the npm lockfile with npm install --package-lock-only.";
        readonly complexity: "trivial";
        readonly tags: ["npm", "lockfile", "reproducibility"];
        readonly match: {
            readonly kind: "direct-dependency-drift";
            readonly files: ["package.json", "**/package.json", "package-lock.json", "**/package-lock.json", "npm-shrinkwrap.json", "**/npm-shrinkwrap.json"];
        };
    }, {
        readonly id: "npm.unbounded-dependency";
        readonly title: "Production dependency uses unbounded range";
        readonly summary: "Production dependency uses unbounded range";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Automatic major jumps pull unreviewed code.";
        readonly impact: "Surprise breaking or malicious major versions.";
        readonly recommendation: "Use reviewed versions and commit the lockfile.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "range"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json"];
            readonly pattern: {
                readonly pattern: "\\\"dependencies\\\"\\s*:\\s*\\{[^}]{0,800}\\\"[^\\\"]+\\\"\\s*:\\s*\\\"(?:\\*|latest|>=0\\.0\\.0)\\\"";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "npm.missing-lockfile";
        readonly title: "package.json without npm lockfile";
        readonly summary: "package.json without npm lockfile";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Installs are non-reproducible across machines and CI.";
        readonly impact: "Different dependency trees on each install.";
        readonly recommendation: "Commit package-lock.json from npm install / npm ci.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "lockfile"];
        readonly match: {
            readonly kind: "missing-file";
            readonly triggerFiles: ["package.json"];
            readonly requiredFiles: ["package-lock.json", "npm-shrinkwrap.json"];
        };
    }, {
        readonly id: "npm.git-dependency";
        readonly title: "Production dependency tracks a mutable git branch";
        readonly summary: "Production dependency tracks a mutable git branch";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Branch HEADs move under you.";
        readonly impact: "Non-reproducible installs and force-push risk.";
        readonly recommendation: "Pin git dependencies to full commit SHAs.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "git"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json"];
            readonly pattern: {
                readonly pattern: "\\\"dependencies\\\"\\s*:\\s*\\{[^}]*git(?:\\+https?)?:[^\\\"']+#(?:main|master)[\\\"']";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};

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
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
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
    readonly description: "Reviews npm projects for dangerous lifecycle scripts, mutable dependencies, and missing lockfiles.";
    readonly files: ["package.json", "**/package.json", "package-lock.json", "**/package-lock.json", ".npmrc", "**/.npmrc"];
    readonly rules: [{
        readonly id: "npm.lifecycle-download";
        readonly title: "npm lifecycle downloads and executes remote code";
        readonly summary: "npm lifecycle downloads and executes remote code";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "npm lifecycle downloads and executes remote code weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Vendor or checksum installer inputs.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "lifecycle-download"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json"];
            readonly pattern: {
                readonly pattern: "[\"'](?:preinstall|install|postinstall)[\"']\\s*:\\s*[\"'][^\"']*(?:curl|wget)[^\"']*\\|\\s*(?:ba)?sh";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "npm.unbounded-dependency";
        readonly title: "npm dependency uses a mutable version";
        readonly summary: "npm dependency uses a mutable version";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "npm dependency uses a mutable version weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Use reviewed versions and commit the lockfile.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "unbounded-dependency"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json"];
            readonly pattern: {
                readonly pattern: "[\"'][\\w@_./-]+[\"']\\s*:\\s*[\"'](?:\\*|latest|next)[\"']";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "npm.missing-lockfile";
        readonly title: "npm project has no lockfile";
        readonly summary: "npm project has no lockfile";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "npm project has no lockfile weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Commit a package lockfile.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "missing-lockfile"];
        readonly match: {
            readonly kind: "missing-file";
            readonly triggerFiles: ["package.json", "**/package.json"];
            readonly requiredFiles: ["package-lock.json", "npm-shrinkwrap.json", "**/package-lock.json"];
        };
    }];
};
export {};

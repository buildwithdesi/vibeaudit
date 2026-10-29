# Vibe Audit market and security benchmark

**Research date:** 2026-09-01  
**Status:** directional benchmark based on public, primary-source product documentation and repository evidence.  
**Scope:** scanners and guardrails that overlap with AI-agent files, MCP servers, skills, hooks, source code, secrets, dependencies, repositories, or downloaded artifacts.

## Executive verdict

Vibe Audit is an **8.2/10 fit for its specific threat model**: a developer restores a backup or installs an AI-agent bundle, then needs to stop poisoned skills, hooks, configs, downloads, credential reads, and high-impact mutations before execution. It is approximately **5.8/10 as a general application-security platform**, because it does not replace mature CodeQL, SCA portfolios, runtime sandboxes, EDR, or enterprise monitoring.

The market has strong tools for individual layers, but I found no public product documentation showing one incumbent that combines Vibe Audit’s offline restored-agent scan, control-plane file inventory, external hash baseline, command/interpreter guard, signed skill bundle verification, npm pre-install behavior check, OSV multi-ecosystem SCA, and opt-in Semgrep flow scan in one local-first workflow. This is a positioning inference from the reviewed public capabilities, not a claim that no private or undocumented tool exists.

The most important comparison is **Snyk Agent Scan**. It has broader agent discovery, 15 documented risk categories, a wider agent/OS matrix, signed checksums, and enterprise monitoring. Its own documentation warns that scanning MCP configurations can execute stdio commands and requires explicit consent. Vibe Audit is a better fit for an untrusted restored backup because its target scan stages files and does not execute the target content.

## How the score works

The main score is **agent-control-plane target fit**, not a lab detection rate. Each score is an expert estimate from public evidence, normalized to a 10-point scale.

| Dimension | Weight | What earns points |
| --- | ---: | --- |
| Agent and control-plane coverage | 30% | Skills, hooks, rules, MCP configs, agent scripts, download-to-execution chains, credential paths |
| Static, dependency, and secret detection | 25% | AST or taint analysis, SCA, transitive coverage, secrets, malware or provenance signals |
| Preventive trust boundary | 20% | Offline operation, fail-closed behavior, sandboxing, signature or digest verification, no target execution |
| Usability, privacy, and friction | 15% | Local-first defaults, understandable remediation, low setup cost, clear incomplete state |
| Validation and operational maturity | 10% | Public tests, release evidence, adoption, integrations, support, and independent operational signals |

These are **not comparable precision or recall measurements**. Academic work shows static analysis can miss obfuscation and dynamic execution, while datasets and tool variants make cross-tool comparisons unreliable. A static scanner should not receive a 10/10 simply because its rule count is high. See the [malicious-package benchmark](https://arxiv.org/abs/2603.27549) and the [OSCAR dynamic-analysis study](https://arxiv.org/abs/2409.09356) for the limits behind this caution.

## Why this market exists now

The threat is moving from application source alone into the instructions, tools, and permissions that steer agents. Vendor research is useful market evidence, but it is not a universal prevalence estimate:

| First-party evidence | What it says | What it means |
| --- | --- | --- |
| [Snyk ToxicSkills study](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) | Snyk reports scanning 3,984 skills from ClawHub and skills.sh, finding 36.82% with at least one security flaw, 13.4% with a critical issue, and 76 confirmed malicious payloads. | Agent skills need supply-chain controls. Treat the percentages as directional because the sample and methodology are vendor-controlled. |
| [Snyk agentic-development research](https://snyk.io/blog/agentic-development-security-ai-coding-risk/) | Snyk reports that 43% of nearly 10,000 developer environments used two or more AI coding environments, 50.8% had an MCP server, and 22.8% had a skill installed. | A user-wide inventory matters because risk lives outside the repository. The study may have selection bias. |
| [OWASP excessive agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | OWASP recommends minimizing extensions, functionality, and permissions, and independently approving high-impact actions. | VibeGuard’s command approvals and mutation pauses map to a recognized agent threat model. |
| [OWASP Agentic AI Top 10](https://genai.owasp.org/download/52117/) | The draft maps agentic supply-chain vulnerabilities, unexpected RCE, memory/context poisoning, and human-agent trust exploitation to agent risks. | Restore poisoning and control-plane integrity belong in the product’s first-class categories. |

## Public incident evidence for a safe corpus

The benchmark does not need live malware or a user-supplied archive. Public reports provide behavior labels, while the checked-in corpus uses inert text and harmless code with non-resolving domains.

| Source | Documented evidence | Safe fixture labels |
| --- | --- | --- |
| [Koi Security, ClawHavoc](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) | Koi reported 341 malicious ClawHub skills in an audit of 2,857 skills, using professional names and fake prerequisites to deliver an infostealer. | Social engineering, fake prerequisite, download-to-execution, description mismatch |
| [Snyk ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) | Snyk reports 3,984 skills scanned, 1,467 with a flaw, 534 with a critical issue, and 76 confirmed malicious payloads. | Prompt override, malware delivery, obfuscated exfiltration, destructive intent, credential exposure |
| [Snyk shell-access advisory](https://snyk.io/articles/skill-md-shell-access/) | Snyk documents trojanized archives and shell-command paste lures targeting different platforms. | Platform-specific prerequisite lure, paste-command request, fake update |
| [Bitdefender advisory](https://businessinsights.bitdefender.com/technical-advisory-openclaw-exploitation-enterprise-networks) | Bitdefender independently reports malicious skills, typosquatting, automated uploads, account-takeover signals, and fake software updates. | Typosquat, reputation signal, automated campaign, fake update |
| [OpenClaw security RFC](https://github.com/openclaw/openclaw/issues/10890) | The RFC describes prompt instructions, bundled scripts, compromised updates, and persistence through cron, systemd, or LaunchAgents. | Script attachment, update diff, persistence request, inherited shell/filesystem/network access |
| [OpenClaw CWD injection advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-2qj5-gwg2-xwc4) | Crafted control, bidi, or zero-width characters in a workspace path could influence an agent prompt. | Unicode path injection and control-plane boundary |
| [Anthropic sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) | Anthropic describes prompt-injected code as capable of leaking sensitive information or downloading malware, and treats filesystem/network boundaries as a separate mitigation. | Sandbox-required marker. Static pass must never be called runtime-safe. |
| [Cisco AI Defense Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner) | Cisco documents prompt injection, exfiltration, command injection, obfuscation, secrets, social engineering, supply chain, Unicode steganography, and description-code mismatch categories. | Interoperable behavior labels across the corpus |

Historical skill identifiers in incident reports are stored only as provenance metadata. The benchmark never fetches, installs, or executes those identifiers.

## Existing public benchmark and dataset research

These resources inform the schema and future expansion. They are not copied into the repository as executable payloads.

| Resource | Contribution | Boundary |
| --- | --- | --- |
| [MaliciousSkillBench](https://arxiv.org/abs/2608.19901) | A direct skill benchmark model with provenance-preserving, source-disjoint, and structure-disjoint evaluation splits. | Potentially executable source material has redistribution constraints. Start with metadata and permitted inert text. |
| [MalSkillBench](https://github.com/lxyeternal/MalSkillBench) | Behavior taxonomy and generated samples covering indirect and direct delivery vectors. | Never run its generation or verification pipeline on a normal developer machine. |
| [Agent Skills in the Wild](https://arxiv.org/abs/2601.10338) | Large-scale category prevalence context for exfiltration and privilege escalation. | Detector-defined labels are not universal ground truth. |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) and [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | Dynamic indirect-prompt-injection scenarios for a later runtime adapter. | They evaluate tool-using agents, not local skill-package provenance. |
| [MCPTox](https://ojs.aaai.org/index.php/AAAI/article/view/40895) | Tool-poisoning benchmark for real-world MCP servers. | Adapt labels only after separate license and sandbox review. |

The current repository slice contains eight safe cases. The planned next increment is 20 to 40 fixtures, split by source, campaign, and behavior family rather than random rows. Each future case should carry its source URL, evidence level, expected outcome, content hash, and `execution_policy: never`.

## Ranked agent-security target fit

| Rank | Product | Score | Evidence-based reason for the score |
| ---: | --- | ---: | --- |
| 1 | **Vibe Audit** | **8.2** | Strongest fit for hostile restored agent content. It documents 106 rules, 17 attack surfaces, offline agent scans, fail-closed incomplete coverage, baselines, command inspection, VibeGuard user hooks, signed skill bundles, OSV, Gitleaks, and optional Semgrep. Deductions: early public adoption, no independent recall benchmark, no runtime sandbox or EDR, DAST is not shipped, and VibeGuard remains a user-level boundary. [Product README](https://github.com/buildwithdesi/vibeaudit) |
| 2 | **MCPRadar** | **7.8** | The strongest community analogue for MCP supply-chain work. It combines protocol, source, config, and dependency checks with OSV, CycloneDX, hashes/provenance, snapshots/diffs, and a disposable Docker/Podman sandbox. Deductions: public adoption is tiny, scans are explicitly a pattern detector rather than an exploitability oracle, and coverage is MCP-centered. [Repository](https://github.com/yatuk/mcpradar) |
| 3 | **Snyk Agent Scan** | **7.6** | Broad agent, skill, MCP, IDE, and OS discovery; 15 documented risk categories; signed checksums; scan and background monitoring modes; Windows support. Deductions: CLI is documented as experimental, v0.5.x is planned for deprecation, a Snyk account/token is required, and MCP scanning can execute configured stdio commands. [Repository](https://github.com/snyk/agent-scan) |
| 4 | **Cisco AI Defense Skill Scanner** | **7.5** | Layered static patterns, YARA, optional LLM analysis, behavioral dataflow, a meta-analyzer, SARIF, GitHub Actions, and pre-commit support for Codex and Cursor skills. Deductions: Cisco calls it best-effort, optional integrations add network and data-sharing choices, and it is not a restore baseline or local command firewall. [Repository](https://github.com/cisco-ai-defense/skill-scanner) |
| 5 | **Invariant MCP-Scan** | **7.4** | Combines static scans with a runtime proxy, prompt-injection and tool-poisoning checks, PII/secret restrictions, tool pinning, and agent/MCP config discovery. Deductions: it is primarily an MCP control layer, and public maturity and deployment evidence are lighter than established AppSec vendors. [Documentation](https://github.com/invariantlabs-ai/docs/blob/main/docs/mcp-scan/index.md) |
| 6 | **GitHub Advanced Security** | **7.3** | Very mature CodeQL scanning, dependency graph, Dependabot, dependency review, secret scanning, push protection, SARIF, and repository workflows. Deductions: it is repository- and GitHub-centric, not an offline restored-backup firewall for local agent control files. [Capabilities](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) |
| 7 | **Semgrep Community / AppSec** | **7.2** | Fast local SAST with custom rules, SARIF/JSON, hooks, and broad language coverage. The platform adds cross-file analysis, supply-chain, and secrets. Deductions: it does not natively understand a restored agent control plane, and the strongest supply-chain and secrets workflow is platform-tier functionality. [Community Edition](https://semgrep.dev/products/community-edition/), [pricing](https://semgrep.dev/pricing/) |
| 8 | **Socket** | **7.1** | Strong package behavior and supply-chain signals, including malware, typosquatting, permission creep, abandoned packages, transitive dependencies, and an install-time firewall. Deductions: it is dependency-centric, cloud-oriented, and does not inspect arbitrary agent instructions or hooks as a control plane. [Security](https://socket.dev/security), [pricing](https://socket.dev/pricing) |
| 9 | **Trivy** | **6.9** | Open-source filesystem, repository, container, secret, misconfiguration, license, and SBOM scanning. Deductions: it has excellent artifact breadth but no agent-specific semantics, command guard, or control-plane baseline. [Repository](https://github.com/aquasecurity/trivy), [repository scanning](https://trivy.dev/docs/latest/target/repository/) |
| 10 | **Promptfoo** | **6.7** | LLM- and agent-focused code scanning can trace prompt injection, PII, excessive agency, and dataflows through code. Deductions: cloud is the default for some workflows, and its own security guidance warns that configs, hooks, and plugins can execute code and are not sandboxed. [Code scanning](https://www.promptfoo.dev/docs/code-scanning/), [security guidance](https://github.com/promptfoo/promptfoo/security) |
| 11 | **GuardDog** | **6.3** | Static YARA and metadata rules, package download scanning, attack-chain correlation, and ecosystem coverage across npm, PyPI, Go, Rust, RubyGems, GitHub Actions, and VS Code. Deductions: package malware is the focus, not local agent files or user-wide command policy. [Repository](https://github.com/DataDog/guarddog) |
| 12 | **Gitleaks** | **6.2** | Excellent focused secret and history scanning with directory, stdin, pre-commit, GitHub Action, JSON, SARIF, and redaction support. Deductions: it is intentionally narrow and does not establish whether an agent instruction is malicious. [Repository](https://github.com/gitleaks/gitleaks) |
| 13 | **OSV-Scanner** | **6.2** | Independent, open-source known-vulnerability intelligence for lockfiles and SBOMs across many ecosystems, with recursive scans, offline mode, and call analysis. Deductions: it does not inspect agent instructions, credentials, command chains, or runtime behavior. [Source scanning](https://github.com/google/osv-scanner/blob/main/docs/scan-source.md), [repository](https://github.com/google/osv-scanner) |
| 14 | **OpenGrep** | **6.0** | Open Semgrep-compatible SAST with 30-plus languages, extended taint support, open governance, and signed Cosign releases. Deductions: it is code-centric and has no restored-agent trust model or dependency provenance workflow. [Repository](https://github.com/opengrep/opengrep) |
| 15 | **SonarQube Community Edition** | **6.0** | Mature self-managed static code-quality and security analysis. Deductions: it does not target poisoned skills, hooks, MCP configs, download chains, or backup restore decisions. [Community Edition](https://www.sonarsource.com/products/sonarqube/community-edition/) |
| 16 | **OWASP Dependency-Track** | **5.5** | Strong continuous SBOM inventory, vulnerability, license, and policy management for portfolios. Deductions: it is a lifecycle platform, not a local pre-restore control-plane scanner. [Project site](https://dependencytrack.org/) |
| 17 | **OpenSSF Scorecard** | **5.5** | Useful repository-level signals for dangerous workflows, pinned dependencies, token permissions, SAST, signed releases, and branch protections. Deductions: the project itself says signals are heuristic, and it cannot tell whether a local restored skill or hook is safe. [Checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md), [repository](https://github.com/ossf/scorecard) |

The ordering intentionally puts **MCPRadar behind Vibe Audit but ahead of mature generic scanners**. It has an unusually relevant sandbox and provenance design, but its tiny public adoption and explicit pattern-detector limitation reduce confidence. Snyk Agent Scan has stronger vendor reach and monitoring, but its documented execution boundary is a material risk for untrusted MCP content.

## Emerging community skill scanners

The skill-specific ecosystem is real, but most projects do not publish reproducible benchmarks, release history, or independent validation. I would treat these as **early supplementary signals**, not clean verdicts:

| Community project | Indicative fit | Why it is interesting | Confidence |
| --- | ---: | --- | --- |
| [SkillScan](https://github.com/NMitchem/SkillScan) | 5.8 | Static scanning, LLM behavioral prediction, Docker sandbox, and SARIF are promising. | Low-medium |
| [skill-audit](https://github.com/ondrej-merkun/skill-audit/) | 5.5 | Local rules cover prompt injection, network exfiltration, filesystem access, code execution, obfuscation, secrets, and dependency risk. | Low |
| [SkillScanner](https://github.com/d-wwei/SkillScanner) | 5.2 | Multi-agent skill coverage and a zero-dependency five-layer design. | Low |
| [syedabbast/skill-scanner](https://github.com/syedabbast/skill-scanner) | 4.9 | Static `SKILL.md` rules and zero dependencies. | Low |
| [NVIDIA Skillspector](https://github.com/NVIDIA/skillspector) | 4.9 | Dedicated AI-agent skill scanning direction from a major open-source organization. | Low |
| [claude-skill-audit](https://github.com/tarang-tj/claude-skill-audit) | 4.7 | Looks across skills, agents, hooks, permissions, and MCP config with no dependencies. | Low |
| [obielin/mcpscan](https://github.com/obielin/mcpscan) | 4.3 | Small zero-dependency Python scanner with prompt-injection and unsafe-auth rules. | Low |
| [Vault MCP](https://github.com/vaultmcp/vault) | 4.2 | Local MCP prompt-injection firewall with deterministic and heuristic layers. | Low |

These scores are not negative judgments. They mean **the public evidence is not yet strong enough to support a higher-confidence security claim**. A community scanner can still be valuable as a second opinion, especially when it fails closed on incomplete coverage.

## General AppSec maturity is a separate axis

If the question changes from “Which tool best protects a poisoned AI-agent backup?” to “Which platform covers a normal production application?”, the ranking changes:

| Product | General AppSec score | Primary strength |
| --- | ---: | --- |
| GitHub Advanced Security | 9.2 | CodeQL, dependency graph, secret protection, repository workflow integration |
| Semgrep AppSec | 8.8 | Cross-file SAST, supply-chain analysis, secrets, broad language support |
| Snyk platform | 8.7 | SCA, SAST, IaC, container, license and developer workflow coverage |
| Socket | 8.4 | Package behavior intelligence and install-time dependency protection |
| Trivy | 8.0 | Open-source filesystem, container, repository, secret, misconfiguration, and SBOM coverage |
| SonarQube Community | 7.8 | Mature self-managed code-quality and security analysis |
| OWASP Dependency-Track | 7.4 | SBOM portfolio lifecycle, policy, and vulnerability management |
| OSV-Scanner | 6.9 | Focused multi-ecosystem known-vulnerability and SBOM intelligence |
| Vibe Audit | 5.8 | AI-generated code plus agent control-plane and restore safety |

Vibe Audit should therefore be sold and taught as a **restore firewall for agent control-plane content**, not as a replacement for a full AppSec program.

## Cost and friction snapshot

The core open-source layers can be used without a per-seat license. Operational costs still exist for CI minutes, hosted analysis, artifact storage, or private infrastructure.

| Tool | Public cost or license signal | Practical friction |
| --- | --- | --- |
| OSV-Scanner | Apache-2.0 and free CLI/database use. [Repository](https://github.com/google/osv-scanner) | Local binary verification and database freshness still need an owner. |
| Cosign / Sigstore | Apache-2.0 tooling and a free public-good service. [Cosign](https://github.com/sigstore/cosign), [Sigstore](https://docs.sigstore.dev/) | Private transparency or signing infrastructure is an operational cost, not a license fee. |
| Semgrep | Free Community Edition and free tier limits. Paid Teams is listed from $30 per contributor per month for selected products. [Pricing](https://semgrep.dev/pricing/) | Best cross-file, supply-chain, and secrets workflows can require platform limits or a paid tier. |
| Snyk | Free tier with product test limits. Team is listed from $25 per contributing developer per month. [Plans](https://snyk.io/plans/) | Account/token setup and cloud data-sharing decisions add friction. |
| Socket | Free tier listed at $0 with 1,000 scans per month. Team is listed from $25 per developer per month. [Pricing](https://socket.dev/pricing) | Rich package intelligence is service-backed and dependency-focused. |
| Trivy, Gitleaks, GuardDog, MCPRadar, OpenGrep, Scorecard | Open-source repositories with no per-seat scanner fee in their documented community distributions. [Trivy](https://github.com/aquasecurity/trivy), [Gitleaks](https://github.com/gitleaks/gitleaks), [GuardDog](https://github.com/DataDog/guarddog), [MCPRadar](https://github.com/yatuk/mcpradar), [OpenGrep](https://github.com/opengrep/opengrep), [Scorecard](https://github.com/ossf/scorecard) | Setup, update verification, platform support, and maintenance become the user’s responsibility. |

This is why the default Vibe Audit path should stay local and fast. Optional adapters can add depth without forcing every vibe coder to operate a security platform.

## Market evidence and adoption signals

Public GitHub stars are not security proof, but they show where community gravity currently exists. The reviewed snapshots were approximately: Trivy 37.7k, Gitleaks 29.0k, Semgrep Community 13.1k, OSV-Scanner 10.9k, OpenGrep 2.6k, GuardDog 1.2k, MCPRadar 3, and Vibe Audit 2. These counts fluctuate and should be refreshed before any investor, sales, or curriculum claim. Links: [Trivy](https://github.com/aquasecurity/trivy), [Gitleaks](https://github.com/gitleaks/gitleaks), [Semgrep](https://semgrep.dev/products/community-edition/), [OSV-Scanner](https://github.com/google/osv-scanner), [OpenGrep](https://github.com/opengrep/opengrep), [GuardDog](https://github.com/DataDog/guarddog), [MCPRadar](https://github.com/yatuk/mcpradar), [Vibe Audit](https://github.com/buildwithdesi/vibeaudit).

The market is bifurcating:

1. **Mature horizontal AppSec:** GitHub, Semgrep, Snyk, Socket, Trivy, Gitleaks, OSV-Scanner, Dependency-Track, and Scorecard each own a strong layer.
2. **Agent-aware control and evaluation:** Snyk Agent Scan, Invariant MCP-Scan, MCPRadar, Promptfoo, and a fast-growing community of skill scanners address prompts, tools, skills, MCP, and agent behavior.
3. **The gap:** local restore safety, trusted baseline state, and a single understandable approval path across files, commands, dependencies, signatures, and high-impact mutations.

## What the score says to build next

1. **Publish a benchmark corpus.** Include benign and malicious `SKILL.md`, `AGENTS.md`, hooks, MCP configs, package manifests, download-to-interpreter chains, credential reads, obfuscation, and restore diffs. Report recall, false positives, unsupported coverage, runtime, and whether the target was executed.
2. **Add a disposable dynamic adapter.** Keep it opt-in. Deny network by default. Use a disposable VM or container, read-only inputs, dropped capabilities, bounded CPU and memory, and an artifact receipt. Never let dynamic mode change the default offline scan.
3. **Make the coverage matrix visible.** Show which agent paths, languages, lockfiles, and optional binaries were actually scanned. “Incomplete” must never render as “clean.”
4. **Build independent trust evidence.** Add third-party review, a responsible disclosure policy, signed release attestations, reproducible fixtures, and a public release cadence.
5. **Integrate competitors as second opinions.** Allow optional Snyk Agent Scan, MCPRadar, Semgrep, OSV, Gitleaks, and Trivy adapters. Record their result and tool version, but never treat an external “no findings” result as proof of safety.
6. **Keep the default path fast.** Local static scan, command inspection, baseline verification, and explicit approval should stay the one-command path. Deep tools must be opt-in and explain their cost before running.

## Bottom line

Vibe Audit is not a 10/10 security product. It is an unusually well-shaped **8.2/10 product for one painful, under-served failure mode**. Its advantage is the trust boundary and workflow, not a claim of universal detection. The next proof point is a reproducible public benchmark that demonstrates where it catches poisoned agent content, where it refuses to overclaim, and where a second tool is still required.

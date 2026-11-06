# Threat Model (v0.1)

## Protected workflow

The intended use is **pre-merge authorization verification** for AI Agent projects. TaskLatch reads known local configuration files and an explicitly maintained capability manifest, compares them with a task-scoped contract, and reports newly introduced capabilities and policy changes.

## In scope

- Accidental capability exposure introduced by Agent/tool configuration updates.
- Unauthorized capabilities disclosed by a maintained manifest.
- Basic GitHub Actions token permission escalation declared in workflow YAML.
- Unexpected policy allow-list growth against a trusted Git baseline.
- Simulated `allow`/`deny`/`approval`/`unknown` contract regression tests.

## Out of scope

- Agent authentication, secure identity issuance, credential rotation, and authorization at the API endpoint.
- Runtime tool-call interception and enforcement of human approvals.
- Dynamic MCP tool schemas, shell effects, tool aliases, or bypasses via separate credentials.
- Correctness of user-authored capability manifests.
- GitHub organization-level permissions, OIDC trust, external cloud roles, or live token scope verification.
- Full parsing of arbitrary GitHub Actions YAML or arbitrary Agent integrations.
- Prompt-injection testing, package scanning, malware detection, or DLP.

## Adversarial assumptions

A malicious contributor may edit Agent settings, workflow YAML, manifests, or policy files. CI must run on a trusted workflow configuration and a base revision with protected policy changes. A contributor who controls both the CI definition and the branch protection settings can disable static checks. The scanner therefore deliberately treats unknown semantics as `unknown` rather than `allow`.

## Detection confidence

- `declared`: Capabilities explicitly asserted in a manifest, but not independently verified.
- `inferred`: Parsed from recognized configuration patterns; may differ from effective access.
- `unknown`: No reliable capability inference is possible. Always requires separate review.

## Suggested future milestone

A trusted runtime mediation adapter could enforce a short-lived agent/task/resource authorization decision using isolated API credentials. That adapter would need explicit coverage tests for bypass routes and must never claim to govern tools that bypass it.

# TaskLatch

**Make agent permissions testable before they ship.**

TaskLatch is an **open-source, task-aware authorization verification CLI** for AI agents. It helps developers define expected capabilities, review newly introduced privileges, and test authorization policies in GitHub CI. It does not run language models, start MCP servers, or require a SaaS account.

> **Security boundary:** v0.1 performs static analysis and simulated policy decisions. It **does not authenticate agent identities or enforce permissions at runtime**. Agents with unrestricted shell access, unmanaged credentials, or alternate tool paths can bypass these checks. Treat `UNKNOWN` as a request for manual review, not a successful security verification.

## What it does

- **Task-aware contracts:** Map an agent and task to `allow`, `deny`, and `require_approval` capability rules.
- **Privilege drift checks:** Compare a pull request's declared and inferred capabilities with a trusted Git base. Removing explicit GitHub Actions workflow/job token permissions is treated as a blocking potential regression, even when no new static capability is detected.
- **Policy regression detection:** Flag changes that weaken policy protections (new allows, removed denies, or removed approvals) and newly exposed capabilities that the baseline would have denied.
- **Policy tests:** Run reproducible, fully simulated authorization test cases.
- **CI integration:** Publish a readable permission report to GitHub Actions' step summary without write access to pull requests.
- **Privacy by design:** Ignore MCP environment values; never start discovered MCP servers or tools. Only capability names and repository-relative file locations are included in reports.

## Quick start

Requirements: **Node.js 22 or newer** and Git (for `diff`). This repository is not yet published to npm.

```bash
npm install --ignore-scripts
npm run build
node dist/cli.js init
node dist/cli.js test
node dist/cli.js check --fail-on unknown
```

`init` creates example files that **must be customized** for your actual agents. It refuses to overwrite existing files. If you are working in a checkout of TaskLatch itself, the `.tasklatch/` directory already contains synthetic self-test data, so use `node dist/cli.js test` directly or run `init` in an empty sample repository.

## Policy: one task, one permission contract

`.tasklatch/policy.yaml`:

```yaml
version: 1
defaults:
  unlisted: deny
agents:
  research-agent:
    tasks:
      review-code:
        allow:
          - github.repository.read
        deny:
          - github.repository.write
          - github.repository.delete
          - vercel.production.deploy
        require_approval:
          - github.pull_request.merge
```

Rules are matched in this order: `deny` → `require_approval` → `allow` → default `unlisted`. An agent/task pair without a contract results in `unknown`. A policy decision is not the same thing as an enforced API authorization check.

**Scope of YAML support:** TaskLatch intentionally accepts a strict, safe subset of YAML (two-space maps and scalar lists). Anchors, tags, flow maps, and complex YAML structures are rejected rather than silently interpreted.

## Capability manifest

`.tasklatch/manifest.json` describes known capability exposures for an agent/task. These entries are **declarations**, not proof of actual OAuth token scope or effective permissions.

```json
{
  "version": 1,
  "exposures": [
    {"agent":"research-agent", "task":"review-code", "capability":"github.repository.read"}
  ]
}
```

TaskLatch scans **all** supported files it discovers (there is no 300-file cutoff). It reports scanned paths, and an unreadable source fails the security check rather than silently disappearing from coverage. Individual source files remain subject to a 512 KiB safety limit; files above this limit cause an analysis error. Large repositories may require more processing time and memory.

TaskLatch also scans `.claude/settings.json`, `.mcp.json`, `.cursor/mcp.json`, and `.github/workflows/*.yml` as static, best-effort sources. MCP tool capabilities are reported as **unknown**; configured servers are never executed. GitHub workflow token scopes can be inferred from static `permissions:` declarations; organization-level authorization and dynamic expressions are not verified. `shell.execute.scoped` is not a sandbox.

## Commands

```bash
node dist/cli.js scan --format text
node dist/cli.js check --fail-on deny --format markdown
node dist/cli.js test
node dist/cli.js diff --base main --fail-on unknown --format markdown
```

`--fail-on deny` fails on explicit/implicit denied capabilities; `approval` also fails on approval-required capabilities; `unknown` also fails on unverified capabilities. **For strict CI review, use `--fail-on unknown`.** `check` fails when supported GitHub workflows could inherit unknown token permissions (no explicit workflow-level permission block and at least one job without its own block). `diff` additionally fails when a previously explicit workflow-level or job-level permission declaration is removed, when a potentially weakening policy change is detected, or when either scan has blocking coverage issues. These failures apply regardless of `--fail-on`. The comparison is conservative and may require review of harmless policy rewrites.

Exit codes: `0` = successful operation/no threshold breach; `1` = policy failure; `2` = invalid input or analysis error.

## GitHub Actions

The repository includes `.github/workflows/permission-regression.yml` for self-testing. A consumer can use the composite action after TaskLatch is published and tagged:

```yaml
name: TaskLatch
on:
  pull_request:
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      # Replace OWNER/REPOSITORY and VERSION with an actual published tag.
      - uses: OWNER/REPOSITORY@VERSION
        with:
          base: ${{ github.event.pull_request.base.sha }}
          fail-on: unknown
```

Avoid using `pull_request_target` to execute untrusted PR code. Protect policy-file changes with CODEOWNERS or branch protection rules. The composite action requires its compiled `dist/` files to be committed in the tagged release.

## Safety and limitations

Read [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md). There is **no runtime interception** in this MVP. The `test` command only evaluates policy decisions and does not make live tool/API calls. Unknown MCP semantics, alternate credentials, external authorization and dynamic command behavior remain out of scope. Workflow parsing is intentionally lightweight and supports conventional workflow/job `permissions` blocks; complex YAML, unusual indentation, dynamically constructed permissions, inherited organizational defaults, and reusable workflow authorization semantics are not fully evaluated. Treat unparsed/unknown permission evidence as requiring review, and prefer `--fail-on unknown` for CI. This is a foundation for a future enforcement adapter, not a security certification.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All code, issues, pull requests, and documentation should be written in English. Use synthetic agents and test data; do not post private identities, real credentials, personal discussion transcripts, or customer data.

## Project status

This is the v0.1 public open-source repository. Hosted CI results and release status are tracked in GitHub Actions and pull requests.

## License

Apache-2.0. See [LICENSE](LICENSE).

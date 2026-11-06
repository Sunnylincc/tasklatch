# Security Policy

## Supported versions

TaskLatch v0.1 is an early developer preview. Security fixes will be applied to the current development line as capacity allows.

## Reporting security vulnerabilities

Do not post secrets, credentials, private repository paths, or exploit details in public GitHub issues. Use GitHub's private vulnerability reporting feature once enabled for this repository. Until the repository is published and configured, do not assume a working private security-reporting channel exists.

## Trust boundaries

- **No runtime enforcement:** TaskLatch does not mediate Agent API calls, act as an OAuth server, or authenticate agents.
- **No external execution:** Static MCP/Agent configurations are treated as untrusted data. The scanner never starts MCP servers, executes tool commands, or fetches remote MCP descriptions.
- **No secret reporting:** Environment variable values and tool arguments are not intentionally printed. File and capability names do appear in reports.
- **No automatic code modification:** The CLI does not alter credentials or Agent permission configuration. `init` writes example files only if they do not already exist.
- **Review policy changes:** CI should require code-owner review for `.tasklatch/` and workflow changes. An actor who can disable CI or edit policies outside protected review can undermine these checks.

For unresolved threats and known blind spots, see `docs/threat-model.md`.

# Contributing to TaskLatch

Thank you for contributing. Please use English for issues, commits, PR titles, descriptions, code comments, and documentation.

## Development

```bash
npm install --ignore-scripts
npm run verify
node dist/cli.js test
node dist/cli.js check
```

Keep the runtime dependency footprint minimal. All new scanners must avoid executing discovered files, external commands, Agent tools, or MCP servers. Maintain tests for malformed input, permission widening, sensitive value suppression, and unknown capabilities.

## Privacy and originality

Contribute only code and examples you have the right to share. Use made-up organizations, identities, domain names, and token placeholders. Never include personal conversations, confidential project documents, private URLs, actual credentials, or proprietary competitor source code. This repository uses an independent implementation under Apache-2.0.

## Pull request checklist

- [ ] Tests and static verification pass.
- [ ] All changes and PR text are in English.
- [ ] Examples use synthetic data only.
- [ ] No private data, secrets, or unpublished internal work are present.
- [ ] Security claims are scoped to actual implementation and tests.

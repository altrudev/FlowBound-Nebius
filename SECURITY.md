# Security Policy

FlowBound-Nebius treats model output as untrusted proposal data, not authority.

## Security invariants

1. A model cannot enlarge its own authority envelope.
2. Repository mutations must be bound to a repository, branch, and predecessor revision.
3. Filesystem access is deny-by-default outside explicit read/write scopes.
4. Known secret locations remain denied even if a broader path rule is configured.
5. Commands are deny-by-default and must match an explicit command allowlist.
6. Network access is deny-by-default.
7. Dependency changes and git push are never silently authorized; when enabled they escalate.
8. Execution success is not established by the executor's own claim. Successor state must be re-observed.
9. Receipts may not claim more than the configured claim ceiling.
10. API keys, tokens, and credentials must come from environment/runtime secret stores and must not be committed.

## Threat model

The hackathon demo explicitly tests:
- prompt injection embedded in repository files;
- attempts to read `.env` or SSH material;
- attempts to write outside approved files;
- arbitrary shell execution;
- arbitrary network egress;
- dependency manipulation;
- direct push attempts;
- stale predecessor state;
- executor claims that disagree with observed successor state.

## Reporting

Please open a GitHub issue for non-sensitive security defects. For vulnerabilities that would expose secrets or enable real exploitation, contact the maintainer privately before publishing details.

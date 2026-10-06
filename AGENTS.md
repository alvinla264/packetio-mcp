# Agent instructions

## Commit messages

All commits must follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

- Use `feat` for new features and `fix` for bug fixes.
- Other appropriate types include `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, and `revert`. Use lowercase types consistently.
- An optional scope identifies the affected component, such as `capture`, `pcap`, or `decoder`.
- Provide a concise description immediately after the colon and space.
- Separate an optional body and footers with blank lines. Explain intent and important limitations in the body when useful.
- Mark breaking changes with `!` immediately before the colon, or with an uppercase `BREAKING CHANGE: <description>` footer. Explain the breaking change in the description or footer.
- Use trailer-style footers such as `Refs: #123`. Split unrelated changes into separate commits when practical.

Examples:

```text
feat(pcap): add capture summaries
fix(capture): exclude queued frames from other interfaces
docs: document USB Ethernet passthrough
feat(api)!: rename capture filter argument

BREAKING CHANGE: callers must use display_filter instead of filter_expression.
```

## Repository hygiene

- Never commit device credentials, private MCP client configuration, virtual environments, or local captures containing sensitive traffic.
- Keep public implementation and documentation vendor-neutral.
- Document known limitations accurately; do not claim a passing unit suite proves physical packet delivery or timing correctness.

# Security and publication policy

## Trust boundary

This is a local, Linux stdio MCP server for trusted clients on isolated test
links. A client can transmit arbitrary Ethernet traffic, select any accessible
interface and read captured payloads. Those are powerful intentional features,
not a safe API for untrusted users. Restrict client access and approve test
interfaces/traffic outside the server. Do not expose unauthenticated HTTP/SSE.

Run as a normal user. The dedicated capability-bearing interpreter is a
**general Python interpreter**: every program it executes receives CAP_NET_RAW.
Protect its path, source and packages; install it mode 0700. Never setcap shared
Python, run setup/server/tests as root, or grant passwordless sudo to a general
interpreter. Setup invokes sudo only for capability installation/removal.
Existing installations must explicitly refresh their executable permissions;
updating source does not change an already-installed interpreter.

## Capture storage

The default directory is `~/.local/state/pktgen-mcp/captures`, configurable via
`PKTGEN_CAPTURE_DIR`. Existing roots must belong to the server user and have no
group/other permission bits (0700 recommended). New directories are private;
new captures and JSON reports are 0600. Unsafe existing directories are refused,
not silently chmodded. Evidence is not automatically moved from old locations.

Inputs must be regular files. Directory components and files are opened using
Linux descriptors with no-follow semantics. Outputs are written privately and
published without replacing an existing name: use a new filename for each run.
JSON sidecars use the same policy and are checked before a declarative test
transmits. Symlinks, special files and pathname substitution must not redirect
file operations outside their intended tree. Paths containing symlinked parent
directories are unsupported, including custom capture roots.

Do not store captures on shared/untrusted filesystems. Choose a directory whose
ancestors cannot be renamed by another user. A malicious process running under
the **same user identity** is not isolated by this server. Set external storage
quotas/retention and back up evidence deliberately; no automatic deletion or
aggregate disk quota is implemented.

## Bounds and residual risks

Raw hex is limited to 55,296 input characters and 9,216 decoded bytes; built
frames may not exceed 9,216 bytes. Filters are limited to 4,096 characters and
128 tokens, bounding parser/AST recursion. Capture/read/tshark limits are
reported by `describe_capabilities`. Invalid send expectations are checked
before transmission.

Per-call limits are not a global concurrency/memory budget. Scapy/tshark parse
untrusted bytes before some display bounds apply; bounded output is not a
parser sandbox. Keep dependencies patched, trust the selected executable/PATH,
and consider process isolation for complex dissection. Socket sends and bounded
capture assertions are not evidence of universal delivery or DUT conformance.

## Before committing or publishing

1. Review `git diff --cached` and `git status --short`; stage explicit files,
   never local environments, credentials, MCP client configuration or captures.
2. Run `python3 scripts/check_secrets.py` **after staging**. It scans exact index
   content and available Git blobs/commit/tag objects, reporting only candidate
   locations/types. This pattern-based check can miss secrets and can flag
   harmless examples; investigate findings instead of blindly bypassing them.
3. Configure the intended email using `git config --local user.email <email>`
   and enable the included check with `git config --local core.hooksPath .githooks`.
   The check rejects author/committer environment overrides that disagree with
   that email. Hooks are opt-in guardrails, not a guarantee; run the check again
   before pushing.
4. Run offline regressions with `python scripts/test_offline.py` and a current
   dependency advisory check. Use a maintained full secret scanner (for example,
   Gitleaks with redacted output) on history and the prospective publication tree. Review
   every dependency that was skipped or unavailable, not just the exit code.
   Use the public-index `uv.lock` with `uv sync --locked --extra dev` for the
   reproducible environment; refresh/audit the lock deliberately.
5. Inspect effective author/committer identity, signing settings and the entire
   history to be published. Existing commit metadata does not change when Git
   configuration changes. Amend/rewrite unpublished history only with owner
   approval; never force-push shared history without coordination.

Ignored files can still be committed with `git add -f`; Git history retains
previous contents. If a real credential is found, revoke/rotate it before any
history cleanup. Removing a value from the latest tree is not sufficient.

No secret scan, test suite or advisory service can certify zero vulnerabilities.
Report security problems privately to the repository owner without posting
credentials, exploit captures or private device details in a public issue.

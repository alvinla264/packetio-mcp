#!/usr/bin/env python3
"""Dependency-free, redacted secret checks on tracked files and Git objects.

A guardrail, not a replacement for dedicated secret scanners/manual review.
Never print matching values. Untracked private files are not publication inputs;
add files to the index before running the final release check.
"""
import re
import subprocess
import sys

PATTERNS = {
    'private-key': rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----',
    'aws-access-id': rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    'github-token': rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b',
    'slack-token': rb'\bxox[baprs]-[A-Za-z0-9-]{20,}\b',
    'credential-url': rb'[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@',
    'jwt-shaped': rb'\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b',
    'credential-literal': rb'''(?i)\b(?:password|passwd|api_key|api_secret|access_token|auth_token|client_secret)\s*[:=]\s*["'][^"'\r\n]{6,}["']''',
}


def git(*args):
    return subprocess.check_output(['git', *args])


def main():
    count = 0
    hits = 0
    def scan(data, label):
        nonlocal count, hits
        count += 1
        for name, pattern in PATTERNS.items():
            for match in re.finditer(pattern, data):
                hits += 1
                line = data[:match.start()].count(b'\n') + 1
                print(f'{label}:{line}: {name}: REDACTED', file=sys.stderr)
    # Catch environment overrides of the intended local commit identity.
    try:
        expected_email = git('config', '--local', 'user.email').decode().strip()
    except subprocess.CalledProcessError:
        print('Set repository-local user.email before the publication check.', file=sys.stderr)
        return 1
    for variable in ('GIT_AUTHOR_IDENT', 'GIT_COMMITTER_IDENT'):
        identity = git('var', variable).decode()
        match = re.search(r'<([^<>]+)>', identity)
        if not match or match.group(1) != expected_email:
            print(f'{variable}: email differs from repository-local user.email; refusing commit', file=sys.stderr)
            return 1
    # Scan the exact index content, not a potentially different working copy.
    for entry in git('ls-files', '-s', '-z').split(b'\0'):
        if not entry:
            continue
        metadata, filename = entry.split(b'\t', 1)
        mode, oid, stage = metadata.split()
        if mode == b'160000':
            raise RuntimeError('submodules require a separate publication audit')
        scan(git('cat-file', 'blob', oid.decode()), 'index:' + filename.decode(errors='replace'))
    for entry in git('cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype)').splitlines():
        oid, kind = entry.decode().split()
        if kind in ('blob', 'commit', 'tag'):
            scan(git('cat-file', kind, oid), 'git:' + oid[:12])
    print(f'Scanned {count} index/object inputs; {hits} secret candidates (values redacted).')
    return 1 if hits else 0


if __name__ == '__main__':
    sys.exit(main())

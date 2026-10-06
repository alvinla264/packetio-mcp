#!/usr/bin/env bash
#
# Grant CAP_NET_RAW to a dedicated copy of the interpreter backing this venv.
#
# Raw AF_PACKET sockets need CAP_NET_RAW. Granting it to the interpreter lets
# the MCP server run as your normal user, with no sudo at run time.
#
# Why a copy instead of the venv interpreter directly:
#   .venv/bin/python is usually a symlink to the system Python. setcap follows
#   symlinks, so setting the capability there would grant raw-socket access to
#   every invocation of that interpreter for every user on the machine. Copying
#   the binary avoids modifying shared Python. ANY code run with this copy
#   gets CAP_NET_RAW; access restrictions, not Python, provide the boundary.
#
# Re-run this after the system Python is upgraded: the copy is a static binary
# and does not receive distribution updates.
#
# Usage:
#   ./setup-capabilities.sh          # configure
#   ./setup-capabilities.sh --check  # report status without changing anything
#   ./setup-capabilities.sh --remove # drop the capability and the copy

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV="${PKTGEN_VENV:-$SCRIPT_DIR/.venv}"
CAP_BIN="$VENV/bin/python3-capped"
CAPABILITY="cap_net_raw+ep"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

[ "$EUID" -ne 0 ] || die "run setup as the intended normal user, not sudo/root"

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

venv_python() {
    [ -x "$VENV/bin/python" ] || die "no interpreter at $VENV/bin/python; create the venv first"
    readlink -f "$VENV/bin/python"
}

verify_capability() {
    # Confirm the capability is actually usable, not merely recorded on disk.
    [ -x "$CAP_BIN" ] || return 1
    "$CAP_BIN" - <<'PY' >/dev/null 2>&1
import socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.close()
PY
}

status() {
    info "venv            : $VENV"
    if [ -x "$CAP_BIN" ]; then
        info "capped binary   : $CAP_BIN"
        info "capability      : $(getcap "$CAP_BIN" 2>/dev/null || echo 'none')"
        if verify_capability; then
            info "raw socket      : OK (no sudo needed)"
            return 0
        fi
        info "raw socket      : FAILED - capability present but not usable"
        info "                  (filesystem may be mounted nosuid or ignore xattrs)"
        return 1
    fi
    info "capped binary   : not configured"
    return 1
}

remove() {
    if [ -e "$CAP_BIN" ]; then
        sudo setcap -r "$CAP_BIN" 2>/dev/null || true
        rm -f "$CAP_BIN"
        info "removed $CAP_BIN"
    else
        info "nothing to remove"
    fi
}

configure() {
    require_command setcap
    require_command getcap

    local source
    source="$(venv_python)"

    if [ -L "$VENV/bin/python" ] && [ "$source" = "$(readlink -f "$VENV/bin/python")" ]; then
        info "note: $VENV/bin/python is a symlink to $source"
        info "      installing a dedicated copy so the capability stays scoped"
    fi

    # Refresh the copy so it matches the current interpreter, then re-apply the
    # capability (a plain copy loses it).
    rm -f "$CAP_BIN"
    cp "$source" "$CAP_BIN"
    chmod 700 "$CAP_BIN"

    sudo setcap "$CAPABILITY" "$CAP_BIN" \
        || die "setcap failed; run this script with a user permitted to use sudo"

    if verify_capability; then
        info "configured: $CAP_BIN ($(getcap "$CAP_BIN"))"
        info "the MCP server can now run without sudo"
        return 0
    fi

    die "capability was set but a raw socket still failed; check the filesystem mount options"
}

case "${1:-}" in
    --check|-c) status ;;
    --remove|-r) remove ;;
    --help|-h) sed -n '3,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
    "") configure ;;
    *) die "unknown option: $1 (try --help)" ;;
esac

#!/usr/bin/env bash
# ©AngelaMos | 2026
# uninstall.sh

set -euo pipefail

BINARY="erinyes"
INSTALL_DIR="${ERINYES_INSTALL_DIR:-$HOME/.local/bin}"

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

info()  { printf '%s\n' "  ${CYAN}+${RESET} $*" >&2; }
ok()    { printf '%s\n' "  ${GREEN}+${RESET} $*" >&2; }
warn()  { printf '%s\n' "  ${YELLOW}!${RESET} $*" >&2; }
die()   { printf '%s\n' "  ${RED}x $*${RESET}" >&2; exit 1; }
header(){ printf '\n%s\n\n' "${BOLD}${CYAN}--- $* ---${RESET}" >&2; }
have()  { command -v "$1" >/dev/null 2>&1; }

KEEP_CACHE=0
KEEP_CONFIG=1

usage() {
    cat >&2 <<USAGE
uninstall.sh - remove ${BINARY}

  ./uninstall.sh [options]

options:
  --prefix DIR   where the binary was installed (default: ${INSTALL_DIR})
  --keep-cache   keep the downloaded-blob cache
  --purge        also delete the user config and user signature overlays
  -h, --help     this help
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)     INSTALL_DIR="$2"; shift 2 ;;
        --prefix=*)   INSTALL_DIR="${1#*=}"; shift ;;
        --keep-cache) KEEP_CACHE=1; shift ;;
        --purge)      KEEP_CONFIG=0; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

config_dir() {
    if [ -n "${ERINYES_CONFIG_DIR:-}" ]; then printf '%s\n' "$ERINYES_CONFIG_DIR"; return; fi
    printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/${BINARY}"
}

cache_dir() {
    if [ -n "${ERINYES_CACHE_DIR:-}" ]; then printf '%s\n' "$ERINYES_CACHE_DIR"; return; fi
    printf '%s\n' "${XDG_CACHE_HOME:-$HOME/.cache}/${BINARY}"
}

remove_path_line() {
    local rc
    for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
        [ -f "$rc" ] || continue
        grep -q "$INSTALL_DIR" "$rc" 2>/dev/null || continue
        local tmp
        tmp="$(mktemp)"
        grep -v -F "export PATH=\"$INSTALL_DIR:\$PATH\"" "$rc" > "$tmp"
        mv "$tmp" "$rc"
        ok "removed the PATH line from $rc"
    done

    local fishconf="$HOME/.config/fish/conf.d/${BINARY}.fish"
    if [ -f "$fishconf" ]; then
        rm -f "$fishconf"
        ok "removed $fishconf"
    fi
}

main() {
    header "Removing ${BINARY}"

    if [ -f "$INSTALL_DIR/$BINARY" ]; then
        rm -f "$INSTALL_DIR/$BINARY"
        ok "removed $INSTALL_DIR/$BINARY"
    else
        warn "no binary at $INSTALL_DIR/$BINARY"
    fi

    if have go; then
        local gobin
        gobin="$(go env GOBIN)"
        [ -n "$gobin" ] || gobin="$(go env GOPATH)/bin"
        if [ -f "$gobin/$BINARY" ]; then
            rm -f "$gobin/$BINARY"
            ok "removed $gobin/$BINARY (go install copy)"
        fi
    fi

    remove_path_line

    local src cache cfg
    src="${XDG_CACHE_HOME:-$HOME/.cache}/${BINARY}-src"
    if [ -d "$src" ]; then
        rm -rf "$src"
        ok "removed the source clone at $src"
    fi

    if [ "$KEEP_CACHE" -eq 0 ]; then
        cache="$(cache_dir)"
        if [ -d "$cache" ]; then
            rm -rf "$cache"
            ok "removed the blob cache at $cache"
        fi
    else
        info "kept the blob cache at $(cache_dir)"
    fi

    cfg="$(config_dir)"
    if [ "$KEEP_CONFIG" -eq 0 ]; then
        if [ -d "$cfg" ]; then
            rm -rf "$cfg"
            ok "removed the config and signature overlays at $cfg"
        fi
    elif [ -d "$cfg" ]; then
        info "kept your config and signature overlays at $cfg ${DIM}(--purge deletes them)${RESET}"
    fi

    printf '\n%s\n\n' "  ${GREEN}${BOLD}${BINARY} removed.${RESET}" >&2
    return 0
}

main "$@" </dev/null

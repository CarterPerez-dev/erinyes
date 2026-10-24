#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

REPO_OWNER="CarterPerez-dev"
REPO_NAME="erinyes"
BINARY="erinyes"
TAGLINE="hunt obfuscated malware hiding in open source"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
INSTALL_DIR="${ERINYES_INSTALL_DIR:-$HOME/.local/bin}"
DEFAULT_BRANCH="main"
MIN_GO="1.25"
GO_FALLBACK="1.25.3"
PREBUILT=1

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

trap 'printf "%s\n" "${RED}x install failed${RESET}" >&2' ERR
TMP_DIR=""
cleanup() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT

banner() {
    printf '%s' "${CYAN}${BOLD}" >&2
    cat >&2 <<'ART'
   _____ ____  ___ _   ____  _____________
  / ___// __ \/ _ \ | / /\ \/ / ____/ ___/
  \__ \/ /_/ / // / |/ /  \  / __/  \__ \
 ___/ / _, _/ // /| /    / / /___  ___/ /
/____/_/ |_/___/ |__/   /_/_____/ /____/
ART
    printf '%s\n' "${RESET}" >&2
    printf '%s\n' "  ${DIM}${TAGLINE}${RESET}" >&2
}

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if have sudo; then SUDO="sudo"; fi
fi

pkg_install() {
    if   have apt-get; then $SUDO apt-get update -y || warn "apt update had errors; continuing"
                            $SUDO apt-get install -y --no-install-recommends "$@"
    elif have dnf;     then $SUDO dnf install -y "$@"
    elif have pacman;  then $SUDO pacman -S --needed --noconfirm "$@"
    elif have zypper;  then $SUDO zypper install -y "$@"
    elif have apk;     then $SUDO apk add "$@"
    elif have brew;    then brew install "$@"
    else die "no known package manager. Install manually: $*"; fi
}

download() {
    if   have curl; then curl -fsSL "$1" -o "$2" || return 1
    elif have wget; then wget -qO "$2" "$1" || return 1
    else die "need curl or wget"; fi
}

usage() {
    cat >&2 <<USAGE
install.sh - install ${BINARY}

  ./install.sh [options]
  curl -fsSL https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download/install.sh | bash

options:
  --prefix DIR   install dir (default: ${INSTALL_DIR})
  --from-source  skip release binaries and build locally
  --version TAG  install a specific release tag (default: latest)
  -h, --help     this help

environment:
  ERINYES_INSTALL_DIR   same as --prefix
  GH_TOKEN              optional GitHub CLI token for private release downloads
  NO_COLOR              disable colored output
USAGE
}

WANT_VERSION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)      [ $# -ge 2 ] && [ -n "$2" ] || die "--prefix requires a directory"; INSTALL_DIR="$2"; shift 2 ;;
        --prefix=*)    INSTALL_DIR="${1#*=}"; [ -n "$INSTALL_DIR" ] || die "--prefix requires a directory"; shift ;;
        --from-source) PREBUILT=0; shift ;;
        --version)     [ $# -ge 2 ] && [ -n "$2" ] || die "--version requires a tag"; WANT_VERSION="$2"; shift 2 ;;
        --version=*)   WANT_VERSION="${1#*=}"; [ -n "$WANT_VERSION" ] || die "--version requires a tag"; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             die "unknown option: $1 (try --help)" ;;
    esac
done

OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    MINGW*|MSYS*|CYGWIN*)
        die "Windows is not supported by this script. Use WSL, or: go install github.com/${REPO_OWNER}/${REPO_NAME}/cmd/${BINARY}@latest" ;;
    *) die "unsupported OS: $OS" ;;
esac
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported arch: $ARCH (erinyes ships amd64 and arm64)" ;;
esac

version_ge() {
    awk -v actual="$1" -v required="$2" 'BEGIN {
        split(actual, a, "."); split(required, r, ".")
        for (i = 1; i <= 3; i++) {
            if (a[i] + 0 > r[i] + 0) exit 0
            if (a[i] + 0 < r[i] + 0) exit 1
        }
        exit 0
    }'
}

resolve_repo() {
    local self="${BASH_SOURCE[0]:-}" local_repo=""
    if [ -f "./go.mod" ] && [ -d "./cmd/${BINARY}" ]; then
        local_repo="$(pwd)"
    elif [ -n "$self" ] && [ -f "$(dirname "$self")/go.mod" ]; then
        local_repo="$(cd "$(dirname "$self")" && pwd)"
    fi
    if [ -n "$local_repo" ] && [ -z "$WANT_VERSION" ]; then
        printf '%s\n' "$local_repo"; return
    fi
    if ! have git; then
        warn "git is missing, installing it"
        pkg_install git
    fi
    have git || die "could not install git; install it then re-run"

    if [ -n "$WANT_VERSION" ]; then
        local source="$REPO_URL"
        if [ -n "$local_repo" ] && git -C "$local_repo" show-ref --verify --quiet "refs/tags/$WANT_VERSION"; then
            source="$local_repo"
        fi
        info "cloning release ${WANT_VERSION}"
        git clone --depth 1 --branch "$WANT_VERSION" --quiet "$source" "$TMP_DIR/source" \
            || die "could not clone release ${WANT_VERSION}"
        printf '%s\n' "$TMP_DIR/source"
        return
    fi

    local cache="${XDG_CACHE_HOME:-$HOME/.cache}/${BINARY}-src"
    if [ -d "$cache/.git" ]; then
        info "updating cached clone at $cache"
        git -C "$cache" pull --ff-only --quiet || die "could not update the cached clone at $cache"
    else
        info "cloning ${REPO_URL}"
        git clone --depth 1 --branch "$DEFAULT_BRANCH" --quiet "$REPO_URL" "$cache" \
            || die "clone failed from ${REPO_URL}"
    fi
    printf '%s\n' "$cache"
}

go_version() {
    go version 2>/dev/null | awk '{print $3}' | sed 's/^go//'
}

install_go_tarball() {
    local ver="$GO_FALLBACK"
    local url="https://go.dev/dl/go${ver}.${OS}-${ARCH}.tar.gz"
    local dest="$HOME/.local/go"

    info "downloading Go ${ver} from go.dev"
    download "$url" "$TMP_DIR/go.tar.gz" || die "could not download $url"

    rm -rf "$dest"
    mkdir -p "$(dirname "$dest")"
    tar -xzf "$TMP_DIR/go.tar.gz" -C "$TMP_DIR"
    mv "$TMP_DIR/go" "$dest"

    export PATH="$dest/bin:$PATH"
    hash -r 2>/dev/null || true
    ok "Go ${ver} installed to $dest"
}

need_toolchain() {
    if have go && version_ge "$(go_version)" "$MIN_GO"; then
        ok "go $(go_version)"
        return
    fi

    if have go; then
        warn "go $(go_version) is older than the required ${MIN_GO}"
    else
        info "Go is not installed"
    fi

    if have brew; then
        pkg_install go || true
    elif have pacman; then
        pkg_install go || true
    fi

    hash -r 2>/dev/null || true
    if ! have go || ! version_ge "$(go_version)" "$MIN_GO"; then
        install_go_tarball
    fi

    have go || die "could not install Go. Install it from https://go.dev/dl/ then re-run"
    version_ge "$(go_version)" "$MIN_GO" || die "go $(go_version) is too old, need >= ${MIN_GO}"
    ok "go $(go_version)"
}

build_from_source() {
    local version commit
    version="$(git -C . describe --tags --always --dirty 2>/dev/null || echo dev)"
    commit="$(git -C . rev-parse --short HEAD 2>/dev/null || echo unknown)"

    info "building ${BINARY} ${version}"
    mkdir -p "$INSTALL_DIR"
    CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${version} -X main.commit=${commit}" \
        -o "$INSTALL_DIR/$BINARY" "./cmd/${BINARY}"
    chmod +x "$INSTALL_DIR/$BINARY"
    ok "built ${BINARY} -> ${INSTALL_DIR}/${BINARY}"
}

latest_tag() {
    if have gh; then
        local tag
        if tag="$(gh release view --repo "${REPO_OWNER}/${REPO_NAME}" --json tagName --jq .tagName 2>/dev/null)" && [ -n "$tag" ]; then
            printf '%s\n' "$tag"
            return
        fi
    fi
    download "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" /dev/stdout 2>/dev/null \
        | grep '"tag_name":' | head -n1 | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/'
}

download_release_asset() {
    local ver="$1" name="$2" destination="$3"
    if have gh && gh release download "$ver" --repo "${REPO_OWNER}/${REPO_NAME}" \
        --pattern "$name" --output "$destination" --clobber 2>/dev/null; then
        return
    fi
    download "https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${ver}/${name}" "$destination"
}

verify_checksum() {
    local file="$1" sums="$2" name="$3" expected actual
    expected="$(grep -E "[[:space:]]\*?${name}\$" "$sums" | awk '{print $1}' | head -n1)"
    if [ -z "$expected" ]; then
        warn "no checksum listed for ${name}, cannot verify"
        return 1
    fi
    if   have sha256sum; then actual="$(sha256sum "$file" | awk '{print $1}')"
    elif have shasum;    then actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    else warn "no sha256 tool available, cannot verify"; return 1; fi

    if [ "$expected" != "$actual" ]; then
        die "checksum mismatch for ${name}: expected ${expected}, got ${actual}"
    fi
    ok "sha256 verified"
    return 0
}

try_prebuilt() {
    [ "$PREBUILT" = "1" ] || return 1

    local ver archive
    ver="${WANT_VERSION}"
    if [ -z "$ver" ]; then
        ver="$(latest_tag || true)"
    fi
    if [ -z "$ver" ]; then
        info "no published release found, building from source"
        return 1
    fi

    archive="${BINARY}_${ver#v}_${OS}_${ARCH}.tar.gz"
    WANT_VERSION="$ver"

    if ! download_release_asset "$ver" "$archive" "$TMP_DIR/$archive"; then
        warn "no prebuilt binary for ${OS}/${ARCH} in ${ver}, building from source"
        return 1
    fi

    download_release_asset "$ver" checksums.txt "$TMP_DIR/checksums.txt" \
        || die "checksums.txt is unavailable for ${ver}"
    verify_checksum "$TMP_DIR/$archive" "$TMP_DIR/checksums.txt" "$archive" \
        || die "could not verify ${archive}"

    tar -xzf "$TMP_DIR/$archive" -C "$TMP_DIR" || die "could not extract ${archive}"
    [ -f "$TMP_DIR/$BINARY" ] || { warn "archive did not contain ${BINARY}, building from source"; return 1; }

    mkdir -p "$INSTALL_DIR" || die "could not create ${INSTALL_DIR}"
    install -m 0755 "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY" || die "could not install ${BINARY} to ${INSTALL_DIR}"
    ok "installed ${ver} -> ${INSTALL_DIR}/${BINARY}"
}

wire_path() {
    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ok "$INSTALL_DIR is already on PATH"; return ;;
    esac

    local shell rc=""
    shell="$(basename "${SHELL:-bash}")"
    case "$shell" in
        zsh)  rc="$HOME/.zshrc" ;;
        fish) mkdir -p "$HOME/.config/fish/conf.d"
              echo "fish_add_path $INSTALL_DIR" > "$HOME/.config/fish/conf.d/${BINARY}.fish"
              ok "added $INSTALL_DIR to fish conf.d" ;;
        bash) rc="$HOME/.bashrc"; [ -f "$rc" ] || rc="$HOME/.bash_profile" ;;
        *)    rc="$HOME/.profile" ;;
    esac

    if [ -n "$rc" ] && ! grep -q "$INSTALL_DIR" "$rc" 2>/dev/null; then
        printf '\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$rc"
        ok "added $INSTALL_DIR to PATH in $rc"
    fi
    export PATH="$INSTALL_DIR:$PATH"
}

main() {
    banner
    TMP_DIR="$(mktemp -d)"

    if have "$BINARY"; then
        info "existing install at $(command -v "$BINARY"), updating"
    fi

    REPO=""
    if ! try_prebuilt; then
        header "Building from source"
        REPO="$(resolve_repo)"
        cd "$REPO"
        need_toolchain
        build_from_source
    fi

    wire_path

    header "Verify"
    have "$BINARY" || die "installed to $INSTALL_DIR but ${BINARY} is still not on PATH"
    ok "$BINARY -> $(command -v "$BINARY")"
    "$BINARY" version >&2

    header "Self-test"
    if "$BINARY" signatures list >/dev/null 2>&1; then
        ok "signature catalog loads"
    else
        warn "the signature catalog did not load, run '${BINARY} signatures list' to see why"
    fi

    printf '\n%s\n\n' "  ${GREEN}${BOLD}${BINARY} is ready.${RESET}" >&2
    cat >&2 <<FOOTER
  ${DIM}scan a checkout (never touches the network):${RESET}
    ${CYAN}${BINARY} scan ./some-repo${RESET}

  ${DIM}retrohunt GitHub for a signature (needs \$GITHUB_TOKEN or \`gh auth login\`):${RESET}
    ${CYAN}${BINARY} hunt pymapper-fs-loader${RESET}

  ${DIM}check a hash against the known-malicious catalog:${RESET}
    ${CYAN}${BINARY} verify <sha256>${RESET}

  ${DIM}see what is loaded:${RESET}
    ${CYAN}${BINARY} signatures list${RESET}

  ${DIM}docs: https://github.com/${REPO_OWNER}/${REPO_NAME}${RESET}
FOOTER

    if have just && [ -n "$REPO" ] && [ -f "${REPO}/justfile" ]; then
        printf '%s\n' "  ${DIM}dev commands: cd ${REPO} && just${RESET}" >&2
    fi
    return 0
}

main "$@" </dev/null

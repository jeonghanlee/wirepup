#!/bin/bash -p
# Copy caller-verified binary or completion bytes into a protected directory.
# Build and version checks belong to the unprivileged installation driver.

set -euo pipefail
[[ $- == *p* ]] || { printf '%s\n' 'FAIL: invoke with /bin/bash -p' >&2; exit 1; }
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset BASH_ENV ENV CDPATH
umask 022

artifact=binary
install_mode=0755
if [[ "${1:-}" == --completion ]]; then
    artifact=completion
    install_mode=0644
    shift
fi
readonly artifact install_mode
check_only=false
if [[ "${1:-}" == --check ]]; then
    check_only=true
    shift
fi
readonly destination="${1:-}"
readonly expected_digest="${2:-}"
readonly allow_replace="${3:-0}"
staged_path=""

function die {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

function cleanup {
    local status=$?

    if [[ -n "${staged_path}" ]]; then
        rm -f -- "${staged_path}"
    fi
    return "${status}"
}

function check_parents {
    local parent="${destination%/*}"
    local owner
    local mode

    while :; do
        [[ ! -L "${parent}" ]] || die "installation parent is a symlink: ${parent}"
        if [[ -e "${parent}" ]]; then
            [[ -d "${parent}" ]] || die "installation parent is not a directory: ${parent}"
            if "${check_only}"; then
                [[ -x "${parent}" ]] || die "installation parent is not accessible to the invoking user: ${parent}"
            fi
            owner="$(stat -c %u -- "${parent}")"
            mode="$(stat -c %a -- "${parent}")"
            [[ "${owner}" == 0 ]] || die "installation parent is not owned by root: ${parent}"
            (( (8#${mode} & 0022) == 0 )) || die "installation parent is writable by group or others: ${parent}"
        fi
        [[ "${parent}" != / ]] || break
        parent="${parent%/*}"
        parent="${parent:-/}"
    done
}

function check_destination {
    [[ ! -L "${destination}" ]] || die "destination is a symlink"
    [[ ! -e "${destination}" || -f "${destination}" ]] || die "destination is not a regular file"
}

if [[ "${artifact}" == completion ]]; then
    [[ "${destination}" == /*/share/bash-completion/completions/wirepup ]] || die "expected an absolute Bash completion destination"
else
    [[ "${destination}" == /*/bin/wirepup ]] || die "expected an absolute destination ending in /bin/wirepup"
fi
[[ "${destination}" == "$(realpath -ms -- "${destination}")" ]] || die "destination must not contain dot components or repeated separators"
check_parents
check_destination
if "${check_only}"; then
    [[ $# -eq 1 ]] || die "--check requires exactly one destination"
    exit 0
fi
[[ ${EUID} -eq 0 ]] || die "this copy operation requires root"
[[ $# -ge 2 && $# -le 3 && "${expected_digest}" =~ ^[a-f0-9]{64}$ ]] || die "expected the verified source SHA-256 digest"
[[ "${allow_replace}" == 0 || "${allow_replace}" == 1 ]] || die "replacement approval must be 0 or 1"
[[ ! -e "${destination}" || "${allow_replace}" == 1 ]] || die "replacement was not approved; existing file was preserved"
mkdir -p -- "${destination%/*}"
check_parents
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
staged_path="$(mktemp "${destination%/*}/.wirepup.XXXXXXXXXX")"
cat > "${staged_path}"
[[ -s "${staged_path}" ]] || die "no file bytes received; existing installation was preserved"
actual_digest="$(sha256sum -- "${staged_path}")"
[[ "${actual_digest%% *}" == "${expected_digest}" ]] || die "copied bytes differ from verified source; existing installation was preserved"
chmod "${install_mode}" -- "${staged_path}"
# X_OK also checks the mount's noexec flag without executing code as root.
if [[ "${artifact}" == binary ]]; then
    [[ -x "${staged_path}" ]] || die "destination does not permit execution (noexec); existing installation was preserved"
fi
check_destination
if [[ "${allow_replace}" == 1 ]]; then
    mv -fT -- "${staged_path}" "${destination}"
else
    mv -nT -- "${staged_path}" "${destination}"
    [[ ! -e "${staged_path}" ]] || die "destination appeared during installation; rerun to approve replacement"
fi
staged_path=""
printf 'PASS: root-owned %s installed with mode %s\n' "${artifact}" "${install_mode}"

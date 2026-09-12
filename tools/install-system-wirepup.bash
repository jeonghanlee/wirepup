#!/bin/bash -p
# Copy caller-verified binary or completion bytes into a protected directory,
# or manage the RHEL secure_path symlink and remove installed artifacts.
# Build and version checks belong to the unprivileged installation driver.

set -euo pipefail
[[ $- == *p* ]] || { printf '%s\n' 'FAIL: invoke with /bin/bash -p' >&2; exit 1; }
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset BASH_ENV ENV CDPATH
umask 022

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

# Every segment from the target's parent up to / must be a root-owned directory
# that is not a symlink and not writable by group or others. The optional second
# argument, when "access", also requires the invoking user can traverse; it is
# used by --check, which runs as that user, not by the root-side operations.
function check_parents {
    local target="$1"
    local access="${2:-}"
    local parent="${target%/*}"
    local owner
    local mode

    while :; do
        [[ ! -L "${parent}" ]] || die "installation parent is a symlink: ${parent}"
        if [[ -e "${parent}" ]]; then
            [[ -d "${parent}" ]] || die "installation parent is not a directory: ${parent}"
            if [[ "${access}" == access ]]; then
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

# The symlink path and the artifact paths are fixed shapes under a prefix.
function require_canonical {
    local path="$1"
    [[ "${path}" == "$(realpath -ms -- "${path}")" ]] || die "path must not contain dot components or repeated separators: ${path}"
}

# --- Symlink and removal modes. Each handles one action and exits. ---

if [[ "${1:-}" == --symlink ]]; then
    shift
    link_path="${1:-}"
    link_target="${2:-}"
    [[ $# -eq 2 ]] || die "--symlink requires a link path and a target"
    [[ "${link_path}" == /*/wirepup ]] || die "symlink path must be absolute and end in /wirepup"
    [[ "${link_target}" == /*/bin/wirepup ]] || die "symlink target must be absolute and end in /bin/wirepup"
    require_canonical "${link_path}"
    require_canonical "${link_target}"
    [[ ${EUID} -eq 0 ]] || die "creating the symlink requires root"
    [[ -f "${link_target}" && ! -L "${link_target}" ]] || die "symlink target is not an installed regular file: ${link_target}"
    check_parents "${link_path}"
    # Never replace a real file; only create or update our own symlink.
    [[ ! -e "${link_path}" || -L "${link_path}" ]] || die "refusing to replace a non-symlink at ${link_path}"
    ln -sfn -- "${link_target}" "${link_path}"
    [[ -L "${link_path}" && "$(readlink -- "${link_path}")" == "${link_target}" ]] \
        || die "symlink verification failed: ${link_path}"
    printf 'PASS: %s -> %s\n' "${link_path}" "${link_target}"
    exit 0
fi

if [[ "${1:-}" == --unsymlink ]]; then
    shift
    link_path="${1:-}"
    link_target="${2:-}"
    [[ $# -eq 2 ]] || die "--unsymlink requires a link path and a target"
    [[ "${link_path}" == /*/wirepup ]] || die "symlink path must be absolute and end in /wirepup"
    [[ "${link_target}" == /*/bin/wirepup ]] || die "symlink target must be absolute and end in /bin/wirepup"
    require_canonical "${link_path}"
    [[ ${EUID} -eq 0 ]] || die "removing the symlink requires root"
    check_parents "${link_path}"
    if [[ -L "${link_path}" && "$(readlink -- "${link_path}")" == "${link_target}" ]]; then
        rm -f -- "${link_path}"
        printf 'PASS: removed symlink %s\n' "${link_path}"
    else
        printf 'SKIP: %s is not a symlink to %s; left unchanged\n' "${link_path}" "${link_target}"
    fi
    exit 0
fi

if [[ "${1:-}" == --remove ]]; then
    shift
    remove_path="${1:-}"
    [[ $# -eq 1 ]] || die "--remove requires exactly one path"
    [[ "${remove_path}" == /*/bin/wirepup || "${remove_path}" == /*/share/bash-completion/completions/wirepup ]] \
        || die "refusing to remove an unexpected path: ${remove_path}"
    require_canonical "${remove_path}"
    [[ ${EUID} -eq 0 ]] || die "removing a protected file requires root"
    check_parents "${remove_path}"
    [[ ! -L "${remove_path}" ]] || die "refusing to remove a symlink at the file path: ${remove_path}"
    if [[ -e "${remove_path}" ]]; then
        [[ -f "${remove_path}" ]] || die "refusing to remove a non-regular file: ${remove_path}"
        rm -f -- "${remove_path}"
        printf 'PASS: removed %s\n' "${remove_path}"
    else
        printf 'SKIP: %s is already absent\n' "${remove_path}"
    fi
    exit 0
fi

# --- Copy mode: install verified bytes into a protected destination. ---

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
if "${check_only}"; then
    check_parents "${destination}" access
else
    check_parents "${destination}"
fi
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
check_parents "${destination}"
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

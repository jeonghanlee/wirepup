#!/usr/bin/env bash
# Install the built executable and verify command resolution.

set -euo pipefail

readonly action="${1:-}"
readonly source_path="${2:-}"
destination="${3:-}"
if [[ "${destination}" == /*/bin/wirepup ]]; then
    installation_prefix="${destination%/bin/wirepup}"
    destination="${installation_prefix%/}/bin/wirepup"
fi
readonly destination
readonly repository="${4:-}"
readonly install_command="${INSTALL_COMMAND:-install}"
readonly install_force="${INSTALL_FORCE:-0}"
readonly command_name="wirepup"
allow_replace=0
staged_path=""
source_snapshot=""

function cleanup_staged_file {
    local status=$?

    if [[ -n "${staged_path}" ]]; then
        rm -f -- "${staged_path}"
    fi
    if [[ -n "${source_snapshot}" ]]; then
        rm -f -- "${source_snapshot}"
    fi
    return "${status}"
}

function die {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

function print_state {
    local active_path
    local state="missing"

    if [[ -f "${destination}" && -x "${destination}" ]]; then
        state="executable"
    elif [[ -e "${destination}" || -L "${destination}" ]]; then
        state="present but not a regular executable"
    fi
    active_path="$(type -P "${command_name}" || true)"
    printf 'Destination: %s (%s)\n' "${destination}" "${state}"
    printf 'Active command: %s\n' "${active_path:-not found}"
}

function check_install_paths {
    local realpath_command
    local source_resolved
    local destination_resolved

    realpath_command="$(command -v realpath || true)"
    if [[ -z "${realpath_command}" || ! -x "${realpath_command}" ]]; then
        printf '%s\n' "Install on Debian: apt install coreutils" >&2
        die "realpath is required to check installation paths"
    fi
    [[ ! -d "${source_path}" ]] || die "BIN must name a file, not a directory"
    [[ ! -L "${destination}" ]] || die "destination is a symlink"
    [[ ! -e "${destination}" || -f "${destination}" ]] || die "destination is not a regular file"
    source_resolved="$("${realpath_command}" -m -- "${source_path}")"
    destination_resolved="$("${realpath_command}" -m -- "${destination}")"
    if [[ "${source_resolved}" == "${destination_resolved}" || "${source_path}" -ef "${destination}" ]]; then
        die "build output and installation destination refer to the same file"
    fi
}

function needs_sudo {
    local parent="${destination%/*}"

    while [[ ! -e "${parent}" ]]; do
        parent="${parent%/*}"
        parent="${parent:-/}"
    done
    [[ ! -w "${parent}" || ! -x "${parent}" ]]
}

function check_privileges {
    local tool_path

    if needs_sudo; then
        [[ -x /usr/bin/sudo ]] || die "sudo is required for this destination; install sudo or choose a writable INSTALL_LOCATION"
        tool_path="$(command -v "${install_command}" || true)"
        [[ -n "${tool_path}" && "${tool_path}" -ef /usr/bin/install ]] || \
            die "custom INSTALL is supported only for writable destinations"
        /bin/bash -p tools/install-system-wirepup.bash --check "${destination}"
    fi
}

function print_command {
    printf 'make -C %q %s INSTALL_LOCATION=%q' "${repository}" "$1" "${destination%/bin/wirepup}"
    if [[ ${#build_settings[@]} -gt 0 ]]; then
        printf ' %q' "${build_settings[@]}"
    fi
    printf '\n'
}

function confirm_replacement {
    local answer=""

    [[ -f "${destination}" ]] || return 0
    if [[ "${install_force}" == 1 ]]; then
        printf 'Replacement approved by INSTALL_FORCE=1: %s\n' "${destination}"
        allow_replace=1
        return 0
    fi
    [[ -t 0 ]] || die "destination already exists; run interactively or explicitly approve replacement with INSTALL_FORCE=1"
    printf 'Existing file: %s\nReplace this file? [y/N] ' "${destination}"
    if ! IFS= read -r answer; then
        printf '\n%s\n' 'Cancelled: no answer received; existing file was preserved.' >&2
        exit 1
    fi
    case "${answer}" in
        y|Y|yes|YES|Yes) allow_replace=1 ;;
        *)
            printf '%s\n' 'Cancelled: existing file was preserved.'
            exit 1
            ;;
    esac
}

function check_installation {
    local active_path

    print_state
    [[ -f "${destination}" && -x "${destination}" ]] || die "installed executable is missing"
    active_path="$(type -P "${command_name}" || true)"
    if [[ -z "${active_path}" || ! "${active_path}" -ef "${destination}" ]]; then
        # The hint expands PATH in the operator's shell, not in this process.
        # shellcheck disable=SC2016
        printf 'Activate in the current shell: export PATH=%q:"$PATH"\n' "${destination%/*}"
        die "PATH does not resolve to the installed executable"
    fi
    "${destination}" version
    printf '%s\n' "PASS: WirePup installation is active"
}

[[ $# -ge 4 ]] || die "usage: install-wirepup.bash <preflight|dry-run|apply|check> SOURCE DESTINATION REPOSITORY [NAME=VALUE ...]"
shift 4
declare -ar build_settings=("$@")
[[ "${destination}" == /*/bin/wirepup ]] || die "destination must be an absolute path ending in /bin/wirepup"
[[ "${install_force}" == 0 || "${install_force}" == 1 ]] || die "INSTALL_FORCE must be 0 or 1"

case "${action}" in
    preflight)
        [[ ${EUID} -ne 0 ]] || die "run make install as your normal user; only the file installation uses sudo"
        check_install_paths
        check_privileges
        ;;
    dry-run)
        check_install_paths
        check_privileges
        print_state
        printf 'Source: %s\n' "${source_path}"
        printf 'Proposed action: build and install at %s\n' "${destination}"
        if [[ -f "${destination}" ]]; then
            if [[ "${install_force}" == 1 ]]; then
                printf '%s\n' 'Replacement: explicitly approved by INSTALL_FORCE=1'
            else
                printf '%s\n' 'Replacement: will ask before replacing the existing file (default: no)'
            fi
        fi
        if needs_sudo; then
            printf '%s\n' "Privileges: sudo for the file installation only (authentication may be required)"
        else
            printf '%s\n' "Privileges: current user; sudo is not needed"
        fi
        printf 'Apply: '
        print_command install.apply
        printf 'Verify: '
        print_command install.check
        printf '%s\n' "No filesystem changes were made."
        ;;
    apply)
        [[ ${EUID} -ne 0 ]] || die "run make install as your normal user; only the file installation uses sudo"
        check_install_paths
        check_privileges
        print_state
        confirm_replacement
        [[ -f "${source_path}" && -x "${source_path}" ]] || die "build output is missing or not executable"
        tool_path="$(command -v "${install_command}" || true)"
        if [[ -z "${tool_path}" || ! -x "${tool_path}" ]]; then
            printf '%s\n' "Install on Debian: apt install coreutils" >&2
            die "install command is missing"
        fi
        source_executable="${source_path}"
        if [[ "${source_executable}" != /* ]]; then
            source_executable="${repository}/${source_executable}"
        fi
        printf 'Checking build output: %s\n' "${source_executable}"
        if ! "${source_executable}" version; then
            die "build output cannot run on this host; existing installation was preserved"
        fi
        printf 'Installing executable: %s\n' "${destination}"
        if needs_sudo; then
            trap cleanup_staged_file EXIT
            trap 'exit 130' INT
            trap 'exit 143' TERM
            # The build already ran here; TMPDIR may be mounted noexec.
            resolved_source="$(realpath -- "${source_executable}")"
            source_snapshot="$(mktemp "${resolved_source%/*}/.wirepup-source.XXXXXXXXXX")"
            cp -- "${source_path}" "${source_snapshot}"
            chmod 0700 -- "${source_snapshot}"
            "${source_snapshot}" version || die "installation snapshot cannot run; existing installation was preserved"
            source_digest="$(sha256sum -- "${source_snapshot}")"
            source_digest="${source_digest%% *}"
            # Only the copy runs as root; the build and executable checks do not.
            # The invoking user opens the build output, including on NFS homes.
            # shellcheck disable=SC2024
            /usr/bin/sudo /bin/bash -p tools/install-system-wirepup.bash "${destination}" "${source_digest}" "${allow_replace}" < "${source_snapshot}"
            cmp -s -- "${source_snapshot}" "${destination}" || die "installed bytes differ from the verified snapshot"
            "${destination}" version
            printf '%s\n' "PASS: WirePup executable installed"
            printf 'Verify: '
            print_command install.check
            printf '%s\n' "Verify sudo command resolution: sudo wirepup version"
            exit 0
        fi
        (umask 022; mkdir -p -- "${destination%/*}")
        trap cleanup_staged_file EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        staged_path="$(mktemp "${destination%/*}/.wirepup.XXXXXXXXXX")"
        "${install_command}" -T -m 0755 -- "${source_path}" "${staged_path}"
        [[ -f "${staged_path}" && -x "${staged_path}" ]] || die "installation did not produce an executable"
        if ! "${staged_path}" version; then
            die "staged executable cannot run on this host; existing installation was preserved"
        fi
        check_install_paths
        if [[ "${allow_replace}" == 1 ]]; then
            mv -fT -- "${staged_path}" "${destination}"
        else
            mv -nT -- "${staged_path}" "${destination}"
            [[ ! -e "${staged_path}" ]] || die "destination appeared during installation; rerun to approve replacement"
        fi
        staged_path=""
        printf '%s\n' "PASS: WirePup executable installed"
        printf 'Verify: '
        print_command install.check
        ;;
    check)
        check_installation
        ;;
    *)
        die "unsupported action: ${action}"
        ;;
esac

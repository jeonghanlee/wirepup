#!/usr/bin/env bash
# Install the built executable and verify command resolution.

set -euo pipefail

readonly action="${1:-}"
readonly source_path="${2:-}"
readonly destination="${3:-}"
readonly repository="${4:-}"
readonly install_command="${INSTALL_COMMAND:-install}"
readonly command_name="wirepup"
staged_path=""

function cleanup_staged_file {
    local status=$?

    if [[ -n "${staged_path}" ]]; then
        rm -f -- "${staged_path}"
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
    [[ ! -L "${destination}" && ! -d "${destination}" ]] || die "destination is a symlink or directory"
    source_resolved="$("${realpath_command}" -m -- "${source_path}")"
    destination_resolved="$("${realpath_command}" -m -- "${destination}")"
    if [[ "${source_resolved}" == "${destination_resolved}" || "${source_path}" -ef "${destination}" ]]; then
        die "build output and installation destination refer to the same file"
    fi
}

function print_command {
    printf 'make -C %q %s INSTALL_LOCATION=%q' "${repository}" "$1" "${destination%/bin/wirepup}"
    if [[ ${#build_settings[@]} -gt 0 ]]; then
        printf ' %q' "${build_settings[@]}"
    fi
    printf '\n'
}

function check_installation {
    local active_path

    print_state
    [[ -f "${destination}" && -x "${destination}" ]] || die "installed executable is missing"
    active_path="$(type -P "${command_name}" || true)"
    if [[ -z "${active_path}" || ! "${active_path}" -ef "${destination}" ]]; then
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

case "${action}" in
    preflight)
        check_install_paths
        ;;
    dry-run)
        check_install_paths
        print_state
        printf 'Source: %s\n' "${source_path}"
        printf 'Proposed action: build and install at %s\n' "${destination}"
        printf 'Apply: '
        print_command install.apply
        printf 'Verify: '
        print_command install.check
        printf '%s\n' "No filesystem changes were made."
        ;;
    apply)
        check_install_paths
        print_state
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
        mv -fT -- "${staged_path}" "${destination}"
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

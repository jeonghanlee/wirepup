#!/usr/bin/env bash
# Install and verify the executable and Bash completion as the invoking user.

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
readonly completion_source="${repository}/completions/wirepup.bash"
readonly completion_destination="${destination%/bin/wirepup}/share/bash-completion/completions/wirepup"
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
    printf 'Completion: %s\n' "${completion_destination}"
}

function check_install_paths {
    local source="${1:-${source_path}}"
    local target="${2:-${destination}}"
    local realpath_command
    local source_resolved
    local destination_resolved

    realpath_command="$(command -v realpath || true)"
    if [[ -z "${realpath_command}" || ! -x "${realpath_command}" ]]; then
        printf '%s\n' "Install on Debian: apt install coreutils" >&2
        die "realpath is required to check installation paths"
    fi
    [[ ! -d "${source}" ]] || die "source must name a file, not a directory"
    [[ ! -L "${target}" ]] || die "destination is a symlink"
    [[ ! -e "${target}" || -f "${target}" ]] || die "destination is not a regular file"
    source_resolved="$("${realpath_command}" -m -- "${source}")"
    destination_resolved="$("${realpath_command}" -m -- "${target}")"
    if [[ "${source_resolved}" == "${destination_resolved}" || "${source}" -ef "${target}" ]]; then
        die "build output and installation destination refer to the same file"
    fi
}

function check_all_install_paths {
    check_install_paths
    check_install_paths "${completion_source}" "${completion_destination}"
    check_install_paths "${source_path}" "${completion_destination}"
    check_install_paths "${completion_source}" "${destination}"
}

function needs_sudo {
    local target="${1:-${destination}}"
    local parent="${target%/*}"

    while [[ ! -e "${parent}" ]]; do
        parent="${parent%/*}"
        parent="${parent:-/}"
    done
    [[ ! -w "${parent}" || ! -x "${parent}" ]]
}

function check_privileges {
    local target="${1:-${destination}}"
    local artifact="${2:-binary}"
    local tool_path
    local -a helper_args=()

    if needs_sudo "${target}"; then
        [[ -x /usr/bin/sudo ]] || die "sudo is required for this destination; install sudo or choose a writable INSTALL_LOCATION"
        tool_path="$(command -v "${install_command}" || true)"
        [[ -n "${tool_path}" && "${tool_path}" -ef /usr/bin/install ]] || \
            die "custom INSTALL is supported only for writable destinations"
        if [[ "${artifact}" == completion ]]; then helper_args+=(--completion); fi
        /bin/bash -p tools/install-system-wirepup.bash "${helper_args[@]}" --check "${target}"
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
    local target="${1:-${destination}}"
    local answer=""

    allow_replace=0
    [[ -f "${target}" ]] || return 0
    if [[ "${install_force}" == 1 ]]; then
        printf 'Replacement approved by INSTALL_FORCE=1: %s\n' "${target}"
        allow_replace=1
        return 0
    fi
    [[ -t 0 ]] || die "destination already exists; run interactively or explicitly approve replacement with INSTALL_FORCE=1"
    printf 'Existing file: %s\nReplace this file? [y/N] ' "${target}"
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

function validate_completion {
    local file="${1}"

    [[ -f "${file}" && -r "${file}" ]] || die "Bash completion is missing or unreadable: ${file}"
    bash -n "${file}" || die "Bash completion has invalid syntax: ${file}"
    # Ignore inherited functions and startup files while checking the handler.
    # Privileged Bash mode changes shell startup, not the invoking user's UID.
    bash --noprofile --norc -p -c '
        source "$1" || exit 1
        specification=$(complete -p wirepup) || exit 1
        pattern="(^|[[:space:]])-F[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]"
        [[ "${specification}" =~ ${pattern} ]] || exit 1
        declare -F -- "${BASH_REMATCH[2]}" >/dev/null
    ' _ "${file}" || die "Bash completion does not register wirepup with a defined function: ${file}"
}

function check_completion {
    [[ ! -L "${completion_destination}" ]] || die "installed Bash completion is a symlink"
    validate_completion "${completion_destination}"
    printf '%s\n' 'PASS: installed Bash completion registers a defined function for wirepup'
    printf 'Activate in this Bash shell: source %q\n' "${completion_destination}"
    printf '%s\n' 'Automatic loading requires bash-completion and a discoverable prefix; explicit source works without it.'
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
    check_completion
    printf '%s\n' "PASS: WirePup installation is active"
}

function install_file {
    local source="${1}" target="${2}" artifact="${3}" approved="${4}"
    local mode=0755 source_digest
    local -a helper_args=()
    if [[ "${artifact}" == completion ]]; then mode=0644; helper_args+=(--completion); fi
    printf 'Installing %s: %s\n' "${artifact}" "${target}"
    if needs_sudo "${target}"; then
        # Use the verified build directory; TMPDIR may be mounted noexec.
        source_snapshot="$(mktemp "${snapshot_directory}/.wirepup-source.XXXXXXXXXX")"
        cp -- "${source}" "${source_snapshot}"
        chmod 0600 -- "${source_snapshot}"
        if [[ "${artifact}" == binary ]]; then
            chmod 0700 -- "${source_snapshot}"
            "${source_snapshot}" version || die "installation snapshot cannot run; existing installation was preserved"
        else
            validate_completion "${source_snapshot}"
        fi
        source_digest="$(sha256sum -- "${source_snapshot}")"
        source_digest="${source_digest%% *}"
        # The invoking user opens the source; root never executes either file.
        # shellcheck disable=SC2024
        /usr/bin/sudo /bin/bash -p tools/install-system-wirepup.bash "${helper_args[@]}" "${target}" "${source_digest}" "${approved}" < "${source_snapshot}"
        cmp -s -- "${source_snapshot}" "${target}" || die "installed bytes differ from the verified snapshot"
        rm -f -- "${source_snapshot}"
        source_snapshot=""
    else
        (umask 022; mkdir -p -- "${target%/*}")
        staged_path="$(mktemp "${target%/*}/.wirepup.XXXXXXXXXX")"
        "${install_command}" -T -m "${mode}" -- "${source}" "${staged_path}"
        [[ -f "${staged_path}" ]] || die "installation did not produce a regular file"
        if [[ "${artifact}" == binary ]]; then
            [[ -x "${staged_path}" ]] || die "installation did not produce an executable"
            "${staged_path}" version || die "staged executable cannot run; existing installation was preserved"
        else
            validate_completion "${staged_path}"
        fi
        check_install_paths "${source}" "${target}"
        if [[ "${approved}" == 1 ]]; then
            mv -fT -- "${staged_path}" "${target}"
        else
            mv -nT -- "${staged_path}" "${target}"
            [[ ! -e "${staged_path}" ]] || die "destination appeared during installation; rerun to approve replacement"
        fi
        staged_path=""
    fi
}

[[ $# -ge 4 ]] || die "usage: install-wirepup.bash <preflight|dry-run|apply|check> SOURCE DESTINATION REPOSITORY [NAME=VALUE ...]"
shift 4
declare -ar build_settings=("$@")
[[ "${destination}" == /*/bin/wirepup ]] || die "destination must be an absolute path ending in /bin/wirepup"
[[ "${install_force}" == 0 || "${install_force}" == 1 ]] || die "INSTALL_FORCE must be 0 or 1"
[[ ${EUID} -ne 0 ]] || die "run make install as your normal user; only the file installation uses sudo"

case "${action}" in
    preflight)
        check_all_install_paths
        check_privileges
        check_privileges "${completion_destination}" completion
        validate_completion "${completion_source}"
        ;;
    dry-run)
        check_all_install_paths
        check_privileges
        check_privileges "${completion_destination}" completion
        print_state
        printf 'Source: %s\n' "${source_path}"
        printf 'Proposed action: build and install at %s\n' "${destination}"
        printf 'Proposed action: install Bash completion at %s (mode 0644)\n' "${completion_destination}"
        if [[ -f "${destination}" || -f "${completion_destination}" ]]; then
            if [[ "${install_force}" == 1 ]]; then
                printf '%s\n' 'Replacement: explicitly approved by INSTALL_FORCE=1'
            else
                printf '%s\n' 'Replacement: will ask before replacing the existing file (default: no)'
            fi
        fi
        if needs_sudo || needs_sudo "${completion_destination}"; then
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
        check_all_install_paths
        check_privileges
        check_privileges "${completion_destination}" completion
        print_state
        confirm_replacement
        binary_approved="${allow_replace}"
        confirm_replacement "${completion_destination}"
        completion_approved="${allow_replace}"
        validate_completion "${completion_source}"
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
        resolved_source="$(realpath -- "${source_executable}")"
        snapshot_directory="${resolved_source%/*}"
        trap cleanup_staged_file EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        install_file "${source_path}" "${destination}" binary "${binary_approved}"
        install_file "${completion_source}" "${completion_destination}" completion "${completion_approved}"
        "${destination}" version
        check_completion
        printf '%s\n' "PASS: WirePup executable and Bash completion installed"
        printf 'Verify: '
        print_command install.check
        if needs_sudo; then printf '%s\n' "Verify sudo command resolution: sudo wirepup version"; fi
        ;;
    check)
        check_installation
        ;;
    *)
        die "unsupported action: ${action}"
        ;;
esac

#!/usr/bin/env bash
# Exercise the shipped Make workflow locally, or its protected-copy path on a lab VM.
# --system uses an existing bin/wirepup and requires non-interactive sudo.

set -euo pipefail
repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository
cd -- "${repository}"
readonly mode="${1:-local}"
[[ $# -le 1 && ( "${mode}" == local || "${mode}" == --system ) ]] || exit 2
[[ ${EUID} -ne 0 ]] || { printf '%s\n' 'Run as a normal user.' >&2; exit 2; }
scratch="$(mktemp -d)"
readonly scratch
system_prefix=""

function cleanup {
    local status=$?

    if [[ ${status} -eq 0 ]]; then
        if [[ -n "${system_prefix}" ]]; then
            sudo -n rm -rf -- "${system_prefix}"
        fi
        rm -rf -- "${scratch}"
    else
        printf 'Retained test paths: %s %s\n' "${scratch}" "${system_prefix}" >&2
    fi
    return "${status}"
}
trap cleanup EXIT

function expect_failure {
    if "$@" > "${scratch}/failure.log" 2>&1; then
        printf 'Unexpected success: %s\n' "$*" >&2
        exit 1
    fi
}

if [[ "${mode}" == local ]]; then
    prefix="${scratch}/local/ prefix  path"
    make install.dry-run "INSTALL_LOCATION=${prefix}/" > "${scratch}/preview.log"
    grep -Fq "Destination: ${prefix}/bin/wirepup" "${scratch}/preview.log"
    [[ ! -e "${prefix}" ]]
    grep -Fq 'sudo is not needed' "${scratch}/preview.log"
    make install "INSTALL_LOCATION=${prefix}"
    cmp bin/wirepup "${prefix}/bin/wirepup"
    completion="${prefix}/share/bash-completion/completions/wirepup"
    cmp completions/wirepup.bash "${completion}"
    [[ "$(stat -c %a "${completion}")" == 644 ]]
    [[ "$(stat -c %a "${prefix}/bin/wirepup")" == 755 ]]
    PATH="${prefix}/bin:${PATH}" make install.check "INSTALL_LOCATION=${prefix}"
    mv -- "${completion}" "${completion}.held"
    expect_failure env PATH="${prefix}/bin:${PATH}" make install.check "INSTALL_LOCATION=${prefix}"
    grep -Fq 'completion is missing' "${scratch}/failure.log"
    mv -- "${completion}.held" "${completion}"
    python3 tests/completion.py "${prefix}/bin/wirepup" "${completion}"
    expect_failure env PATH=/usr/bin:/bin make install.check "INSTALL_LOCATION=${prefix}"
    grep -Fq 'PATH does not resolve' "${scratch}/failure.log"
    mkdir -p "${scratch}/symlink/bin"
    ln -s "${prefix}/bin/wirepup" "${scratch}/symlink/bin/wirepup"
    expect_failure make install "INSTALL_LOCATION=${scratch}/symlink"
    cmp bin/wirepup "${prefix}/bin/wirepup"
    mkdir -p "${scratch}/completion-symlink/share/bash-completion/completions"
    ln -s "${completion}" "${scratch}/completion-symlink/share/bash-completion/completions/wirepup"
    expect_failure make install "INSTALL_LOCATION=${scratch}/completion-symlink"
    [[ ! -e "${scratch}/completion-symlink/bin/wirepup" ]]
    printf '%s\n' 'PASS: local Make build/install/check, spaces, shadowing, and symlink refusal'
else
    sudo -n true
    [[ -x bin/wirepup ]]
    [[ -x bin/wirepup.previous ]] || { printf '%s\n' 'Provide a second real build at bin/wirepup.previous.' >&2; exit 1; }
    if cmp -s bin/wirepup bin/wirepup.previous; then
        printf '%s\n' 'The two test builds must differ.' >&2
        exit 1
    fi
    digest="$(sha256sum bin/wirepup)"
    digest="${digest%% *}"
    system_prefix="/opt/wirepup-install-test-$(date +%s)-$$"
    [[ ! -e "${system_prefix}" ]]
    bash tools/install-wirepup.bash dry-run bin/wirepup "${system_prefix}/bin/wirepup" "${repository}" > "${scratch}/preview.log"
    [[ ! -e "${system_prefix}" ]]
    grep -Fq 'sudo for the file installation only' "${scratch}/preview.log"
    expect_failure bash tools/install-wirepup.bash dry-run bin/wirepup /root/wirepup-test/bin/wirepup "${repository}"
    grep -Fq 'not accessible to the invoking user' "${scratch}/failure.log"
    bash tools/install-wirepup.bash apply bin/wirepup.previous "${system_prefix}/bin/wirepup" "${repository}"
    cmp bin/wirepup.previous "${system_prefix}/bin/wirepup"
    [[ "$(stat -c '%u:%a' "${system_prefix}/bin/wirepup")" == 0:755 ]]
    expect_failure bash tools/install-wirepup.bash apply bin/wirepup "${system_prefix}/bin/wirepup" "${repository}" < /dev/null
    grep -Fq 'destination already exists' "${scratch}/failure.log"
    cmp bin/wirepup.previous "${system_prefix}/bin/wirepup"
    INSTALL_FORCE=1 bash tools/install-wirepup.bash apply bin/wirepup "${system_prefix}/bin/wirepup" "${repository}" < /dev/null
    cmp bin/wirepup "${system_prefix}/bin/wirepup"
    completion="${system_prefix}/share/bash-completion/completions/wirepup"
    cmp completions/wirepup.bash "${completion}"
    [[ "$(stat -c '%u:%a' "${completion}")" == 0:644 ]]
    completion_digest="$(sha256sum completions/wirepup.bash)"
    completion_digest="${completion_digest%% *}"
    expect_failure sudo -n /bin/bash -p tools/install-system-wirepup.bash --completion "${completion}" "${completion_digest}" < completions/wirepup.bash
    grep -Fq 'replacement was not approved' "${scratch}/failure.log"
    expect_failure sudo -n /bin/bash -p tools/install-system-wirepup.bash --completion "${completion}" "${completion_digest}" 1 < /dev/null
    grep -Fq 'no file bytes' "${scratch}/failure.log"
    cmp completions/wirepup.bash "${completion}"
    expect_failure sudo -n /bin/bash -p tools/install-system-wirepup.bash "${system_prefix}/bin/wirepup" "${digest}" < bin/wirepup
    grep -Fq 'replacement was not approved' "${scratch}/failure.log"
    cmp bin/wirepup "${system_prefix}/bin/wirepup"
    PATH="${system_prefix}/bin:${PATH}" bash tools/install-wirepup.bash check bin/wirepup "${system_prefix}/bin/wirepup" "${repository}"
    expect_failure sudo -n bash tools/install-wirepup.bash check bin/wirepup "${system_prefix}/bin/wirepup" "${repository}"
    grep -Fq 'normal user' "${scratch}/failure.log"
    python3 tests/completion.py "${system_prefix}/bin/wirepup" "${completion}"
    expect_failure sudo -n /bin/bash -p tools/install-system-wirepup.bash "${system_prefix}/bin/wirepup" "${digest}" 1 < /dev/null
    grep -Fq 'no file bytes' "${scratch}/failure.log"
    cmp bin/wirepup "${system_prefix}/bin/wirepup"
    printf '%s\n' 'incomplete executable' > "${scratch}/truncated"
    expect_failure sudo -n /bin/bash -p tools/install-system-wirepup.bash "${system_prefix}/bin/wirepup" "${digest}" 1 < "${scratch}/truncated"
    grep -Fq 'copied bytes differ' "${scratch}/failure.log"
    cmp bin/wirepup "${system_prefix}/bin/wirepup"
    sudo -n chmod g+w "${system_prefix}"
    expect_failure sudo -n /bin/bash -p tools/install-system-wirepup.bash "${system_prefix}/bin/wirepup" "${digest}" 1 < bin/wirepup
    grep -Fq 'writable by group or others' "${scratch}/failure.log"
    sudo -n chmod g-w "${system_prefix}"
    cmp bin/wirepup "${system_prefix}/bin/wirepup"
    [[ -z "$(find "${system_prefix}" -name '.wirepup.*' -print)" ]]
    python3 tests/install-confirmation.py --system "${system_prefix}"
    sudo -n unshare --mount --propagation private /usr/bin/python3 -I tests/install-confirmation.py --noexec "${system_prefix}" "$(id -un)"
    printf '%s\n' 'PASS: real sudo copy, root ownership, mode, empty-input preservation, and unsafe-parent refusal'
fi

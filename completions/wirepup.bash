# Bash completion for WirePup. Source this file; do not execute it.
# Only fixed help invocations, sysfs interface names, and local paths are read.

# Decode shell quoting as text without evaluating substitutions or expansions.
function _wirepup_unquote {
    local input="${1}" char quote="" escaped=0 i
    REPLY=""
    for ((i = 0; i < ${#input}; i++)); do
        char="${input:i:1}"
        if ((escaped)); then
            if [[ "${quote}" == '"' && "${char}" != [\$\`\"\\] ]]; then
                REPLY+="\\"
            fi
            REPLY+="${char}"
            escaped=0
        elif [[ "${char}" == \\ && "${quote}" != "'" ]]; then
            escaped=1
        elif [[ -n "${quote}" ]]; then
            if [[ "${char}" == "${quote}" ]]; then quote=""; else REPLY+="${char}"; fi
        elif [[ "${char}" == '"' || "${char}" == "'" ]]; then
            quote="${char}"
        else
            REPLY+="${char}"
        fi
    done
    if ((escaped)); then REPLY+="\\"; fi
    return 0
}

function _wirepup {
    local executable="${COMP_WORDS[0]}" line word name kind cur value option=""
    local i last start=2 positional=0 pending="" join=0 end_options=0 prefix="" needle candidate
    local assignment="" trim="" REPLY="" file_argument=0
    local -a words=() commands=() children=() path=() flags=() candidates=()
    local -A takes_value=()
    local command_line='^  ([a-z][a-z-]*)[[:space:]]+'
    local flag_line='^  -([a-z][a-z-]*)([[:space:]]+([a-z]+))?[[:space:]]*$'
    COMPREPLY=()

    # Bash splits '=' and ':' by default. Reassemble them for option context;
    # trim the corresponding prefix from replies at the Readline boundary.
    for ((i = 0; i <= COMP_CWORD; i++)); do
        word="${COMP_WORDS[i]}"
        last=$((${#words[@]} - 1))
        if [[ ( "${word}" == = || "${word}" == : ) && ${last} -ge 0 ]]; then
            words[last]+="${word}"
            trim="${words[last]}"
            join=1
        elif ((join)); then
            words[last]+="${word}"
            join=0
        else
            words+=("${word}")
            trim=""
        fi
    done
    last=$((${#words[@]} - 1))
    for ((i = 1; i <= last; i++)); do
        _wirepup_unquote "${words[i]}"
        words[i]="${REPLY}"
    done
    cur="${words[last]}"
    _wirepup_unquote "${trim}"
    trim="${REPLY}"

    while IFS= read -r line; do
        if [[ "${line}" =~ ${command_line} ]]; then commands+=("${BASH_REMATCH[1]}"); fi
    done < <("${executable}" help 2>/dev/null)
    ((${#commands[@]})) || return 0
    if ((last == 1)); then
        candidates=("${commands[@]}" help -h --help)
        for candidate in "${candidates[@]}"; do
            if [[ "${candidate}" == "${cur}"* ]]; then COMPREPLY+=("${candidate}"); fi
        done
        return 0
    fi
    for name in "${commands[@]}"; do
        if [[ "${words[1]}" == "${name}" ]]; then path=("${name}"); break; fi
    done
    ((${#path[@]})) || return 0
    [[ "${path[0]}" != version ]] || return 0
    if [[ "${path[0]}" == epics ]]; then
        while IFS= read -r line; do
            if [[ "${line}" == 'usage: wirepup epics <'* ]]; then
                line="${line#*<}"; line="${line%%>*}"
                IFS='|' read -r -a children <<< "${line}"
            fi
        done < <("${executable}" epics 2>&1)
        if ((last == 2)); then
            for candidate in "${children[@]}"; do
                if [[ "${candidate}" == "${cur}"* ]]; then COMPREPLY+=("${candidate}"); fi
            done
            return 0
        fi
        for name in "${children[@]}"; do
            if [[ "${words[2]}" == "${name}" ]]; then path+=("${name}"); break; fi
        done
        ((${#path[@]} == 2)) || return 0
        start=3
    fi

    # Read arity from Go's real FlagSet output, never from the typed arguments.
    while IFS= read -r line; do
        if [[ "${line}" =~ ${flag_line} ]]; then
            name="${BASH_REMATCH[1]}"; kind="${BASH_REMATCH[3]:-}"
            takes_value[${name}]="${kind}"
            if [[ ${#name} == 1 || ( "${cur}" == -?* && "${cur}" != --* ) ]]; then
                flags+=("-${name}")
            else
                flags+=("--${name}")
            fi
        fi
    done < <("${executable}" "${path[@]}" --help 2>&1)
    takes_value[h]=""; takes_value[help]=""
    flags+=(-h --help)
    for ((i = start; i < last; i++)); do
        word="${words[i]}"
        if [[ -n "${pending}" ]]; then pending=""; continue; fi
        if [[ ${end_options} == 0 && "${word}" == -- ]]; then end_options=1; continue; fi
        if [[ ${end_options} == 0 && "${word}" == -* ]]; then
            name="${word#-}"; name="${name#-}"; name="${name%%=*}"
            [[ "${name}" =~ ^[a-z][a-z-]*$ ]] || return 0
            [[ ${takes_value[${name}]+present} ]] || return 0
            if [[ "${word}" != *=* && -n "${takes_value[${name}]}" ]]; then pending="${name}"; fi
        else
            case "${path[*]}" in
                read|diagnose|'epics diagnose'|'epics find'|connect|disconnect) positional=$((positional + 1)) ;;
                *) return 0 ;;
            esac
            ((positional <= 1)) || return 0
        fi
    done
    value="${cur}"
    if [[ -n "${pending}" ]]; then
        option="${pending}"
    elif [[ ${end_options} == 0 && "${cur}" == -*=* ]]; then
        name="${cur%%=*}"; name="${name#-}"; name="${name#-}"
        [[ "${name}" =~ ^[a-z][a-z-]*$ ]] || return 0
        [[ ${takes_value[${name}]+present} ]] || return 0
        option="${name}"
        value="${cur#*=}"
        assignment="${cur%%=*}="
        if [[ -z "${takes_value[${name}]}" ]]; then candidates=(true false); fi
    elif [[ ${end_options} == 0 && "${cur}" == -* ]]; then
        for candidate in "${flags[@]}"; do
            if [[ "${candidate}" == "${cur}"* ]]; then COMPREPLY+=("${candidate}"); fi
        done
        return 0
    elif [[ "${path[*]}" == read && ${positional} == 0 ]]; then
        option=pcap
        file_argument=1
    else
        return 0
    fi

    # These finite protocol values are checked against the CLI in the tests.
    case "${option}" in
        protocol) candidates=(frame arp lldp ipv4 dhcp ipv6 ndp tcp ca pva) ;;
        search) candidates=(ca pva) ;;
        i|interface)
            for name in /sys/class/net/*; do
                [[ -e "${name}" ]] || continue
                candidates+=("${name##*/}")
            done
            ;;
    esac
    case "${option}:${path[*]}" in
        protocol:*|search:*|i:diagnose|interface:diagnose|'i:epics diagnose'|'interface:epics diagnose'|pcap:diagnose|'pcap:epics diagnose')
            if [[ "${value}" == *,* ]]; then prefix="${value%,*},"; value="${value##*,}"; fi
            ;;
    esac
    needle="${value}"
    case "${option}" in
        pcap|o|output|oui-file)
            if [[ "${needle}" == \~/* ]]; then needle="${HOME}/${needle:2}"; fi
            mapfile -t candidates < <(compgen -f -- "${needle}")
            # compopt is available only while Readline is completing.
            compopt -o filenames 2>/dev/null || :
            for ((i = 0; i < ${#candidates[@]}; i++)); do
                if [[ -d "${candidates[i]}" ]]; then candidates[i]+=/; fi
            done
            ;;
    esac
    for candidate in "${candidates[@]}"; do
        [[ "${candidate}" == "${needle}"* ]] || continue
        case "${option}" in
            protocol|search|i|interface)
                [[ ",${prefix}" != *",${candidate},"* ]] || continue
                ;;
        esac
        # The CLI treats dash-prefixed filenames as flags even after '--'.
        # Readline can insert './' only when it is replacing the whole word.
        if ((file_argument)) && [[ "${candidate}" == -* ]]; then
            [[ -z "${trim}" ]] || continue
            candidate="./${candidate}"
        fi
        candidate="${assignment}${prefix}${candidate}"
        COMPREPLY+=("${candidate#"${trim}"}")
    done
    return 0
}

complete -F _wirepup wirepup

# bash completion for aman

_aman() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Main commands
    opts="help version periksa periksa-all periksa-security update serve"

    # Subcommands
    case "${prev}" in
        periksa)
            opts="--jenis --sasaran --format --online --help"
            ;;
        periksa-all|scan-all)
            opts="--format --json --help"
            ;;
        periksa-security)
            opts="--format --json --help"
            ;;
        update)
            opts="--cve --self --all --help"
            ;;
        serve)
            opts="--port --host --help"
            ;;
        --jenis)
            opts="folder docker web"
            ;;
        --format|--json)
            opts="text json"
            ;;
        --online)
            opts="true false"
            ;;
        help|--help|-h)
            opts=""
            ;;
        *)
            ;;
    esac

    # Complete options
    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi

    # Complete main commands
    if [[ ${COMP_CWORD} == 1 ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi

    # Complete targets (common paths)
    if [[ "${prev}" == "--sasaran" ]] ; then
        _filedir
        return 0
    fi
}

# Register completion
complete -F _aman aman

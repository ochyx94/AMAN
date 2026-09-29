# zsh completion for aman

_aman() {
    local -a commands
    commands=(
        'help:Display help information'
        'version:Show version information'
        'periksa:Run vulnerability scan'
        'periksa-all:Run comprehensive server scan'
        'periksa-security:Run security scan'
        'update:Update CVE database or AMAN'
        'serve:Start web dashboard'
    )

    local -a opts
    opts=(
        '--help[Show help]'
        '--version[Show version]'
    )

    local -a scan_opts
    scan_opts=(
        '--jenis[Scan type]:(folder docker web)'
        '--sasaran[Target path or URL]'
        '--format[Output format]:(text json)'
        '--online[Enable online check]'
    )

    local -a update_opts
    update_opts=(
        '--cve[Update CVE database only]'
        '--self[Update AMAN only]'
        '--all[Update everything]'
    )

    local -a serve_opts
    serve_opts=(
        '--port[Port number]'
        '--host[Host address]'
    )

    _arguments -s \
        ${opts[@]} \
        ${scan_opts[@]} \
        ${update_opts[@]} \
        ${serve_opts[@]} \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            _describe 'commands' commands
            ;;
        args)
            case $words[1] in
                periksa)
                    _describe 'scan options' scan_opts
                    ;;
                update)
                    _describe 'update options' update_opts
                    ;;
                serve)
                    _describe 'serve options' serve_opts
                    ;;
            esac
            ;;
    esac
}

_aman "$@"

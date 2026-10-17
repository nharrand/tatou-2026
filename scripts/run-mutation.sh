#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
    echo "Expected one scope or session command. Run make help for usage." >&2
    exit 2
fi

scope="${1:-all}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "$scope" in
    pause|resume)
        exec "$script_dir/../server/.venv/bin/python" "$script_dir/mutation-session.py" "$scope" ;;
    help|-h|--help)
        echo "Use make help for the supported commands."
        exit 0 ;;
    all) set -- ;;
    backend) set -- 'server.*' 'login_rate_limit.*' ;;
    francesco|davide|khaled) set -- "watermarking_methods.$scope.*" ;;
    common) set -- 'watermarking_methods.group13.*' 'watermarking_methods.add_after_eof.*' \
        'watermarking_method.*' 'watermarking_utils.*' 'watermarking_cli.*' ;;
    *) echo "Unknown command: $scope. Run make help for usage." >&2; exit 2 ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/../server"
.venv/bin/python "$script_dir/mutation-session.py" check
read -r -p "This will overwrite previous outputs in server/mutants/ and start the '$scope' campaign. Continue? [y/N] " answer
case "$answer" in
    y|Y) ;;
    *) echo "Cancelled."; exit 0 ;;
esac
rm -rf -- mutants
.venv/bin/python "$script_dir/mutation-session.py" record "$@"
export SECRET_KEY="$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
exec "$PWD/.venv/bin/mutmut" run "$@"

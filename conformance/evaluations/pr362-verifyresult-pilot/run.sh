#!/bin/sh
set -eu

PACKAGE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}

usage() {
    echo "usage:" >&2
    echo "  $0 verify-historical <candidate-checkout>" >&2
    echo "  $0 reproduce <candidate-checkout> <new-output-directory>" >&2
    echo "  $0 verify-bundle <bundle-directory> [candidate-checkout]" >&2
    exit 2
}

[ "$#" -ge 2 ] || usage
MODE=$1

case "$MODE" in
    verify-historical)
        [ "$#" -eq 2 ] || usage
        CANDIDATE=$2
        exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
            "$PACKAGE_ROOT/runner/eval_pr362.py" \
            --candidate "$CANDIDATE" \
            --cases "$PACKAGE_ROOT/cases.json" \
            --verify-historical-result "$PACKAGE_ROOT/historical/results.json" \
            --historical-harness "$PACKAGE_ROOT/historical/eval_pr362.py"
        ;;
    reproduce)
        [ "$#" -eq 3 ] || usage
        CANDIDATE=$2
        exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
            "$PACKAGE_ROOT/runner/eval_pr362.py" \
            --candidate "$CANDIDATE" \
            --cases "$PACKAGE_ROOT/cases.json" \
            --output-dir "$3"
        ;;
    verify-bundle)
        [ "$#" -eq 2 ] || [ "$#" -eq 3 ] || usage
        if [ "$#" -eq 3 ]; then
            exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
                "$PACKAGE_ROOT/runner/eval_pr362.py" \
                --candidate "$3" \
                --cases "$PACKAGE_ROOT/cases.json" \
                --bundle-dir "$2"
        fi
        exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
            "$PACKAGE_ROOT/runner/eval_pr362.py" \
            --cases "$PACKAGE_ROOT/cases.json" \
            --bundle-dir "$2"
        ;;
    *)
        usage
        ;;
esac

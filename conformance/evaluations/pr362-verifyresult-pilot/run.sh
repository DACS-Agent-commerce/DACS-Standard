#!/bin/sh
set -eu

PACKAGE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}

usage() {
    echo "usage:" >&2
    echo "  $0 verify-historical <candidate-checkout>" >&2
    echo "  $0 reproduce <candidate-checkout> <new-output-directory>" >&2
    echo "  $0 verify-portable <candidate-checkout> <results.json>" >&2
    exit 2
}

[ "$#" -ge 2 ] || usage
MODE=$1
CANDIDATE=$2

case "$MODE" in
    verify-historical)
        [ "$#" -eq 2 ] || usage
        exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
            "$PACKAGE_ROOT/runner/eval_pr362.py" \
            --candidate "$CANDIDATE" \
            --cases "$PACKAGE_ROOT/cases.json" \
            --verify-results "$PACKAGE_ROOT/historical/results.json" \
            --historical-harness "$PACKAGE_ROOT/historical/eval_pr362.py"
        ;;
    reproduce)
        [ "$#" -eq 3 ] || usage
        exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
            "$PACKAGE_ROOT/runner/eval_pr362.py" \
            --candidate "$CANDIDATE" \
            --cases "$PACKAGE_ROOT/cases.json" \
            --output-dir "$3"
        ;;
    verify-portable)
        [ "$#" -eq 3 ] || usage
        exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
            "$PACKAGE_ROOT/runner/eval_pr362.py" \
            --candidate "$CANDIDATE" \
            --cases "$PACKAGE_ROOT/cases.json" \
            --verify-results "$3"
        ;;
    *)
        usage
        ;;
esac

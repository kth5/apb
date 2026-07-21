#!/usr/bin/env bash
# Run APB integration tests in a project virtualenv.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${APB_VENV:-$ROOT_DIR/.venv}"
PYTHON="$VENV_DIR/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  echo "Creating virtualenv at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

echo "Using Python: $PYTHON"
"$PYTHON" -m pip install -q -U pip
"$PYTHON" -m pip install -q -e "$ROOT_DIR[dev]"

export APB_INTEGRATION=1
cd "$ROOT_DIR"
exec "$PYTHON" -m pytest -m integration "$@"

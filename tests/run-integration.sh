#!/usr/bin/env bash
# Run APB integration tests in a project virtualenv with multipart>=1.3 available.
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

if ! "$PYTHON" -c "import importlib.metadata as m; import multipart; version = tuple(int(part) for part in m.version('multipart').split('.')[:2]); assert version >= (1, 3); assert multipart.MultipartParser"; then
  echo "multipart>=1.3 is still unavailable in $VENV_DIR" >&2
  exit 1
fi

export APB_INTEGRATION=1
cd "$ROOT_DIR"
exec "$PYTHON" -m pytest -m integration "$@"

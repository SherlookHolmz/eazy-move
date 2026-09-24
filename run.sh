#!/usr/bin/env bash
set -Eeuo pipefail
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV="${BASE_DIR}/.venv"
APP="${BASE_DIR}/pasarguard_manager.py"

if [[ ! -x "${VENV}/bin/python" ]]; then
  echo "[ERROR] The project is not installed yet. Run: sudo bash install.sh"
  exit 1
fi
if [[ ! -f "$APP" ]]; then
  echo "[ERROR] pasarguard_manager.py was not found."
  exit 1
fi

exec "${VENV}/bin/python" "$APP" "$@"

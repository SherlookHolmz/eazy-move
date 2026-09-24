#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/SherlookHolmz/eazy-move.git"
INSTALL_DIR="/opt/eazy-move"
APP="pasarguard_manager.py"
VENV="${INSTALL_DIR}/.venv"

info(){ printf '\033[1;36m[INFO]\033[0m %s\n' "$*"; }
ok(){ printf '\033[1;32m[ OK ]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
err(){ printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; }
trap 'err "Installation failed at line $LINENO."' ERR

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  err "Run as root: sudo bash install.sh"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

if ! command -v apt-get >/dev/null 2>&1; then
  err "This installer supports Ubuntu/Debian only."
  exit 1
fi

info "Installing system prerequisites..."
apt-get update -y >/dev/null
apt-get install -y ca-certificates curl git openssh-client python3 python3-venv python3-pip >/dev/null

if ! command -v docker >/dev/null 2>&1; then
  info "Docker not found. Installing Docker..."
  if apt-cache show docker.io >/dev/null 2>&1; then
    apt-get install -y docker.io >/dev/null
  else
    curl -fsSL https://get.docker.com | sh
  fi
fi
systemctl enable --now docker >/dev/null 2>&1 || true

if ! docker compose version >/dev/null 2>&1; then
  info "Docker Compose plugin not found. Installing..."
  if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
    apt-get install -y docker-compose-v2 >/dev/null
  elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
    apt-get install -y docker-compose-plugin >/dev/null
  else
    curl -fsSL https://get.docker.com | sh
  fi
fi

evaluate_source_dir(){
  local here
  here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "${here}/${APP}" && -f "${here}/requirements.txt" ]]; then
    printf '%s\n' "$here"
    return 0
  fi
  return 1
}

SOURCE_DIR=""
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
# Only use local project files when this is a real script file executed from
# a TTY. With "curl ... | sudo bash", BASH_SOURCE may be empty, while the
# current directory can still contain an old checkout. Never use that as
# the source for a piped install.
if [[ -t 0 && -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]] && SOURCE_DIR="$(evaluate_source_dir 2>/dev/null)"; then
  info "Using the local project files."
else
  info "Downloading the project from GitHub..."
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    git -C "$INSTALL_DIR" fetch --depth=1 origin main
    git -C "$INSTALL_DIR" reset --hard origin/main
  else
    rm -rf "$INSTALL_DIR"
    git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
  fi
  SOURCE_DIR="$INSTALL_DIR"
fi

if [[ ! -f "${SOURCE_DIR}/${APP}" ]]; then
  err "${APP} is missing from the project. Upload the project files to the repository first."
  exit 1
fi

# Keep a stable installation location even when install.sh was run from a clone elsewhere.
if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
  mkdir -p "$INSTALL_DIR"
  cp -a "$SOURCE_DIR/." "$INSTALL_DIR/"
  SOURCE_DIR="$INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR"
info "Creating isolated Python environment..."
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip >/dev/null
"$VENV/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt" >/dev/null

chmod +x "$INSTALL_DIR/${APP}" "$INSTALL_DIR/run.sh" 2>/dev/null || true

ok "PasarGuard Manager is ready."
echo
echo "Run it with:"
echo "  sudo ${INSTALL_DIR}/run.sh"
echo
echo "Or simply run the installer again anytime to update it."
echo

# Do not start the interactive application when install.sh receives its stdin from a pipe.
# This is the normal case for: curl ... | sudo bash
if [[ -t 0 ]]; then
  exec "$INSTALL_DIR/run.sh" "$@"
fi

info "Installation completed. Interactive launch was skipped because stdin is not a TTY."
echo "Run it with: sudo $INSTALL_DIR/run.sh"

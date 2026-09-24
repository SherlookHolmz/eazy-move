#!/usr/bin/env python3
"""
PasarGuard Manager
------------------
Migration/backup utility for PasarGuard Panel + PasarGuard Node.

Author: Sherlook
Project: PasarGuard Manager
Version: 2.0.3

Goals:
- Safe local backup/restore
- Remote migration over SSH/SFTP
- PostgreSQL/TimescaleDB, MySQL/MariaDB, and SQLite detection
- NATS named-volume capture when present
- Caddy/reverse-proxy and external certificate capture
- SHA-256 archive verification
- Terminal-first CLI with interactive fallback
- No automatic modification of SSL configuration during restore
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import http.client
import json
import os
import re
import shutil
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
import zipfile
from pathlib import Path
from typing import Iterable, Optional

try:
    import paramiko
except ImportError as exc:
    print("ERROR: Paramiko is required. Install it with: python3 -m pip install -r requirements.txt")
    raise SystemExit(2) from exc


APP_NAME = "PasarGuard Manager"
VERSION = "2.0.3"
AUTHOR = "Sherlook"

PASARGUARD_DIR = Path("/opt/pasarguard")
PG_NODE_DIR = Path("/opt/pg-node")
PASARGUARD_DATA_DIR = Path("/var/lib/pasarguard")
PG_NODE_DATA_DIR = Path("/var/lib/pg-node")

DEFAULT_BACKUP_DIR = Path.cwd()
DEFAULT_REMOTE_DIR = Path("/tmp/pasarguard-manager")

COMPOSE_DOWN_TIMEOUT = 30
SERVICE_READY_TIMEOUT = 180
STACK_READY_TIMEOUT = 180
DATABASE_RESTORE_TIMEOUT = 3600
SSH_TIMEOUT = 30
SSH_BANNER_TIMEOUT = 30
SFTP_CHUNK = 1024 * 1024
FILE_COPY_CHUNK = 1024 * 1024

POSTGRES_CANDIDATES = ("timescaledb", "postgresql", "postgres")
MYSQL_CANDIDATES = ("mysql", "mariadb")

CERT_PATH_REGEX = re.compile(
    r"(/(?:[\w.\-+~]+/)+[\w.\-+~]+\.(?:pem|crt|key|cer))",
    re.IGNORECASE,
)

SQL_DIALECTS = {
    "postgres": ("postgresql", "postgres"),
    "mysql": ("mysql", "mariadb"),
    "sqlite": ("sqlite",),
}


class C:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


if not supports_color():
    for _name in ("HEADER", "BLUE", "CYAN", "GREEN", "YELLOW", "RED", "RESET", "BOLD"):
        setattr(C, _name, "")


def info(msg: str) -> None:
    print(f"{C.BLUE}ℹ️  [INFO]{C.RESET} {msg}")


def success(msg: str) -> None:
    print(f"{C.GREEN}✅ [SUCCESS]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}⚠️  [WARNING]{C.RESET} {msg}")


def error(msg: str) -> None:
    print(f"{C.RED}❌ [ERROR]{C.RESET} {msg}")


def header(title: str) -> None:
    line = "=" * 72
    print(f"\n{C.HEADER}{C.BOLD}{line}{C.RESET}")
    print(f"{C.HEADER}{C.BOLD}{title.center(72)}{C.RESET}")
    print(f"{C.HEADER}{C.BOLD}{line}{C.RESET}\n")


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    value = input(f"{C.CYAN}{prompt} [{suffix}]: {C.RESET}").strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}


def fmt_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(FILE_COPY_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ensure_root() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        error("This utility must run as root on the source/local server.")
        print("Run: sudo python3 pasarguard_manager.py")
        return False
    return True


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_local(
    args: list[str],
    *,
    cwd: Optional[Path] = None,
    stdin=None,
    capture: bool = True,
    check: bool = False,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        stdin=stdin,
        capture_output=capture,
        text=True,
        check=check,
        timeout=timeout,
    )


def shell_local(
    command: str,
    *,
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired as exc:
        return 124, "", f"timeout: {exc}"


def ssh_shell(client: paramiko.SSHClient, command: str, timeout: int = SSH_TIMEOUT) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    channel = stdout.channel
    channel.settimeout(timeout)
    try:
        code = channel.recv_exit_status()
        out = stdout.read().decode("utf-8", "replace").strip()
        err = stderr.read().decode("utf-8", "replace").strip()
        return code, out, err
    except socket.timeout:
        return 124, "", "SSH command timed out"


def ssh_run_checked(
    client: paramiko.SSHClient,
    command: str,
    description: str,
    *,
    required: bool = True,
    timeout: int = SSH_TIMEOUT,
) -> bool:
    print(f"{C.CYAN}🌐 [SSH]{C.RESET} {description}...")
    code, out, err = ssh_shell(client, command, timeout=timeout)
    if code == 0:
        success("Done.")
        return True
    error(f"Command failed ({code}).")
    if err:
        error(err)
    elif out:
        error(out)
    return not required


def env_read(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        result[key] = value
    return result


def env_get(path: Path, key: str, default: Optional[str] = None) -> Optional[str]:
    return env_read(path).get(key, default)


def env_set(path: Path, key: str, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text(errors="replace").splitlines() if path.exists() else []
    found = False
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            current = stripped.split("=", 1)[0].strip()
            if current == key:
                out.append(f'{key}="{value}"')
                found = True
                continue
        out.append(line)
    if not found:
        out.append(f'{key}="{value}"')
    path.write_text("\n".join(out) + "\n")
    os.chmod(path, 0o600)


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def mysql_literal(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def pg_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def pg_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def parse_database_url(url: str) -> dict[str, Optional[str]]:
    parsed = urllib.parse.urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    family = "sqlite" if scheme.startswith("sqlite") else (
        "postgres" if scheme.startswith("postgres") else (
            "mysql" if scheme.startswith(("mysql", "mariadb")) else "unknown"
        )
    )
    user = urllib.parse.unquote(parsed.username) if parsed.username else None
    password = urllib.parse.unquote(parsed.password) if parsed.password else None
    db_name = urllib.parse.unquote(parsed.path.lstrip("/")) if parsed.path else None
    return {
        "family": family,
        "user": user,
        "password": password,
        "database": db_name,
        "host": parsed.hostname,
        "port": str(parsed.port) if parsed.port else None,
    }


def read_db_config(compose_dir: Path) -> dict[str, Optional[str]]:
    env = env_read(compose_dir / ".env")
    url = env.get("SQLALCHEMY_DATABASE_URL")
    if url:
        cfg = parse_database_url(url)
        if cfg["family"] != "unknown":
            return cfg

    # Compatibility with older PasarGuard installations that used DB_*.
    db_user = env.get("DB_USER") or env.get("MYSQL_USER") or env.get("POSTGRES_USER") or "pasarguard"
    db_name = env.get("DB_NAME") or env.get("MYSQL_DATABASE") or env.get("POSTGRES_DB") or "pasarguard"
    service = "unknown"

    if env.get("DATABASE") in {"sqlite", "sqlite3"}:
        service = "sqlite"
    return {
        "family": service,
        "user": db_user,
        "password": env.get("DB_PASSWORD") or env.get("MYSQL_PASSWORD") or env.get("POSTGRES_PASSWORD"),
        "database": db_name,
        "host": None,
        "port": None,
    }


def list_compose_services(compose_dir: Path) -> list[str]:
    code, out, _ = shell_local("docker compose config --services", cwd=compose_dir)
    if code != 0:
        return []
    return [x.strip() for x in out.splitlines() if x.strip()]


def list_compose_volumes(compose_dir: Path) -> list[str]:
    code, out, _ = shell_local("docker compose config --volumes", cwd=compose_dir)
    if code != 0:
        return []
    return [x.strip() for x in out.splitlines() if x.strip()]


def resolve_db_service(compose_dir: Path, family: str) -> Optional[str]:
    services = list_compose_services(compose_dir)
    candidates = POSTGRES_CANDIDATES if family == "postgres" else MYSQL_CANDIDATES
    for name in candidates:
        if name in services:
            return name

    # Fallback: inspect service images.
    code, out, _ = shell_local(
        "docker compose config --format json",
        cwd=compose_dir,
    )
    if code == 0 and out:
        try:
            data = json.loads(out)
            for name, service in (data.get("services") or {}).items():
                image = str(service.get("image") or "").lower()
                if family == "postgres" and ("postgres" in image or "timescale" in image):
                    return name
                if family == "mysql" and ("mysql" in image or "mariadb" in image):
                    return name
        except json.JSONDecodeError:
            pass
    return None


def detect_db_family(compose_dir: Path) -> str:
    cfg = read_db_config(compose_dir)
    if cfg["family"] in {"postgres", "mysql", "sqlite"}:
        return str(cfg["family"])

    services = list_compose_services(compose_dir)
    if any(x in services for x in POSTGRES_CANDIDATES):
        return "postgres"
    if any(x in services for x in MYSQL_CANDIDATES):
        return "mysql"

    return "unknown"


def capture_postgres_runtime(compose_dir: Path, service: str) -> dict[str, object]:
    """Capture the exact PostgreSQL/TimescaleDB runtime used by the source backup."""
    runtime: dict[str, object] = {"service": service}

    code, out, err = shell_local(
        f"docker compose ps -q {shlex.quote(service)}",
        cwd=compose_dir,
        timeout=30,
    )
    container_id = out.strip().splitlines()[0] if code == 0 and out.strip() else ""
    if not container_id:
        raise RuntimeError(err or "Could not find the running database container.")

    # RepoDigests belongs to the IMAGE inspect object, not the CONTAINER
    # inspect object. Older versions of this code queried it from
    # \`docker inspect <container>\`, which fails with:
    # template: :1:25: executing "" at <.RepoDigests>: map has no entry for key "RepoDigests"
    # Get the configured image from the container first, then inspect that image.
    inspect_cmd = (
        "docker inspect -f '{{.Config.Image}}' "
        f"{shlex.quote(container_id)}"
    )
    code, image, err = shell_local(inspect_cmd, timeout=30)
    image = image.strip()
    if code != 0 or not image:
        raise RuntimeError(err or "Could not determine the source database image.")
    runtime["image"] = image

    digest_cmd = (
        "docker image inspect -f '{{join .RepoDigests \",\"}}' "
        f"{shlex.quote(image)}"
    )
    code, digests, err = shell_local(digest_cmd, timeout=30)
    if code == 0 and digests.strip():
        runtime["repo_digests"] = [x for x in digests.strip().split(",") if x]
    else:
        # A local/private/dangling image may have no RepoDigests. This is not
        # fatal because Compose can still restore the image from its tag.
        runtime["repo_digests"] = []

    # Only require TimescaleDB when it is actually installed in the
    # source database. PostgreSQL itself is a supported PasarGuard backend.
    code, out, err = db_exec_local(
        compose_dir,
        service,
        'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres '
        "-Atc \"SELECT COALESCE((SELECT extversion || '|' || n.nspname "
        "FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace "
        "WHERE e.extname='timescaledb'), '');\"",
    )
    if code != 0:
        raise RuntimeError(err or out or "Could not detect the source TimescaleDB version.")

    value = out.strip().splitlines()[0].strip() if out.strip() else ""
    if value:
        parts = value.split("|", 1)
        version = parts[0].strip()
        schema = parts[1].strip() if len(parts) > 1 else "public"
        if version:
            runtime["timescaledb_version"] = version
            runtime["timescaledb_schema"] = schema or "public"

    return runtime


def is_special(path: Path) -> Optional[str]:
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return None
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISCHR(mode):
        return "char-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return None


def copy_tree_safe(src: Path, dst: Path) -> tuple[bool, list[tuple[str, str]], list[tuple[str, str]]]:
    """
    Copy a directory without ever trying to read sockets/FIFOs/devices.
    Returns (ok, skipped_special, failed).
    """
    skipped: list[tuple[str, str]] = []
    failed: list[tuple[str, str]] = []
    if not src.exists():
        return True, [], []

    dst.mkdir(parents=True, exist_ok=True)

    for root, dirs, files in os.walk(src, topdown=True, followlinks=False):
        root_p = Path(root)
        rel = root_p.relative_to(src)
        out_root = dst / rel
        out_root.mkdir(parents=True, exist_ok=True)

        # Preserve directory symlinks by replacing the traversed directory entry.
        kept_dirs = []
        for d in dirs:
            s = root_p / d
            if s.is_symlink():
                d_target = os.readlink(s)
                t = out_root / d
                try:
                    if t.exists() or t.is_symlink():
                        t.unlink()
                    os.symlink(d_target, t)
                except OSError as exc:
                    failed.append((str(s), str(exc)))
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for name in files:
            s = root_p / name
            t = out_root / name
            reason = is_special(s)
            if reason:
                skipped.append((str(s), reason))
                continue
            try:
                if s.is_symlink():
                    if t.exists() or t.is_symlink():
                        t.unlink()
                    os.symlink(os.readlink(s), t)
                else:
                    shutil.copy2(s, t, follow_symlinks=False)
            except OSError as exc:
                failed.append((str(s), str(exc)))
    return not failed, skipped, failed


def zip_add_tree(zf: zipfile.ZipFile, src: Path, arc_prefix: str) -> None:
    """
    Add tree contents while preserving regular-file data and symlink targets.
    Special runtime nodes were already excluded by copy_tree_safe.
    """
    if not src.exists():
        return
    for path in src.rglob("*"):
        rel = path.relative_to(src)
        arc = Path(arc_prefix) / rel
        if path.is_dir() and not path.is_symlink():
            zf.writestr(str(arc).rstrip("/") + "/", b"")
        elif path.is_symlink():
            info = zipfile.ZipInfo(str(arc))
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, os.readlink(path).encode())
        elif path.is_file():
            zf.write(path, str(arc))


def safe_extract_zip(zip_path: Path, destination: Path) -> None:
    destination = destination.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        bad = zf.testzip()
        if bad:
            raise RuntimeError(f"ZIP CRC check failed for member: {bad}")

        members = list(zf.infolist())

        # Pass 1: create directories and regular files. Symlinks are delayed so a
        # malicious link cannot redirect a later member outside the extraction root.
        for member in members:
            target = (destination / member.filename).resolve()
            if os.path.commonpath([str(destination), str(target)]) != str(destination):
                raise RuntimeError(f"Unsafe ZIP member path: {member.filename}")

            mode = (member.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                continue
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member, "r") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=FILE_COPY_CHUNK)
            # Restore executable/read-only bits when present.
            file_mode = stat.S_IMODE(mode)
            if file_mode:
                try:
                    os.chmod(target, file_mode)
                except OSError:
                    pass

        # Pass 2: recreate symlinks.
        for member in members:
            mode = (member.external_attr >> 16) & 0xFFFF
            if not stat.S_ISLNK(mode):
                continue
            link_path = destination / member.filename
            link_path.parent.mkdir(parents=True, exist_ok=True)
            target_text = zf.read(member).decode("utf-8")
            if link_path.exists() or link_path.is_symlink():
                link_path.unlink()
            os.symlink(target_text, link_path)


def validate_archive(zip_path: Path) -> dict:
    if not zip_path.is_file():
        raise FileNotFoundError(zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        if "manifest.json" not in zf.namelist():
            raise RuntimeError("This archive has no manifest.json and is not a v2 backup.")
        manifest = json.loads(zf.read("manifest.json").decode())
        if manifest.get("format") != "pasarguard-manager":
            raise RuntimeError("Unknown backup format.")
        if manifest.get("format_version") != 2:
            raise RuntimeError(f"Unsupported backup format version: {manifest.get('format_version')}")
        bad = zf.testzip()
        if bad:
            raise RuntimeError(f"ZIP integrity check failed at: {bad}")
        return manifest


def wait_local_service(compose_dir: Path, service: str, family: str, timeout: int = SERVICE_READY_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if family == "postgres":
            cmd = f"docker compose exec -T {shlex.quote(service)} pg_isready -U \"$POSTGRES_USER\" -d postgres"
        else:
            cmd = (
                f"docker compose exec -T {shlex.quote(service)} "
                f"sh -c 'mysqladmin ping -uroot -p\"$MYSQL_ROOT_PASSWORD\" --silent'"
            )
        code, _, _ = shell_local(cmd, cwd=compose_dir)
        if code == 0:
            return True
        time.sleep(2)
    return False


def wait_remote_service(client: paramiko.SSHClient, compose_dir: Path, service: str, family: str) -> bool:
    deadline = time.time() + SERVICE_READY_TIMEOUT
    while time.time() < deadline:
        if family == "postgres":
            cmd = (
                f"cd {shlex.quote(str(compose_dir))} && "
                f"docker compose exec -T {shlex.quote(service)} pg_isready "
                f"-U \"$POSTGRES_USER\" -d postgres"
            )
        else:
            cmd = (
                f"cd {shlex.quote(str(compose_dir))} && "
                f"docker compose exec -T {shlex.quote(service)} "
                f"sh -c 'mysqladmin ping -uroot -p\"$MYSQL_ROOT_PASSWORD\" --silent'"
            )
        code, _, _ = ssh_shell(client, cmd, timeout=15)
        if code == 0:
            return True
        time.sleep(2)
    return False


def compose_up_local(compose_dir: Path, services: Optional[list[str]] = None) -> bool:
    args = ["docker", "compose", "up", "-d"] + (services or [])
    p = run_local(args, cwd=compose_dir, capture=True)
    if p.returncode != 0:
        error(p.stderr or p.stdout)
        return False
    return True


def compose_down_local(compose_dir: Path) -> bool:
    p = run_local(
        ["docker", "compose", "down", "--remove-orphans", "-t", str(COMPOSE_DOWN_TIMEOUT)],
        cwd=compose_dir,
        capture=True,
    )
    if p.returncode == 0:
        return True
    warn(p.stderr or p.stdout)
    return False


def compose_ps_local(compose_dir: Path) -> str:
    code, out, err = shell_local("docker compose ps", cwd=compose_dir)
    return out or err


def compose_up_remote(client: paramiko.SSHClient, compose_dir: Path, services: Optional[list[str]] = None) -> bool:
    svc = " ".join(shlex.quote(x) for x in (services or []))
    cmd = f"cd {shlex.quote(str(compose_dir))} && docker compose up -d {svc}".strip()
    code, out, err = ssh_shell(client, cmd, timeout=60)
    if code != 0:
        error(err or out)
        return False
    return True


def compose_down_remote(client: paramiko.SSHClient, compose_dir: Path) -> bool:
    cmd = f"cd {shlex.quote(str(compose_dir))} && docker compose down --remove-orphans -t {COMPOSE_DOWN_TIMEOUT}"
    code, out, err = ssh_shell(client, cmd, timeout=60)
    if code != 0:
        warn(err or out)
        return False
    return True


def verify_stack_local(compose_dir: Path) -> bool:
    code, out, err = shell_local(
        "docker compose ps --format json",
        cwd=compose_dir,
    )
    if code != 0:
        error(err or out)
        return False
    if not out.strip():
        return False

    try:
        rows = json.loads(out)
        if isinstance(rows, dict):
            rows = [rows]
    except json.JSONDecodeError:
        # Older docker compose can return tabular output only.
        status = compose_ps_local(compose_dir)
        return "Up" in status or "running" in status.lower()

    good = True
    for row in rows:
        state = str(row.get("State") or row.get("state") or "").lower()
        health = str(row.get("Health") or row.get("health") or "").lower()
        if state not in {"running"}:
            good = False
        if health and health not in {"healthy", "running"}:
            good = False
    return good


def verify_stack_remote(client: paramiko.SSHClient, compose_dir: Path) -> bool:
    cmd = f"cd {shlex.quote(str(compose_dir))} && docker compose ps --format json"
    code, out, err = ssh_shell(client, cmd, timeout=30)
    if code != 0:
        error(err or out)
        return False
    if not out.strip():
        return False
    try:
        rows = json.loads(out)
        if isinstance(rows, dict):
            rows = [rows]
    except json.JSONDecodeError:
        return "Up" in out or "running" in out.lower()

    good = True
    for row in rows:
        state = str(row.get("State") or row.get("state") or "").lower()
        health = str(row.get("Health") or row.get("health") or "").lower()
        if state not in {"running"}:
            good = False
        if health and health not in {"healthy", "running"}:
            good = False
    return good


def ensure_target_dirs_local() -> None:
    for p in (PASARGUARD_DIR, PG_NODE_DIR, PASARGUARD_DATA_DIR, PG_NODE_DATA_DIR):
        p.mkdir(parents=True, exist_ok=True)


def clean_target_dirs_local() -> None:
    # Fixed, trusted paths only.
    for p in (PASARGUARD_DIR, PG_NODE_DIR, PASARGUARD_DATA_DIR, PG_NODE_DATA_DIR):
        if p.exists():
            shutil.rmtree(p)
        p.mkdir(parents=True, exist_ok=True)


def clean_target_dirs_remote(client: paramiko.SSHClient) -> None:
    targets = [PASARGUARD_DIR, PG_NODE_DIR, PASARGUARD_DATA_DIR, PG_NODE_DATA_DIR]
    cmd = " && ".join(f"rm -rf {shlex.quote(str(p))} && mkdir -p {shlex.quote(str(p))}" for p in targets)
    code, out, err = ssh_shell(client, cmd, timeout=60)
    if code != 0:
        raise RuntimeError(err or out or "Could not clean target directories")


def db_exec_local(compose_dir: Path, service: str, inner: str) -> tuple[int, str, str]:
    cmd = (
        f"docker compose exec -T {shlex.quote(service)} "
        f"sh -c {shell_single_quote(inner)}"
    )
    return shell_local(cmd, cwd=compose_dir)


def db_exec_remote(client: paramiko.SSHClient, compose_dir: Path, service: str, inner: str) -> tuple[int, str, str]:
    cmd = (
        f"cd {shlex.quote(str(compose_dir))} && docker compose exec -T "
        f"{shlex.quote(service)} sh -c {shell_single_quote(inner)}"
    )
    return ssh_shell(client, cmd, timeout=120)


def dump_postgres_local(compose_dir: Path, service: str, cfg: dict, dump_path: Path) -> None:
    user = cfg.get("user") or "postgres"
    db = cfg.get("database") or "pasarguard"
    command = f"pg_dump -U {shell_single_quote(user)} -d {shell_single_quote(db)}"
    code, _, err = db_exec_local(compose_dir, service, command)
    if code != 0:
        raise RuntimeError(f"pg_dump failed: {err or code}")

    # Re-run with shell redirection so the database stream lands outside the container.
    outer = (
        f"docker compose exec -T {shlex.quote(service)} "
        f"pg_dump -U {shlex.quote(user)} -d {shlex.quote(db)}"
    )
    p = subprocess.run(
        outer,
        cwd=str(compose_dir),
        shell=True,
        stdout=dump_path.open("wb"),
        stderr=subprocess.PIPE,
    )
    if p.returncode != 0:
        raise RuntimeError(f"pg_dump failed: {p.stderr.decode(errors='replace').strip()}")


def dump_mysql_local(compose_dir: Path, service: str, cfg: dict, dump_path: Path) -> None:
    db = cfg.get("database") or "pasarguard"
    dump_cmds = [
        f"mariadb-dump -uroot -p\"$MYSQL_ROOT_PASSWORD\" --databases {shlex.quote(db)}",
        f"mysqldump -uroot -p\"$MYSQL_ROOT_PASSWORD\" --databases {shlex.quote(db)}",
    ]
    last_error = ""
    for inner in dump_cmds:
        outer = (
            f"docker compose exec -T {shlex.quote(service)} "
            f"sh -c {shell_single_quote(inner)}"
        )
        p = subprocess.run(
            outer,
            cwd=str(compose_dir),
            shell=True,
            stdout=dump_path.open("wb"),
            stderr=subprocess.PIPE,
        )
        if p.returncode == 0 and dump_path.stat().st_size > 0:
            return
        last_error = p.stderr.decode(errors="replace").strip()
    raise RuntimeError(f"MySQL/MariaDB dump failed: {last_error}")


def pg_admin_sql_local(compose_dir: Path, service: str, sql: str) -> tuple[int, str, str]:
    # PostgreSQL official images expose POSTGRES_USER inside the DB container.
    inner = f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c {shell_single_quote(sql)}'
    return db_exec_local(compose_dir, service, inner)


def pg_admin_sql_remote(client: paramiko.SSHClient, compose_dir: Path, service: str, sql: str) -> tuple[int, str, str]:
    inner = f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c {shell_single_quote(sql)}'
    return db_exec_remote(client, compose_dir, service, inner)


def ensure_postgres_role_and_database_local(compose_dir: Path, service: str, cfg: dict) -> None:
    user = cfg.get("user") or "postgres"
    password = cfg.get("password")
    db = cfg.get("database") or "pasarguard"

    if user != "postgres":
        sql = (
            "DO $$ BEGIN "
            f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {pg_literal(user)}) "
            f"THEN CREATE ROLE {pg_identifier(user)} LOGIN; END IF; END $$;"
        )
        code, out, err = pg_admin_sql_local(compose_dir, service, sql)
        if code != 0:
            raise RuntimeError(err or out or "Could not create PostgreSQL application role")
        if password:
            sql = f"ALTER ROLE {pg_identifier(user)} PASSWORD {pg_literal(password)};"
            code, out, err = pg_admin_sql_local(compose_dir, service, sql)
            if code != 0:
                raise RuntimeError(err or out or "Could not update PostgreSQL application role password")

    sql = (
        f"DROP DATABASE IF EXISTS {pg_identifier(db)} WITH (FORCE); "
        f"CREATE DATABASE {pg_identifier(db)} OWNER {pg_identifier(user)};"
    )
    code, out, err = pg_admin_sql_local(compose_dir, service, sql)
    if code != 0:
        raise RuntimeError(err or out or "Could not recreate PostgreSQL database")


def ensure_postgres_role_and_database_remote(client: paramiko.SSHClient, compose_dir: Path, service: str, cfg: dict) -> None:
    user = cfg.get("user") or "postgres"
    password = cfg.get("password")
    db = cfg.get("database") or "pasarguard"

    if user != "postgres":
        sql = (
            "DO $$ BEGIN "
            f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {pg_literal(user)}) "
            f"THEN CREATE ROLE {pg_identifier(user)} LOGIN; END IF; END $$;"
        )
        code, out, err = pg_admin_sql_remote(client, compose_dir, service, sql)
        if code != 0:
            raise RuntimeError(err or out or "Could not create PostgreSQL application role")
        if password:
            sql = f"ALTER ROLE {pg_identifier(user)} PASSWORD {pg_literal(password)};"
            code, out, err = pg_admin_sql_remote(client, compose_dir, service, sql)
            if code != 0:
                raise RuntimeError(err or out or "Could not update PostgreSQL application role password")

    sql = (
        f"DROP DATABASE IF EXISTS {pg_identifier(db)} WITH (FORCE); "
        f"CREATE DATABASE {pg_identifier(db)} OWNER {pg_identifier(user)};"
    )
    code, out, err = pg_admin_sql_remote(client, compose_dir, service, sql)
    if code != 0:
        raise RuntimeError(err or out or "Could not recreate PostgreSQL database")


def restore_postgres_local(compose_dir: Path, service: str, cfg: dict, dump_path: Path) -> None:
    user = cfg.get("user") or "postgres"
    db = cfg.get("database") or "pasarguard"

    ensure_postgres_role_and_database_local(compose_dir, service, cfg)

    outer = (
        f"docker compose exec -T {shlex.quote(service)} "
        f"psql -v ON_ERROR_STOP=1 -U {shlex.quote(user)} -d {shlex.quote(db)}"
    )
    with dump_path.open("rb") as src:
        p = subprocess.run(
            outer,
            cwd=str(compose_dir),
            shell=True,
            stdin=src,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=DATABASE_RESTORE_TIMEOUT,
        )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors="replace").strip() or "PostgreSQL restore failed")


def restore_mysql_local(compose_dir: Path, service: str, cfg: dict, dump_path: Path) -> None:
    db = cfg.get("database") or "pasarguard"
    user = cfg.get("user")
    password = cfg.get("password")

    # The container's root password is authoritative.
    inner = f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "DROP DATABASE IF EXISTS {db.replace("`", "``")}; CREATE DATABASE `{db.replace("`", "``")}`;"'
    code, out, err = db_exec_local(compose_dir, service, inner)
    if code != 0:
        raise RuntimeError(err or out or "Could not recreate MySQL/MariaDB database")

    inner_restore = f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" {shell_single_quote(db)}'
    outer = (
        f"docker compose exec -T {shlex.quote(service)} "
        f"sh -c {shell_single_quote(inner_restore)}"
    )
    with dump_path.open("rb") as src:
        p = subprocess.run(
            outer,
            cwd=str(compose_dir),
            shell=True,
            stdin=src,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=DATABASE_RESTORE_TIMEOUT,
        )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors="replace").strip() or "MySQL/MariaDB restore failed")

    if user and user != "root" and password is not None:
        db_lit = mysql_literal(db)
        user_lit = mysql_literal(user)
        pwd_lit = mysql_literal(password)
        grant_sql = (
            f"CREATE USER IF NOT EXISTS {user_lit}@'%' IDENTIFIED BY {pwd_lit}; "
            f"ALTER USER {user_lit}@'%' IDENTIFIED BY {pwd_lit}; "
            f"GRANT ALL PRIVILEGES ON `{db.replace('`', '``')}`.* TO {user_lit}@'%'; "
            "FLUSH PRIVILEGES;"
        )
        code, out, err = db_exec_local(
            compose_dir, service, f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e {shell_single_quote(grant_sql)}'
        )
        if code != 0:
            raise RuntimeError(err or out or "Could not recreate MySQL/MariaDB application user")


def ensure_remote_postgres_runtime(
    client: paramiko.SSHClient,
    compose_dir: Path,
    service: str,
    runtime: Optional[dict[str, object]] = None,
) -> None:
    """
    Make the target database container use the image declared by the restored
    compose file. This is important for TimescaleDB: a pre-existing container
    can otherwise keep an older image even after docker-compose.yml is restored.
    """
    runtime = runtime or {}
    image = str(runtime.get("image") or "").strip()
    digests = [str(x).strip() for x in (runtime.get("repo_digests") or []) if str(x).strip()]
    expected_version = str(runtime.get("timescaledb_version") or "").strip()
    expected_schema = str(runtime.get("timescaledb_schema") or "public").strip() or "public"

    # Prefer the exact source image digest. A mutable tag can point to a
    # different TimescaleDB build on the target and cause "$libdir/timescaledb-X"
    # restore failures.
    if digests:
        digest = digests[0]
        code, out, err = ssh_shell(
            client,
            f"docker pull {shlex.quote(digest)}",
            timeout=600,
        )
        if code != 0:
            raise RuntimeError(err or out or f"Could not pull the source database image digest: {digest}")
        if image:
            code, out, err = ssh_shell(
                client,
                f"docker tag {shlex.quote(digest)} {shlex.quote(image)}",
                timeout=60,
            )
            if code != 0:
                raise RuntimeError(err or out or "Could not tag the exact source database image for Compose")
    else:
        code, out, err = ssh_shell(
            client,
            f"cd {shlex.quote(str(compose_dir))} && "
            f"docker compose pull --quiet {shlex.quote(service)}",
            timeout=600,
        )
        if code != 0:
            raise RuntimeError(err or out or "Could not pull the database image from the restored compose file")

    code, out, err = ssh_shell(
        client,
        f"cd {shlex.quote(str(compose_dir))} && "
        f"docker compose up -d --force-recreate {shlex.quote(service)}",
        timeout=300,
    )
    if code != 0:
        raise RuntimeError(err or out or "Could not recreate the database container")

    if not wait_remote_service(client, compose_dir, service, "postgres"):
        raise RuntimeError("PostgreSQL/TimescaleDB did not become ready after image refresh")

    if expected_version:
        code, out, err = db_exec_remote(
            client,
            compose_dir,
            service,
            "psql -v ON_ERROR_STOP=1 -U \"$POSTGRES_USER\" -d postgres "
            "-Atc \"SELECT COALESCE((SELECT string_agg(version, ',' ORDER BY version) "
            "FROM pg_available_extension_versions WHERE name='timescaledb'), '');\"",
        )
        if code != 0:
            raise RuntimeError(err or out or "Could not inspect TimescaleDB availability")

        available_versions = out.strip().splitlines()[0].strip() if out.strip() else ""
        versions = {x.strip() for x in available_versions.split(",") if x.strip()}
        if expected_version not in versions:
            raise RuntimeError(
                "TimescaleDB version mismatch before restore: "
                f"source requires {expected_version}, target image provides "
                f"{available_versions or 'no TimescaleDB versions'}. "
                "The database restore was stopped before importing SQL."
            )

        info(
            f"Remote TimescaleDB extension version available: {expected_version} "
            f"(schema: {expected_schema})"
        )
    else:
        info("Source database does not use TimescaleDB; no TimescaleDB image check required.")


def prepare_timescaledb_restore_remote(
    client: paramiko.SSHClient,
    compose_dir: Path,
    service: str,
    database: str,
    runtime: Optional[dict[str, object]] = None,
) -> None:
    """
    Prepare a freshly-created PostgreSQL database for a TimescaleDB dump.

    A pg_dump from TimescaleDB can contain function definitions that reference
    the versioned shared library (for example $libdir/timescaledb-2.30.1).
    The extension must exist in the target database before the SQL dump is
    replayed, otherwise PostgreSQL tries to resolve those functions against
    the empty database and fails.
    """
    runtime = runtime or {}
    expected_version = str(runtime.get("timescaledb_version") or "").strip()
    if not expected_version:
        return

    schema = str(runtime.get("timescaledb_schema") or "public").strip() or "public"
    schema_sql = pg_identifier(schema)
    db_sql = shell_single_quote(database)

    # The PostgreSQL superuser from the container environment creates the
    # extension. Creating it at the exact source version also validates that
    # the target image actually contains the required extension library.
    inner = (
        f"psql -v ON_ERROR_STOP=1 -U \"$POSTGRES_USER\" -d {db_sql} "
        f"-c {shell_single_quote(f'CREATE SCHEMA IF NOT EXISTS {schema_sql}; CREATE EXTENSION IF NOT EXISTS timescaledb WITH SCHEMA {schema_sql} VERSION {pg_literal(expected_version)}; SELECT {schema_sql}.timescaledb_pre_restore();')}"
    )
    code, out, err = db_exec_remote(client, compose_dir, service, inner)
    if code != 0:
        raise RuntimeError(
            err or out or
            "Could not enable TimescaleDB at the exact source version before restore"
        )

    info(
        f"TimescaleDB {expected_version} enabled in target database "
        f"{database} and pre-restore mode is active."
    )


def finish_timescaledb_restore_remote(
    client: paramiko.SSHClient,
    compose_dir: Path,
    service: str,
    database: str,
    runtime: Optional[dict[str, object]] = None,
) -> None:
    runtime = runtime or {}
    expected_version = str(runtime.get("timescaledb_version") or "").strip()
    if not expected_version:
        return

    schema = str(runtime.get("timescaledb_schema") or "public").strip() or "public"
    schema_sql = pg_identifier(schema)
    db_sql = shell_single_quote(database)

    inner = (
        f"psql -v ON_ERROR_STOP=1 -U \"$POSTGRES_USER\" -d {db_sql} "
        f"-c {shell_single_quote(f'SELECT {schema_sql}.timescaledb_post_restore();')}"
    )
    code, out, err = db_exec_remote(client, compose_dir, service, inner)
    if code != 0:
        raise RuntimeError(
            err or out or
            "TimescaleDB post-restore failed after database import"
        )

    info(f"TimescaleDB {expected_version} post-restore completed.")


def restore_database_remote(
    client: paramiko.SSHClient,
    compose_dir: Path,
    service: str,
    family: str,
    cfg: dict,
    remote_dump: str,
    runtime: Optional[dict[str, object]] = None,
) -> None:
    user = cfg.get("user") or "postgres"
    db = cfg.get("database") or "pasarguard"

    if family == "postgres":
        ensure_remote_postgres_runtime(client, compose_dir, service, runtime)
        if user != "postgres":
            sql = (
                "DO $$ BEGIN "
                f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {pg_literal(user)}) "
                f"THEN CREATE ROLE {pg_identifier(user)} LOGIN; END IF; END $$;"
            )
            code, out, err = pg_admin_sql_remote(client, compose_dir, service, sql)
            if code != 0:
                raise RuntimeError(err or out or "Could not create PostgreSQL application role")
            if cfg.get("password"):
                sql = f"ALTER ROLE {pg_identifier(user)} PASSWORD {pg_literal(str(cfg['password']))};"
                code, out, err = pg_admin_sql_remote(client, compose_dir, service, sql)
                if code != 0:
                    raise RuntimeError(err or out or "Could not update PostgreSQL application role password")

        sql = (
            f"DROP DATABASE IF EXISTS {pg_identifier(db)} WITH (FORCE); "
            f"CREATE DATABASE {pg_identifier(db)} OWNER {pg_identifier(user)};"
        )
        code, out, err = pg_admin_sql_remote(client, compose_dir, service, sql)
        if code != 0:
            raise RuntimeError(err or out or "Could not recreate PostgreSQL database")

        # A fresh PostgreSQL database has no TimescaleDB extension objects.
        # Prepare the extension and enter TimescaleDB restore mode before
        # replaying the dump so versioned $libdir/timescaledb-X.Y.Z symbols
        # resolve correctly.
        prepare_timescaledb_restore_remote(
            client,
            compose_dir,
            service,
            str(db),
            runtime,
        )

        command = (
            f"cd {shlex.quote(str(compose_dir))} && "
            f"cat {shlex.quote(remote_dump)} | docker compose exec -T {shlex.quote(service)} "
            f"psql -v ON_ERROR_STOP=1 -U {shlex.quote(user)} -d {shlex.quote(db)}"
        )
    else:
        mysql_db = db.replace("`", "``")
        inner = (
            f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e '
            f'"DROP DATABASE IF EXISTS `{mysql_db}`; CREATE DATABASE `{mysql_db}`;"'
        )
        code, out, err = db_exec_remote(client, compose_dir, service, inner)
        if code != 0:
            raise RuntimeError(err or out or "Could not recreate MySQL/MariaDB database")
        inner_restore = f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" {shell_single_quote(db)}'
        command = (
            f"cd {shlex.quote(str(compose_dir))} && "
            f"cat {shlex.quote(remote_dump)} | docker compose exec -T {shlex.quote(service)} "
            f"sh -c {shell_single_quote(inner_restore)}"
        )

    code, out, err = ssh_shell(client, command, timeout=DATABASE_RESTORE_TIMEOUT)
    if code != 0:
        raise RuntimeError(err or out or "Remote database restore failed")

    if family == "postgres":
        finish_timescaledb_restore_remote(
            client,
            compose_dir,
            service,
            str(db),
            runtime,
        )

    if family == "mysql" and cfg.get("user") and cfg["user"] != "root" and cfg.get("password") is not None:
        user = str(cfg["user"])
        password = str(cfg["password"])
        grant_sql = (
            f"CREATE USER IF NOT EXISTS {mysql_literal(user)}@'%' IDENTIFIED BY {mysql_literal(password)}; "
            f"ALTER USER {mysql_literal(user)}@'%' IDENTIFIED BY {mysql_literal(password)}; "
            f"GRANT ALL PRIVILEGES ON `{db.replace('`', '``')}`.* TO {mysql_literal(user)}@'%'; "
            "FLUSH PRIVILEGES;"
        )
        code, out, err = db_exec_remote(
            client,
            compose_dir,
            service,
            f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e {shell_single_quote(grant_sql)}',
        )
        if code != 0:
            raise RuntimeError(err or out or "Could not recreate MySQL/MariaDB application user")


def scan_text_file_for_paths(path: Path, max_bytes: int = 16 * 1024 * 1024) -> set[str]:
    found: set[str] = set()
    try:
        if path.stat().st_size > max_bytes:
            return found
        data = path.read_text(errors="ignore")
        found.update(m.group(1) for m in CERT_PATH_REGEX.finditer(data))
    except (OSError, UnicodeDecodeError):
        pass
    return found


def discover_extra_certs(opt_dir: Path, data_dir: Path, dump_paths: Iterable[Path]) -> list[str]:
    candidates: set[str] = set()

    env = env_read(opt_dir / ".env")
    for key in ("UVICORN_SSL_CERTFILE", "UVICORN_SSL_KEYFILE"):
        if env.get(key):
            candidates.add(env[key])

    for p in dump_paths:
        candidates |= scan_text_file_for_paths(p)

    text_suffixes = {".json", ".yaml", ".yml", ".conf", ".ini", ".txt", ".env"}
    if data_dir.exists():
        for p in data_dir.rglob("*"):
            if p.is_file() and p.suffix.lower() in text_suffixes:
                candidates |= scan_text_file_for_paths(p, max_bytes=4 * 1024 * 1024)

    covered_prefixes = [str(PASARGUARD_DATA_DIR), str(PG_NODE_DATA_DIR), str(opt_dir), str(PG_NODE_DIR)]
    result = []
    for p in sorted(candidates):
        try:
            resolved = str(Path(p).resolve())
            if not Path(resolved).is_file():
                continue
            if any(resolved == prefix or resolved.startswith(prefix + os.sep) for prefix in covered_prefixes):
                continue
            result.append(resolved)
        except OSError:
            continue
    return result


def inspect_nats_volumes_local(compose_dir: Path) -> list[dict[str, str]]:
    code, out, _ = shell_local(
        "docker ps -a --format '{{.ID}}\\t{{.Names}}\\t{{.Image}}'",
        cwd=compose_dir,
    )
    if code != 0:
        return []
    result: list[dict[str, str]] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        cid, name, image = parts
        if "nats" not in name.lower() and "nats" not in image.lower():
            continue

        inspect_code, inspect_out, _ = shell_local(
            f"docker inspect {shlex.quote(cid)} --format '{{{{json .Mounts}}}}'"
        )
        if inspect_code != 0:
            continue
        try:
            mounts = json.loads(inspect_out)
        except json.JSONDecodeError:
            continue
        for m in mounts or []:
            if m.get("Type") != "volume":
                continue
            source = m.get("Name") or m.get("Source")
            mountpoint = m.get("Source")
            if source and mountpoint:
                result.append({
                    "container": name,
                    "volume": source,
                    "mountpoint": mountpoint,
                })
    # unique by volume
    unique = {item["volume"]: item for item in result}
    return list(unique.values())


def backup_volume_to_file(volume_mountpoint: Path, out_file: Path) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    p = subprocess.run(
        ["tar", "-czf", str(out_file), "-C", str(volume_mountpoint), "."],
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr or "tar backup failed")


def restore_file_to_volume(archive: Path, mountpoint: Path) -> None:
    mountpoint.mkdir(parents=True, exist_ok=True)
    p = subprocess.run(
        ["tar", "-xzf", str(archive), "-C", str(mountpoint)],
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr or "tar restore failed")


def detect_caddy_sources_local() -> list[dict[str, str]]:
    code, out, _ = shell_local(
        "docker ps -a --format '{{.ID}}\\t{{.Names}}\\t{{.Image}}'"
    )
    if code != 0:
        return []

    result: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        cid, name, image = parts
        if "caddy" not in image.lower() and "caddy" not in name.lower():
            continue

        project_code, project_dir, _ = shell_local(
            "docker inspect -f '{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}' "
            + shlex.quote(cid)
        )
        if project_code == 0 and project_dir and project_dir != "<no value>" and Path(project_dir).is_dir():
            key = ("path", project_dir, "")
            if key not in seen:
                seen.add(key)
                result.append({"kind": "path", "source": project_dir, "label": f"compose-project:{name}"})

        mount_code, mount_out, _ = shell_local(
            f"docker inspect {shlex.quote(cid)} --format '{{{{json .Mounts}}}}'"
        )
        if mount_code == 0:
            try:
                mounts = json.loads(mount_out)
            except json.JSONDecodeError:
                mounts = []
            for m in mounts or []:
                m_type = m.get("Type")
                if m_type == "bind":
                    source = m.get("Source")
                    if source and Path(source).exists():
                        key = ("path", source, "")
                        if key not in seen:
                            seen.add(key)
                            result.append({"kind": "path", "source": source, "label": f"caddy-bind:{name}"})
                elif m_type == "volume":
                    volume = m.get("Name")
                    mountpoint = m.get("Source")
                    if volume and mountpoint:
                        key = ("volume", volume, "")
                        if key not in seen:
                            seen.add(key)
                            result.append({
                                "kind": "volume",
                                "source": volume,
                                "mountpoint": mountpoint,
                                "label": f"caddy-volume:{name}",
                            })

    # Native service fallback.
    code, out, _ = shell_local("systemctl is-active caddy 2>/dev/null")
    if code == 0 and out.strip() == "active":
        for source in ("/etc/caddy", "/var/lib/caddy"):
            p = Path(source)
            if p.exists():
                key = ("path", source, "")
                if key not in seen:
                    seen.add(key)
                    result.append({"kind": "path", "source": source, "label": "native-caddy"})
    return result


def restore_path_from_tree(staging_root: Path, relative_name: str, destination: Path) -> None:
    source = staging_root / relative_name
    if not source.exists():
        raise RuntimeError(f"Missing backup path: {relative_name}")
    if destination.exists():
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        else:
            destination.unlink()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir() and not source.is_symlink():
        shutil.copytree(source, destination, symlinks=True)
    else:
        shutil.copy2(source, destination, follow_symlinks=False)


def add_tree_to_zip(zf: zipfile.ZipFile, root: Path) -> None:
    """
    Add a staged tree while preserving symlinks instead of dereferencing them.
    """
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        arcname = str(rel)
        if path.is_symlink():
            info = zipfile.ZipInfo(arcname)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, os.readlink(path).encode("utf-8"))
        elif path.is_dir():
            info = zipfile.ZipInfo(arcname.rstrip("/") + "/")
            info.create_system = 3
            info.external_attr = (stat.S_IFDIR | 0o755) << 16
            zf.writestr(info, b"")
        elif path.is_file():
            zf.write(path, arcname)

def backup_create(
    *,
    backup_dir: Path,
    db_family: Optional[str] = None,
    include_caddy: bool = True,
    include_nats: bool = True,
) -> Path:
    compose_dir = PASARGUARD_DIR
    if not (compose_dir / "docker-compose.yml").is_file():
        raise RuntimeError(f"Missing {compose_dir}/docker-compose.yml")

    detected = detect_db_family(compose_dir)
    family = db_family or detected
    if family == "unknown":
        raise RuntimeError("Could not detect database backend. Use --db postgres|mysql|sqlite.")

    cfg = read_db_config(compose_dir)
    if family in {"postgres", "mysql"}:
        cfg["family"] = family

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)
    archive = backup_dir / f"pasarguard_backup_{timestamp}_{uuid.uuid4().hex[:8]}.zip"

    work = Path(tempfile.mkdtemp(prefix="pgm_", dir="/tmp"))
    dump_dir = work / "database"
    app_dir = work / "pasarguard_data"
    node_opt = work / "pg_node_opt"
    node_data = work / "pg_node_data"
    extras_dir = work / "extra_certs"
    caddy_dir = work / "caddy"
    nats_dir = work / "nats"
    dump_dir.mkdir()

    manifest = {
        "format": "pasarguard-manager",
        "format_version": 2,
        "version": VERSION,
        "author": AUTHOR,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "database": {
            "family": family,
            "user": cfg.get("user"),
            "database": cfg.get("database"),
        },
        "database_runtime": {},
        "paths": {},
        "files": {},
        "nats": [],
        "caddy": [],
        "extra_certs": [],
    }

    try:
        env_path = PASARGUARD_DIR / ".env"
        compose_path = PASARGUARD_DIR / "docker-compose.yml"
        if compose_path.exists():
            shutil.copy2(compose_path, work / "docker-compose.yml")
        if env_path.exists():
            shutil.copy2(env_path, work / ".env")
            os.chmod(work / ".env", 0o600)

        dump_paths: list[Path] = []
        if family == "postgres":
            service = resolve_db_service(compose_dir, "postgres")
            if not service:
                raise RuntimeError("Could not resolve PostgreSQL/TimescaleDB compose service.")
            if not wait_local_service(compose_dir, service, "postgres"):
                raise RuntimeError("PostgreSQL/TimescaleDB is not ready.")
            manifest["database_runtime"] = capture_postgres_runtime(compose_dir, service)
            dump_path = dump_dir / "pasarguard.sql"
            # Stream directly once; do not double-run the dump.
            user = cfg.get("user") or "postgres"
            db = cfg.get("database") or "pasarguard"
            outer = (
                f"docker compose exec -T {shlex.quote(service)} "
                f"pg_dump -U {shlex.quote(user)} -d {shlex.quote(db)}"
            )
            with dump_path.open("wb") as dst:
                p = subprocess.run(
                    outer,
                    cwd=compose_dir,
                    shell=True,
                    stdout=dst,
                    stderr=subprocess.PIPE,
                )
            if p.returncode != 0 or dump_path.stat().st_size == 0:
                raise RuntimeError(p.stderr.decode(errors="replace").strip() or "PostgreSQL dump failed")
            dump_paths.append(dump_path)

        elif family == "mysql":
            service = resolve_db_service(compose_dir, "mysql")
            if not service:
                raise RuntimeError("Could not resolve MySQL/MariaDB compose service.")
            if not wait_local_service(compose_dir, service, "mysql"):
                raise RuntimeError("MySQL/MariaDB is not ready.")
            dump_path = dump_dir / "pasarguard.sql"
            db = cfg.get("database") or "pasarguard"
            candidates = [
                f"mariadb-dump -uroot -p\"$MYSQL_ROOT_PASSWORD\" --databases {shlex.quote(db)}",
                f"mysqldump -uroot -p\"$MYSQL_ROOT_PASSWORD\" --databases {shlex.quote(db)}",
            ]
            ok = False
            last_err = ""
            for inner in candidates:
                outer = (
                    f"docker compose exec -T {shlex.quote(service)} "
                    f"sh -c {shell_single_quote(inner)}"
                )
                with dump_path.open("wb") as dst:
                    p = subprocess.run(
                        outer,
                        cwd=compose_dir,
                        shell=True,
                        stdout=dst,
                        stderr=subprocess.PIPE,
                    )
                last_err = p.stderr.decode(errors="replace").strip()
                if p.returncode == 0 and dump_path.stat().st_size > 0:
                    ok = True
                    break
            if not ok:
                raise RuntimeError(last_err or "MySQL/MariaDB dump failed")
            dump_paths.append(dump_path)

        # SQLite is already stored in /var/lib/pasarguard and is covered below.

        ok, skipped, failed = copy_tree_safe(PASARGUARD_DATA_DIR, app_dir)
        if not ok:
            raise RuntimeError(f"Pasarguard data copy failed: {failed[:3]}")
        if skipped:
            warn(f"Skipped {len(skipped)} runtime special files under /var/lib/pasarguard.")

        ok, skipped, failed = copy_tree_safe(PG_NODE_DIR, node_opt)
        if not ok:
            raise RuntimeError(f"PG-Node config copy failed: {failed[:3]}")
        if skipped:
            warn(f"Skipped {len(skipped)} runtime special files under /opt/pg-node.")

        ok, skipped, failed = copy_tree_safe(PG_NODE_DATA_DIR, node_data)
        if not ok:
            raise RuntimeError(f"PG-Node data copy failed: {failed[:3]}")
        if skipped:
            warn(f"Skipped {len(skipped)} runtime special files under /var/lib/pg-node.")

        extra_certs = discover_extra_certs(PASARGUARD_DIR, PASARGUARD_DATA_DIR, dump_paths)
        for index, source in enumerate(extra_certs):
            destination = extras_dir / f"cert_{index:03d}" / Path(source).name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            manifest["extra_certs"].append({
                "source": source,
                "archive_path": str(destination.relative_to(work)),
            })

        if include_nats and env_get(PASARGUARD_DIR / ".env", "NATS_ENABLED", "false").lower() in {"1", "true", "yes"}:
            for item in inspect_nats_volumes_local(compose_dir):
                volume_dir = nats_dir / item["volume"]
                volume_dir.mkdir(parents=True, exist_ok=True)
                archive_path = volume_dir / "volume.tar.gz"
                backup_volume_to_file(Path(item["mountpoint"]), archive_path)
                manifest["nats"].append({
                    "volume": item["volume"],
                    "archive_path": str(archive_path.relative_to(work)),
                })

        if include_caddy:
            for idx, item in enumerate(detect_caddy_sources_local()):
                dest_name = f"source_{idx:03d}"
                if item["kind"] == "path":
                    src = Path(item["source"])
                    if not src.exists():
                        continue
                    dest = caddy_dir / dest_name
                    ok, skipped, failed = copy_tree_safe(src, dest)
                    if not ok:
                        warn(f"Skipping Caddy source {src}: {failed[:2]}")
                        continue
                    manifest["caddy"].append({
                        "kind": "path",
                        "source": str(src),
                        "label": item["label"],
                        "archive_path": dest_name,
                        "skipped_special": len(skipped),
                    })
                else:
                    volume = item["source"]
                    src_mountpoint = Path(item["mountpoint"])
                    if not src_mountpoint.exists():
                        continue
                    dest = caddy_dir / dest_name / "volume.tar.gz"
                    try:
                        backup_volume_to_file(src_mountpoint, dest)
                    except Exception as exc:
                        warn(f"Skipping Caddy volume {volume}: {exc}")
                        continue
                    manifest["caddy"].append({
                        "kind": "volume",
                        "volume": volume,
                        "label": item["label"],
                        "archive_path": str(dest.relative_to(caddy_dir)),
                    })

        # File checksums are calculated on staged files, then the archive itself gets a
        # separate SHA-256 next.
        for p in dump_paths:
            manifest["files"][str(p.relative_to(work))] = {
                "sha256": sha256_file(p),
                "size": p.stat().st_size,
            }

        (work / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        os.chmod(work / "manifest.json", 0o600)

        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            add_tree_to_zip(zf, work)

        validate_archive(archive)
        success(f"Backup created: {archive} ({fmt_bytes(archive.stat().st_size)})")
        success(f"SHA-256: {sha256_file(archive)}")
        warn("The ZIP contains .env and may contain private keys/certificates. Treat it as a secret.")
        return archive
    finally:
        shutil.rmtree(work, ignore_errors=True)


def restore_local(
    archive: Path,
    *,
    force: bool,
    disable_nodes: bool,
) -> None:
    manifest = validate_archive(archive)
    if not force:
        header("DESTRUCTIVE RESTORE")
        print(f"Backup: {archive}")
        print(f"Database: {manifest.get('database', {})}")
        if not ask_yes_no("This will overwrite the local PasarGuard installation. Continue?", False):
            warn("Restore cancelled.")
            return

    compose_down_local(PG_NODE_DIR) if (PG_NODE_DIR / "docker-compose.yml").exists() else None
    compose_down_local(PASARGUARD_DIR) if (PASARGUARD_DIR / "docker-compose.yml").exists() else None

    staging = Path(tempfile.mkdtemp(prefix="pgm_restore_", dir="/tmp"))
    try:
        safe_extract_zip(archive, staging)

        for rel, meta in (manifest.get("files") or {}).items():
            target = staging / rel
            if not target.is_file():
                raise RuntimeError(f"Backup member missing: {rel}")
            if target.stat().st_size != int(meta.get("size", -1)):
                raise RuntimeError(f"Backup member size mismatch: {rel}")
            if sha256_file(target) != meta.get("sha256"):
                raise RuntimeError(f"Backup member SHA-256 mismatch: {rel}")

        clean_target_dirs_local()

        for rel, dst in (
            ("docker-compose.yml", PASARGUARD_DIR / "docker-compose.yml"),
            (".env", PASARGUARD_DIR / ".env"),
        ):
            src = staging / rel
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

        shutil.copytree(staging / "pasarguard_data", PASARGUARD_DATA_DIR, dirs_exist_ok=True, symlinks=True) \
            if (staging / "pasarguard_data").exists() else None
        shutil.copytree(staging / "pg_node_opt", PG_NODE_DIR, dirs_exist_ok=True, symlinks=True) \
            if (staging / "pg_node_opt").exists() else None
        shutil.copytree(staging / "pg_node_data", PG_NODE_DATA_DIR, dirs_exist_ok=True, symlinks=True) \
            if (staging / "pg_node_data").exists() else None

        # Restore exact external certificate/key paths captured by the backup.
        for item in manifest.get("extra_certs", []):
            src = staging / item["archive_path"]
            dest = Path(item["source"])
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

        # Restore Caddy/reverse-proxy data without executing arbitrary shell scripts.
        for item in manifest.get("caddy", []):
            if item.get("kind") == "volume":
                volume = item["volume"]
                code, out, err = shell_local(
                    f"docker volume create {shlex.quote(volume)} >/dev/null && "
                    f"docker volume inspect {shlex.quote(volume)} --format '{{{{.Mountpoint}}}}'"
                )
                if code != 0 or not out:
                    warn(f"Could not restore Caddy volume {volume}: {err or out}")
                    continue
                restore_file_to_volume(
                    staging / "caddy" / item["archive_path"],
                    Path(out.strip()),
                )
                continue

            src = staging / "caddy" / item["archive_path"]
            dest = Path(item["source"])
            if dest.exists() and dest != Path("/"):
                if dest.is_dir() and not dest.is_symlink():
                    shutil.rmtree(dest)
                else:
                    dest.unlink()
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, dest, dirs_exist_ok=True, symlinks=True)

        # Restore NATS named volumes after Docker is available.
        for item in manifest.get("nats", []):
            volume = item["volume"]
            code, out, err = shell_local(
                f"docker volume inspect {shlex.quote(volume)} --format '{{{{.Mountpoint}}}}'"
            )
            if code != 0 or not out:
                # Compose may create it when the stack starts; do that first.
                compose_up_local(PASARGUARD_DIR, services=["nats"])
                code, out, err = shell_local(
                    f"docker volume inspect {shlex.quote(volume)} --format '{{{{.Mountpoint}}}}'"
                )
            if code == 0 and out:
                restore_file_to_volume(staging / item["archive_path"], Path(out))
            else:
                warn(f"Could not locate NATS volume '{volume}'. Its archive remains in staging.")

        family = str(manifest["database"]["family"])
        cfg = read_db_config(PASARGUARD_DIR)
        if family in {"postgres", "mysql"}:
            service = resolve_db_service(PASARGUARD_DIR, family)
            if not service:
                raise RuntimeError(f"Could not resolve {family} service after restore.")
            if not compose_up_local(PASARGUARD_DIR, [service]):
                raise RuntimeError("Could not start database service.")
            if not wait_local_service(PASARGUARD_DIR, service, family):
                raise RuntimeError("Database did not become ready.")

            restore_postgres_local(PASARGUARD_DIR, service, cfg, staging / "database" / "pasarguard.sql") \
                if family == "postgres" else restore_mysql_local(PASARGUARD_DIR, service, cfg, staging / "database" / "pasarguard.sql")

        if disable_nodes:
            disable_restored_nodes_local(PASARGUARD_DIR, family, cfg)

        # Do not silently change SSL behavior. Diagnose only.
        check_ssl_paths_local()

        if not compose_up_local(PASARGUARD_DIR):
            raise RuntimeError("Pasarguard stack failed to start.")
        if PG_NODE_DIR.exists() and (PG_NODE_DIR / "docker-compose.yml").exists():
            if not compose_up_local(PG_NODE_DIR):
                raise RuntimeError("PG-Node stack failed to start.")

        if not verify_stack_local(PASARGUARD_DIR):
            raise RuntimeError("Pasarguard stack verification failed.")

        success("Local restore completed and the Pasarguard stack is running.")
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def disable_restored_nodes_local(compose_dir: Path, family: str, cfg: dict) -> bool:
    """
    Best-effort compatibility helper. Newer PasarGuard versions may use a different
    status model; failure is reported instead of turning a successful restore into
    a hard failure.
    """
    try:
        if family == "postgres":
            service = resolve_db_service(compose_dir, "postgres")
            if not service:
                return False
            db = cfg.get("database") or "pasarguard"
            user = cfg.get("user") or "postgres"
            sql = "UPDATE nodes SET status='disabled';"
            code, out, err = db_exec_local(
                compose_dir,
                service,
                f"psql -U {shlex.quote(user)} -d {shlex.quote(db)} -c {shell_single_quote(sql)}",
            )
        elif family == "mysql":
            service = resolve_db_service(compose_dir, "mysql")
            if not service:
                return False
            db = cfg.get("database") or "pasarguard"
            code, out, err = db_exec_local(
                compose_dir,
                service,
                f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" {shell_single_quote(db)} -e {shell_single_quote("UPDATE nodes SET status=\'disabled\';")}',
            )
        else:
            return False

        if code == 0:
            success("Restored nodes were set to disabled before the panel started.")
            return True

        warn(f"Could not disable restored nodes automatically: {err or out}")
        return False
    except Exception as exc:
        warn(f"Could not disable restored nodes automatically: {exc}")
        return False


def check_ssl_paths_local() -> None:
    env = env_read(PASARGUARD_DIR / ".env")
    missing = []
    for key in ("UVICORN_SSL_CERTFILE", "UVICORN_SSL_KEYFILE"):
        value = env.get(key)
        if value and not Path(value).is_file():
            missing.append((key, value))
    if missing:
        warn("The restored .env references missing TLS files. No automatic SSL changes were made.")
        for key, value in missing:
            warn(f"  {key} -> {value}")
    else:
        info("SSL path check passed (or panel SSL is not configured directly).")


def preflight_local(db_override: Optional[str] = None) -> bool:
    problems: list[str] = []
    for cmd in ("docker", "tar"):
        if not command_exists(cmd):
            problems.append(f"missing command: {cmd}")
    if not (PASARGUARD_DIR / "docker-compose.yml").exists():
        problems.append(f"missing: {PASARGUARD_DIR}/docker-compose.yml")

    if problems:
        for p in problems:
            error(p)
        return False

    code, out, err = shell_local("docker compose config --quiet", cwd=PASARGUARD_DIR)
    if code != 0:
        error(f"docker compose configuration is invalid: {err or out}")
        return False

    family = db_override or detect_db_family(PASARGUARD_DIR)
    info(f"Detected database backend: {family}")

    if family in {"postgres", "mysql"}:
        service = resolve_db_service(PASARGUARD_DIR, family)
        if not service:
            error(f"Could not resolve database service for {family}.")
            return False
        info(f"Database service: {service}")
    elif family == "sqlite":
        info("SQLite detected; database file is included in /var/lib/pasarguard.")
    else:
        error("Unsupported/unknown database backend.")
        return False

    total, used, free = shutil.disk_usage("/")
    info(f"Root filesystem: {fmt_bytes(used)} used / {fmt_bytes(total)} total / {fmt_bytes(free)} free")
    return True


class SSHConnector:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        key_file: Optional[Path],
        accept_new_host_key: bool,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.accept_new_host_key = accept_new_host_key
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if accept_new_host_key else paramiko.RejectPolicy()
        )

    def connect(self) -> paramiko.SSHClient:
        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            key_filename=str(self.key_file) if self.key_file else None,
            timeout=SSH_TIMEOUT,
            auth_timeout=SSH_TIMEOUT,
            banner_timeout=SSH_BANNER_TIMEOUT,
            look_for_keys=True,
            allow_agent=True,
        )
        success(f"SSH connected to {self.host}:{self.port}")
        return self.client

    def close(self) -> None:
        self.client.close()


def sftp_upload_with_hash(client: paramiko.SSHClient, local: Path, remote: str) -> tuple[int, str]:
    sftp = client.open_sftp()
    try:
        local_size = local.stat().st_size
        sent = 0

        with local.open("rb") as src, sftp.file(remote, "wb") as dst:
            while True:
                chunk = src.read(SFTP_CHUNK)
                if not chunk:
                    break
                dst.write(chunk)
                sent += len(chunk)

        remote_size = sftp.stat(remote).st_size
        if remote_size != local_size:
            raise RuntimeError(f"SFTP size mismatch: local={local_size}, remote={remote_size}")

        code, out, err = ssh_shell(
            client,
            f"sha256sum {shlex.quote(remote)}",
            timeout=60,
        )
        if code != 0:
            raise RuntimeError(err or out or "Remote sha256sum failed")
        remote_hash = out.split()[0].strip()
        local_hash = sha256_file(local)
        if remote_hash != local_hash:
            raise RuntimeError("Remote SHA-256 does not match local SHA-256")
        return sent, local_hash
    finally:
        sftp.close()


def restore_remote(
    client: paramiko.SSHClient,
    archive: Path,
    *,
    force: bool,
    disable_nodes: bool,
) -> None:
    # Upload to /tmp so cleaning /opt/pasarguard cannot delete the archive.
    remote_root = Path("/tmp/pasarguard-manager")
    remote_archive = remote_root / archive.name

    ssh_run_checked(client, f"mkdir -p {shlex.quote(str(remote_root))}", "Creating remote staging directory")
    info(f"Uploading {archive.name}...")
    _, digest = sftp_upload_with_hash(client, archive, str(remote_archive))
    success(f"Upload verified with SHA-256 {digest}")

    code, out, err = ssh_shell(
        client,
        f"python3 - {shlex.quote(str(remote_archive))} <<'PY'\n"
        "import sys, zipfile, json\n"
        "p=sys.argv[1]\n"
        "with zipfile.ZipFile(p) as z:\n"
        "    if z.testzip(): raise SystemExit(2)\n"
        "    m=json.loads(z.read('manifest.json'))\n"
        "    if m.get('format')!='pasarguard-manager' or m.get('format_version')!=2: raise SystemExit(3)\n"
        "print(json.dumps(m))\n"
        "PY",
        timeout=60,
    )
    if code != 0:
        raise RuntimeError(err or out or "Remote archive validation failed.")
    manifest = json.loads(out)

    if not force:
        header("REMOTE DESTRUCTIVE RESTORE")
        print(f"Target: {client.get_transport().getpeername()[0]}")
        print(f"Database: {manifest.get('database', {})}")
        if not ask_yes_no("Overwrite the remote Pasarguard installation?", False):
            warn("Remote restore cancelled.")
            return

    # Stop before deleting anything.
    if not compose_down_remote(client, PG_NODE_DIR):
        warn("PG-Node compose down returned non-zero; continuing only if the next directory operation succeeds.")
    if not compose_down_remote(client, PASARGUARD_DIR):
        warn("Pasarguard compose down returned non-zero; continuing only if the next directory operation succeeds.")

    clean_target_dirs_remote(client)

    extract_dir = remote_root / "extracted"
    ssh_run_checked(
        client,
        f"rm -rf {shlex.quote(str(extract_dir))} && mkdir -p {shlex.quote(str(extract_dir))} && "
        f"python3 - {shlex.quote(str(remote_archive))} {shlex.quote(str(extract_dir))} <<'PY'\n"
        "import sys, zipfile, os\n"
        "z=zipfile.ZipFile(sys.argv[1]); d=os.path.realpath(sys.argv[2]); items=z.infolist()\n"
        "if z.testzip(): raise SystemExit(2)\n"
        "for i in items:\n"
        "    t=os.path.realpath(os.path.join(d,i.filename))\n"
        "    if os.path.commonpath([d,t])!=d: raise SystemExit(4)\n"
        "for i in items:\n"
        "    mode=(i.external_attr>>16)&0xFFFF\n"
        "    if __import__('stat').S_ISLNK(mode): continue\n"
        "    t=os.path.join(d,i.filename)\n"
        "    if i.is_dir(): os.makedirs(t,exist_ok=True); continue\n"
        "    os.makedirs(os.path.dirname(t),exist_ok=True)\n"
        "    with z.open(i) as src, open(t,'wb') as dst:\n"
        "        while True:\n"
        "            chunk=src.read(1024*1024)\n"
        "            if not chunk: break\n"
        "            dst.write(chunk)\n"
        "for i in items:\n"
        "    mode=(i.external_attr>>16)&0xFFFF\n"
        "    if not __import__('stat').S_ISLNK(mode): continue\n"
        "    t=os.path.join(d,i.filename); os.makedirs(os.path.dirname(t),exist_ok=True)\n"
        "    if os.path.lexists(t): os.unlink(t)\n"
        "    os.symlink(z.read(i).decode(),t)\n"
        "print('extracted')\n"
        "PY",
        "Extracting backup archive",
        timeout=120,
    )

    # Verify staged database files against the backup manifest before touching the database.
    verify_script = (
        "python3 - <<'PY'\n"
        "import hashlib, json, pathlib\n"
        f"root=pathlib.Path({str(extract_dir)!r})\n"
        "m=json.loads((root/'manifest.json').read_text())\n"
        "for rel, meta in (m.get('files') or {}).items():\n"
        "    p=root/rel\n"
        "    if not p.is_file(): raise SystemExit(f'missing backup member: {rel}')\n"
        "    h=hashlib.sha256()\n"
        "    with p.open('rb') as f:\n"
        "        for chunk in iter(lambda:f.read(1024*1024), b''):\n"
        "            h.update(chunk)\n"
        "    if h.hexdigest() != meta.get('sha256'): raise SystemExit(f'checksum mismatch: {rel}')\n"
        "print('manifest checksums: OK')\n"
        "PY"
    )
    if not ssh_run_checked(client, verify_script, "Verifying backup member checksums"):
        raise RuntimeError("Backup member verification failed on remote host")

    # Restore filesystem content first.
    copy_commands = [
        (extract_dir / "docker-compose.yml", PASARGUARD_DIR / "docker-compose.yml"),
        (extract_dir / ".env", PASARGUARD_DIR / ".env"),
    ]
    for src, dst in copy_commands:
        ssh_run_checked(
            client,
            f"test ! -e {shlex.quote(str(src))} || cp -a {shlex.quote(str(src))} {shlex.quote(str(dst))}",
            f"Restoring {src.name}",
            required=True,
        )

    for src, dst, label in (
        (extract_dir / "pasarguard_data", PASARGUARD_DATA_DIR, "Pasarguard data"),
        (extract_dir / "pg_node_opt", PG_NODE_DIR, "PG-Node config"),
        (extract_dir / "pg_node_data", PG_NODE_DATA_DIR, "PG-Node data"),
    ):
        ssh_run_checked(
            client,
            f"test ! -d {shlex.quote(str(src))} || cp -a {shlex.quote(str(src))}/. {shlex.quote(str(dst))}/",
            f"Restoring {label}",
        )

    # External certs and Caddy are restored by manifest-defined exact paths.
    for item in manifest.get("extra_certs", []):
        src = extract_dir / item["archive_path"]
        dst = Path(item["source"])
        ssh_run_checked(
            client,
            f"mkdir -p {shlex.quote(str(dst.parent))} && cp -a {shlex.quote(str(src))} {shlex.quote(str(dst))}",
            f"Restoring certificate {dst}",
        )

    for item in manifest.get("caddy", []):
        if item.get("kind") == "volume":
            volume = item["volume"]
            src = extract_dir / "caddy" / item["archive_path"]
            code, out, err = ssh_shell(
                client,
                f"docker volume create {shlex.quote(volume)} >/dev/null && "
                f"docker volume inspect {shlex.quote(volume)} --format '{{{{.Mountpoint}}}}'",
            )
            if code != 0 or not out:
                warn(f"Could not restore Caddy volume {volume}: {err or out}")
                continue
            mountpoint = out.strip()
            code, out, err = ssh_shell(
                client,
                f"tar -xzf {shlex.quote(str(src))} -C {shlex.quote(mountpoint)}",
                timeout=120,
            )
            if code != 0:
                warn(f"Could not restore Caddy volume {volume}: {err or out}")
            continue

        src = extract_dir / "caddy" / item["archive_path"]
        dst = Path(item["source"])
        # Destination path came from the source machine's own manifest.
        ssh_run_checked(
            client,
            f"rm -rf {shlex.quote(str(dst))} && mkdir -p {shlex.quote(str(dst.parent))} && "
            f"cp -a {shlex.quote(str(src))} {shlex.quote(str(dst))}",
            f"Restoring reverse-proxy data to {dst}",
        )

    family = str(manifest["database"]["family"])
    cfg = {
        "family": family,
        "user": manifest["database"].get("user"),
        "database": manifest["database"].get("database"),
        "password": None,
    }

    # Re-read target .env to get the actual target password/URL.
    target_cfg = read_db_config(PASARGUARD_DIR)
    if target_cfg.get("user"):
        cfg["user"] = target_cfg["user"]
    if target_cfg.get("database"):
        cfg["database"] = target_cfg["database"]
    if target_cfg.get("password"):
        cfg["password"] = target_cfg["password"]

    if family in {"postgres", "mysql"}:
        service = resolve_remote_db_service(client, PASARGUARD_DIR, family)
        if not service:
            raise RuntimeError(f"Could not resolve remote database service for {family}")
        if not compose_up_remote(client, PASARGUARD_DIR, [service]):
            raise RuntimeError("Could not start remote database service")
        if not wait_remote_service(client, PASARGUARD_DIR, service, family):
            raise RuntimeError("Remote database did not become ready")

        remote_dump = extract_dir / "database" / "pasarguard.sql"
        restore_database_remote(
            client,
            PASARGUARD_DIR,
            service,
            family,
            cfg,
            str(remote_dump),
            manifest.get("database_runtime") or {},
        )

    if disable_nodes:
        # Best effort on target. We intentionally do not fail migration if the
        # table/schema differs between PasarGuard versions.
        if family in {"postgres", "mysql"}:
            code, out, err = remote_disable_nodes(client, PASARGUARD_DIR, family, cfg)
            if code == 0:
                success("Restored nodes disabled on target.")
            else:
                warn(f"Could not disable restored nodes automatically: {err or out}")

    # NATS volumes: create/restore through Docker volume mountpoint.
    for item in manifest.get("nats", []):
        volume = item["volume"]
        archive_path = extract_dir / item["archive_path"]
        code, out, err = ssh_shell(
            client,
            f"docker volume create {shlex.quote(volume)} >/dev/null && "
            f"docker volume inspect {shlex.quote(volume)} --format '{{{{.Mountpoint}}}}'",
        )
        if code != 0 or not out:
            warn(f"Could not restore NATS volume {volume}: {err or out}")
            continue
        mountpoint = out.strip()
        code, out, err = ssh_shell(
            client,
            f"tar -xzf {shlex.quote(str(archive_path))} -C {shlex.quote(mountpoint)}",
            timeout=120,
        )
        if code != 0:
            warn(f"Could not restore NATS volume {volume}: {err or out}")

    remote_check_ssl(client)
    if not compose_up_remote(client, PASARGUARD_DIR):
        raise RuntimeError("Remote Pasarguard stack failed to start")
    if (PG_NODE_DIR / "docker-compose.yml").exists() or await_remote_file(client, PG_NODE_DIR / "docker-compose.yml"):
        if not compose_up_remote(client, PG_NODE_DIR):
            raise RuntimeError("Remote PG-Node stack failed to start")

    if not verify_stack_remote(client, PASARGUARD_DIR):
        raise RuntimeError("Remote Pasarguard stack verification failed")

    ssh_shell(client, f"rm -rf {shlex.quote(str(remote_root))}")
    success("Remote restore completed and the Pasarguard stack is running.")


def await_remote_file(client: paramiko.SSHClient, path: str | Path) -> bool:
    code, _, _ = ssh_shell(client, f"test -f {shlex.quote(str(path))}", timeout=10)
    return code == 0


def resolve_remote_db_service(client: paramiko.SSHClient, compose_dir: Path, family: str) -> Optional[str]:
    code, out, _ = ssh_shell(
        client,
        f"cd {shlex.quote(str(compose_dir))} && docker compose config --services",
        timeout=30,
    )
    if code != 0:
        return None
    services = [x.strip() for x in out.splitlines() if x.strip()]
    candidates = POSTGRES_CANDIDATES if family == "postgres" else MYSQL_CANDIDATES
    for name in candidates:
        if name in services:
            return name
    return None


def remote_disable_nodes(
    client: paramiko.SSHClient,
    compose_dir: Path,
    family: str,
    cfg: dict,
) -> tuple[int, str, str]:
    service = resolve_remote_db_service(client, compose_dir, family)
    if not service:
        return 1, "", "database service not found"
    db = cfg.get("database") or "pasarguard"
    user = cfg.get("user") or ("postgres" if family == "postgres" else "root")
    if family == "postgres":
        sql = "UPDATE nodes SET status='disabled';"
        return db_exec_remote(
            client,
            compose_dir,
            service,
            f"psql -U {shlex.quote(user)} -d {shlex.quote(db)} -c {shell_single_quote(sql)}",
        )
    return db_exec_remote(
        client,
        compose_dir,
        service,
        f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" {shell_single_quote(db)} -e {shell_single_quote("UPDATE nodes SET status=\'disabled\';")}',
    )


def remote_check_ssl(client: paramiko.SSHClient) -> None:
    env_path = str(PASARGUARD_DIR / ".env")
    code, out, _ = ssh_shell(client, f"test -f {shlex.quote(env_path)} && cat {shlex.quote(env_path)}")
    if code != 0:
        return

    values = {}
    for line in out.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            v = v.strip().strip('"').strip("'")
            values[k.strip()] = v

    missing = []
    for key in ("UVICORN_SSL_CERTFILE", "UVICORN_SSL_KEYFILE"):
        p = values.get(key)
        if p:
            code, _, _ = ssh_shell(client, f"test -f {shlex.quote(p)}")
            if code != 0:
                missing.append((key, p))
    if missing:
        warn("Target .env references missing TLS files. SSL settings were left unchanged.")
        for key, p in missing:
            warn(f"  {key} -> {p}")


def migrate(
    *,
    archive: Optional[Path],
    host: str,
    port: int,
    username: str,
    password: Optional[str],
    key_file: Optional[Path],
    accept_new_host_key: bool,
    force: bool,
    disable_nodes: bool,
) -> None:
    if archive is None:
        archive = backup_create(backup_dir=DEFAULT_BACKUP_DIR)

    connector = SSHConnector(
        host, port, username, password, key_file, accept_new_host_key
    )
    client = None
    try:
        client = connector.connect()
        restore_remote(client, archive, force=force, disable_nodes=disable_nodes)
    finally:
        if client:
            connector.close()

    # Keep the generated backup unless explicitly told otherwise. This is safer
    # than the original behavior, which always deleted it in finally{}.
    success(f"Migration archive kept at: {archive}")


def stream_telegram_file(token: str, chat_id: str, file_path: Path, caption: str = "") -> tuple[bool, str]:
    boundary = "----PasarGuardManager" + uuid.uuid4().hex
    url_host = "api.telegram.org"
    path = f"/bot{token}/sendDocument"

    file_size = file_path.stat().st_size
    filename = file_path.name

    prefix_parts = [
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="chat_id"\r\n\r\n',
        str(chat_id).encode(),
        b"\r\n",
    ]
    if caption:
        prefix_parts += [
            f"--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="caption"\r\n\r\n',
            caption.encode(),
            b"\r\n",
        ]
    prefix_parts += [
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'.encode(),
        b"Content-Type: application/zip\r\n\r\n",
    ]
    suffix = f"\r\n--{boundary}--\r\n".encode()
    total = sum(len(p) for p in prefix_parts) + file_size + len(suffix)

    conn = http.client.HTTPSConnection(url_host, timeout=120)
    try:
        conn.putrequest("POST", path)
        conn.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        conn.putheader("Content-Length", str(total))
        conn.endheaders()

        for part in prefix_parts:
            conn.send(part)

        with file_path.open("rb") as f:
            while True:
                chunk = f.read(SFTP_CHUNK)
                if not chunk:
                    break
                conn.send(chunk)

        conn.send(suffix)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        if resp.status == 200:
            return True, body
        return False, f"Telegram HTTP {resp.status}: {body}"
    except Exception as exc:
        return False, str(exc)
    finally:
        conn.close()


def schedule_telegram(interval_hours: float, token: str, chat_id: str) -> None:
    if interval_hours <= 0:
        raise ValueError("interval-hours must be greater than zero")

    info(f"Telegram scheduler started: every {interval_hours:g} hour(s)")
    try:
        while True:
            started = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            info(f"Starting scheduled backup at {started}")
            try:
                archive = backup_create(backup_dir=DEFAULT_BACKUP_DIR, include_caddy=False)
                ok, details = stream_telegram_file(
                    token,
                    chat_id,
                    archive,
                    f"PasarGuard Manager backup\nDate: {started}\nSHA-256: {sha256_file(archive)}",
                )
                if ok:
                    success("Backup sent to Telegram.")
                    archive.unlink(missing_ok=True)
                else:
                    error(details)
                    warn(f"Local backup was kept at {archive}")
            except Exception as exc:
                error(f"Scheduled backup failed: {exc}")
            time.sleep(interval_hours * 3600)
    except KeyboardInterrupt:
        print()
        warn("Scheduler stopped by user.")


def interactive_menu() -> None:
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        header(f"{APP_NAME} v{VERSION}")
        print(f"{C.CYAN}Author: {AUTHOR}{C.RESET}\n")
        print("  1) 🔎 Preflight / Health Check")
        print("  2) 💾 Create Local Backup")
        print("  3) 🔄 Restore Local Backup")
        print("  4) 🚀 Migrate to New Server")
        print("  5) 🤖 Telegram Backup Scheduler")
        print("  6) 🚪 Exit\n")

        try:
            choice = input(f"{C.CYAN}Select [1-6]: {C.RESET}").strip()
        except EOFError:
            print("\nEOF received. Exiting.")
            return

        try:
            if choice == "1":
                preflight_local()
                input("\nPress ENTER...")
            elif choice == "2":
                db = input("Database [auto/postgres/mysql/sqlite]: ").strip().lower() or None
                archive = backup_create(backup_dir=DEFAULT_BACKUP_DIR, db_family=db)
                print(f"\nBackup: {archive}")
                input("\nPress ENTER...")
            elif choice == "3":
                archive = Path(input("Backup ZIP path: ").strip())
                restore_local(archive, force=False, disable_nodes=ask_yes_no("Disable restored nodes before panel startup?", True))
                input("\nPress ENTER...")
            elif choice == "4":
                host = input("New server IP/hostname: ").strip()
                port_text = input("SSH port [22]: ").strip() or "22"
                username = input("SSH username [root]: ").strip() or "root"
                use_key = input("SSH private key path (leave empty for password): ").strip()
                password = None if use_key else getpass.getpass("SSH password: ")
                archive_choice = input("Use existing backup ZIP path (leave empty to create a new one): ").strip()
                archive = Path(archive_choice) if archive_choice else None
                migrate(
                    archive=archive,
                    host=host,
                    port=int(port_text),
                    username=username,
                    password=password,
                    key_file=Path(use_key) if use_key else None,
                    accept_new_host_key=ask_yes_no("Accept a new SSH host key?", False),
                    force=False,
                    disable_nodes=ask_yes_no("Disable restored nodes before panel startup?", True),
                )
                input("\nPress ENTER...")
            elif choice == "5":
                token = getpass.getpass("Telegram bot token: ")
                chat_id = input("Telegram chat ID: ").strip()
                hours = float(input("Interval hours [6]: ").strip() or "6")
                schedule_telegram(hours, token, chat_id)
            elif choice == "6":
                print("Bye.")
                return
            else:
                warn("Invalid option.")
                time.sleep(1)
        except EOFError:
            print()
            warn("Input stream closed. Exiting.")
            return
        except KeyboardInterrupt:
            print()
            warn("Operation cancelled.")
            time.sleep(1)
        except Exception as exc:
            error(str(exc))
            input("\nPress ENTER...")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pasarguard-manager",
        description="Terminal migration/backup utility for PasarGuard Panel + PG-Node.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command")

    pre = sub.add_parser("check", help="Run local preflight checks")
    pre.add_argument("--db", choices=["postgres", "mysql", "sqlite"], default=None)

    backup = sub.add_parser("backup", help="Create a local backup")
    backup.add_argument("-o", "--output-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    backup.add_argument("--db", choices=["postgres", "mysql", "sqlite"], default=None)
    backup.add_argument("--no-caddy", action="store_true")
    backup.add_argument("--no-nats", action="store_true")

    restore = sub.add_parser("restore", help="Restore a local backup")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--yes", action="store_true")
    restore.add_argument("--no-disable-nodes", action="store_true")

    mig = sub.add_parser("migrate", help="Create/choose backup and migrate it to another server")
    mig.add_argument("--host", required=True)
    mig.add_argument("--port", type=int, default=22)
    mig.add_argument("--user", default="root")
    mig.add_argument("--password", action="store_true", help="Prompt for SSH password")
    mig.add_argument("--key", type=Path, default=None)
    mig.add_argument("--archive", type=Path, default=None)
    mig.add_argument("--accept-new-host-key", action="store_true")
    mig.add_argument("--yes", action="store_true")
    mig.add_argument("--no-disable-nodes", action="store_true")

    tg = sub.add_parser("telegram", help="Run recurring Telegram backups")
    tg.add_argument("--token", default=None)
    tg.add_argument("--chat-id", required=True)
    tg.add_argument("--interval-hours", type=float, default=6.0)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not ensure_root():
        return 1

    if not args.command:
        interactive_menu()
        return 0

    try:
        if args.command == "check":
            return 0 if preflight_local(args.db) else 1

        if args.command == "backup":
            if not preflight_local(args.db):
                return 1
            archive = backup_create(
                backup_dir=args.output_dir,
                db_family=args.db,
                include_caddy=not args.no_caddy,
                include_nats=not args.no_nats,
            )
            print(archive)
            return 0

        if args.command == "restore":
            restore_local(
                args.archive,
                force=args.yes,
                disable_nodes=not args.no_disable_nodes,
            )
            return 0

        if args.command == "migrate":
            password = getpass.getpass("SSH password: ") if args.password or not args.key else None
            migrate(
                archive=args.archive,
                host=args.host,
                port=args.port,
                username=args.user,
                password=password,
                key_file=args.key,
                accept_new_host_key=args.accept_new_host_key,
                force=args.yes,
                disable_nodes=not args.no_disable_nodes,
            )
            return 0

        if args.command == "telegram":
            token = args.token or getpass.getpass("Telegram bot token: ")
            schedule_telegram(args.interval_hours, token, args.chat_id)
            return 0

    except KeyboardInterrupt:
        warn("Operation cancelled.")
        return 130
    except Exception as exc:
        error(str(exc))
        return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""PasarGuard Manager v3 - backup, restore and remote migration utility.

This version is deliberately fail-closed around PostgreSQL/TimescaleDB restores.
It captures the database runtime from the actual application database, pins the
source database image when a digest is available, verifies the required
TimescaleDB extension before importing SQL, and never mutates SSL settings.
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
import shlex
import shutil
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
from typing import Any, Iterable, Optional

try:
    import paramiko
except ImportError as exc:
    print("ERROR: Paramiko is required. Run: python3 -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2) from exc

APP_NAME = "PasarGuard Manager"
VERSION = "3.0.0"
AUTHOR = "Sherlook"

PASARGUARD_DIR = Path("/opt/pasarguard")
PG_NODE_DIR = Path("/opt/pg-node")
PASARGUARD_DATA_DIR = Path("/var/lib/pasarguard")
PG_NODE_DATA_DIR = Path("/var/lib/pg-node")
DEFAULT_REMOTE_DIR = Path("/tmp/pasarguard-manager")

SSH_TIMEOUT = 30
SSH_BANNER_TIMEOUT = 30
DATABASE_RESTORE_TIMEOUT = 3600
SERVICE_READY_TIMEOUT = 180
FILE_CHUNK = 1024 * 1024

POSTGRES_CANDIDATES = ("timescaledb", "postgresql", "postgres")
MYSQL_CANDIDATES = ("mysql", "mariadb")
CERT_PATH_RE = re.compile(r"(/(?:[\w.\-+~]+/)+[\w.\-+~]+\.(?:pem|crt|key|cer))", re.I)


class Color:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


if not (sys.stdout.isatty() and os.environ.get("TERM") != "dumb"):
    for _n in vars(Color):
        if not _n.startswith("_"):
            setattr(Color, _n, "")


def info(msg: str) -> None:
    print(f"{Color.BLUE}ℹ️  [INFO]{Color.RESET} {msg}")


def success(msg: str) -> None:
    print(f"{Color.GREEN}✅ [SUCCESS]{Color.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{Color.YELLOW}⚠️  [WARNING]{Color.RESET} {msg}")


def error(msg: str) -> None:
    print(f"{Color.RED}❌ [ERROR]{Color.RESET} {msg}")


def header(title: str) -> None:
    line = "=" * 72
    print(f"\n{Color.HEADER}{Color.BOLD}{line}{Color.RESET}")
    print(f"{Color.HEADER}{Color.BOLD}{title.center(72)}{Color.RESET}")
    print(f"{Color.HEADER}{Color.BOLD}{line}{Color.RESET}\n")


def confirm(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    value = input(f"{Color.CYAN}{prompt} [{suffix}]: {Color.RESET}").strip().lower()
    return default if not value else value in {"y", "yes"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(FILE_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fmt_bytes(value: int) -> str:
    n = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{value} B"


def require_root() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        error("Run this program as root.")
        return False
    return True


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_local(argv: list[str], *, cwd: Optional[Path] = None, timeout: Optional[int] = None,
              input_data: Optional[bytes] = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, cwd=str(cwd) if cwd else None, stdin=subprocess.PIPE if input_data is not None else None,
                          input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)


def shell_local(command: str, *, cwd: Optional[Path] = None, timeout: Optional[int] = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(command, cwd=str(cwd) if cwd else None, shell=True, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired as exc:
        return 124, "", f"timeout: {exc}"


def shell_quote(value: Any) -> str:
    return shlex.quote(str(value))


def ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = SSH_TIMEOUT) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    channel = stdout.channel
    channel.settimeout(timeout)
    try:
        code = channel.recv_exit_status()
        return code, stdout.read().decode("utf-8", "replace").strip(), stderr.read().decode("utf-8", "replace").strip()
    except socket.timeout:
        return 124, "", "SSH command timed out"


def run_remote_checked(client: paramiko.SSHClient, command: str, description: str,
                       *, timeout: int = SSH_TIMEOUT) -> tuple[str, str]:
    print(f"{Color.CYAN}🌐 [SSH]{Color.RESET} {description}...")
    code, out, err = ssh_exec(client, command, timeout=timeout)
    if code != 0:
        raise RuntimeError(f"{description} failed: {err or out or f'exit {code}'}")
    success("Done.")
    return out, err


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


def pg_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def pg_lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def mysql_lit(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def parse_db_url(url: str) -> dict[str, Optional[str]]:
    parsed = urllib.parse.urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    if scheme.startswith("sqlite"):
        family = "sqlite"
    elif scheme.startswith("postgres"):
        family = "postgres"
    elif scheme.startswith(("mysql", "mariadb")):
        family = "mysql"
    else:
        family = "unknown"
    return {
        "family": family,
        "user": urllib.parse.unquote(parsed.username) if parsed.username else None,
        "password": urllib.parse.unquote(parsed.password) if parsed.password else None,
        "database": urllib.parse.unquote(parsed.path.lstrip("/")) if parsed.path else None,
        "host": parsed.hostname,
        "port": str(parsed.port) if parsed.port else None,
    }


def read_db_config(compose_dir: Path) -> dict[str, Optional[str]]:
    env = env_read(compose_dir / ".env")
    url = env.get("SQLALCHEMY_DATABASE_URL")
    if url:
        cfg = parse_db_url(url)
        if cfg["family"] != "unknown":
            return cfg

    family = "sqlite" if env.get("DATABASE", "").lower() in {"sqlite", "sqlite3"} else "unknown"
    return {
        "family": family,
        "user": env.get("POSTGRES_USER") or env.get("DB_USER") or env.get("MYSQL_USER") or "pasarguard",
        "password": env.get("POSTGRES_PASSWORD") or env.get("DB_PASSWORD") or env.get("MYSQL_PASSWORD"),
        "database": env.get("POSTGRES_DB") or env.get("DB_NAME") or env.get("MYSQL_DATABASE") or "pasarguard",
        "host": None,
        "port": None,
    }


def compose_config(dir_path: Path) -> dict[str, Any]:
    p = run_local(["docker", "compose", "config", "--format", "json"], cwd=dir_path, timeout=60)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).decode(errors="replace").strip() or "Invalid docker compose configuration")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("docker compose returned invalid JSON") from exc


def compose_services(dir_path: Path) -> dict[str, Any]:
    return compose_config(dir_path).get("services") or {}


def database_storage_mounts_from_config(config: dict[str, Any], service: str, family: str) -> list[dict[str, Any]]:
    """Return only persistent DB data mounts, including whether a named volume is external."""
    service_spec = (config.get("services") or {}).get(service) or {}
    top_volumes = config.get("volumes") or {}
    mounts: list[dict[str, Any]] = []
    targets = ("/var/lib/postgresql", "/var/lib/postgresql/data") if family == "postgres" else ("/var/lib/mysql",)
    for raw_item in service_spec.get("volumes") or []:
        item = raw_item
        if isinstance(item, str):
            parts = item.split(":", 2)
            if len(parts) < 2:
                continue
            item = {"type": "bind", "source": parts[0], "target": parts[1]}
        target = str(item.get("target") or "")
        if not any(target == candidate for candidate in targets):
            continue
        kind = str(item.get("type") or "bind")
        source = str(item.get("source") or "")
        external = False
        if kind == "volume":
            # Compose's normalized service mount usually stores the resolved Docker
            # volume name in `source`, while external=true lives in top-level volumes.
            for key, spec in top_volumes.items():
                spec = spec or {}
                resolved_name = str(spec.get("name") or key)
                if source in {str(key), resolved_name}:
                    external = bool(spec.get("external", False))
                    break
            external = external or bool((item.get("volume") or {}).get("external", False))
        mounts.append({
            "type": kind,
            "source": source,
            "target": target,
            "read_only": bool(item.get("read_only", False)),
            "external": external,
        })
    return mounts


def database_storage_mounts_local(dir_path: Path, service: str, family: str) -> list[dict[str, Any]]:
    return database_storage_mounts_from_config(compose_config(dir_path), service, family)


def safe_db_storage_path(path_text: str) -> Path:
    p = Path(path_text).resolve(strict=False)
    allowed = (Path("/var/lib"), Path("/srv"), Path("/data"))
    if not p.is_absolute() or not any(p == base or base in p.parents for base in allowed):
        raise RuntimeError(f"Refusing to modify unsafe database storage path: {path_text}")
    return p


def prepare_db_storage_local(dir_path: Path, service: str, family: str) -> None:
    """Move existing target DB storage out of the way so the logical dump gets a clean cluster."""
    mounts = database_storage_mounts_local(dir_path, service, family)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    for mount in mounts:
        if mount.get("read_only"):
            raise RuntimeError(f"Database storage mount is read-only: {mount['target']}")
        kind = mount.get("type")
        source = str(mount.get("source") or "")
        if kind == "bind":
            path = safe_db_storage_path(source)
            if path.exists() or path.is_symlink():
                backup_root = Path("/var/backups/pasarguard-manager/db-storage")
                backup_root.mkdir(parents=True, exist_ok=True)
                backup = backup_root / f"{path.name}.pgm-old-{stamp}-{uuid.uuid4().hex[:6]}"
                shutil.move(str(path), str(backup))
                info(f"Moved old database storage to {backup}")
            path.mkdir(parents=True, exist_ok=True)
        elif kind == "volume":
            if mount.get("external"):
                raise RuntimeError(f"External Docker volume cannot be replaced safely: {source}")
            if source:
                code, out, err = shell_local(f"docker volume inspect {shell_quote(source)}", timeout=30)
                if code == 0:
                    backup = f"{source}.pgm-old-{stamp}-{uuid.uuid4().hex[:6]}"
                    code, out, err = shell_local(f"docker volume rename {shell_quote(source)} {shell_quote(backup)}", timeout=60)
                    if code != 0:
                        raise RuntimeError(err or out or f"Could not move Docker volume {source}")
                    info(f"Moved old Docker database volume to {backup}")
        # tmpfs and other ephemeral mounts do not carry persistent DB state.


def database_storage_mounts_remote(client: paramiko.SSHClient, dir_path: Path, service: str, family: str) -> list[dict[str, Any]]:
    code, out, err = ssh_exec(client, f"cd {shell_quote(dir_path)} && docker compose config --format json", timeout=60)
    if code != 0:
        raise RuntimeError(err or out or "Could not inspect remote database storage mounts")
    try:
        config = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Remote Docker Compose returned invalid JSON") from exc
    return database_storage_mounts_from_config(config, service, family)


def prepare_db_storage_remote(client: paramiko.SSHClient, dir_path: Path, service: str, family: str) -> None:
    mounts = database_storage_mounts_remote(client, dir_path, service, family)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    for mount in mounts:
        if mount.get("read_only"):
            raise RuntimeError(f"Database storage mount is read-only: {mount['target']}")
        kind = mount.get("type")
        source = str(mount.get("source") or "")
        if kind == "bind":
            # Reuse the same conservative roots as the local implementation.
            path = Path(source).resolve(strict=False)
            allowed = (Path("/var/lib"), Path("/srv"), Path("/data"))
            if not path.is_absolute() or not any(path == base or base in path.parents for base in allowed):
                raise RuntimeError(f"Refusing to modify unsafe remote database storage path: {source}")
            backup = Path(f"/var/backups/pasarguard-manager/db-storage/{path.name}.pgm-old-{stamp}-{uuid.uuid4().hex[:6]}")
            code, out, err = ssh_exec(client, f"mkdir -p /var/backups/pasarguard-manager/db-storage && if test -e {shell_quote(path)} || test -L {shell_quote(path)}; then mv {shell_quote(path)} {shell_quote(backup)}; fi; mkdir -p {shell_quote(path)}", timeout=120)
            if code != 0:
                raise RuntimeError(err or out or f"Could not replace remote database storage {path}")
            info(f"Moved old remote database storage to {backup}")
        elif kind == "volume":
            if mount.get("external"):
                raise RuntimeError(f"External Docker volume cannot be replaced safely: {source}")
            if source:
                backup = f"{source}.pgm-old-{stamp}-{uuid.uuid4().hex[:6]}"
                cmd = f"if docker volume inspect {shell_quote(source)} >/dev/null 2>&1; then docker volume rename {shell_quote(source)} {shell_quote(backup)}; fi"
                code, out, err = ssh_exec(client, cmd, timeout=60)
                if code != 0:
                    raise RuntimeError(err or out or f"Could not move remote Docker volume {source}")
                info(f"Moved old remote Docker database volume to {backup}")


def validate_image_runtime_local(image: str, runtime: dict[str, Any]) -> None:
    """Validate the immutable DB image without mounting the live target database."""
    checks = ["postgres --version", "pg_config --version"]
    if runtime.get("timescaledb_installed"):
        checks.append("pkglib=$(pg_config --pkglibdir); test -f \"$pkglib/timescaledb-%s.so\"" % runtime["timescaledb_version"])
    cmd = " && ".join(checks)
    p = run_local(["docker", "run", "--rm", "--entrypoint", "sh", image, "-c", cmd], timeout=180)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors="replace").strip() or "Source database image failed runtime validation")
    output = p.stdout.decode(errors="replace")
    expected_pg = str(runtime.get("postgres_version_num") or "")
    if expected_pg:
        m = re.search(r"PostgreSQL (\d+)", output)
        if m and m.group(1) != expected_pg[:2]:
            raise RuntimeError(f"PostgreSQL major version mismatch: source {expected_pg}, image {m.group(1)}")


def validate_image_runtime_remote(client: paramiko.SSHClient, image: str, runtime: dict[str, Any]) -> None:
    checks = ["postgres --version", "pg_config --version"]
    if runtime.get("timescaledb_installed"):
        checks.append("pkglib=$(pg_config --pkglibdir); test -f \"$pkglib/timescaledb-%s.so\"" % runtime["timescaledb_version"])
    command = f"docker run --rm --entrypoint sh {shell_quote(image)} -c {shell_single_quote(' && '.join(checks))}"
    code, out, err = ssh_exec(client, command, timeout=180)
    if code != 0:
        raise RuntimeError(err or out or "Source database image failed runtime validation")
    expected_pg = str(runtime.get("postgres_version_num") or "")
    if expected_pg:
        m = re.search(r"PostgreSQL (\d+)", out)
        if m and m.group(1) != expected_pg[:2]:
            raise RuntimeError(f"PostgreSQL major version mismatch: source {expected_pg}, image {m.group(1)}")


def resolve_db_service(dir_path: Path, family: str) -> Optional[str]:
    services = compose_services(dir_path)
    candidates = POSTGRES_CANDIDATES if family == "postgres" else MYSQL_CANDIDATES
    for name in candidates:
        if name in services:
            return name
    for name, spec in services.items():
        image = str(spec.get("image") or "").lower()
        if family == "postgres" and ("postgres" in image or "timescale" in image):
            return name
        if family == "mysql" and ("mysql" in image or "mariadb" in image):
            return name
    return None


def db_exec_local(compose_dir: Path, service: str, command: str, *, timeout: int = 120) -> tuple[int, str, str]:
    cmd = f"docker compose exec -T {shell_quote(service)} sh -c {shell_single_quote(command)}"
    return shell_local(cmd, cwd=compose_dir, timeout=timeout)


def db_exec_remote(client: paramiko.SSHClient, compose_dir: Path, service: str, command: str,
                   *, timeout: int = 120) -> tuple[int, str, str]:
    cmd = f"cd {shell_quote(compose_dir)} && docker compose exec -T {shell_quote(service)} sh -c {shell_single_quote(command)}"
    return ssh_exec(client, cmd, timeout=timeout)


def wait_db_local(compose_dir: Path, service: str, family: str, timeout: int = SERVICE_READY_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if family == "postgres":
            code, _, _ = db_exec_local(compose_dir, service, 'pg_isready -U "$POSTGRES_USER" -d postgres', timeout=15)
        else:
            code, _, _ = db_exec_local(compose_dir, service, 'mysqladmin ping -uroot -p"$MYSQL_ROOT_PASSWORD" --silent', timeout=15)
        if code == 0:
            return True
        time.sleep(2)
    return False


def wait_db_remote(client: paramiko.SSHClient, compose_dir: Path, service: str, family: str,
                   timeout: int = SERVICE_READY_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if family == "postgres":
            inner = 'pg_isready -U "$POSTGRES_USER" -d postgres'
        else:
            inner = 'mysqladmin ping -uroot -p"$MYSQL_ROOT_PASSWORD" --silent'
        code, _, _ = db_exec_remote(client, compose_dir, service, inner, timeout=20)
        if code == 0:
            return True
        time.sleep(2)
    return False


def image_for_container_local(compose_dir: Path, service: str) -> tuple[str, list[str]]:
    code, cid, err = shell_local(f"docker compose ps -q {shell_quote(service)}", cwd=compose_dir, timeout=30)
    if code != 0 or not cid.strip():
        raise RuntimeError(err or "Database container is not running")
    cid = cid.strip().splitlines()[0]
    code, image, err = shell_local(f"docker inspect -f '{{{{.Config.Image}}}}' {shell_quote(cid)}", timeout=30)
    if code != 0 or not image.strip():
        raise RuntimeError(err or "Could not determine database image")
    image = image.strip()
    code, digests, _ = shell_local(f"docker image inspect -f '{{{{join .RepoDigests \",\"}}}}' {shell_quote(image)}", timeout=30)
    repo_digests = [x for x in digests.split(",") if x] if code == 0 and digests.strip() else []
    return image, repo_digests


def capture_postgres_runtime(compose_dir: Path, service: str, database: str) -> dict[str, Any]:
    """Capture runtime facts from the *application DB*, not the postgres maintenance DB."""
    image, digests = image_for_container_local(compose_dir, service)
    pg_sql = (
        "SELECT current_setting('server_version'), current_setting('server_version_num'), "
        "COALESCE((SELECT extversion FROM pg_extension WHERE extname='timescaledb'), ''), "
        "COALESCE((SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace "
        "WHERE e.extname='timescaledb'), ''), "
        "COALESCE(current_setting('shared_preload_libraries', true), '');"
    )
    code, out, err = db_exec_local(
        compose_dir, service,
        f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d {shell_quote(database)} -AtF "|" -c {shell_single_quote(pg_sql)}',
    )
    if code != 0:
        raise RuntimeError(err or out or "Could not inspect PostgreSQL runtime")
    fields = out.strip().splitlines()[0].split("|") if out.strip() else []
    pg_version = fields[0].strip() if len(fields) > 0 else ""
    pg_version_num = fields[1].strip() if len(fields) > 1 else ""
    ts_version = fields[2].strip() if len(fields) > 2 else ""
    ts_schema = fields[3].strip() if len(fields) > 3 else "public"
    preload = fields[4].strip() if len(fields) > 4 else ""

    # If TimescaleDB is installed in the source database, its exact version must be
    # present in the manifest. Missing version is a hard backup failure rather than a
    # reason to continue with a potentially unrecoverable dump.
    if ts_version and not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", ts_version):
        raise RuntimeError(f"Unexpected TimescaleDB extension version: {ts_version}")

    library_rows: list[str] = []
    code, out, err = db_exec_local(
        compose_dir, service,
        "pkglib=$(pg_config --pkglibdir) && find \"$pkglib\" -maxdepth 1 -type f -name 'timescaledb-*.so' -printf '%f\\n' | sort",
    )
    if code == 0:
        library_rows = [line.strip() for line in out.splitlines() if line.strip()]

    runtime: dict[str, Any] = {
        "service": service,
        "image": image,
        "repo_digests": digests,
        "postgres_version": pg_version,
        "postgres_version_num": pg_version_num,
        "timescaledb_installed": bool(ts_version),
        "timescaledb_version": ts_version or None,
        "timescaledb_schema": ts_schema or "public",
        "shared_preload_libraries": preload,
        "timescaledb_libraries": library_rows,
    }
    if runtime["timescaledb_installed"] and not library_rows:
        raise RuntimeError("TimescaleDB is registered in the application database but no timescaledb shared library was found in the source image")
    return runtime


def copy_tree_safe(src: Path, dst: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    skipped: list[tuple[str, str]] = []
    failed: list[tuple[str, str]] = []
    if not src.exists():
        return skipped, failed
    dst.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(src, topdown=True, followlinks=False):
        rp = Path(root)
        rel = rp.relative_to(src)
        out_root = dst / rel
        out_root.mkdir(parents=True, exist_ok=True)
        keep_dirs = []
        for d in dirs:
            sp = rp / d
            tp = out_root / d
            if sp.is_symlink():
                try:
                    if tp.exists() or tp.is_symlink(): tp.unlink()
                    os.symlink(os.readlink(sp), tp)
                except OSError as exc:
                    failed.append((str(sp), str(exc)))
            else:
                keep_dirs.append(d)
        dirs[:] = keep_dirs
        for f in files:
            sp = rp / f
            tp = out_root / f
            mode = os.lstat(sp).st_mode
            if stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                skipped.append((str(sp), stat.filemode(mode)))
                continue
            try:
                if sp.is_symlink():
                    if tp.exists() or tp.is_symlink(): tp.unlink()
                    os.symlink(os.readlink(sp), tp)
                else:
                    shutil.copy2(sp, tp, follow_symlinks=False)
            except OSError as exc:
                failed.append((str(sp), str(exc)))
    return skipped, failed


def add_tree_to_zip(zf: zipfile.ZipFile, root: Path) -> None:
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        arc = str(rel)
        if path.is_symlink():
            zi = zipfile.ZipInfo(arc)
            zi.create_system = 3
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(zi, os.readlink(path).encode())
        elif path.is_dir():
            zi = zipfile.ZipInfo(arc.rstrip("/") + "/")
            zi.create_system = 3
            zi.external_attr = (stat.S_IFDIR | 0o755) << 16
            zf.writestr(zi, b"")
        elif path.is_file():
            zf.write(path, arc)


def safe_extract_zip(archive: Path, dest: Path) -> None:
    dest = dest.resolve()
    with zipfile.ZipFile(archive) as zf:
        bad = zf.testzip()
        if bad:
            raise RuntimeError(f"ZIP CRC failed: {bad}")
        entries = zf.infolist()
        for e in entries:
            target = (dest / e.filename).resolve()
            if os.path.commonpath([str(dest), str(target)]) != str(dest):
                raise RuntimeError(f"Unsafe ZIP member: {e.filename}")
        for e in entries:
            mode = (e.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                continue
            target = dest / e.filename
            if e.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(e) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, FILE_CHUNK)
            perms = stat.S_IMODE(mode)
            if perms:
                try: os.chmod(target, perms)
                except OSError: pass
        for e in entries:
            mode = (e.external_attr >> 16) & 0xFFFF
            if not stat.S_ISLNK(mode): continue
            link = dest / e.filename
            target_text = zf.read(e).decode("utf-8")
            if os.path.isabs(target_text):
                raise RuntimeError(f"Unsafe absolute symlink in backup: {e.filename} -> {target_text}")
            resolved_target = (link.parent / target_text).resolve(strict=False)
            if os.path.commonpath([str(dest), str(resolved_target)]) != str(dest):
                raise RuntimeError(f"Unsafe symlink target in backup: {e.filename} -> {target_text}")
            link.parent.mkdir(parents=True, exist_ok=True)
            if link.exists() or link.is_symlink(): link.unlink()
            os.symlink(target_text, link)


def archive_manifest(archive: Path) -> dict[str, Any]:
    if not archive.is_file():
        raise FileNotFoundError(archive)
    with zipfile.ZipFile(archive) as zf:
        if "manifest.json" not in zf.namelist():
            raise RuntimeError("Backup is missing manifest.json")
        manifest = json.loads(zf.read("manifest.json"))
        if manifest.get("format") != "pasarguard-manager":
            raise RuntimeError("Unknown backup format")
        if int(manifest.get("format_version", 0)) not in {2, 3}:
            raise RuntimeError(f"Unsupported backup format: {manifest.get('format_version')}")
        if zf.testzip():
            raise RuntimeError("Backup ZIP integrity check failed")
        return manifest


def verify_staged_files(root: Path, manifest: dict[str, Any]) -> None:
    for rel, meta in (manifest.get("files") or {}).items():
        path = root / rel
        if not path.is_file():
            raise RuntimeError(f"Backup member missing: {rel}")
        expected_size = int(meta.get("size", -1))
        if path.stat().st_size != expected_size:
            raise RuntimeError(f"Backup size mismatch: {rel}")
        if sha256_file(path) != meta.get("sha256"):
            raise RuntimeError(f"Backup SHA-256 mismatch: {rel}")


def db_admin_sql_remote(client: paramiko.SSHClient, compose_dir: Path, service: str, sql: str) -> tuple[int, str, str]:
    cmd = f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c {shell_single_quote(sql)}'
    return db_exec_remote(client, compose_dir, service, cmd)


def validate_source_runtime(manifest: dict[str, Any]) -> dict[str, Any]:
    runtime = manifest.get("database_runtime") or {}
    family = (manifest.get("database") or {}).get("family")
    if family != "postgres":
        return runtime
    if not runtime.get("image"):
        raise RuntimeError("Backup manifest has no PostgreSQL source image. Refusing remote restore.")
    if runtime.get("timescaledb_installed"):
        version = str(runtime.get("timescaledb_version") or "")
        if not version:
            raise RuntimeError("Backup says TimescaleDB is installed but does not contain its exact extension version. Create a new backup before restoring.")
        libraries = [str(x) for x in (runtime.get("timescaledb_libraries") or [])]
        if not libraries:
            raise RuntimeError("Backup says TimescaleDB is installed but did not record a TimescaleDB library. Refusing restore.")
        expected_library = f"timescaledb-{version}.so"
        if expected_library not in libraries:
            raise RuntimeError(f"Backup TimescaleDB metadata is inconsistent: {expected_library} is missing from recorded libraries.")
    if family == "postgres" and not runtime.get("postgres_version_num"):
        raise RuntimeError("Backup does not contain PostgreSQL server-version metadata. Create a new backup before restoring.")
    return runtime


def backup_nats_volumes_local(output_dir: Path) -> list[dict[str, str]]:
    code, out, _ = shell_local("docker ps -a --format '{{.ID}}\\t{{.Names}}\\t{{.Image}}'")
    if code != 0: return []
    result: dict[str, dict[str, str]] = {}
    for row in out.splitlines():
        parts = row.split("\t")
        if len(parts) != 3: continue
        cid, name, image = parts
        if "nats" not in name.lower() and "nats" not in image.lower(): continue
        code, mounts_json, _ = shell_local(f"docker inspect {shell_quote(cid)} --format '{{{{json .Mounts}}}}'")
        if code != 0: continue
        try: mounts = json.loads(mounts_json)
        except json.JSONDecodeError: continue
        for m in mounts or []:
            if m.get("Type") != "volume" or not m.get("Name") or not m.get("Source"): continue
            result[m["Name"]] = {"container": name, "volume": m["Name"], "mountpoint": m["Source"]}
    return list(result.values())


def tar_volume(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    p = run_local(["tar", "-czf", str(destination), "-C", str(source), "."], timeout=600)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors="replace") or "tar failed")


def extra_cert_paths(compose_dir: Path, data_dir: Path, dumps: Iterable[Path]) -> list[str]:
    found: set[str] = set()
    env = env_read(compose_dir / ".env")
    for key in ("UVICORN_SSL_CERTFILE", "UVICORN_SSL_KEYFILE"):
        if env.get(key): found.add(env[key])
    for dump in dumps:
        try:
            if dump.stat().st_size <= 16 * 1024 * 1024:
                found.update(m.group(1) for m in CERT_PATH_RE.finditer(dump.read_text(errors="ignore")))
        except OSError:
            pass
    for path in data_dir.rglob("*") if data_dir.exists() else []:
        if path.is_file() and path.suffix.lower() in {".json", ".yml", ".yaml", ".conf", ".ini", ".env", ".txt"}:
            try:
                if path.stat().st_size <= 4 * 1024 * 1024:
                    found.update(m.group(1) for m in CERT_PATH_RE.finditer(path.read_text(errors="ignore")))
            except OSError:
                pass
    covered = [PASARGUARD_DIR.resolve(), PG_NODE_DIR.resolve(), PASARGUARD_DATA_DIR.resolve(), PG_NODE_DATA_DIR.resolve()]
    result = []
    for item in sorted(found):
        try:
            p = Path(item).expanduser().resolve()
            if not p.is_file(): continue
            if any(p == base or base in p.parents for base in covered): continue
            result.append(str(p))
        except OSError:
            continue
    return result


def backup_create(output_dir: Path, *, db_override: Optional[str] = None,
                  include_caddy: bool = True, include_nats: bool = True) -> Path:
    if not (PASARGUARD_DIR / "docker-compose.yml").is_file():
        raise RuntimeError(f"Missing {PASARGUARD_DIR}/docker-compose.yml")
    compose_config(PASARGUARD_DIR)
    cfg = read_db_config(PASARGUARD_DIR)
    family = db_override or cfg.get("family") or "unknown"
    if family == "unknown":
        family = "postgres" if resolve_db_service(PASARGUARD_DIR, "postgres") else ("mysql" if resolve_db_service(PASARGUARD_DIR, "mysql") else "unknown")
    if family not in {"postgres", "mysql", "sqlite"}:
        raise RuntimeError("Could not detect database backend")
    if family == "postgres":
        cfg["family"] = "postgres"
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"pasarguard_backup_{timestamp}_{uuid.uuid4().hex[:8]}.zip"
    work = Path(tempfile.mkdtemp(prefix="pgm_backup_", dir="/tmp"))
    try:
        (work / "database").mkdir()
        manifest: dict[str, Any] = {
            "format": "pasarguard-manager",
            "format_version": 3,
            "version": VERSION,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "database": {"family": family, "user": cfg.get("user"), "database": cfg.get("database")},
            "database_runtime": {}, "database_storage": [], "files": {}, "nats": [], "caddy": [], "extra_certs": [],
        }
        shutil.copy2(PASARGUARD_DIR / "docker-compose.yml", work / "docker-compose.yml")
        if (PASARGUARD_DIR / ".env").exists():
            shutil.copy2(PASARGUARD_DIR / ".env", work / ".env")
            os.chmod(work / ".env", 0o600)

        dumps: list[Path] = []
        if family == "postgres":
            service = resolve_db_service(PASARGUARD_DIR, "postgres")
            if not service: raise RuntimeError("PostgreSQL service not found")
            if not wait_db_local(PASARGUARD_DIR, service, "postgres"): raise RuntimeError("PostgreSQL is not ready")
            db = str(cfg.get("database") or "pasarguard")
            user = str(cfg.get("user") or "postgres")
            manifest["database_runtime"] = capture_postgres_runtime(PASARGUARD_DIR, service, db)
            manifest["database_storage"] = database_storage_mounts_local(PASARGUARD_DIR, service, "postgres")
            dump = work / "database" / "pasarguard.sql"
            argv = ["docker", "compose", "exec", "-T", service, "pg_dump", "-U", user, "-d", db]
            with dump.open("wb") as fh:
                p = subprocess.run(argv, cwd=str(PASARGUARD_DIR), stdout=fh, stderr=subprocess.PIPE, timeout=DATABASE_RESTORE_TIMEOUT, check=False)
            if p.returncode != 0 or dump.stat().st_size == 0:
                raise RuntimeError(p.stderr.decode(errors="replace").strip() or "PostgreSQL dump failed")
            dumps.append(dump)
        elif family == "mysql":
            service = resolve_db_service(PASARGUARD_DIR, "mysql")
            if not service: raise RuntimeError("MySQL/MariaDB service not found")
            if not wait_db_local(PASARGUARD_DIR, service, "mysql"): raise RuntimeError("MySQL/MariaDB is not ready")
            db = str(cfg.get("database") or "pasarguard")
            manifest["database_storage"] = database_storage_mounts_local(PASARGUARD_DIR, service, "mysql")
            dump = work / "database" / "pasarguard.sql"
            ok = False
            last = ""
            for tool in ("mariadb-dump", "mysqldump"):
                inner = f'{tool} -uroot -p"$MYSQL_ROOT_PASSWORD" --databases {shell_quote(db)}'
                argv = ["docker", "compose", "exec", "-T", service, "sh", "-c", inner]
                with dump.open("wb") as fh:
                    p = subprocess.run(argv, cwd=str(PASARGUARD_DIR), stdout=fh, stderr=subprocess.PIPE, timeout=DATABASE_RESTORE_TIMEOUT, check=False)
                last = p.stderr.decode(errors="replace").strip()
                if p.returncode == 0 and dump.stat().st_size > 0: ok = True; break
            if not ok: raise RuntimeError(last or "MySQL/MariaDB dump failed")
            dumps.append(dump)

        for src, rel in ((PASARGUARD_DATA_DIR, "pasarguard_data"), (PG_NODE_DIR, "pg_node_opt"), (PG_NODE_DATA_DIR, "pg_node_data")):
            skipped, failed = copy_tree_safe(src, work / rel)
            if failed: raise RuntimeError(f"Failed to copy {src}: {failed[:3]}")
            if skipped: warn(f"Skipped {len(skipped)} special runtime files under {src}")

        for i, source in enumerate(extra_cert_paths(PASARGUARD_DIR, PASARGUARD_DATA_DIR, dumps)):
            dest = work / "extra_certs" / f"cert_{i:03d}" / Path(source).name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)
            manifest["extra_certs"].append({"source": source, "archive_path": str(dest.relative_to(work))})

        if include_nats and env_read(PASARGUARD_DIR / ".env").get("NATS_ENABLED", "false").lower() in {"1", "true", "yes"}:
            for item in backup_nats_volumes_local(work / "nats"):
                manifest["nats"].append(item)

        # Record Caddy bind sources/compose project paths conservatively. Volumes are intentionally handled separately.
        if include_caddy:
            manifest["caddy"] = discover_caddy_sources_local(work / "caddy")

        for path in dumps:
            rel = str(path.relative_to(work))
            manifest["files"][rel] = {"sha256": sha256_file(path), "size": path.stat().st_size}

        (work / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        os.chmod(work / "manifest.json", 0o600)
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            add_tree_to_zip(zf, work)
        archive_manifest(archive)
        success(f"Backup created: {archive} ({fmt_bytes(archive.stat().st_size)})")
        success(f"SHA-256: {sha256_file(archive)}")
        warn("Backups can contain .env, database credentials and private keys. Keep them secret.")
        return archive
    finally:
        shutil.rmtree(work, ignore_errors=True)


def backup_nats_volumes_local(work_root: Path) -> list[dict[str, str]]:
    work_root.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, str]] = []
    for item in backup_nats_volumes_local_raw():
        archive = work_root / item["volume"] / "volume.tar.gz"
        tar_volume(Path(item["mountpoint"]), archive)
        items.append({"volume": item["volume"], "archive_path": str(archive.relative_to(work_root.parent))})
    return items


def backup_nats_volumes_local_raw() -> list[dict[str, str]]:
    code, out, _ = shell_local("docker ps -a --format '{{.ID}}\\t{{.Names}}\\t{{.Image}}'")
    if code != 0: return []
    result: dict[str, dict[str, str]] = {}
    for row in out.splitlines():
        parts = row.split("\t")
        if len(parts) != 3: continue
        cid, name, image = parts
        if "nats" not in name.lower() and "nats" not in image.lower(): continue
        code, mounts, _ = shell_local(f"docker inspect {shell_quote(cid)} --format '{{{{json .Mounts}}}}'")
        if code != 0: continue
        try: mounts = json.loads(mounts)
        except json.JSONDecodeError: continue
        for m in mounts or []:
            if m.get("Type") == "volume" and m.get("Name") and m.get("Source"):
                result[m["Name"]] = {"container": name, "volume": m["Name"], "mountpoint": m["Source"]}
    return list(result.values())


def discover_caddy_sources_local(work_root: Path) -> list[dict[str, str]]:
    """Capture Caddy bind mounts and named volumes without executing container scripts."""
    work_root.mkdir(parents=True, exist_ok=True)
    code, out, _ = shell_local("docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}'")
    if code != 0:
        return []
    result: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    seen_volumes: set[str] = set()
    index = 0
    for row in out.splitlines():
        parts = row.split("\t")
        if len(parts) != 3:
            continue
        cid, name, image = parts
        if "caddy" not in name.lower() and "caddy" not in image.lower():
            continue
        code, mounts, _ = shell_local(f"docker inspect {shell_quote(cid)} --format '{{{{json .Mounts}}}}'")
        if code != 0:
            continue
        try:
            mount_list = json.loads(mounts)
        except json.JSONDecodeError:
            mount_list = []
        for mount in mount_list or []:
            kind = mount.get("Type")
            if kind == "bind" and mount.get("Source"):
                source = Path(str(mount["Source"]))
                if not source.exists():
                    continue
                key = str(source.resolve(strict=False))
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                dest = work_root / f"source_{index:03d}"
                index += 1
                skipped, failed = copy_tree_safe(source, dest) if source.is_dir() else ([], [])
                if source.is_file():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, dest)
                if failed:
                    warn(f"Skipping Caddy source {source}: {failed[:2]}")
                    continue
                result.append({
                    "kind": "path",
                    "source": str(source),
                    "archive_path": str(dest.relative_to(work_root.parent)),
                    "label": name,
                })
                if skipped:
                    result[-1]["skipped_special"] = str(len(skipped))
            elif kind == "volume" and mount.get("Name") and mount.get("Source"):
                volume = str(mount["Name"])
                if volume in seen_volumes:
                    continue
                seen_volumes.add(volume)
                dest = work_root / f"source_{index:03d}" / "volume.tar.gz"
                index += 1
                try:
                    tar_volume(Path(str(mount["Source"])), dest)
                except Exception as exc:
                    warn(f"Skipping Caddy volume {volume}: {exc}")
                    continue
                result.append({
                    "kind": "volume",
                    "volume": volume,
                    "archive_path": str(dest.relative_to(work_root.parent)),
                    "label": name,
                })
    return result


def safe_restore_path(path_text: str) -> Path:
    p = Path(path_text)
    if not p.is_absolute() or p == Path("/"):
        raise RuntimeError(f"Unsafe restore destination: {path_text}")
    # Prevent an archive from replacing critical system directories outside the
    # application's known domains. Certificate paths can still live under /etc,
    # /opt and /var/lib, which covers normal PasarGuard deployments.
    allowed = (Path("/etc"), Path("/opt"), Path("/var/lib"), Path("/var/www"), Path("/usr/local/share"))
    resolved = p.resolve(strict=False)
    if not any(resolved == base or base in resolved.parents for base in allowed):
        raise RuntimeError(f"Restore path is outside allowed application roots: {path_text}")
    return resolved


def compose_down_remote(client: paramiko.SSHClient, dir_path: Path) -> None:
    code, out, err = ssh_exec(client, f"test -f {shell_quote(dir_path / 'docker-compose.yml')}")
    if code != 0: return
    code, out, err = ssh_exec(client, f"cd {shell_quote(dir_path)} && docker compose down --remove-orphans -t 30", timeout=90)
    if code != 0: raise RuntimeError(f"Could not stop compose stack at {dir_path}: {err or out}")


def compose_up_remote(client: paramiko.SSHClient, dir_path: Path, services: Optional[list[str]] = None) -> None:
    suffix = " ".join(shell_quote(x) for x in (services or []))
    code, out, err = ssh_exec(client, f"cd {shell_quote(dir_path)} && docker compose up -d {suffix}".strip(), timeout=300)
    if code != 0: raise RuntimeError(err or out or f"docker compose up failed at {dir_path}")


def resolve_remote_db_service(client: paramiko.SSHClient, dir_path: Path, family: str) -> Optional[str]:
    code, out, err = ssh_exec(client, f"cd {shell_quote(dir_path)} && docker compose config --services", timeout=60)
    if code != 0:
        raise RuntimeError(err or out or "Could not read remote Compose services")
    services = [line.strip() for line in out.splitlines() if line.strip()]
    candidates = POSTGRES_CANDIDATES if family == "postgres" else MYSQL_CANDIDATES
    for name in candidates:
        if name in services:
            return name
    # Fallback to image inspection when service name is customized.
    code, cfg, err = ssh_exec(client, f"cd {shell_quote(dir_path)} && docker compose config --format json", timeout=60)
    if code == 0:
        try:
            data = json.loads(cfg)
            for name, spec in (data.get("services") or {}).items():
                image = str(spec.get("image") or "").lower()
                if family == "postgres" and ("postgres" in image or "timescale" in image):
                    return name
                if family == "mysql" and ("mysql" in image or "mariadb" in image):
                    return name
        except json.JSONDecodeError:
            pass
    return None


def compose_down_local(dir_path: Path) -> None:
    if not (dir_path / "docker-compose.yml").is_file():
        return
    p = run_local(["docker", "compose", "down", "--remove-orphans", "-t", "30"], cwd=dir_path, timeout=90)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).decode(errors="replace").strip() or f"Could not stop stack at {dir_path}")


def compose_up_local(dir_path: Path, services: Optional[list[str]] = None) -> None:
    suffix = services or []
    p = run_local(["docker", "compose", "up", "-d", *suffix], cwd=dir_path, timeout=300)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).decode(errors="replace").strip() or f"Could not start stack at {dir_path}")


def prepare_local_db_image(dir_path: Path, service: str, runtime: dict[str, Any]) -> None:
    image = str(runtime.get("image") or "")
    digests = [str(x) for x in (runtime.get("repo_digests") or []) if str(x)]
    if not image:
        raise RuntimeError("Source database image is missing from backup manifest")
    exact = digests[0] if digests else image
    p = run_local(["docker", "pull", exact], timeout=900)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors="replace").strip() or "Could not pull source database image")
    if digests:
        p = run_local(["docker", "tag", exact, image], timeout=60)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode(errors="replace").strip() or "Could not tag exact source database image")
    elif image:
        warn("Source DB image has no immutable RepoDigest; validating the recorded image tag only.")
    validate_image_runtime_local(image, runtime)


def compose_stack_healthy_remote(client: paramiko.SSHClient, dir_path: Path) -> bool:
    code, out, err = ssh_exec(client, f"cd {shell_quote(dir_path)} && docker compose ps --format json", timeout=30)
    if code != 0 or not out: return False
    try:
        rows = json.loads(out)
        rows = [rows] if isinstance(rows, dict) else rows
    except json.JSONDecodeError:
        return "Up" in out or "running" in out.lower()
    for row in rows:
        state = str(row.get("State") or row.get("state") or "").lower()
        health = str(row.get("Health") or row.get("health") or "").lower()
        if state != "running": return False
        if health and health not in {"healthy", "running"}: return False
    return bool(rows)


def remote_prepare_db_image(client: paramiko.SSHClient, compose_dir: Path, service: str, runtime: dict[str, Any]) -> None:
    image = str(runtime.get("image") or "")
    digests = [str(x) for x in (runtime.get("repo_digests") or []) if str(x)]
    if not image:
        raise RuntimeError("Source database image is missing from backup manifest")
    if digests:
        exact = digests[0]
        code, out, err = ssh_exec(client, f"docker pull {shell_quote(exact)}", timeout=900)
        if code != 0:
            raise RuntimeError(f"Could not pull exact source database image {exact}: {err or out}")
        code, out, err = ssh_exec(client, f"docker tag {shell_quote(exact)} {shell_quote(image)}", timeout=60)
        if code != 0:
            raise RuntimeError(f"Could not tag exact source image for Compose: {err or out}")
    else:
        warn("Source DB image has no immutable RepoDigest; validating the recorded image tag only.")
        code, out, err = ssh_exec(client, f"docker pull {shell_quote(image)}", timeout=900)
        if code != 0:
            raise RuntimeError(f"Could not pull source database image {image}: {err or out}")
    validate_image_runtime_remote(client, image, runtime)


def prepare_timescaledb_target(client: paramiko.SSHClient, compose_dir: Path, service: str,
                               database: str, runtime: dict[str, Any]) -> None:
    if not runtime.get("timescaledb_installed"): return
    version = str(runtime.get("timescaledb_version") or "")
    schema = str(runtime.get("timescaledb_schema") or "public")
    sql = (
        f"CREATE SCHEMA IF NOT EXISTS {pg_ident(schema)}; "
        f"CREATE EXTENSION IF NOT EXISTS timescaledb WITH SCHEMA {pg_ident(schema)} VERSION {pg_lit(version)};"
    )
    code, out, err = db_exec_remote(client, compose_dir, service,
                                     f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d {shell_quote(database)} -c {shell_single_quote(sql)}')
    if code != 0: raise RuntimeError(f"Could not create TimescaleDB {version} in target database: {err or out}")
    # These hooks are only used when the installed version exposes them.
    hook_sql = "SELECT to_regprocedure('timescaledb_pre_restore()') IS NOT NULL;"
    code, out, err = db_exec_remote(client, compose_dir, service,
                                     f'psql -U "$POSTGRES_USER" -d {shell_quote(database)} -Atc {shell_single_quote(hook_sql)}')
    if code == 0 and out.strip().lower() == "t":
        code, out, err = db_exec_remote(client, compose_dir, service,
                                         f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d {shell_quote(database)} -c "SELECT {pg_ident(schema)}.timescaledb_pre_restore();"')
        if code != 0: raise RuntimeError(f"TimescaleDB pre-restore hook failed: {err or out}")


def finish_timescaledb_target(client: paramiko.SSHClient, compose_dir: Path, service: str,
                              database: str, runtime: dict[str, Any]) -> None:
    if not runtime.get("timescaledb_installed"): return
    schema = str(runtime.get("timescaledb_schema") or "public")
    hook_sql = "SELECT to_regprocedure('timescaledb_post_restore()') IS NOT NULL;"
    code, out, err = db_exec_remote(client, compose_dir, service,
                                     f'psql -U "$POSTGRES_USER" -d {shell_quote(database)} -Atc {shell_single_quote(hook_sql)}')
    if code == 0 and out.strip().lower() == "t":
        code, out, err = db_exec_remote(client, compose_dir, service,
                                         f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d {shell_quote(database)} -c "SELECT {pg_ident(schema)}.timescaledb_post_restore();"')
        if code != 0: raise RuntimeError(f"TimescaleDB post-restore hook failed: {err or out}")


def restore_mysql_local(compose_dir: Path, service: str, cfg: dict[str, Optional[str]], dump_path: Path) -> None:
    db = str(cfg.get("database") or "pasarguard")
    code, out, err = db_exec_local(compose_dir, service,
                                    f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "DROP DATABASE IF EXISTS `{db.replace("`", "``")}`; CREATE DATABASE `{db.replace("`", "``")}`;"')
    if code != 0: raise RuntimeError(err or out or "Could not recreate local MySQL database")
    p = run_local(["docker", "compose", "exec", "-T", service, "sh", "-c", f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" {shell_quote(db)}'],
                  cwd=compose_dir, timeout=DATABASE_RESTORE_TIMEOUT, input_data=dump_path.read_bytes())
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors="replace").strip() or "Local MySQL restore failed")


def restore_postgres_remote(client: paramiko.SSHClient, compose_dir: Path, service: str,
                            cfg: dict[str, Optional[str]], dump_path: Path, runtime: dict[str, Any]) -> None:
    db = str(cfg.get("database") or "pasarguard")
    user = str(cfg.get("user") or "postgres")
    if user != "postgres":
        sql = f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname={pg_lit(user)}) THEN CREATE ROLE {pg_ident(user)} LOGIN; END IF; END $$;"
        if cfg.get("password"):
            sql += f" ALTER ROLE {pg_ident(user)} PASSWORD {pg_lit(str(cfg['password']))};"
        code, out, err = db_admin_sql_remote(client, compose_dir, service, sql)
        if code != 0: raise RuntimeError(err or out or "Could not prepare PostgreSQL role")
    code, out, err = db_admin_sql_remote(client, compose_dir, service,
                                         f"DROP DATABASE IF EXISTS {pg_ident(db)} WITH (FORCE); CREATE DATABASE {pg_ident(db)} OWNER {pg_ident(user)};")
    if code != 0: raise RuntimeError(err or out or "Could not recreate PostgreSQL database")
    prepare_timescaledb_target(client, compose_dir, service, db, runtime)
    # Feed SQL directly into psql from the remote host; no shell expansion of the dump itself.
    command = (
        f"cd {shell_quote(compose_dir)} && "
        f"cat {shell_quote(dump_path)} | docker compose exec -T {shell_quote(service)} "
        f"psql -v ON_ERROR_STOP=1 -U {shell_quote(user)} -d {shell_quote(db)}"
    )
    code, out, err = ssh_exec(client, command, timeout=DATABASE_RESTORE_TIMEOUT)
    if code != 0:
        raise RuntimeError(f"PostgreSQL restore failed: {err or out or f'exit {code}'}")
    finish_timescaledb_target(client, compose_dir, service, db, runtime)

    # Final extension version check: catch stale $libdir references before the stack starts.
    sql = "SELECT COALESCE((SELECT extversion FROM pg_extension WHERE extname='timescaledb'), '');"
    code, out, err = db_exec_remote(client, compose_dir, service,
                                    f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d {shell_quote(db)} -Atc {shell_single_quote(sql)}')
    if code != 0: raise RuntimeError(err or out or "Could not verify restored TimescaleDB extension")
    actual = out.strip().splitlines()[0].strip() if out.strip() else ""
    expected = str(runtime.get("timescaledb_version") or "")
    if runtime.get("timescaledb_installed") and actual != expected:
        raise RuntimeError(f"Restored TimescaleDB extension version is {actual or 'missing'}, expected {expected}")


def restore_postgres_local(compose_dir: Path, service: str, cfg: dict[str, Optional[str]],
                            dump_path: Path, runtime: dict[str, Any]) -> None:
    db = str(cfg.get("database") or "pasarguard")
    user = str(cfg.get("user") or "postgres")
    if user != "postgres":
        sql = f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname={pg_lit(user)}) THEN CREATE ROLE {pg_ident(user)} LOGIN; END IF; END $$;"
        if cfg.get("password"):
            sql += f" ALTER ROLE {pg_ident(user)} PASSWORD {pg_lit(str(cfg['password']))};"
        code, out, err = db_admin_sql_local(compose_dir, service, sql)
        if code != 0: raise RuntimeError(err or out or "Could not prepare local PostgreSQL role")
    code, out, err = db_admin_sql_local(compose_dir, service,
                                         f"DROP DATABASE IF EXISTS {pg_ident(db)} WITH (FORCE); CREATE DATABASE {pg_ident(db)} OWNER {pg_ident(user)};")
    if code != 0: raise RuntimeError(err or out or "Could not recreate local PostgreSQL database")
    if runtime.get("timescaledb_installed"):
        version = str(runtime.get("timescaledb_version") or "")
        schema = str(runtime.get("timescaledb_schema") or "public")
        sql = f"CREATE SCHEMA IF NOT EXISTS {pg_ident(schema)}; CREATE EXTENSION IF NOT EXISTS timescaledb WITH SCHEMA {pg_ident(schema)} VERSION {pg_lit(version)};"
        code, out, err = db_exec_local(compose_dir, service, f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d {shell_quote(db)} -c {shell_single_quote(sql)}')
        if code != 0: raise RuntimeError(f"Could not create local TimescaleDB {version}: {err or out}")
    command = ["docker", "compose", "exec", "-T", service, "psql", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", db]
    p = run_local(command, cwd=compose_dir, timeout=DATABASE_RESTORE_TIMEOUT, input_data=dump_path.read_bytes())
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors="replace").strip() or "Local PostgreSQL restore failed")
    sql = "SELECT COALESCE((SELECT extversion FROM pg_extension WHERE extname='timescaledb'), '');"
    code, out, err = db_exec_local(compose_dir, service, f'psql -U "$POSTGRES_USER" -d {shell_quote(db)} -Atc {shell_single_quote(sql)}')
    if code != 0: raise RuntimeError(err or out or "Could not verify local TimescaleDB")
    if runtime.get("timescaledb_installed") and (not out.strip() or out.strip().splitlines()[0].strip() != str(runtime.get("timescaledb_version"))):
        raise RuntimeError("Local TimescaleDB extension version does not match the backup")


def db_admin_sql_local(compose_dir: Path, service: str, sql: str) -> tuple[int, str, str]:
    return db_exec_local(compose_dir, service, f'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c {shell_single_quote(sql)}')


def restore_mysql_remote(client: paramiko.SSHClient, compose_dir: Path, service: str,
                         cfg: dict[str, Optional[str]], dump_path: Path) -> None:
    db = str(cfg.get("database") or "pasarguard")
    code, out, err = db_exec_remote(client, compose_dir, service,
                                     f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "DROP DATABASE IF EXISTS `{db.replace("`", "``")}`; CREATE DATABASE `{db.replace("`", "``")}`;"')
    if code != 0: raise RuntimeError(err or out or "Could not recreate MySQL database")
    command = (f"cd {shell_quote(compose_dir)} && cat {shell_quote(dump_path)} | "
               f"docker compose exec -T {shell_quote(service)} sh -c {shell_single_quote(f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" {shell_quote(db)}')}")
    code, out, err = ssh_exec(client, command, timeout=DATABASE_RESTORE_TIMEOUT)
    if code != 0: raise RuntimeError(err or out or "MySQL restore failed")


def write_remote_extract_script() -> str:
    return r'''python3 - "$1" "$2" <<'PY'
import json, os, stat, sys, zipfile
archive, dest = sys.argv[1], os.path.realpath(sys.argv[2])
os.makedirs(dest, exist_ok=True)
with zipfile.ZipFile(archive) as z:
    bad = z.testzip()
    if bad: raise SystemExit(f"CRC failed: {bad}")
    items = z.infolist()
    for i in items:
        target = os.path.realpath(os.path.join(dest, i.filename))
        if os.path.commonpath([dest, target]) != dest:
            raise SystemExit(f"Unsafe archive member: {i.filename}")
    for i in items:
        mode = (i.external_attr >> 16) & 0xffff
        if stat.S_ISLNK(mode): continue
        target = os.path.join(dest, i.filename)
        if i.is_dir(): os.makedirs(target, exist_ok=True); continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with z.open(i) as src, open(target, "wb") as dst:
            while True:
                chunk = src.read(1024*1024)
                if not chunk: break
                dst.write(chunk)
    for i in items:
        mode = (i.external_attr >> 16) & 0xffff
        if not stat.S_ISLNK(mode): continue
        target = os.path.join(dest, i.filename)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.lexists(target): os.unlink(target)
        os.symlink(z.read(i).decode(), target)
PY'''


def validate_remote_manifest(client: paramiko.SSHClient, extract_dir: Path) -> dict[str, Any]:
    script = (
        "python3 - <<'PY'\n"
        "import hashlib,json,pathlib\n"
        f"root=pathlib.Path({str(extract_dir)!r})\n"
        "m=json.loads((root/'manifest.json').read_text())\n"
        "assert m.get('format')=='pasarguard-manager'\n"
        "assert int(m.get('format_version',0)) in (2,3)\n"
        "for rel,meta in (m.get('files') or {}).items():\n"
        " p=root/rel\n"
        " if not p.is_file(): raise SystemExit('missing: '+rel)\n"
        " if p.stat().st_size != int(meta.get('size',-1)): raise SystemExit('size mismatch: '+rel)\n"
        " h=hashlib.sha256(p.read_bytes()).hexdigest()\n"
        " if h != meta.get('sha256'): raise SystemExit('checksum mismatch: '+rel)\n"
        "print(json.dumps(m))\n"
        "PY"
    )
    out, _ = run_remote_checked(client, script, "Verifying backup manifest and database checksums", timeout=120)
    return json.loads(out.splitlines()[-1])


def restore_remote_tar_volume(client: paramiko.SSHClient, volume: str, archive_path: Path) -> None:
    code, out, err = ssh_exec(client, f"docker volume create {shell_quote(volume)} >/dev/null && docker volume inspect {shell_quote(volume)} --format '{{{{.Mountpoint}}}}'", timeout=60)
    if code != 0 or not out:
        raise RuntimeError(f"Could not create/inspect Docker volume {volume}: {err or out}")
    mountpoint = out.strip()
    code, out, err = ssh_exec(client, f"tar -xzf {shell_quote(archive_path)} -C {shell_quote(mountpoint)}", timeout=600)
    if code != 0:
        raise RuntimeError(f"Could not restore Docker volume {volume}: {err or out}")


def restore_caddy_remote(client: paramiko.SSHClient, extract_dir: Path, manifest: dict[str, Any]) -> None:
    for item in manifest.get("caddy", []):
        if item.get("kind") == "volume":
            restore_remote_tar_volume(client, str(item["volume"]), extract_dir / item["archive_path"])
            continue
        src = extract_dir / item["archive_path"]
        dst = safe_restore_path(str(item["source"]))
        code, out, err = ssh_exec(client, f"rm -rf {shell_quote(dst)} && mkdir -p {shell_quote(dst.parent)} && cp -a {shell_quote(src)} {shell_quote(dst)}", timeout=300)
        if code != 0:
            raise RuntimeError(f"Could not restore Caddy data {dst}: {err or out}")


def restore_nats_remote(client: paramiko.SSHClient, extract_dir: Path, manifest: dict[str, Any]) -> None:
    for item in manifest.get("nats", []):
        restore_remote_tar_volume(client, str(item["volume"]), extract_dir / item["archive_path"])


def restore_remote(client: paramiko.SSHClient, archive: Path, *, force: bool, disable_nodes: bool) -> None:
    archive_manifest_local = archive_manifest(archive)
    runtime = validate_source_runtime(archive_manifest_local)
    remote_root = DEFAULT_REMOTE_DIR
    remote_archive = remote_root / archive.name
    run_remote_checked(client, f"mkdir -p {shell_quote(remote_root)}", "Creating remote staging directory")
    info(f"Uploading {archive.name}...")
    sftp = client.open_sftp()
    try:
        with archive.open("rb") as src, sftp.file(str(remote_archive), "wb") as dst:
            while True:
                chunk = src.read(FILE_CHUNK)
                if not chunk: break
                dst.write(chunk)
        remote_size = sftp.stat(str(remote_archive)).st_size
    finally:
        sftp.close()
    if remote_size != archive.stat().st_size: raise RuntimeError("Remote backup size does not match local archive")
    code, out, err = ssh_exec(client, f"sha256sum {shell_quote(remote_archive)}", timeout=120)
    if code != 0 or not out: raise RuntimeError(err or "Remote SHA-256 failed")
    remote_hash = out.split()[0]
    local_hash = sha256_file(archive)
    if remote_hash != local_hash: raise RuntimeError("Remote SHA-256 differs from local backup")
    success(f"Upload verified: {local_hash}")

    extract_dir = remote_root / "extracted"
    script = write_remote_extract_script().replace("\"$1\"", shell_quote(remote_archive)).replace("\"$2\"", shell_quote(extract_dir))
    run_remote_checked(client, f"rm -rf {shell_quote(extract_dir)} && mkdir -p {shell_quote(extract_dir)} && {script}", "Extracting backup archive", timeout=180)
    manifest = validate_remote_manifest(client, extract_dir)
    runtime = validate_source_runtime(manifest)

    if not force:
        header("REMOTE DESTRUCTIVE RESTORE")
        print(f"Target: {client.get_transport().getpeername()[0]}")
        print(f"Database: {manifest.get('database', {})}")
        if not confirm("Overwrite the remote PasarGuard installation?", False):
            warn("Restore cancelled")
            return

    family = str((manifest.get("database") or {}).get("family") or "unknown")
    if family not in {"postgres", "mysql", "sqlite"}: raise RuntimeError(f"Unsupported database family in backup: {family}")

    # Copy only compose/.env first; do not destroy the live install before the
    # database image and extension preflight succeeds.
    run_remote_checked(client, f"mkdir -p {shell_quote(PASARGUARD_DIR)} && cp -a {shell_quote(extract_dir / 'docker-compose.yml')} {shell_quote(PASARGUARD_DIR / 'docker-compose.yml')} && "
                      f"if test -f {shell_quote(extract_dir / '.env')}; then cp -a {shell_quote(extract_dir / '.env')} {shell_quote(PASARGUARD_DIR / '.env')}; fi",
                      "Installing restored compose configuration")

    service = resolve_remote_db_service(client, PASARGUARD_DIR, family)
    if family in {"postgres", "mysql"} and not service: raise RuntimeError("Could not resolve restored database service")

    if family == "postgres":
        # Pull/recreate exact DB image BEFORE destructive data operations.
        run_remote_checked(client, f"cd {shell_quote(PASARGUARD_DIR)} && docker compose config --quiet", "Validating restored Docker Compose configuration", timeout=60)
        remote_prepare_db_image(client, PASARGUARD_DIR, service, runtime)
    elif family == "mysql":
        code, out, err = ssh_exec(client, f"cd {shell_quote(PASARGUARD_DIR)} && docker compose pull {shell_quote(service)}", timeout=900)
        if code != 0: raise RuntimeError(err or out or "Could not pull MySQL image")

    # Now that the DB runtime is known to be compatible, stop and replace app data.
    compose_down_remote(client, PG_NODE_DIR)
    compose_down_remote(client, PASARGUARD_DIR)
    if family in {"postgres", "mysql"}:
        prepare_db_storage_remote(client, PASARGUARD_DIR, service, family)
    run_remote_checked(client,
                      "rm -rf /opt/pasarguard /opt/pg-node /var/lib/pasarguard /var/lib/pg-node && "
                      "mkdir -p /opt/pasarguard /opt/pg-node /var/lib/pasarguard /var/lib/pg-node",
                      "Preparing target filesystem")
    # Reinstall compose/env and filesystem payloads after the cleanup.
    run_remote_checked(client, f"cp -a {shell_quote(extract_dir / 'docker-compose.yml')} {shell_quote(PASARGUARD_DIR / 'docker-compose.yml')} && "
                      f"if test -f {shell_quote(extract_dir / '.env')}; then cp -a {shell_quote(extract_dir / '.env')} {shell_quote(PASARGUARD_DIR / '.env')}; fi",
                      "Restoring Docker Compose and environment")
    for src_name, dst, label in (("pasarguard_data", PASARGUARD_DATA_DIR, "PasarGuard data"),
                                 ("pg_node_opt", PG_NODE_DIR, "PG-Node config"),
                                 ("pg_node_data", PG_NODE_DATA_DIR, "PG-Node data")):
        src = extract_dir / src_name
        if src.is_dir():
            run_remote_checked(client, f"cp -a {shell_quote(src)}/. {shell_quote(dst)}/", f"Restoring {label}", timeout=300)

    for item in manifest.get("extra_certs", []):
        src = extract_dir / item["archive_path"]
        dst = safe_restore_path(item["source"])
        run_remote_checked(client, f"mkdir -p {shell_quote(dst.parent)} && cp -a {shell_quote(src)} {shell_quote(dst)}", f"Restoring certificate {dst}")

    restore_caddy_remote(client, extract_dir, manifest)
    restore_nats_remote(client, extract_dir, manifest)

    # Restore the DB now that all target paths are stable.
    cfg = read_db_config(PASARGUARD_DIR)
    db_service = resolve_remote_db_service(client, PASARGUARD_DIR, family)
    if family == "postgres":
        # The exact image was already verified; start the service without pulling a new image.
        run_remote_checked(client, f"cd {shell_quote(PASARGUARD_DIR)} && docker compose up -d {shell_quote(db_service)}", "Starting PostgreSQL/TimescaleDB", timeout=300)
        if not wait_db_remote(client, PASARGUARD_DIR, db_service, "postgres"): raise RuntimeError("PostgreSQL did not become ready")
        restore_postgres_remote(client, PASARGUARD_DIR, db_service, cfg, extract_dir / "database" / "pasarguard.sql", runtime)
    elif family == "mysql":
        run_remote_checked(client, f"cd {shell_quote(PASARGUARD_DIR)} && docker compose up -d {shell_quote(db_service)}", "Starting MySQL/MariaDB", timeout=300)
        if not wait_db_remote(client, PASARGUARD_DIR, db_service, "mysql"): raise RuntimeError("MySQL/MariaDB did not become ready")
        restore_mysql_remote(client, PASARGUARD_DIR, db_service, cfg, extract_dir / "database" / "pasarguard.sql")

    if disable_nodes and family in {"postgres", "mysql"}:
        try:
            if family == "postgres":
                sql = "UPDATE nodes SET status='disabled';"
                code, out, err = db_exec_remote(client, PASARGUARD_DIR, db_service,
                                                 f'psql -U "$POSTGRES_USER" -d {shell_quote(str(cfg.get("database") or "pasarguard"))} -c {shell_single_quote(sql)}')
            else:
                code, out, err = db_exec_remote(client, PASARGUARD_DIR, db_service,
                                                 f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" {shell_quote(str(cfg.get("database") or "pasarguard"))} -e {shell_single_quote("UPDATE nodes SET status=\'disabled\';")}')
            if code == 0: info("Restored nodes were disabled before panel startup")
            else: warn(f"Could not disable restored nodes: {err or out}")
        except Exception as exc:
            warn(f"Could not disable restored nodes: {exc}")

    # Final stack start and health check. We do not rewrite SSL configuration.
    run_remote_checked(client, f"cd {shell_quote(PASARGUARD_DIR)} && docker compose up -d", "Starting PasarGuard stack", timeout=300)
    if not compose_stack_healthy_remote(client, PASARGUARD_DIR):
        code, out, err = ssh_exec(client, f"cd {shell_quote(PASARGUARD_DIR)} && docker compose ps && docker compose logs --tail=120", timeout=120)
        raise RuntimeError("PasarGuard stack is not healthy after restore. " + (out or err or ""))

    if await_remote_file(client, PG_NODE_DIR / "docker-compose.yml"):
        compose_up_remote(client, PG_NODE_DIR)

    run_remote_checked(client, f"rm -rf {shell_quote(remote_root)}", "Cleaning remote temporary restore files")
    success("Remote restore completed and the PasarGuard stack is healthy")


def await_remote_file(client: paramiko.SSHClient, path: Path) -> bool:
    code, _, _ = ssh_exec(client, f"test -f {shell_quote(path)}")
    return code == 0


class SSHConnector:
    def __init__(self, host: str, port: int, username: str, password: Optional[str], key: Optional[Path], accept_new: bool):
        self.host, self.port, self.username = host, port, username
        self.password, self.key = password, key
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy() if accept_new else paramiko.RejectPolicy())

    def connect(self) -> paramiko.SSHClient:
        self.client.connect(hostname=self.host, port=self.port, username=self.username, password=self.password,
                            key_filename=str(self.key) if self.key else None, timeout=SSH_TIMEOUT,
                            auth_timeout=SSH_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT, look_for_keys=True, allow_agent=True)
        success(f"SSH connected to {self.host}:{self.port}")
        return self.client

    def close(self) -> None:
        self.client.close()


def migrate(archive: Optional[Path], host: str, port: int, username: str, password: Optional[str],
            key: Optional[Path], accept_new: bool, force: bool, disable_nodes: bool) -> None:
    if archive is None:
        archive = backup_create(Path.cwd())
    manifest = archive_manifest(archive)
    validate_source_runtime(manifest)
    connector = SSHConnector(host, port, username, password, key, accept_new)
    client = None
    try:
        client = connector.connect()
        restore_remote(client, archive, force=force, disable_nodes=disable_nodes)
    finally:
        if client: connector.close()
    success(f"Migration archive kept at: {archive}")


def stream_telegram_file(token: str, chat_id: str, path: Path, caption: str = "") -> tuple[bool, str]:
    boundary = "----PasarGuardManager" + uuid.uuid4().hex
    host = "api.telegram.org"
    request_path = f"/bot{token}/sendDocument"
    size = path.stat().st_size
    parts = [f"--{boundary}\r\n".encode(), b'Content-Disposition: form-data; name="chat_id"\r\n\r\n', chat_id.encode(), b"\r\n"]
    if caption:
        parts += [f"--{boundary}\r\n".encode(), b'Content-Disposition: form-data; name="caption"\r\n\r\n', caption.encode(), b"\r\n"]
    parts += [f"--{boundary}\r\n".encode(), f'Content-Disposition: form-data; name="document"; filename="{path.name}"\r\n'.encode(), b"Content-Type: application/zip\r\n\r\n"]
    suffix = f"\r\n--{boundary}--\r\n".encode()
    conn = http.client.HTTPSConnection(host, timeout=120)
    try:
        conn.putrequest("POST", request_path)
        conn.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        conn.putheader("Content-Length", str(sum(map(len, parts)) + size + len(suffix)))
        conn.endheaders()
        for part in parts: conn.send(part)
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(FILE_CHUNK), b""): conn.send(chunk)
        conn.send(suffix)
        resp = conn.getresponse(); body = resp.read().decode("utf-8", "replace")
        return resp.status == 200, body
    except Exception as exc:
        return False, str(exc)
    finally:
        conn.close()


def preflight_local(db_override: Optional[str] = None) -> bool:
    problems = [cmd for cmd in ("docker", "tar") if not command_exists(cmd)]
    if not (PASARGUARD_DIR / "docker-compose.yml").is_file(): problems.append(str(PASARGUARD_DIR / "docker-compose.yml"))
    if problems:
        for item in problems: error(f"Missing prerequisite: {item}")
        return False
    try:
        compose_config(PASARGUARD_DIR)
    except Exception as exc:
        error(str(exc)); return False
    cfg = read_db_config(PASARGUARD_DIR)
    family = db_override or cfg.get("family") or "unknown"
    if family == "unknown": family = "postgres" if resolve_db_service(PASARGUARD_DIR, "postgres") else ("mysql" if resolve_db_service(PASARGUARD_DIR, "mysql") else "unknown")
    info(f"Database backend: {family}")
    if family in {"postgres", "mysql"}:
        service = resolve_db_service(PASARGUARD_DIR, family)
        if not service: error("Database service not found"); return False
        info(f"Database service: {service}")
    if family not in {"postgres", "mysql", "sqlite"}: error("Unsupported database backend"); return False
    total, used, free = shutil.disk_usage("/")
    info(f"Disk: {fmt_bytes(used)} used / {fmt_bytes(total)} total / {fmt_bytes(free)} free")
    return True


def selftest() -> int:
    header("SELF-TEST")
    assert parse_db_url("postgresql://user:pass@example/db") ["family"] == "postgres"
    assert parse_db_url("mysql://u:p@db/name")["family"] == "mysql"
    assert parse_db_url("sqlite:///var/lib/pasarguard/db.sqlite")["family"] == "sqlite"
    temp = Path(tempfile.mkdtemp(prefix="pgm_test_"))
    try:
        work = temp / "work"; work.mkdir()
        (work / "manifest.json").write_text(json.dumps({"format":"pasarguard-manager","format_version":3,"files":{}}))
        archive = temp / "test.zip"
        with zipfile.ZipFile(archive, "w") as zf: add_tree_to_zip(zf, work)
        assert archive_manifest(archive)["format_version"] == 3
        safe_extract_zip(archive, temp / "extract")
        bad = temp / "bad.zip"
        with zipfile.ZipFile(bad, "w") as zf: zf.writestr("../escape", "x")
        try:
            safe_extract_zip(bad, temp / "extract2")
        except RuntimeError:
            pass
        else:
            raise AssertionError("path traversal was not blocked")
    finally:
        shutil.rmtree(temp, ignore_errors=True)
    print("All self-tests passed.")
    return 0


def interactive() -> int:
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        header(f"{APP_NAME} v{VERSION}")
        print("  1) Preflight / Health Check")
        print("  2) Create Backup")
        print("  3) Restore Backup")
        print("  4) Migrate to New Server")
        print("  5) Telegram Backup")
        print("  6) Self-test")
        print("  7) Exit\n")
        try: choice = input("Select [1-7]: ").strip()
        except EOFError: return 0
        try:
            if choice == "1": preflight_local(); input("\nPress ENTER...")
            elif choice == "2": print(backup_create(Path.cwd())) ; input("\nPress ENTER...")
            elif choice == "3": restore_cmd()
            elif choice == "4": migrate_cmd()
            elif choice == "5": telegram_cmd()
            elif choice == "6": selftest(); input("\nPress ENTER...")
            elif choice == "7": return 0
            else: warn("Invalid choice")
        except KeyboardInterrupt: warn("Cancelled")
        except Exception as exc: error(str(exc)); input("\nPress ENTER...")


def set_nodes_disabled_local(compose_dir: Path, service: str, cfg: dict[str, Optional[str]], family: str) -> None:
    db = str(cfg.get("database") or "pasarguard")
    if family == "postgres":
        code, out, err = db_exec_local(compose_dir, service, f'psql -U "$POSTGRES_USER" -d {shell_quote(db)} -c {shell_single_quote("UPDATE nodes SET status=\'disabled\';")}')
    else:
        code, out, err = db_exec_local(compose_dir, service, f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" {shell_quote(db)} -e {shell_single_quote("UPDATE nodes SET status=\'disabled\';")}')
    if code != 0:
        warn(f"Could not disable restored nodes automatically: {err or out}")
    else:
        info("Restored nodes were disabled before panel startup")


def restore_local(archive: Path, *, force: bool = False, disable_nodes: bool = True) -> None:
    manifest = archive_manifest(archive)
    runtime = validate_source_runtime(manifest)
    if not force and not confirm("This will overwrite the local PasarGuard installation. Continue?", False):
        warn("Restore cancelled")
        return
    family = str((manifest.get("database") or {}).get("family") or "unknown")
    staging = Path(tempfile.mkdtemp(prefix="pgm_restore_", dir="/tmp"))
    try:
        safe_extract_zip(archive, staging)
        verify_staged_files(staging, manifest)
        # Install compose/.env early, but verify the new DB image before deleting application data.
        PASARGUARD_DIR.mkdir(parents=True, exist_ok=True)
        if (staging / "docker-compose.yml").is_file(): shutil.copy2(staging / "docker-compose.yml", PASARGUARD_DIR / "docker-compose.yml")
        if (staging / ".env").is_file(): shutil.copy2(staging / ".env", PASARGUARD_DIR / ".env")
        if family in {"postgres", "mysql"}:
            compose_config(PASARGUARD_DIR)
            service = resolve_db_service(PASARGUARD_DIR, family)
            if not service: raise RuntimeError(f"Could not resolve {family} service")
            if family == "postgres":
                compose_down_local(PASARGUARD_DIR)
                prepare_local_db_image(PASARGUARD_DIR, service, runtime)
            else:
                run_local(["docker","compose","pull",service],cwd=PASARGUARD_DIR,timeout=900)
        if (PG_NODE_DIR / "docker-compose.yml").is_file(): compose_down_local(PG_NODE_DIR)
        compose_down_local(PASARGUARD_DIR)
        if family in {"postgres", "mysql"}:
            prepare_db_storage_local(PASARGUARD_DIR, service, family)
        # Replace application and node data only after DB preflight.
        for target in (PASARGUARD_DIR, PG_NODE_DIR, PASARGUARD_DATA_DIR, PG_NODE_DATA_DIR):
            if target.exists():
                if target.is_dir(): shutil.rmtree(target)
                else: target.unlink()
            target.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staging / "docker-compose.yml", PASARGUARD_DIR / "docker-compose.yml")
        if (staging / ".env").is_file(): shutil.copy2(staging / ".env", PASARGUARD_DIR / ".env")
        for src_name, dst in (("pasarguard_data", PASARGUARD_DATA_DIR),("pg_node_opt",PG_NODE_DIR),("pg_node_data",PG_NODE_DATA_DIR)):
            src = staging / src_name
            if src.is_dir(): shutil.copytree(src, dst, dirs_exist_ok=True, symlinks=True)
        # External certs.
        for item in manifest.get("extra_certs", []):
            src = staging / item["archive_path"]
            dst = safe_restore_path(item["source"])
            dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst)
        # Restore NATS volumes.
        for item in manifest.get("nats", []):
            volume = str(item["volume"]); archive_path = staging / item["archive_path"]
            code, out, err = shell_local(f"docker volume create {shell_quote(volume)} >/dev/null && docker volume inspect {shell_quote(volume)} --format '{{{{.Mountpoint}}}}'")
            if code != 0 or not out: raise RuntimeError(f"Could not create NATS volume {volume}: {err or out}")
            p = run_local(["tar","-xzf",str(archive_path),"-C",out.strip()],timeout=600)
            if p.returncode != 0: raise RuntimeError(p.stderr.decode(errors="replace") or f"NATS volume restore failed: {volume}")
        # Caddy bind/volume sources.
        for item in manifest.get("caddy", []):
            if item.get("kind") == "volume":
                volume = str(item["volume"]); archive_path = staging / item["archive_path"]
                code, out, err = shell_local(f"docker volume create {shell_quote(volume)} >/dev/null && docker volume inspect {shell_quote(volume)} --format '{{{{.Mountpoint}}}}'")
                if code != 0 or not out: raise RuntimeError(f"Could not create Caddy volume {volume}: {err or out}")
                p = run_local(["tar","-xzf",str(archive_path),"-C",out.strip()],timeout=600)
                if p.returncode != 0: raise RuntimeError(p.stderr.decode(errors="replace") or f"Caddy volume restore failed: {volume}")
            else:
                src = staging / item["archive_path"]; dst = safe_restore_path(item["source"])
                if dst.exists():
                    if dst.is_dir() and not dst.is_symlink(): shutil.rmtree(dst)
                    else: dst.unlink()
                dst.parent.mkdir(parents=True, exist_ok=True)
                if src.is_dir(): shutil.copytree(src, dst, symlinks=True)
                else: shutil.copy2(src, dst)
        db_service_local = None
        cfg = read_db_config(PASARGUARD_DIR)
        if family in {"postgres", "mysql"}:
            db_service_local = resolve_db_service(PASARGUARD_DIR, family)
            if not db_service_local: raise RuntimeError("Database service not found after restore")
            compose_up_local(PASARGUARD_DIR, [db_service_local])
            if not wait_db_local(PASARGUARD_DIR, db_service_local, family): raise RuntimeError("Database did not become ready")
            if family == "postgres": restore_postgres_local(PASARGUARD_DIR, db_service_local, cfg, staging/"database"/"pasarguard.sql", runtime)
            else: restore_mysql_local(PASARGUARD_DIR, db_service_local, cfg, staging/"database"/"pasarguard.sql")
            if disable_nodes:
                set_nodes_disabled_local(PASARGUARD_DIR, db_service_local, cfg, family)
        compose_up_local(PASARGUARD_DIR)
        if (PG_NODE_DIR / "docker-compose.yml").is_file(): compose_up_local(PG_NODE_DIR)
        success("Local restore completed")
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def restore_cmd() -> None:
    archive = Path(input("Backup ZIP path: ").strip())
    restore_local(archive, force=False, disable_nodes=True)


def migrate_cmd() -> None:
    host = input("New server IP/hostname: ").strip()
    port = int(input("SSH port [22]: ").strip() or "22")
    username = input("SSH username [root]: ").strip() or "root"
    key_text = input("SSH private key path (leave empty for password): ").strip()
    key = Path(key_text) if key_text else None
    password = None if key else getpass.getpass("SSH password: ")
    archive_text = input("Existing backup ZIP (leave empty to create one): ").strip()
    archive = Path(archive_text) if archive_text else None
    migrate(archive, host, port, username, password, key, confirm("Accept unknown SSH host key?", False), False, True)


def schedule_telegram(interval_hours: float, token: str, chat_id: str) -> None:
    if interval_hours <= 0:
        raise ValueError("interval-hours must be greater than zero")
    info(f"Telegram scheduler started: every {interval_hours:g} hour(s)")
    while True:
        started = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            archive = backup_create(Path.cwd(), include_caddy=False)
            ok, details = stream_telegram_file(token, chat_id, archive, f"PasarGuard backup\nDate: {started}\nSHA-256: {sha256_file(archive)}")
            if ok:
                success("Backup sent to Telegram")
                archive.unlink(missing_ok=True)
            else:
                error(details)
        except Exception as exc:
            error(f"Scheduled backup failed: {exc}")
        try:
            time.sleep(interval_hours * 3600)
        except KeyboardInterrupt:
            warn("Telegram scheduler stopped")
            return


def telegram_cmd() -> None:
    token = getpass.getpass("Telegram bot token: ")
    chat_id = input("Telegram chat ID: ").strip()
    hours = float(input("Interval hours [6]: ").strip() or "6")
    schedule_telegram(hours, token, chat_id)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pasarguard-manager")
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="command")
    c = sub.add_parser("check"); c.add_argument("--db", choices=["postgres","mysql","sqlite"])
    b = sub.add_parser("backup"); b.add_argument("-o","--output-dir",type=Path,default=Path.cwd()); b.add_argument("--db",choices=["postgres","mysql","sqlite"]); b.add_argument("--no-caddy",action="store_true"); b.add_argument("--no-nats",action="store_true")
    r = sub.add_parser("restore"); r.add_argument("archive",type=Path)
    m = sub.add_parser("migrate"); m.add_argument("--host",required=True); m.add_argument("--port",type=int,default=22); m.add_argument("--user",default="root"); m.add_argument("--password",action="store_true"); m.add_argument("--key",type=Path); m.add_argument("--archive",type=Path); m.add_argument("--accept-new-host-key",action="store_true"); m.add_argument("--yes",action="store_true"); m.add_argument("--no-disable-nodes",action="store_true")
    tg = sub.add_parser("telegram"); tg.add_argument("--token", default=None); tg.add_argument("--chat-id", required=True); tg.add_argument("--interval-hours", type=float, default=6.0)
    sub.add_parser("selftest")
    return p


def main() -> int:
    if not require_root(): return 1
    p = parser(); args = p.parse_args()
    if not args.command: return interactive()
    try:
        if args.command == "check": return 0 if preflight_local(args.db) else 1
        if args.command == "selftest": return selftest()
        if args.command == "telegram":
            token = args.token or getpass.getpass("Telegram bot token: ")
            schedule_telegram(args.interval_hours, token, args.chat_id)
            return 0
        if args.command == "backup":
            if not preflight_local(args.db): return 1
            print(backup_create(args.output_dir, db_override=args.db, include_caddy=not args.no_caddy, include_nats=not args.no_nats)); return 0
        if args.command == "restore": return restore_cmd_cli(args.archive)
        if args.command == "migrate":
            password = getpass.getpass("SSH password: ") if args.password or not args.key else None
            migrate(args.archive, args.host, args.port, args.user, password, args.key, args.accept_new_host_key, args.yes, not args.no_disable_nodes); return 0
    except KeyboardInterrupt: warn("Cancelled"); return 130
    except Exception as exc: error(str(exc)); return 1
    return 0


def restore_cmd_cli(archive: Path) -> int:
    restore_local(archive, force=False, disable_nodes=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

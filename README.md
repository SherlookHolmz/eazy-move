[README(1).md](https://github.com/user-attachments/files/32607465/README.1.md)
# PasarGuard Manager

A terminal-first backup, restore, and migration utility for **PasarGuard Panel** and **PasarGuard Node**.

**Author:** Sherlook  
**Version:** 2.0.0

## What it does

PasarGuard Manager is designed for moving an existing PasarGuard installation from an old Linux server to a new one without relying on fragile manual copy/paste steps.

It can:

- detect SQLite, PostgreSQL/TimescaleDB, MySQL, and MariaDB from PasarGuard's current configuration;
- create a self-contained ZIP backup containing the panel configuration, `.env`, PasarGuard data, PG-Node configuration/data, database dump, detected external TLS files, Caddy/reverse-proxy data, and NATS named volumes when available;
- validate the backup using ZIP CRC checks and SHA-256;
- restore locally with path traversal protection;
- migrate to another Linux server over SSH/SFTP;
- verify the uploaded archive with a remote SHA-256 check;
- recreate application database users from `SQLALCHEMY_DATABASE_URL` when required;
- keep SSL settings unchanged and only report missing certificate/key paths;
- optionally disable restored nodes before the new panel takes over them;
- send backups to Telegram without loading the entire archive into RAM.

Current PasarGuard configuration uses `/opt/pasarguard/.env`, `/var/lib/pasarguard`, and `SQLALCHEMY_DATABASE_URL` for the database connection. PasarGuard's current documentation lists SQLite, MySQL, MariaDB, PostgreSQL, and TimescaleDB as supported backends. For multi-worker mode, NATS is required and may use a persistent Docker volume.

## Requirements

- Linux
- Python 3.10+
- Docker + Docker Compose plugin
- root privileges
- Python package: `paramiko`

Install the Python dependency:

```bash
python3 -m pip install -r requirements.txt
```

The utility intentionally does **not** silently install packages with `apt` or `pip`.

## Quick start

### Check the current server

```bash
sudo python3 pasarguard_manager.py check
```

### Create a local backup

```bash
sudo python3 pasarguard_manager.py backup
```

Choose a backup directory:

```bash
sudo python3 pasarguard_manager.py backup -o /var/backups/pasarguard
```

Force a database family:

```bash
sudo python3 pasarguard_manager.py backup --db postgres
```

Disable optional Caddy/NATS capture:

```bash
sudo python3 pasarguard_manager.py backup --no-caddy --no-nats
```

### Restore a local backup

```bash
sudo python3 pasarguard_manager.py restore ./pasarguard_backup_....zip
```

For automation:

```bash
sudo python3 pasarguard_manager.py restore ./backup.zip --yes
```

By default restored nodes are disabled before the panel starts. Use `--no-disable-nodes` to skip that step.

### Migrate to another server

Password authentication:

```bash
sudo python3 pasarguard_manager.py migrate \
  --host 203.0.113.10 \
  --port 22 \
  --user root \
  --password \
  --accept-new-host-key
```

SSH key authentication:

```bash
sudo python3 pasarguard_manager.py migrate \
  --host 203.0.113.10 \
  --port 22 \
  --user root \
  --key /root/.ssh/id_ed25519 \
  --accept-new-host-key
```

Reuse an existing backup instead of creating another one:

```bash
sudo python3 pasarguard_manager.py migrate \
  --host 203.0.113.10 \
  --archive ./pasarguard_backup_....zip \
  --key /root/.ssh/id_ed25519 \
  --accept-new-host-key
```

For non-interactive use, add `--yes`.

### Telegram scheduler

```bash
sudo python3 pasarguard_manager.py telegram \
  --chat-id 123456789 \
  --interval-hours 6
```

The bot token can be passed with `--token` or entered securely at the prompt.

## Interactive mode

Running the program without a subcommand opens a terminal menu:

```bash
sudo python3 pasarguard_manager.py
```

The menu provides preflight checks, backup, restore, migration, and Telegram scheduling.

## Important migration behavior

### The source panel is not automatically shut down

Remote migration is intentionally designed so the **old server can stay online** while the backup is transferred.

After restore, the tool can set the imported node records to `disabled` before starting the new panel. This reduces the chance of the old and new panels simultaneously trying to manage the same nodes.

### SSL is not silently changed

The previous implementation could blank `UVICORN_SSL_CERTFILE` / `UVICORN_SSL_KEYFILE` when paths were missing. Version 2.0.0 does **not** do that.

It reports missing TLS files and leaves the original configuration unchanged.

### Backups contain secrets

The archive may contain:

- `.env`
- database passwords
- API keys
- TLS private keys
- node credentials

Treat backup ZIP files as sensitive infrastructure secrets. Do not commit them to Git.

## Safety improvements in v2

The original script was heavily shell-driven and assumed older PasarGuard variable names. The new version changes the migration logic in several important ways:

1. It reads `SQLALCHEMY_DATABASE_URL` first and keeps compatibility with old `DB_*` variables.
2. Failed database dumps stop the backup instead of creating a false-success archive.
3. Special runtime files such as sockets/FIFOs are skipped rather than crashing a copy operation.
4. Backup archives are validated before use.
5. Database dump members are SHA-256 checked during restore.
6. Remote SFTP uploads are verified with both file size and SHA-256.
7. The restore path validates ZIP member paths to block `../` traversal.
8. Symlinks are preserved by the backup format.
9. SSH host-key verification defaults to rejection instead of silently trusting any new key.
10. SSH passwords are entered with `getpass` instead of plain `input()`.
11. Telegram uploads stream the ZIP instead of loading the entire file into memory.
12. Caddy/NATS handling is manifest-based instead of executing generated shell restore scripts.
13. SSL configuration is diagnosed, not silently rewritten.
14. The generated backup is kept after migration instead of being deleted automatically.

## Supported layout

The tool expects the standard PasarGuard locations:

```text
/opt/pasarguard
/opt/pasarguard/.env
/opt/pasarguard/docker-compose.yml
/var/lib/pasarguard

/opt/pg-node
/var/lib/pg-node
```

## Backup format

Each archive contains a `manifest.json` describing:

```text
database/
pasarguard_data/
pg_node_opt/
pg_node_data/
extra_certs/
caddy/
nats/
docker-compose.yml
.env
manifest.json
```

The manifest is used to validate the database dump, track external files, and restore Docker-volume data without running arbitrary restore scripts.

## Limitations

- A live filesystem backup can still contain application-level state changes that happen during the copy. Database consistency is protected by native database dumps; runtime directories are copied defensively.
- Docker images are not saved into the backup. If a compose file uses a floating tag such as `latest`, the new server may pull a different image than the old server.
- Extremely large databases may need more than the default one-hour restore timeout; the constant can be adjusted in the script.
- Automatic node disabling depends on the installed PasarGuard schema. If the schema has changed, the tool reports the failure instead of declaring a successful disable.
- Caddy capture is automatic for detectable Docker/systemd setups, but unusual custom reverse-proxy layouts may still require manual migration.

## Development

Run a syntax check:

```bash
python3 -m py_compile pasarguard_manager.py
```

The project is intentionally a single-file utility so it can be copied to a server and executed immediately.

## Official references

- PasarGuard Panel: https://github.com/PasarGuard/panel
- PasarGuard Scripts: https://github.com/PasarGuard/scripts
- PasarGuard Node: https://github.com/PasarGuard/node
- PasarGuard documentation: https://docs.pasarguard.org/

---

Built by **Sherlook** for terminal-based PasarGuard migration and recovery.

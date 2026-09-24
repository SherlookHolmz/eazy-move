# Original code audit

## Scope

Reviewed `pasarguard_manager (3).py` as uploaded and rebuilt it as v2.0.0.

## Confirmed issues in the original

### Critical — backup could report success after a failed database dump

The PostgreSQL and MySQL dump commands returned a boolean from `run_command()`, but `create_backup()` did not check that return value before continuing to archive the backup.

Result: a failed/empty/partial SQL dump could still be packaged as a successful backup.

### Critical — NATS was detected but not actually backed up

The original code only emitted a warning when `NATS_ENABLED` was true and explicitly said its Docker named volume was not captured.

That is incomplete for PasarGuard multi-worker deployments.

### High — SSL configuration could be silently rewritten

During restore, if `UVICORN_SSL_CERTFILE` or `UVICORN_SSL_KEYFILE` did not exist, the original `heal_ssl_env_*()` path blanked those variables and assumed a reverse proxy was in front of the panel.

That can change the panel's TLS behavior even when the operator did not ask for it.

### High — SFTP "integrity" check was only file-size based

The original migration compared local and remote ZIP sizes after SFTP upload.

Equal sizes do not prove identical content. v2 performs SHA-256 verification.

### High — current PasarGuard database configuration was only partially understood

The original logic primarily looked for `DB_USER` / `DB_NAME`.

Current PasarGuard configuration uses `SQLALCHEMY_DATABASE_URL`, which contains the database type, user, password, host, and database name.

v2 parses that variable first and keeps compatibility with older `DB_*` installations.

### High — PostgreSQL globals restore was brittle

The original backup generated `pg_dumpall --globals-only` using the application user and later restored it with the same application user.

That can fail when the application account is not sufficiently privileged or when roles already exist on the target.

v2 makes the application role/database explicitly on the target and treats a normal database dump as the source of application data.

### High — backup copies live runtime directories

The original copy routine correctly skipped sockets/FIFOs, but it still copied live application/node directories while the services were running.

This is safer than crashing, but it is not a filesystem snapshot. v2 keeps the defensive copy behavior and clearly distinguishes database consistency from live filesystem state.

### Medium — Telegram upload loaded the whole ZIP into RAM

The original `send_telegram_file()` read the entire backup file and constructed the complete multipart body in memory.

For large PasarGuard backups this creates unnecessary memory pressure.

v2 streams the multipart upload.

### Medium — SSH trusted any new host key

The original migration used `paramiko.AutoAddPolicy()` unconditionally.

That removes SSH host-key verification for the first connection.

v2 rejects unknown keys by default and exposes `--accept-new-host-key` as an explicit opt-in.

### Medium — SSH password was collected with ordinary `input()`

The root password was visible while being typed.

v2 uses `getpass`.

### Medium — restore scripts were generated and executed

The original Caddy/certificate restore mechanism generated shell scripts and executed them during restore.

v2 replaces this with manifest-defined copy operations and Docker-volume restoration.

### Medium — backup files were automatically deleted after migration

The original migration removed the local ZIP in `finally{}`.

That means a later rollback copy could be unavailable immediately after a successful/failed migration.

v2 keeps the archive by default.

### Medium — scheduled interval accepted zero/negative values

The original Telegram scheduler converted arbitrary numeric input to seconds. A zero/negative value could cause a tight loop.

v2 rejects non-positive intervals.

### Medium — database service names were hard-coded

The original implementation improved older hard-coded assumptions by supporting:

- `timescaledb`
- `postgresql`
- `postgres`
- `mysql`
- `mariadb`

v2 also inspects compose configuration/image names as a fallback.

### Medium — manual restore depended on the operator selecting the correct database family

The old menu asked the user which family to use instead of reading the backup/config itself.

v2 stores the detected database family in `manifest.json` and restores from the recorded type.

## Additional v2 safeguards

- ZIP CRC validation
- path traversal protection during local and remote extraction
- per-dump SHA-256 verification
- remote archive SHA-256 verification
- symlink preservation
- Caddy bind mount + named-volume capture
- NATS named-volume capture
- no automatic SSL rewriting
- explicit destructive restore confirmation
- manifest-driven restore
- standard PasarGuard paths preserved
- CLI and interactive terminal modes

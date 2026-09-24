# PasarGuard Manager

Simple terminal utility for **backing up, restoring, and migrating PasarGuard Panel + PG-Node** between servers.

**Developer:** Sherlook

## Easy Install

On an **Ubuntu/Debian** server, run:

```bash
curl -fsSL https://raw.githubusercontent.com/SherlookHolmz/eazy-move/main/install.sh | sudo bash
```

The installer automatically:

- installs Python and required system packages;
- installs Docker and Docker Compose when needed;
- downloads this project from GitHub;
- creates an isolated Python environment;
- installs Python dependencies;
- starts the terminal application.

### Manual install

```bash
git clone https://github.com/SherlookHolmz/eazy-move.git
cd eazy-move
sudo bash install.sh
```

Run it again with:

```bash
sudo /opt/eazy-move/run.sh
```

## Features

- Local backup and restore
- Direct SSH/SFTP migration
- Database detection
- SHA-256 backup verification
- Service health checks
- NATS and Caddy capture when detected
- External SSL certificate capture
- Node conflict protection
- Telegram backup support

## Commands

```bash
sudo /opt/eazy-move/run.sh check
sudo /opt/eazy-move/run.sh backup
sudo /opt/eazy-move/run.sh restore ./backup.zip
sudo /opt/eazy-move/run.sh migrate --host SERVER_IP
```

The application UI is intentionally **English-only** for reliable terminal/SSH rendering.

## Security

Backups may contain `.env` files, database passwords, API keys, node data, and SSL private keys.

**Never upload backup archives to GitHub.**

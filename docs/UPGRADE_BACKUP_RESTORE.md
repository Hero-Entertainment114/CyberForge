# Upgrade, Backup and Restore — Official Stable v2.1.0

## Persistent paths

- Versioned code: `/opt/cyberforge-server/releases/<version>`
- Active release symlink: `/opt/cyberforge-server/current`
- Data: `/var/lib/cyberforge-server`
- Environment and secrets: `/etc/cyberforge-server/server.env`
- Local backups: `/var/backups/cyberforge-server`

The installer does not overwrite the environment file or persistent data directory.

## Upgrade

Run `sudo ./deploy/install.sh` from the extracted source package. The installer stages a virtual environment, stops the service, creates and verifies a database backup, runs additive schema/audit preflight, switches the `current` symlink atomically, reloads systemd and checks the local health endpoint. If the new version fails to start or pass health, it restores the previous active pointer and unit file. Previous version directories are retained.

The shipped service unit remains loopback-only. Any deliberate private-IP bind requires a reviewed systemd drop-in plus explicit bind and trusted-proxy settings. The installer intentionally fails closed if a configured PostgreSQL database cannot be backed up (for example, when `pg_dump` is missing). Do not bypass this check in production; provision the official PostgreSQL client tools or complete a separately verified backup before upgrading.

## Backups

Create a backup:

```bash
sudo -u cyberforge-server /opt/cyberforge-server/current/.venv/bin/python \
  /opt/cyberforge-server/current/server.py --data-dir /var/lib/cyberforge-server backup
```

Verify a backup:

```bash
sudo -u cyberforge-server /opt/cyberforge-server/current/.venv/bin/python \
  /opt/cyberforge-server/current/server.py --data-dir /var/lib/cyberforge-server \
  verify-backup --path /var/backups/cyberforge-server/<backup-file>
```

SQLite uses the online backup API and `PRAGMA quick_check`. PostgreSQL uses `pg_dump --format=custom` and `pg_restore --list`. Backup files are mode 0600 and are stored under a mode-0700 service-owned directory by the installer.

Copy backups off-host and test restore regularly. A local backup does not protect against loss of the entire server or disk.

## Restore SQLite

1. Stop the service.
2. Run `verify-backup`; do not restore an invalid file.
3. Move the current `server.sqlite3` aside instead of overwriting it immediately.
4. Copy the verified backup to `/var/lib/cyberforge-server/server.sqlite3`.
5. Set owner `cyberforge-server:cyberforge-server` and mode `0600`.
6. Start the service; verify health, audit chain, tokens, feed records and detection rules.

## Restore PostgreSQL

Restore into a recovery database first. Use the organization's approved restore procedure; a typical custom-format command is:

```bash
pg_restore --clean --if-exists --no-owner --no-acl -d "$CF_RECOVERY_DATABASE_URL" backup.dump
```

Validate the restored database and migration state before switching all control-plane instances. Do not run destructive `pg_restore --clean` against a live shared database without a maintenance window and verified recovery point.

## Secrets and encryption keys

Back up `/etc/cyberforge-server/server.env` through the organization's secrets process. Preserve `CF_DISTRIBUTED_DATA_KEY` exactly across all PostgreSQL replicas and restores; otherwise encrypted AI job payload/results cannot be decrypted. Never place API keys, node tokens or database passwords in support bundles or source archives.

## Manual rollback

If the installer already performed rollback, verify `current` and the systemd unit. For a manual code-only rollback, stop the service, repoint `current` to a retained prior release directory, restore the corresponding unit if needed, run `systemctl daemon-reload`, and start the service. Code rollback does not reverse additive database schema changes. Restore a database backup only when intentionally reverting data to its backup point and after considering data written since that point.

# Implemented module catalog

The source of truth is `CHECK_MODULES` in [linux_inspection.py](../scripts/linux_inspection.py). There are 21 entries: 13 shell-based checks, three Python database runners, and five MySQL CLI query groups. An omitted `--check`, like `--check all`, selects all entries. Unknown names are printed and skipped; an entirely invalid selection returns failure.

| Module | Collection scope | Execution path |
| --- | --- | --- |
| `system` | OS/kernel, hostname, network configuration, uptime, login observations | SSH shell |
| `cpu` | CPU model/cores, one `top` snapshot, load averages, processes | SSH shell |
| `memory` | `free`, `/proc/meminfo`, swap, OOM observations | SSH shell |
| `disk` | Filesystems, inodes, file scans, disk I/O, mount observations | SSH shell |
| `network` | Interfaces, sockets, routing, firewall observations | SSH shell |
| `process` | Process counts, zombies, common services, cron listings | SSH shell |
| `log` | System, authentication, kernel, restart, and crash log excerpts | SSH shell |
| `security` | Account, sudo, SSH configuration, and authorized-key observations | SSH shell |
| `hardware` | Thermal, DMI, disk/SMART, RAID, PCI observations | SSH shell |
| `middleware` | Common database, web server, JVM, Redis, and Docker commands | SSH shell |
| `backup` | Existing backup files/jobs, local ports, certificates | SSH shell |
| `alert` | Resource snapshots, disk/inode warnings, swap warnings, login/zombie counts | SSH shell |
| `jvm_crash` | JVM processes, crash logs, OOM excerpts, `jstat`, `jmap`, `jstack` | SSH shell; JDK tools needed |
| `mysql_deep` | Status, memory/configuration, size/index/lock/replication/slow-query observations | Local PyMySQL; SSH forwarding fallback |
| `oracle_deep` | Instance/session, SGA/PGA, tablespace, index, blocking, and configuration observations | Local `oracledb` driver |
| `mssql_deep` | Sessions, memory, sizes, performance counters, indexes, locks, configuration | Local `pyodbc` plus native SQL Server ODBC driver |
| `db_health` | MySQL version/uptime, sizes, connections, buffer-hit and bottleneck queries | Target-side MySQL CLI over SSH |
| `db_security` | MySQL accounts/privileges/settings and sensitive-looking column names | Target-side MySQL CLI over SSH |
| `db_locks` | MySQL transactions, waits, blocking chains, lock metadata | Target-side MySQL CLI over SSH |
| `db_backup` | MySQL backup-related settings, table engines, auto-increment observations | Target-side MySQL CLI over SSH |
| `db_sql` | Missing primary keys, table/index metadata, unused/redundancy heuristics | Target-side MySQL CLI over SSH |

These are implemented collection paths, not a tested compatibility matrix. Some queries require elevated metadata privileges and specific database versions. The backup auto-increment query references `COLUMN_TYPE` on `information_schema.TABLES` and needs correction for typical MySQL schemas. Other version-dependent queries can also fail. Results are observations and text heuristics, not a security certification or measured diagnosis accuracy.

## Scope boundaries

`db_backup` does not run dumps or install scheduled jobs. `db_sql` has no arbitrary `--sql` or `--schema-table` interface. PostgreSQL appears in a middleware service-status loop, but there is no PostgreSQL diagnostic runner or `--pg-*` interface. Sensitive-column checks inspect names rather than scanning stored row values for secrets.

`alert` emits disk and inode warnings above 85% and a swap warning above 50%. It also prints CPU/memory percentages; the CLI, HTML renderer, and notification summary apply different parsing and display rules. There is no unified configurable alert policy. Those constants are thresholds, not measured outcomes.

The Python functions issue predefined diagnostic queries. The CLI does not expose write-SQL operations, but it also does not implement an SQL authorization layer. Several collected outputs contain query text, account names, authorized public keys, or log excerpts; keep reports local.

## Data and display

Single-host JSON contains `meta` and `results`. Successful collection paths use per-module `stdout`/`stderr`; other paths use `error`. Skips are represented through messages, not a separate normalized status enum.

The HTML renderer has explicit detail panels for the 16 shell/Python-runner entries. The five `db_*` groups remain in text/JSON output and do not have dedicated HTML panels. Host cards and metrics use regex extraction from raw command text. Missing or unparsable values can appear as `N/A` or defaults; inspect JSON when assessing results.

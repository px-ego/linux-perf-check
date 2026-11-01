# Configuration and usage details

Run commands from the repository root. Use the Python interpreter in the environment where you installed [requirements.txt](../requirements.txt). The examples use Windows PowerShell; target-side commands are Linux shell commands.

## Main collector

`scripts/linux_inspection.py` reads CLI options and an explicitly named JSON inventory. It does not read YAML, `.env`, or `LINUX_PERF_*` variables. Single-host `-o` and `--json-output` are optional: without them the collector only prints its report. HTML output is for batch mode.

Use `--check` to name a comma-separated set from the [module catalog](modules.md). Inherited defaults select every module. `--module-workers 1` chooses serial execution. `--timeout` defaults to 120 seconds; `--module-timeout` supplies the parallel module command timeout, with the limitations described in [architecture](architecture.md#known-limitations).

## Inventory

Copy [examples/inventory.example.json](../examples/inventory.example.json) to `inventory.json`. The example is disabled by default. Replace the illustrative target/user/key, set `enabled: true`, and keep that edited file local.

| Server field | Actual behavior |
| --- | --- |
| `host`, `port` | SSH target and port; port defaults to 22 |
| `user` | SSH user; inherited fallback is `root`; the example uses `inspector` |
| `alias`, `tags` | Report display metadata; use trusted text |
| `enabled` | Defaults to true if omitted; false entries are filtered |
| `auth.type` | `key` selects key authentication; other values currently take the password path |
| `auth.value` | Key path or password; key paths expand `~` in inventory mode |
| `db_auth` | MySQL credentials for `mysql_deep` and the five MySQL CLI groups |
| `oracle_auth`, `mssql_auth` | Direct Oracle/SQL Server runner credentials |

`settings.check_modules` accepts a comma-separated string or a list. `settings.timeout` supplies the batch SSH timeout; `--timeout` is only forwarded in single-host mode. `settings.output_dir` defaults to `./reports`; `--output-dir` overrides it. Either `settings.generate_html: true` or `--html` enables HTML generation.

Pass worker counts explicitly: CLI defaults `--workers 3` and `--module-workers 5` take precedence over the similarly named inventory settings, even when the flags are omitted. `--module-timeout` can override `settings.module_timeout`.

Database credentials can be placed on a host or under `settings`; a host mapping takes precedence as a whole, without merging fields. The fields actually consumed are `host`, `port`, `user`, and `password`. Oracle's single-host CLI also supports `--oracle-service`; inventory normalization currently drops `service` and uses `ORCL`. A `databases` array and `db_auth.type` do not choose different database engines.

For example, add this field to an enabled lab server for MySQL modules, filling the password only in the ignored local file:

```json
{
  "db_auth": {
    "host": "db.example.invalid",
    "port": 3306,
    "user": "metrics_reader",
    "password": ""
  }
}
```

This is a fragment, not a complete inventory. `db_auth.host` is the database address, not the SSH address. Python runners initially interpret it from the client; MySQL CLI groups interpret it from the remote Linux host. Use an address appropriate for the chosen path. Keep diagnostic database accounts limited to the privileges required by the selected queries; insufficient privileges can yield partial reports.

To select the MySQL CLI groups with the local inventory:

```powershell
.\.venv\Scripts\python.exe scripts/linux_inspection.py --inventory inventory.json --check db_health,db_locks --workers 1
```

## Optional database dependencies

The base install covers SSH collection, report generation, YAML loading, and notifications. No database drivers are imported for the documented small host-check selection.

| Module | Additional client dependency | Other prerequisite |
| --- | --- | --- |
| `mysql_deep` | `PyMySQL` | Reachable database; parallel path also opens SSH |
| `oracle_deep` | `oracledb` | Reachable Oracle instance/service and metadata permissions |
| `mssql_deep` | `pyodbc` | Native ODBC Driver 17 or 13 for SQL Server, as requested by the code |
| Five `db_*` query groups | No extra local Python package | `mysql` CLI installed on the SSH target |

If needed, install only the corresponding driver in the same virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install PyMySQL
# Or, for the corresponding runner:
.\.venv\Scripts\python.exe -m pip install oracledb
.\.venv\Scripts\python.exe -m pip install pyodbc
```

Optional driver versions and native ODBC setup were not installed or validated during publication. The base requirements pin the two direct dependencies verified locally; they are not a full transitive dependency lock or a compatibility claim for every Python release.

## Inspection and Feishu notification wrapper

Copy [config/default.example.yaml](../config/default.example.yaml) to `config/default.yaml` and fill the `server` mapping. Only `scripts/run_inspection_and_notify.py` reads this file. Relative key paths use its process working directory; `~` is expanded. Prefer an existing key and do not place private-key material inside the project.

| Value | CLI | Environment | YAML field |
| --- | --- | --- | --- |
| Target | `--host` | `LINUX_PERF_HOST` | `server.host` |
| Port | `--port` | `LINUX_PERF_PORT` | `server.port` |
| User | `--user` | `LINUX_PERF_USER` | `server.user` |
| Key path | `--key` | `LINUX_PERF_KEY` | `server.key` |
| Modules | `--check` | `LINUX_PERF_CHECK` | `server.check` |
| Password fallback | `--password` | `LINUX_PERF_PASSWORD` | Not read from YAML |

For each field: nonempty CLI value > nonempty environment value > YAML value. Port falls back to 22. A resolved key takes precedence over a password, including a key from YAML when a password is supplied through CLI. There is no password retry if key authentication fails.

The wrapper loads YAML even when CLI values are provided; malformed YAML can fail argument resolution. The normal install includes PyYAML. A limited two-level parser is retained as an import fallback; it is not a general YAML parser.

Notification credentials are read from `FEISHU_WEBHOOK_URL` and optional `FEISHU_SECRET`. Set them in the process environment, for example through interactive prompts so values are not embedded in the command itself:

```powershell
$env:FEISHU_WEBHOOK_URL = Read-Host "Feishu bot webhook URL"
# Set this only if bot signing is enabled:
$env:FEISHU_SECRET = Read-Host "Feishu signing secret"
.\.venv\Scripts\python.exe scripts/run_inspection_and_notify.py
```

The command contacts your configured Linux target and sends one outbound message; it was not run against real services for publication. The wrapper writes reports under the repository's `reports/` directory. It has no scheduler loop. To send a standalone message, `feishu_notify.py` accepts `--text`, positional words, or stdin and uses the same Feishu environment variables.

[.env.example](../.env.example) lists supported variable names for reference. Neither copying it to `.env` nor placing it in the repository loads variables; export/set them in the running process or configure your own launcher. The wrapper's YAML file and environment overrides are separate from the collector's batch inventory.

## Legacy helpers

`scripts/ssh_perf_check.py` is a smaller Paramiko/password collector with positional arguments. Its CLI is retained; no key option is implemented. Its `--help` is safe to inspect offline.

`scripts/auto_ssh_check.py` is an older password helper using `pexpect.spawn` and the system `ssh` command. It reads `LINUX_PERF_HOST`, `LINUX_PERF_USER`, and `LINUX_PERF_PASSWORD`. It requires the optional `pexpect` package and a POSIX pseudo-terminal environment; it is not part of the Windows quick start, and no live or POSIX validation was performed. Running it with no arguments is not an offline help command. Both helpers are inherited code, not dependencies of the main collector or notification wrapper.

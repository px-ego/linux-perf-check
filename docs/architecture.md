# Architecture and operational limits

## Collection flow

The collector is a script rather than an installed Python package. It does not require an agent framework, a model key, or a web service. `CHECK_MODULES` stores shell command blocks and database query groups. `DB_RUNNERS` maps three named Python runners to functions.

`run_inspection()` resolves the requested modules, performs an SSH preflight if any shell/MySQL CLI group is selected, dispatches modules, and assembles report sections in selection order. With `--module-workers 1`, it uses a serial path. Otherwise it submits work to a `ThreadPoolExecutor`; each shell worker establishes its own SSH connection. These independent connections avoid sharing one Paramiko client among parallel command executions, at the cost of additional SSH handshakes.

`run_batch_inspection()` loads enabled hosts from an inventory, uses another thread pool across hosts, writes per-host text/JSON files, sorts host results, and builds a text summary and optional HTML report. `--workers` and `--module-workers` are concurrency settings, not speedup guarantees.

## Database paths

- The MySQL runner first tries a direct TCP connection from the client. A supplied SSH client enables a loopback forwarding fallback using a Paramiko `direct-tcpip` channel. In the parallel module path, an SSH connection is established before the MySQL runner is called. Some supplementary size/index queries create separate direct connections and do not reuse the forwarding connection.
- Oracle and SQL Server runners connect directly from the client through optional drivers. The SQL Server code requests ODBC Driver 17, then tries Driver 13; it does not automatically select Driver 18.
- The five `db_*` groups combine predefined MySQL queries into one remote shell invocation and call the target's `mysql` binary. They use `MYSQL_PWD` in the remote command text. This is not a guarantee that credentials cannot be observed by privileged processes or captured in logs.

Database query failures may be handled at a subquery or runner boundary. This is best-effort behavior and does not ensure that every module produces useful data on every database version.

## Reports and notifications

The collector stores raw text and error strings, not a fully normalized metric schema. Text reports retain selected module order. JSON preserves machine-readable module boundaries. The HTML report embeds CSS and a small expand/collapse script and uses no CDN resources.

`run_inspection_and_notify.py` resolves a single target, invokes the collector as a subprocess using the same Python interpreter, reads a JSON report, extracts a few summary metrics and alert lines, and sends a Feishu text payload. `feishu_notify.py` uses the standard library for JSON, optional HMAC signing, and HTTP requests. These scripts do not schedule themselves.

`SKILL.md` is an instruction document for an external agent. Python scripts do not load it or the `references/` directory. An external agent may use those documents to interpret results, but no model invocation or automated diagnosis service is implemented here.

## Known limitations

These are findings from the supplied implementation; the publication preparation preserves runtime behavior.

| Area | Current behavior and implication |
| --- | --- |
| SSH identity | `AutoAddPolicy` accepts unknown host keys and no known-hosts loading/pinning is implemented. There is no strict host-key verification option. |
| Failure reporting | `run_inspection()` returns `True` after building a report even when SSH preflight or modules fail; batch mode also returns `True` after aggregation. Inspect each module's `error`, `stderr`, and output. A zero exit status or a green card is insufficient evidence of a healthy host. |
| Timeouts | SSH commands and some database calls have timeout parameters, but `as_completed()` waits before `future.result(timeout=...)` is used, and executor shutdown waits for workers. The design cannot enforce a hard per-module or whole-job wall-clock deadline. The serial path also uses `timeout` rather than the separate module timeout. |
| Batch logging | `inspect_single_server()` redirects global stdout/stderr inside host threads. Concurrent hosts may mix or misdirect console output. Start with `--workers 1` when inspecting reports. |
| Configuration | CLI defaults for workers override inventory worker settings. Single-host CLI MySQL credentials are only built when `mysql_deep` is selected, so a lone `--check db_health` does not receive them. Inventory mode is the documented path for `db_*` groups. |
| Default selection | Single-host `all` creates database credential dictionaries using CLI defaults, including empty passwords. It can attempt database connections rather than skip all unconfigured runners. Use explicit module selections. |
| Inventory schema | Validation is limited. `databases[]` is not consumed. Oracle inventory credentials lose a supplied `service` field during normalization and fall back to `ORCL`; the single-host `--oracle-service` flag is passed correctly. |
| Rendering | Raw module text is escaped, but aliases, tags, and some extracted metadata are interpolated without consistent HTML escaping. Render only trusted inventory/output; do not publish live reports as a public dashboard. Error-only modules and the five `db_*` groups may not appear in HTML details. |
| Credentials | CLI passwords can enter shell history/process arguments. The notification wrapper passes a password fallback in subprocess arguments. Remote MySQL CLI values are interpolated without robust shell quoting. Use an existing SSH key and keep all configuration local. |
| Report privacy | Process arguments, SQL snippets, user/key metadata, logs, and hardware/network identifiers can be collected. Reports have no automatic redaction. |
| JVM impact | `jmap -histo:live` can trigger Full GC. Log/file scans and privileged hardware commands can also have operational cost. `all` is not guaranteed to be non-intrusive. |
| Notification freshness | If the expected output is missing, the wrapper can fall back to the latest existing report, potentially for another host. Use a clean report directory for a controlled run and verify report metadata. |
| Compatibility | Remote commands assume Linux and commonly use GNU tools/systemd. Missing commands and permissions can produce partial output, often with suppressed errors. No distro or live database version matrix has been validated. |

The next engineering priorities are explicit result statuses and exit codes, strict SSH host-key handling, consistent HTML escaping, thread-safe logging, stronger configuration validation, and reliable cancellation. These are future work, not completed features.

# Validation record

Verified on **2026-11-01** (publication date in Asia/Shanghai) using a Windows client and **CPython 3.11.15**. The checks below concern the separate publication copy. No test suite accompanied the supplied snapshot, so these results are smoke checks and one-time offline probes, not a claim that an existing unit-test suite passed.

## Environment and repeatable checks

A new `.venv` was created inside the publication copy. Installation from [requirements.txt](../requirements.txt) succeeded using the public Python package index, and `pip check` reported no broken requirements. Direct dependencies were Paramiko 5.0.0 and PyYAML 6.0.3. The resolved transitive packages were bcrypt 5.0.0, cryptography 50.0.2, invoke 3.0.3, PyNaCl 1.6.2, cffi 2.1.1, and pycparser 3.12. These are recorded environment versions, not a benchmark or a cross-platform support claim.

| Check | Result | Boundary |
| --- | --- | --- |
| `python -m compileall -q scripts examples` | Passed for six Python files | Syntax/compilation only; does not import optional drivers or execute remote shell blocks |
| `--help` for `linux_inspection.py`, `feishu_notify.py`, `run_inspection_and_notify.py`, and `ssh_perf_check.py` | Four commands exited 0 | Imports and argument parsing only |
| Main CLI with the unedited disabled inventory | Expected exit 1 | No enabled target; no inspection started |
| `python examples/render_sample.py` | Generated text and HTML summaries under ignored `reports/synthetic-demo/` | Entirely synthetic input; no host or external service contacted |
| Markdown review | Relative links, heading anchors, and fenced code blocks checked | Local file/heading existence; no claim of browser rendering validation |
| Publication review | Allowlisted files, ignore rules, pattern scan, and known source-identifier checks reviewed before commit | Pattern-based review, not an exhaustive security audit |
| Original preservation | Original file hashes unchanged; license identical byte-for-byte | No original files were edited; the original directory had no Git metadata |
| Runtime preservation | All five inherited scripts retained equivalent ASTs after normalizing docstrings and help example text | No runtime logic fixes are included in this preparation |

Repeat the compilation, CLI help, and example commands in the [README](../README.md#verification). Actual configuration and generated reports are ignored and are not part of the committed source.

## Additional offline probes

Fourteen one-time scenarios passed with synthetic command output and mocked SSH/HTTP transports. The probe harness was kept outside the upload directory. Unexpected socket connections and unmocked webhook requests were blocked while these scenarios ran.

- Invalid module selection returned failure without attempting SSH.
- Serial and parallel module paths produced the expected per-module text/JSON output, kept text sections in selection order, and closed the fake SSH clients (two scenarios).
- All eight database paths reported skips when runner credentials were absent, without importing drivers or contacting databases.
- A simulated SSH preflight failure still returned a success flag. This reproduces a documented inherited limitation; it does not mean that a real connection succeeded.
- The unedited inventory contained no enabled hosts.
- A synthetic enabled inventory exercised the batch path with one host worker and three module workers, producing per-host text/JSON and batch text/HTML output.
- The untouched YAML template rejected its missing host before execution.
- CLI/environment/YAML precedence, key expansion, and the fallback parser's supported two-level subset behaved as documented.
- Synthetic CPU, memory, disk, alert parsing, and failure-summary detection returned the expected values.
- A missing webhook failed locally before HTTP execution.
- Notification payload/signature fields and success handling were checked with mocked HTTP transport.
- Mocked webhook application errors and malformed JSON were rejected.
- Raw module text was HTML-escaped. Inventory/display metadata is outside that guarantee and remains a documented limitation.

An initial probe invocation stopped because the harness cleared Windows home-directory variables; preserving the existing `USERPROFILE` corrected that harness setup. The final fourteen scenarios passed without changing application logic.

## Historical artifacts and unverified behavior

Five supplied report pairs contained CPU, memory, disk, and alert output, including some error entries. They were treated as private historical artifacts. They do not independently establish who executed the code, that every value came from a real host, or that the current publication copy works against that environment. Their contents were not reused as fixtures, benchmarks, or public demonstrations.

No live SSH session, target shell command, database query, Feishu delivery, hardware probe, paid model call, or production service was used during this preparation. Database drivers and native ODBC setup were not installed; live database compatibility and MySQL forwarding were not tested. The `pexpect` helper was compiled but not imported or run because its optional dependency and POSIX execution environment were outside this Windows quick start. Linux/macOS clients and a Linux distribution matrix remain unverified.

No performance benchmark, before/after speedup, diagnosis-accuracy measurement, cancellation/deadline guarantee, browser interaction check, or production-readiness validation was performed. Known runtime limitations are listed in [architecture.md](architecture.md#known-limitations).

---
name: linux-perf-check
description: Collect selected Linux host diagnostics over SSH, produce local reports, and optionally send a Feishu summary. Includes batch inventory and optional MySQL, Oracle, and SQL Server collection paths.
agent_created: true
---

# Linux inspection agent runbook

Use this document when an external agent is asked to inspect an authorized Linux lab. The Python CLI runs independently of this document and makes no LLM calls. Read the [README](README.md), [module catalog](docs/modules.md), and [configuration guide](docs/configuration.md) before choosing commands. This runbook is a revised adaptation of the supplied agent instructions; see [provenance](docs/provenance.md).

## Select a target and scope

Use a target and credentials explicitly supplied or configured for the current task. Do not infer a target from old reports. Prefer an existing SSH key. Configuring SSH access, editing server configuration, restarting services, killing transactions, creating dumps, or scheduling work are separate actions from inspection and require authorization appropriate to that action.

Start with `system,cpu,memory,alert` unless the user selects another scope. Do not automatically expand an ambiguous request to `all`: that selection includes JVM attachment, file scans, and database connection attempts. Explain the impact of `jvm_crash` before using it; its `jmap -histo:live` command can trigger Full GC.

The main collector reads CLI arguments or an explicit inventory. YAML defaults and `LINUX_PERF_*` overrides are used by the notification wrapper, not the main CLI. Use the paths under `scripts/` from the repository root. The shell examples in the README use a Windows client; Linux commands run on the target.

## Collect and interpret

1. Select explicit modules and local report paths, or use the ignored local inventory for batch mode.
2. Inspect per-module JSON `error`, `stderr`, and `stdout`. Exit status and aggregate success flags do not reliably describe collection completeness.
3. Separate observed facts, missing data, hypotheses, and recommended next checks. A missing metric is unknown, not healthy or zero.
4. Follow [generic diagnostic guidance](references/diagnostics.md) without claiming an automatic root-cause determination.
5. Use the [report template](references/report_template.md), preserving collection scope, time, and uncertainty. Redact target/user/SQL/log details before sharing outside the authorized context.

## Optional notification

Only send a Feishu message when the task authorizes notification. `scripts/run_inspection_and_notify.py` runs once and sends one text summary using `config/default.yaml` plus CLI/environment overrides. The webhook and optional signing secret belong in process environment variables. No scheduler or internal polling loop is implemented.

## Boundaries

There is no PostgreSQL diagnostic runner, embedded LLM, arbitrary SQL executor, backup executor, trend model, or implemented diagnosis score. Database module names describe collection groups, not a guarantee of database/version compatibility. Read [known limitations](docs/architecture.md#known-limitations), including host-key acceptance, HTML escaping, timeout behavior, report freshness, and batch logging. Do not claim a successful real-service validation based on a synthetic fixture or a generated report alone.

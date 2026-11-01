# Provenance and contribution boundaries

## Supplied source

This publication was prepared from a local directory named `linux-perf-check`. Neither that directory nor its ancestors contained Git metadata at inspection time. No branch, remote, commit history, tracked/untracked classification, or authorship timeline could therefore be verified. No independently verified upstream repository URL accompanied the snapshot.

The supplied [LICENSE](../LICENSE) is MIT and credits `Copyright (c) 2026 wanghel2020`. It is retained verbatim. That notice identifies the copyright attribution included in the snapshot; it is not independent verification of each file's author. The supplied agent document also contained an `agent_created: true` marker, which is retained in the revised [SKILL.md](../SKILL.md); it is not a per-file authorship record.

The intended GitHub account is `px-ego`. Repository ownership, this initial snapshot commit, and publication preparation do not prove sole development, original design, or authorship of the inherited implementation. Any portfolio or resume claim about personal implementation work needs separate evidence.

## Changes in the publication copy

- Retained the five Python scripts and the original MIT license. Script changes are limited to formatting and example/docstring/help text; runtime logic is preserved.
- Replaced the README with an English introduction, executable entry-point paths, configuration instructions, architecture, actual module scope, and limitations.
- Added pinned direct dependencies, Git ignore/line-ending rules, an empty-target YAML template, a disabled inventory template, and an environment-variable reference.
- Added an entirely synthetic JSON fixture and a local rendering example. These do not represent real inspection results.
- Replaced the long agent document with a concise Linux inspection runbook, and replaced deployment-specific reference material with generic diagnostic and reporting guidance.
- Removed unsupported documentation claims about speedups, PostgreSQL diagnostic support, automatic backup execution, SQL rewrite/execution, diagnosis scores, and production safety.
- Recorded offline checks and their boundaries in [validation.md](validation.md).

The preparation uses a separate sibling directory and a fresh Git repository. The supplied directory, configuration, reports, and any external source history are not changed or rewritten. This new history is a publication snapshot, not a reconstruction of prior development history.

## Excluded material

Actual `config/default.yaml` and `inventory.json`, supplied `reports/`, and Python bytecode caches were not copied. The supplied reports contained host metadata and command output; their live origin was not independently verified, and they were not used as public examples. The source agent document included deployment observations and credential-like examples; those sections were not retained.

The original `references/ekp_commands.md`, `references/ekp_issues.md`, and `references/ssh_key_automation.md` were outside the maintained Python execution path and carried application-specific or historical setup context. They were excluded. Generic diagnosis/reporting guidance was rewritten without deployment names, credentials, or observed business data; all links from the revised runbook target the included documents.

No original tests, CI workflow, package manifest, or lock file were found. No existing tests or runtime schema assets were discarded. `.gitignore` protects future local files from normal staging; it does not untrack files or remove data from old commits. The new repository does not import source history or sensitive files.

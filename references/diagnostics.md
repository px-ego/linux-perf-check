# Diagnostic reasoning guide

This is guidance for a human or an external agent interpreting the included collector. It is not an executable decision engine, a record of a real incident, or proof of root cause. Select only authorized checks; configuration changes are separate work.

| Symptom | First collection | Questions the evidence can support | Remaining uncertainty |
| --- | --- | --- | --- |
| Host or application is slow | `cpu,memory,alert`, then `disk` if appropriate | Which resource observations are abnormal? Which processes appear expensive? | A single sample does not show duration, causality, or a trend. |
| Service is unreachable | `system,network,process` | Is the expected process/port visible? What routes or firewall observations are available? | Client DNS, an external proxy, and end-to-end reachability require separate evidence. |
| Memory pressure or JVM failure | `memory,log`; optionally `jvm_crash` after impact review | Is there an OOM/crash excerpt, blocked thread, or GC snapshot? | Heap ownership and a sustained leak need deeper analysis; `jmap -histo:live` may trigger Full GC. |
| MySQL queries appear blocked | `db_locks`; optionally `mysql_deep` | What transactions, waits, or deadlock excerpts are visible to the account? | Permissions, sampling time, and server version limit visibility. |
| Storage concerns | `disk,backup`; optionally `db_backup` | What filesystems, files, backup jobs, and database settings are observed? | Observed backup files do not prove restorability; there is no backup executor or growth forecast. |
| Account/configuration concern | `security`; optionally `db_security` | What account, SSH, privilege, or sensitive-looking column metadata is visible? | These heuristics do not establish exploitation, safety, or compliance. |

For each finding, record the module and relevant excerpt, note missing permissions or command failures, and propose the next discriminating check. Do not generate diagnosis probabilities, security grades, capacity forecasts, or improvement percentages without a method and supporting data.

The [module catalog](../docs/modules.md) defines actual names and dependencies. The [architecture notes](../docs/architecture.md#known-limitations) describe inherited failure-reporting and parsing limits. Missing HTML detail should be checked against the JSON report.

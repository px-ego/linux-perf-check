# Inspection interpretation template

Use this template when a person or external agent writes a narrative from collected reports. It is separate from the CLI's generated text/JSON/HTML. Replace placeholders with observed, appropriately redacted information. Use “unknown” for missing data and label synthetic inputs explicitly.

```text
Linux inspection review

Evidence source: live collection / synthetic fixture / supplied historical report
Collection time and timezone: <observed value or unknown>
Target label: <redacted alias>
Requested modules: <names>
Completed / failed / skipped / unverified modules: <names and reasons>

Observed facts
- <module>: <fact and a short redacted excerpt>

Missing or unreliable data
- <module>: <permission, missing tool, parsing, connection, or timeout issue>

Interpretation
- <hypothesis, supporting facts, and uncertainty>

Recommended next checks
1. <check that can distinguish likely causes, with operational impact>

Validation boundary
- <what was actually executed>
- <what has not been tested or established>
```

Do not copy passwords, webhooks, private keys, real host identifiers, raw SQL literals, or business logs into a public report. A zero CLI exit code, generated report, or missing alert is not enough to conclude that every check succeeded. The software has no automatic redaction step.

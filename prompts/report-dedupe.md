You are deduplicating security findings before they are filed as GitHub issues.

Decide whether the NEW finding describes the **same underlying vulnerability** as
the EXISTING already-reported finding. They are the same only if they share the
same root cause at the same code location; two findings that merely touch related
code, the same file, or the same bug class but describe distinct defects are
NOT duplicates.

<new_finding>
{new_finding}
</new_finding>

<existing_finding>
{existing_finding}
</existing_finding>

Respond with ONLY a single JSON object, no prose and no code fence:

{"duplicate": true}

or

{"duplicate": false}

When genuinely unsure, answer `{"duplicate": false}` — filing a second issue is a
smaller cost than dropping a real finding.

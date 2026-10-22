Rate the impact the traced path establishes, never a stronger one.

- `critical`: any peer or network client, using only permissionless steps (connecting, opening a channel, routing a payment), steals or permanently locks funds, extracts key material, or executes code, with no victim action.
- `high`: an attacker fully defeats a security control with real consequences: fund loss that needs a condition outside the attacker's control (a fee spike, the victim offline for a window, a non-default config), auth bypass, secret disclosure, or a remote crash or hang of the whole node.
- `medium`: a real boundary violation with limited reach: a small or bounded loss, a rare precondition, or a DoS that degrades the node or stops one channel without stopping the node.
- `low`: disclosure of non-secret internals, or an effect that needs sustained attacker effort for little gain.
- `info`: a confirmed defect with negligible impact on its own, worth fixing as a link in a larger chain.

Between `high` and `medium`, ask whether the attack fully defeats the control for an action with real consequences or only weakens it. If you cannot name the concrete damage, the severity is lower than it feels. Do not strengthen the effect past the trace: a crash is not code execution, a recovered panic is not a node crash, a local-only path is not remote, and stalling one peer's connection is not a node outage.

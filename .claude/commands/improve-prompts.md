---
description: Review and improve a pipeline prompt for better results at lower token cost
argument-hint: "[prompt name or path, e.g. recon | hunt | validate | report | all (default)]"
allowed-tools: Read, Edit, Glob, Grep, Bash(grep:*), Bash(wc:*), WebFetch, WebSearch
---

You are a senior prompt engineer. Improve the stage prompt(s) in `prompts/` so the
agent produces **better findings while burning fewer tokens**. Token cost is a
first-class metric here (this harness is benchmarked on cost-per-bug), so every
word must earn its place: cut what does not change the model's behavior, sharpen
what does.

## Scope

Target: `$1` (a stage name like `recon`/`hunt`/`validate`/`report`, a path, or
`all`). If empty or `all`, process every `prompts/*.md`. One file at a time.

## Hard constraints (violating these breaks the build or the pipeline)

1. **Preserve every `{placeholder}` token verbatim** — same spelling, same braces.
   They are substituted by `str::replace` in `src/pipeline/*.rs`. Before editing a
   prompt, run `grep -n '"{' src/pipeline/<stage>.rs` (or grep the whole
   `src/pipeline/`) to list the exact placeholders that file feeds, and confirm
   every one still appears in your rewrite. Do not add, rename, or drop one.
2. **Prompts are embedded via `include_str!`** — editing one changes the build.
   Keep the file a valid standalone prompt; do not reference the orchestrator.
3. **Preserve the output contract exactly** — JSON shape, field names, enum
   values, the fenced ```json block, and any "echo `id` verbatim" rule. The
   downstream stage parses this; a drifted schema silently drops findings.
4. **Keep stage-specific invariants** noted in `CLAUDE.md` (e.g. recon's size-tier
   caps, hunt's "report traced-but-latent bugs", validate's "tag don't delete").
   Tightening wording is fine; deleting a behavioral rule is not.

## Ground yourself first

Before drafting, read the prompt-engineering and skill-authoring guidance that
the project's `CLAUDE.md` curates under **Contributing Skills → Resources**
(Skill Authoring Best Practices, The Complete Guide to Building Skills, the
Plugins/Skills docs). Open `CLAUDE.md`, follow those links with `WebFetch`, and
let their principles — progressive disclosure, degrees of freedom, evaluation-
driven iteration — inform the edits below. The checklist that follows is the
short form of that guidance; defer to the source when they conflict.

## Best-practices checklist (apply, don't just check)

Optimize for behavior-per-token. For each prompt:

- **Cut dead weight** — filler, hedging, restated instructions, examples that
  teach nothing new, sentences the model already infers. Prefer one precise
  sentence over three vague ones.
- **Right altitude** — give decision criteria and constraints, not step-by-step
  micromanagement the model handles on its own. Remove freedom only where a wrong
  choice is costly (output format, trust-boundary rules).
- **Front-load the contract** — role, the one job, and the output shape should be
  unmissable. Keep `<role>`/`<style>` tight.
- **Progressive disclosure** — one canonical example beats many near-duplicates.
  Collapse redundant examples; keep the one that disambiguates a real edge case.
- **Specific > generic** — replace abstract guidance ("be thorough") with a
  falsifiable rule ("trace untrusted input to the sink before reporting").
- **Structure for parse-ability** — consistent headers, tables for caps/tiers,
  fenced blocks for output. Reuse the structure already present; don't restyle for
  taste.
- **No contradictions** — a later line must not loosen an earlier hard rule.

## Workflow

Do "Ground yourself first" once, then for each target prompt:

1. Read the prompt and its `src/pipeline/<stage>.rs` to learn the exact
   placeholder + output contract.
2. Note the current size: `wc -w prompts/<stage>.md`.
3. Draft improvements against the checklist. Every cut must be behavior-neutral or
   behavior-improving — never drop a rule the downstream stage relies on.
4. Apply with `Edit`.
5. Verify: re-grep that all placeholders survive, the output JSON block is intact,
   and report the word-count delta.

## Report

Per file, output a compact summary:
- `<stage>.md: <old> → <new> words (-N%)`
- 3–6 bullets, each `<what changed> — <why it helps results or saves tokens>`.
- Any constraint you deliberately left untouched and why.

Do not touch the vendored `skills/`, config, or Rust source except to **read** the
pipeline file for the contract. Show the diff-worthy changes; make no edit you
cannot tie to better results or fewer tokens.

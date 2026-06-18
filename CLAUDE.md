# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# fee1dead — vulnerability discovery harness

A Rust orchestrator that drives AI coding CLIs through a staged pipeline. The
orchestrator never hunts bugs itself; it schedules narrow agent tasks in
parallel, manages per-task scratch dirs, and turns agent output into
schema-validated findings. See `README.md` for the user-facing overview.

## Commands

- Build: `cargo build` (release: `cargo build --release`)
- Test: `cargo test --features mock-runner` — the `mock-runner` feature is
  required for the offline end-to-end test (`tests/e2e.rs`), which drives the
  whole pipeline with `MockRunner` (no network, no API cost).
- Validate config: `cargo run -- check --config config/harness.toml`
- Run pipeline: `cargo run -- run --config config/harness.toml`
- Docker: `docker build -t fee1dead -f docker/Dockerfile .` then run with
  `--cap-add=NET_ADMIN` (firewall needs it). See `README.md` for the run shape.

## Architecture (where things live)

- `src/provider/` — `AgentRunner` trait + `AgentRequest`/`AgentResult`. The only
  seam to any AI CLI. `claude_code.rs` is the sole built-in adapter; **add any
  other CLI via a `type = "exec"` config block, not Rust code** (`generic_exec.rs`,
  `{prompt}`/`{working_dir}` placeholders). `mock.rs` is feature-gated.
- `src/pipeline/` — `mod.rs` sequences stages; one file per stage. All seven
  are built. `feedback.rs` is a cross-run memory (no consumer repos): it writes
  durable seed tasks to `feedback-seeds.jsonl`, which recon merges into the next
  run's queue. Add a stage: create the file, add to the `run_stage` match, and
  to `KNOWN_STAGES` in `config.rs`.
- `src/store/` — `ReportSink` trait + sqlite/jsonl/http sinks. New sinks
  implement the trait and wire into `build_sink`.
- `src/config.rs` — per-run TOML, **validated once at load** (`Config::validate`).
  This is the operator-input trust boundary; fail fast here, assume valid below.
- `src/target.rs` — acquires the target repo before stages run: clones
  `[target].repo` at `ref` into `target_dir`, or asserts a mounted target is
  present. Called at the top of `Pipeline::run`.
- `src/domain.rs` — the inter-stage data contract (`Task`, `Finding`,
  `Validation`, `GapMarker`, `Severity`). Change here ripples to artifacts.
- `src/artifacts.rs` — JSON/JSONL stage IO. **Stages communicate ONLY through
  artifacts** in `out_dir` (`queue.jsonl`, `candidates.jsonl`, `gaps.jsonl`,
  `validated.jsonl`, `hunted.jsonl`, `ARCHITECTURE.md`), never by calling each
  other. Keep it that way: it is what makes stages decoupled and runs resumable.
- `prompts/`, `schema/finding.schema.json` — embedded into the binary via
  `include_str!`; editing them changes the build.
- Skills are routed per task, not per stage: recon emits `suggested_skills` on
  each `Task` (from the vendored suite), and `hunt.rs` names them in the hunter
  prompt. Skills reach the agent through prompt text, not a CLI flag.
- `skills/` — vendored Trail of Bits plugin suite (a plugin marketplace:
  `plugins/<plugin>/skills/<skill>/SKILL.md`). The container registers only the
  pipeline's allow-list of skills as personal skills under `~/.claude/skills/<skill>`
  (see the loop in `docker/Dockerfile`) so `claude` exposes them by name; the rest
  of the suite stays in `/opt/skills` for reference. The allow-list must stay in
  sync with the recon suggestion list in `prompts/recon.md`. Do not edit the
  vendored skills unless updating the vendor copy.

## Conventions

- Hunt is incremental: it appends to result artifacts and records processed task
  ids in `hunted.jsonl`. Never truncate `candidates.jsonl`/`gaps.jsonl` from a
  stage that can run more than once.
- A recon-led run resets per-run artifacts (`artifacts::names::PER_RUN`) at
  startup; `feedback-seeds.jsonl` (`SEEDS`) is deliberately excluded so the
  cross-run memory persists. If you add a durable artifact, keep it out of
  `PER_RUN`.
- The container is the security boundary. The agent runs
  `--dangerously-skip-permissions`; the only real restriction is the
  default-deny egress firewall (`docker/init-firewall.sh`, allow-list sourced
  from config via `fee1dead firewall-hosts`).
- Pure logic (e.g. `dedupe_findings`) is factored out of `run(ctx)` so it can be
  unit-tested without constructing a `StageCtx`. Follow that pattern.

# Contributing Skills

## Resources

**Official Anthropic documentation (always check these first):**

- [Claude Code Plugins](https://code.claude.com/docs/en/plugins)
- [Agent Skills](https://code.claude.com/docs/en/skills)
- [Best Practices](https://code.claude.com/docs/en/skills#best-practices)
- [Skill Authoring Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices) — progressive disclosure, degrees of freedom, workflow checklists
- [The Complete Guide to Building Skills](https://resources.anthropic.com/hubfs/The-Complete-Guide-to-Building-Skill-for-Claude.pdf) ([text](https://gist.github.com/liskl/269ae33835ab4bfdd6140f0beb909873)) — evaluation-driven development, iterative testing

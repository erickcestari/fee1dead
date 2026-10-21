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
  seam to any AI CLI. `claude_code.rs` and `opencode.rs` are the built-in
  adapters: each folds its CLI's events through a `StreamObserver`, while
  `stream.rs` owns the shared spawn/tee/timeout loop and `final_output.rs` the
  answer-file contract; `error.rs` classifies quota vs throttle vs timeout.
  **Add any other CLI via a `type = "exec"` config block, not Rust code**
  (`generic_exec.rs`, `{prompt}`/`{working_dir}` placeholders). `mock.rs` is
  feature-gated. Fields an adapter's CLI has no equivalent for (e.g. a tool
  deny-list) are ignored, never emulated.
- `src/pipeline/` — `mod.rs` sequences stages; one file per stage. Every stage
  agent's request starts from `StageCtx::agent_request` (deny-list, timeout,
  stage model and effort, reference dir, and a `<stage>-<key>` scratch dir and transcript).
  `prompt.rs` holds the prompt fragments several stages append.
  `wishlist.rs` owns the wish hunters and reviewers emit for what the sandbox
  lacks (`wishlist.jsonl`), the agents' channel back to the operator.
  `feedback.rs` is a cross-run memory (no consumer repos): it writes durable
  seed tasks to `feedback-seeds.jsonl`, which the next run's recon reads as
  leads (and consumes). `salvage.rs` gives an agent whose answer does not
  parse, or that timed out, one repair turn in its own session. Add a stage:
  create the file, add a variant to `config::Stage`, and the compiler points at
  the `run_stage` match.
- `src/store/` — `ReportSink` trait + sqlite/jsonl/http/github sinks. New sinks
  implement the trait, get a `config::ReportConfig` variant, and wire into
  `build_sink`.
- `src/config/` — per-run TOML, **validated once at load** (`Config::validate`).
  This is the operator-input trust boundary; fail fast here, assume valid below.
  Prefer types that make an invalid config unrepresentable (`Stage`,
  `ReportConfig`) over runtime checks.
- `src/json_block.rs` — pulls the JSON answer out of an agent's text.
- `src/target.rs` — acquires the target repo before stages run: clones
  `[target].repo` at `ref` into `target_dir`, or asserts a mounted target is
  present, then runs `[target].prepare`. Called at the top of `Pipeline::run`.
  `run_setup` (the `setup` subcommand) runs `[target].setup`; the container
  entrypoint calls it as root before the firewall.
- `src/domain.rs` — the inter-stage data contract (`Task`, `Finding`,
  `Validation`, `GapMarker`, `Wish`, `Severity`). Change here ripples to
  artifacts.
- `src/artifacts.rs` — JSON/JSONL stage IO. **Stages communicate ONLY through
  artifacts** in `out_dir` (`queue.jsonl`, `candidates.jsonl`, `gaps.jsonl`,
  `duplicates.jsonl`, `wishlist.jsonl`, `validated.jsonl`, `findings.json`,
  `hunted.jsonl`, `recon.json`, `run-id.txt`, `run-meta.json`, plus the `logs/` and `pocs/`
  dirs), never by calling each other. Keep it that way: it is what makes stages
  decoupled and runs resumable. `aggregate.rs` joins the hunters' raw output
  into the single reviewable `findings.json` with no agent call, and is also
  exposed as the `fee1dead aggregate` subcommand for compiling a partial run
  after the fact.
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
  `PER_RUN`. `run --resume` skips recon and resets nothing.
- Every agent gets its own `output_dir` (a scratch dir) for its answer file;
  never share one between agents, or one can read another's answer.
- The container is the security boundary. The agent runs
  `--dangerously-skip-permissions`; the only real restriction is the
  default-deny egress firewall (`docker/init-firewall.sh`, allow-list sourced
  from config via `fee1dead firewall-hosts`).
- Pure logic (e.g. `dedupe_findings`) is factored out of `run(ctx)` so it can be
  unit-tested without constructing a `StageCtx`. Follow that pattern.

# Contributing Skills

## Resources

**Official Anthropic documentation (always check these first):**

- [Prompt engineering overview](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/overview)
- [Prompting best practices](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices) — clarity, examples, XML tags, roles, thinking, agentic systems
- [Prompting Claude Fable 5](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/prompting-claude-fable-5) — effort, instruction following, long runs, memory, scaffolding
- [Be clear and direct / add context](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices#be-clear-and-direct) — state the goal and its motivation explicitly
- [Use examples & XML structure](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices#use-examples-effectively) — 3-5 examples in `<example>` tags; wrap instructions/context/input in their own tags
- [Subagent orchestration](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices#subagent-orchestration) — when to fan out vs. work directly
- [Claude Code Plugins](https://code.claude.com/docs/en/plugins)
- [Agent Skills](https://code.claude.com/docs/en/skills)
- [Best Practices](https://code.claude.com/docs/en/skills#best-practices)
- [Skill Authoring Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices) — progressive disclosure, degrees of freedom, workflow checklists
- [The Complete Guide to Building Skills](https://resources.anthropic.com/hubfs/The-Complete-Guide-to-Building-Skill-for-Claude.pdf) ([text](https://gist.github.com/liskl/269ae33835ab4bfdd6140f0beb909873)) — evaluation-driven development, iterative testing

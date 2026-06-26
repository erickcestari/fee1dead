# fee1dead

<img src="./assets/fee1dead.png" alt="fee1dead project icon" width="300" align="right" />

An AI-CLI-agnostic vulnerability discovery harness. An orchestrator drives AI
coding CLIs through a staged pipeline, running many narrow agent tasks in
parallel and turning their output into queryable, schema-validated findings.

The orchestrator does **not** hunt bugs itself. It schedules work, manages
per-task scratch space, and validates/persists results.

## Pipeline

| Stage      | Status   | What it does |
|------------|----------|--------------|
| Recon      | built    | Reads the repo top-down, emits a structured threat model (`recon.json`) and seeds the hunt queue from its `hunt_tasks`. |
| Hunt       | built    | One hunter per task (attack class + scope + a falsifiable hypothesis and concrete `targets` to start from), run concurrently, each in its own scratch dir. Hunters **fork from recon's session** (claude-code only; toggle `run.fork_hunters`) so they inherit its codebase context; cold hunters load `recon.json` instead. **Incremental:** skips already-hunted tasks, so re-queues get a fresh pass. Emits candidate findings + gap markers. |
| Validate   | built    | One independent reviewer re-reads the code and **tags every finding in a single batched call** (`fp-check` skill): `confirmed` / `downgraded` (with corrected severity) / `likely_false_positive`. **Never drops** a finding — a real-but-unproven bug is surfaced, not discarded. |
| Gapfill    | built    | Re-queues areas hunters flagged as under-covered (`origin = gapfill`), deduped against the existing queue. |
| Dedupe     | built    | Collapses findings sharing a root cause (source file + attack class); the highest-severity finding survives. |
| Feedback   | built    | Cross-run memory: distils confirmed findings (hunt variants) and unresolved gaps into durable seed tasks in `feedback-seeds.jsonl`. The next run's recon merges them, so each run starts smarter. |
| Report     | built    | Renders all reportable findings (confirmed + downgraded) against `schema/finding.schema.json` in **one batched call** with a single repair round, then persists via the configured sink. |

Stages communicate only through artifacts in `out_dir` (`queue.jsonl`,
`candidates.jsonl`, `gaps.jsonl`, `validated.jsonl`, `hunted.jsonl`,
`recon.json`), so they are decoupled and runs are resumable. A recon-led
run clears those per-run artifacts at startup; `feedback-seeds.jsonl` is the one
durable artifact and survives, carrying learning between runs. **Reuse the same
`out_dir` (mount) across runs to keep the feedback memory.**

The full agent transcript of each run is teed live to `out_dir/logs/` (one
`<stage>-<label>.jsonl` per agent, the Claude CLI's `stream-json` events), so a
run can be replayed or debugged after the fact — a transcript survives even if
its agent times out. Its final `result` event also carries that agent's cost and
token usage (`total_cost_usd`, `duration_ms`, `num_turns`, and a `usage` block
with token counts and prompt-cache hits), so the harness keeps no separate cost
file — profile a run straight from the logs, e.g.:

```sh
jq -s 'map(select(.type=="result") | .total_cost_usd) | add' out_dir/logs/*.jsonl
```

Each agent is also told to write its complete final answer to
`agent-final-output.txt` in its working dir; the harness reads that file back as
the result (falling back to the stream's final event if the agent didn't write
it) and mirrors it next to the transcript as `out_dir/logs/<stage>-<label>.output.txt`,
so each agent's answer is visible in the out dir without reaching into its scratch
dir. The `logs/` directory is cleared at the start of a recon-led run.

## Architecture

Single Rust binary, modularized:

- `src/provider/` — `AgentRunner` trait + adapters. **Adding any CLI** is a
  config block (`type = "exec"`) with no Rust code; `claude-code` is the only
  built-in adapter. `MockRunner` (feature `mock-runner`) drives offline runs.
- `src/pipeline/` — orchestrator + one file per stage.
- `src/store/` — `ReportSink` trait + SQLite/JSONL/HTTP sinks.
- `src/config.rs` — per-run TOML config, validated at load.
- `prompts/`, `schema/` — embedded into the binary at build time.
- `skills/` — the Trail of Bits plugin suite, mapped to stages in `src/skills.rs`.

## Configure

Edit `config/harness.toml`: target repo path, provider, concurrency, firewall
allow-list, report sink, and which stages to run.

```bash
fee1dead check          --config config/harness.toml   # validate config
fee1dead firewall-hosts --config config/harness.toml   # print allow-list
fee1dead run            --config config/harness.toml   # run the pipeline
```

## Run in Docker (default-deny egress)

The agent runs unrestricted **inside** the container
(`--dangerously-skip-permissions`); the only real restriction is the firewall,
which default-denies egress and allows only the hosts in `[firewall].allow`.

The easiest path is the `justfile` (run `just` to list recipes):

```bash
just image                       # build the image
just run target=/path/to/repo    # mount a local repo and run
just run-clone                   # harness clones the repo itself (see below)
just shell                        # interactive shell in the image
```

### Target the repo by clone (instead of mounting)

Set `[target]` in `config/harness.toml` and the harness clones the repo into
`target_dir` at startup. The git host must be in `[firewall].allow` (the clone
runs after the firewall is up).

```toml
[target]
repo = "https://github.com/org/name.git"
ref  = "main"   # branch, tag, or commit SHA; optional
```

Then `just run-clone` (no local target mount needed). With `[target]` unset, the
harness expects `target_dir` to already contain the code (the mounted case).

### Reference spec / known-good implementation

Set `[reference]` to clone a spec or reference implementation and expose it to
the recon, hunt, and validate agents as ground truth — its path is added to each
agent's readable dirs and named in their prompts. When a reference is set, recon
also emits dedicated `spec-to-code-compliance` hunt tasks (a spec clause paired
with its implementing code), and those hunters apply the `spec-to-code-compliance`
skill. Useful for spec conformance (e.g. the BOLT specs for a Lightning
implementation). The git host must also be in `[firewall].allow`.

```toml
[reference]
repo = "https://github.com/lightning/bolts.git"
ref  = "master"           # optional
dir  = "/work/reference"  # where to clone it; defaults to /work/reference
```

Or directly:

```bash
docker build -t fee1dead -f docker/Dockerfile .

docker run --rm \
  --cap-add=NET_ADMIN \
  -e ANTHROPIC_API_KEY \
  -v /path/to/target/repo:/work/target:ro \
  -v "$PWD/out":/work/out \
  fee1dead
```

**Auth:** set one of these on the host before running (the `just` recipes
forward both, using whichever is set):
- `ANTHROPIC_API_KEY` — API-key billing.
- `CLAUDE_CODE_OAUTH_TOKEN` — Claude Pro/Max OAuth; generate with
  `claude setup-token`. For a raw `docker run`, add `-e CLAUDE_CODE_OAUTH_TOKEN`.

`--cap-add=NET_ADMIN` is required for the firewall. The container is **not**
`--privileged`. Set `FEE1DEAD_SKIP_FIREWALL=1` (or `just run-nofw`) only for
local debugging.

The image bundles **Go** (`ARG GO_VERSION`) and **Python 3 + uv** alongside Node
so hunters can compile PoCs and run Python tooling (several Trail of Bits skills
use `uv run`). `go build` and Python package installs fetch at run time, so the
relevant hosts (`proxy.golang.org`, `sum.golang.org`, `storage.googleapis.com`,
`pypi.org`, `files.pythonhosted.org`, …) must be in `[firewall].allow` — see
`config/lnd.toml` for a worked example.

## Develop

```bash
cargo test --features mock-runner    # unit tests + offline end-to-end pipeline
```

The end-to-end test (`tests/e2e.rs`) runs the full skeleton against the
`MockRunner` with no network or API cost.

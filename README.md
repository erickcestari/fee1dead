# fee1dead

<img src="./assets/fee1dead.png" alt="fee1dead project icon" width="300" align="right" />

A vulnerability discovery harness. It drives AI coding CLIs (Claude Code,
opencode, or any CLI described in config) through a staged pipeline, runs many
narrow agent tasks in parallel, and turns their output into schema-validated
findings. The orchestrator never hunts bugs itself.

## Pipeline

| Stage | What it does |
|-------|--------------|
| `recon` | Reads the repo and writes a threat model (`recon.json`). Its `hunt_tasks` become the queue. Leads from past runs must pass the same bar. |
| `hunt` | One agent per task (attack class, scope, falsifiable hypothesis, start points), run concurrently in priority order. Hunters fork recon's session to reuse its context (`run.fork_hunters`). Each sees the 30 filed reports closest to its task, so it skips known bugs. Emits findings, gaps, and [wishes](#wishlist); PoC sources are copied to `pocs/<finding id>/`. Incremental: only unhunted tasks run. |
| `gapfill` | Re-queues areas hunters flagged as under-covered. Run `hunt` again after it. |
| `dedupe` | Collapses findings with one root cause (same file and attack class, and the same line or a similar title). The most severe survives; the rest go to `duplicates.jsonl`. |
| `skip-reported` | Drops candidates the sink already holds (filed GitHub issues) before validate spends tokens on them. Token overlap settles clear cases; cheap judges take the ambiguous ones concurrently (`run.concurrency`) and fail open. |
| `validate` | Reviewers re-read the code in batches of up to 8 findings grouped by file and tag each `confirmed`, `downgraded`, `likely_false_positive`, or `needs_review`, writing its impact and recommendation. Nothing is dropped. |
| `report` | Writes every finding but `likely_false_positive` to the sink, with its verdict. |
| `feedback` | Turns real bugs (as variant hunts) and open gaps into `feedback-seeds.jsonl` for the next run's recon. |
| `aggregate` | Compiles everything into one reviewable `findings.json`, most severe first and likely false positives last. |

Stages run in the order of `stages.enabled` and talk only through files in
`out_dir`, so they stay decoupled and a run can resume. `report` and
`aggregate` make no agent call. An agent whose answer does not parse, or that
times out, gets one repair turn in its own session.

## Runs

- A run that starts with recon clears the previous run's artifacts except
  `feedback-seeds.jsonl`. Reuse the same `out_dir` to keep that memory.
- A failed stage is logged and the rest still run; the exit code is non-zero.
- `fee1dead run --resume` continues after a usage limit or crash: it skips
  recon, keeps every artifact, and hunts what is left.
- `fee1dead aggregate --out-dir ./out` compiles `findings.json` from a partial
  run without any agent.
- Finding ids are `<run id>-<task id>-F<nn>`, unique across runs.
- `run-meta.json` records the target and reference commits, the fee1dead
  commit, and each stage's model and effort. Reports and issues carry the
  target commit, since `file:line` is ambiguous without it.

Each agent's raw event stream is teed live to `out_dir/logs/<stage>-<label>.jsonl`,
so it survives a timeout, and its answer lands beside it as
`<stage>-<label>.output.json`. `findings.json` sums their cost and token usage
per stage under `summary.cost`.

### Wishlist

When a hunter or reviewer needs something the sandbox lacks, it records a wish
in `wishlist.jsonl` and carries on from the code. `findings.json` lists the
wishes by kind; grant them and re-run.

| `kind` | Grant it with |
|--------|---------------|
| `network` | `[firewall].allow` |
| `source` | `[target].setup` or `[reference]` |
| `toolchain` | `[target].setup` or `docker/Dockerfile` |
| `data` | `[target].setup` or a mounted file |
| `environment` | infrastructure outside the container (another OS, a VM, a live service) |
| `other` | read its `need` |

## Configure

`config/harness.toml` sets the target, provider, concurrency, firewall
allow-list, sink, and stages. Unknown keys fail at load.

```sh
fee1dead check        --config config/harness.toml
fee1dead run          --config config/harness.toml
fee1dead run --resume --config config/harness.toml
```

### Providers

`provider.default` names a `[providers.*]` block. `claude-code` and `opencode`
are built in; any other CLI is a `type = "exec"` block whose `args` take
`{prompt}` and `{working_dir}`.

`[stages.models]` overrides the model for `recon`, `hunt`, `validate`, or
`skip-reported`. Keep `hunt` and `recon` on one model: forked hunters reuse
recon's prompt cache only on the same model.

For opencode:

- `model` must be `provider/model` (e.g. `anthropic/claude-opus-5`; see
  `opencode models`). A bare id is rejected at load, since opencode reports it
  only as "Unexpected server error".
- `[firewall].allow` needs `models.dev`, `registry.npmjs.org`, and the model
  provider's API host.
- Auth is opencode's own: an API key in the environment, or
  `~/.local/share/opencode`, which the `just` recipes mount.

| | claude-code | opencode |
|-|-------------|----------|
| Forked hunters | yes | yes |
| Tool deny-list | enforced | ignored |
| Reasoning effort | set per stage | fixed `variant` from config |
| Trail of Bits skills | registered | not registered; found under `/opt/skills` |
| `max_weekly_usage_pct` | yes (subscription auth) | no |
| `skip-reported` default model | `claude-haiku-4-5` | the provider's `model` |

### Target

```toml
[target]
repo    = "https://github.com/org/name.git"   # clone instead of mounting
ref     = "main"
prepare = ["go mod download"]
setup   = '''
apt-get update && apt-get install -y --no-install-recommends protobuf-compiler
go build ./...
'''
```

Without `repo`, the code must already be at `run.target_dir`. The pipeline
clones and fetches behind the firewall, so the git host must be allowed.

| | `setup` | `prepare` |
|-|---------|-----------|
| Runs as | root, before the firewall | agent, behind the firewall |
| On failure | stops the run | warns and continues |
| When | container start, before `run` | every run, also outside Docker |

`setup` runs under `bash -euxo pipefail` in `target_dir` with the agent's
`HOME`; what it creates under `/work` and `/home/agent` is handed to the agent
afterwards. Install binaries on the default `PATH`. A mounted target is
read-only, so build out of tree.

### Reference

```toml
[reference]
repo = "https://github.com/lightning/bolts.git"
ref  = "master"
dir  = "/work/reference"   # default
```

A spec or known-good implementation that recon, hunt, and validate treat as
ground truth. Recon also emits `spec-to-code-compliance` tasks pairing a spec
clause with the code that implements it.

### Sinks

`[report].sink` is `sqlite`, `jsonl`, `http` (one POST per finding), or
`github` (one issue per finding in `repo`, PAT from `token_env`, default
`GITHUB_PAT`; allow `api.github.com`). The github sink never files a finding
twice and labels `needs_review` issues `needs-review`. Other sinks than
`jsonl` also get a local copy in `out_dir/findings.jsonl`.

## Run in Docker

The container is the security boundary. The agent runs with
`--dangerously-skip-permissions`; a default-deny egress firewall allows only
`[firewall].allow`. It needs `--cap-add=NET_ADMIN`, not `--privileged`.

```sh
just image                      # build
just run target=/path/to/repo   # mount a local repo
just run-clone                  # clone [target].repo instead
just resume                     # continue the last run in ./out
just run-nofw                   # no firewall, local debugging only
just shell
```

Or directly:

```sh
docker build -t fee1dead -f docker/Dockerfile .
docker run --rm --cap-add=NET_ADMIN \
  -e ANTHROPIC_API_KEY \
  -v /path/to/repo:/work/target:ro \
  -v "$PWD/out":/work/out \
  fee1dead
```

Auth is `ANTHROPIC_API_KEY`, or `CLAUDE_CODE_OAUTH_TOKEN` from
`claude setup-token` for Pro/Max. The `just` recipes forward whichever is set,
also from `.env`.

The image ships Claude Code, opencode, Go, Python with uv, and build-essential
so hunters can build PoCs. Toolchains that fetch at run time need their hosts
allowed (e.g. `proxy.golang.org`, `sum.golang.org`, `pypi.org`).

## Develop

```sh
cargo test --features mock-runner
```

`tests/e2e.rs` runs the whole pipeline against `MockRunner`, offline and free.

`src/provider` holds the CLI adapters, `src/pipeline` one file per stage,
`src/store` the sinks, and `src/config` the TOML, validated at load. `prompts/`
and `schema/` are embedded at build time.

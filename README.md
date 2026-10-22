# fee1dead

fee1dead is a vulnerability discovery harness. It drives AI coding CLIs
(Claude Code, opencode, or any CLI described in config) through a staged
pipeline, runs many narrow agent tasks in parallel, and turns their output into
schema-validated findings. The orchestrator schedules agents and never hunts
bugs itself.

## Run

The container is the security boundary. Agents run with
`--dangerously-skip-permissions`, and a default-deny egress firewall lets them
reach only the hosts in `[firewall].allow`. The firewall needs
`--cap-add=NET_ADMIN`; the container does not need `--privileged`.

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

Authenticate with `ANTHROPIC_API_KEY`, or on a Pro or Max plan with the
`CLAUDE_CODE_OAUTH_TOKEN` that `claude setup-token` prints. The `just` recipes
forward whichever is set, including from `.env`.

The image ships Claude Code, opencode, Go, Python with uv, and build-essential,
so hunters can build PoCs. A toolchain that fetches at run time needs its hosts
allowed, such as `proxy.golang.org`, `sum.golang.org`, or `pypi.org`.

## Pipeline

Stages run in the order of `stages.enabled` and exchange data only through
files in `out_dir`, which keeps them independent and lets a run resume. An
agent whose answer does not parse, or that times out, gets one repair turn in
its own session.

- `recon` reads the repo and writes a threat model to `recon.json`. Its
  `hunt_tasks` become the queue. Leads from earlier runs must pass the same
  admission bar as new tasks. When the last audited commit is known, recon
  reviews the changes made since it. `run.wildcard_tasks` appends lead-less
  hunts over the largest modules no task scopes.
- `hunt` runs one agent per task (attack class, scope, falsifiable hypothesis,
  starting points), concurrently and in priority order. Hunters fork recon's
  session to reuse its context (`run.fork_hunters`). Each one sees the 30 filed
  reports and the 15 [ruled-out claims](#cross-run-memory) closest to its task,
  so it skips known bugs and settled questions. A hunter reports findings with
  a traced data path, the hypotheses it disproved, the gaps it left, and
  [wishes](#wishlist). A hunter that cites a `file:line` the target lacks gets
  a repair turn. PoC sources are copied to `pocs/<finding id>/`. Only unhunted
  tasks run, so a second pass picks up just the new ones.
- `critic` is optional. One agent, forked from recon, checks the queue against
  the threat model and queues tasks for attack surface no task covered.
- `gapfill` re-queues the areas hunters flagged as under-covered. Run `hunt`
  again after it or after `critic`.
- `dedupe` treats findings in one file as a single root cause when they share
  the root-cause line, the sink, or a similar title under the same attack
  class. The most severe one survives, and the rest go to `duplicates.jsonl`.
- `skip-reported` drops findings the sink already holds, such as filed GitHub
  issues, before validate spends tokens on them. Token overlap settles the
  clear cases. Cheap judges take the ambiguous ones concurrently
  (`run.concurrency`) and keep a finding when they fail.
- `validate` hands reviewers batches of up to 8 findings grouped by file. A
  reviewer re-reads the code, checks each hop of the hunter's trace, re-runs
  its PoC when there is one, and tags the finding `confirmed`, `downgraded`,
  `likely_false_positive`, or `needs_review`, with its impact and a
  recommended fix. Nothing is dropped.
- `report` writes every finding except `likely_false_positive` ones to the
  sink, with its verdict. It makes no agent call.
- `feedback` updates the [cross-run memory](#cross-run-memory): variant hunts
  around real bugs, gaps no follow-up hunt covered, settled claims, and the
  audited commit.
- `aggregate` compiles the run into one reviewable `findings.json`, most
  severe first and likely false positives last. It makes no agent call.

## Runs

- A run that starts with recon clears the previous run's artifacts, except the
  cross-run memory. Reuse the same `out_dir` to keep it.
- A failed stage is logged and the remaining stages still run. The exit code
  is then non-zero.
- `fee1dead run --resume` continues after a usage limit or a crash. It skips
  recon, keeps every artifact, and hunts what is left.
- `fee1dead aggregate --out-dir ./out` compiles `findings.json` from a partial
  run without calling any agent.
- Finding ids are `<run id>-<task id>-F<nn>`, unique across runs.
- `run-meta.json` records the target and reference commits, the fee1dead
  commit, and each stage's model and effort. Reports and issues carry the
  target commit, because a `file:line` is ambiguous without it.

Each agent's raw event stream is copied live to
`out_dir/logs/<stage>-<label>.jsonl`, so it survives a timeout, and the agent's
answer lands next to it as `<stage>-<label>.output.json`. `findings.json` sums
their cost and token usage per stage under `summary.cost`.

### Cross-run memory

Feedback writes three files that survive the next run's reset:

| File | Read by | Holds |
|------|---------|-------|
| `feedback-seeds.jsonl` | recon, as leads | variant hunts around real bugs, and unfinished gaps |
| `ruled-out.jsonl` | hunters | claims a hunter disproved or a reviewer judged a likely false positive, each with the code that settled it; an entry is dropped once that file changes, which needs a git target |
| `audited-commit.txt` | recon | the target commit the run audited, where the next recon's review of recent changes starts |

### Wishlist

When a hunter or reviewer needs something the sandbox lacks, it records a wish
in `wishlist.jsonl` and carries on from the code. `findings.json` groups the
wishes by kind. Grant them and run again.

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
allow-list, sink, and stages. An unknown key fails at load.

```sh
fee1dead check        --config config/harness.toml
fee1dead run          --config config/harness.toml
fee1dead run --resume --config config/harness.toml
```

### Providers

`provider.default` names a `[providers.*]` block. `claude-code` and `opencode`
are built in. Any other CLI is a `type = "exec"` block whose `args` take
`{prompt}` and `{working_dir}`.

`[stages.models]` overrides the model for `recon`, `hunt`, `critic`,
`validate`, or `skip-reported`. Keep `hunt`, `critic`, and `recon` on one
model, because a forked agent reuses recon's prompt cache only on the same
model.

For opencode:

- `model` must have the `provider/model` form, such as
  `anthropic/claude-opus-5` (see `opencode models`). A bare id fails at load,
  because opencode reports it only as "Unexpected server error".
- `[firewall].allow` needs `models.dev`, `registry.npmjs.org`, and the model
  provider's API host.
- opencode handles its own auth: an API key in the environment, or
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
clones and fetches from behind the firewall, so the git host must be allowed.

| | `setup` | `prepare` |
|-|---------|-----------|
| Runs as | root, before the firewall | agent, behind the firewall |
| On failure | stops the run | warns and continues |
| When | container start, before `run` | every run, also outside Docker |

`setup` runs under `bash -euxo pipefail` in `target_dir` with the agent's
`HOME`, and the agent then owns what it created under `/work` and
`/home/agent`. Install binaries on the default `PATH`. A mounted target is
read-only, so build out of tree.

### Reference

```toml
[reference]
repo = "https://github.com/lightning/bolts.git"
ref  = "master"
dir  = "/work/reference"   # default
```

A reference is a spec or known-good implementation that recon, hunt, and
validate treat as ground truth. With one set, recon also emits
`spec-to-code-compliance` tasks, each pairing a spec clause with the code that
implements it.

### Sinks

`[report].sink` is one of:

- `sqlite`
- `jsonl`
- `http`, one POST per finding
- `github`, one issue per finding in `repo`, with a PAT read from `token_env`
  (default `GITHUB_PAT`). Allow `api.github.com`. It never files a finding
  twice and labels `needs_review` issues `needs-review`.

Every sink except `jsonl` also writes a local copy to `out_dir/findings.jsonl`.

## Develop

```sh
cargo test --features mock-runner
```

`tests/e2e.rs` runs the whole pipeline offline against `MockRunner`, at no API
cost.

`src/provider` holds the CLI adapters, `src/pipeline` one file per stage,
`src/store` the sinks, and `src/config` the TOML, which is validated at load.
`prompts/` and `schema/` are embedded at build time.

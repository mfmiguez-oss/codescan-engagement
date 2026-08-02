# Running the UI locally

Two different web UIs exist in this family of repositories, they answer
different questions, and it is worth knowing which one you want before you
start a server:

| You want to… | Use | Repo |
|---|---|---|
| Work the queue a run produced — read findings, record decisions, draft a PoC | `engagement console` | this repo |
| Configure a pipeline before it runs — pick models per task, toggle enrichment, run a scan | `codescan serve` | `../codescan` |

The engagement console is a **review** surface over a finished run. It is
deliberately not a control panel: it renders a queue and records decisions, and
it cannot start work unless you explicitly hand it that power. The codescan UI
is the opposite — it is where model routing and scan options are chosen.

---

## 1. The engagement console (review a run)

### Prerequisites

The console serves **one run directory**, and it refuses to start without a
queue manifest:

```
no queue manifest at <run_dir>/queue.json — the console shows a run's
findings, so the run has to have produced some
```

That is not a bug to work around. If you see it, the run has not reached the
point of producing a queue — check the run's `report.html` or `audit.jsonl`
first. A run that failed early (the router, say) has no queue and nothing to
review.

### Start it

```bash
ENGAGEMENT_OPERATOR=ada .venv/Scripts/python -c "from engagement.cli import main; import sys; sys.exit(main())" console C:/Users/manue/AppData/Local/Temp/ohw/runs/benchmark-python/run-001 --dev-token local-dev --model claude-haiku-4-5
```

Then open <http://127.0.0.1:8000/>, click **Sign in**, and paste `local-dev`.

`ENGAGEMENT_OPERATOR` is what the audit trail attributes your decisions to. Set
it to something that identifies you; unset, decisions are attributed to a
generic `local operator`, which makes the log much less useful later.

### The flags that matter

| Flag | Default | What it does |
|---|---|---|
| `run_dir` | — | Positional. The run to serve. Must contain `queue.json`. |
| `--host` | `127.0.0.1` | Keep it on loopback locally — see the dev-token rule below. |
| `--port` | `8000` | |
| `--dev-token` | off | Accept this one string as a local analyst **and** approver. |
| `--model` | off | Deployment for on-request PoC drafting. Omitted, drafting is off and the button does nothing. |
| `--decisions` | `<run_dir>/decisions.jsonl` | Where decisions are appended. |
| `--allow-runs` | off | Let a signed-in scanner start scans from the browser. |
| `--run-max-calls` | `200` | Ceiling for a run started that way. |

### Two things that will stop you, by design

**`--dev-token` is refused off loopback.** Bind to anything network-reachable
and the console exits rather than serving:

> refusing to serve: `--dev-token` is a shared string, not an identity, and
> `--host 0.0.0.0` is reachable from a network. Bind to 127.0.0.1, or configure
> OIDC.

The identity model exists so that "a human approved this" has a referent. A
shared string reachable from a network is not one. For anything beyond your own
machine, configure OIDC — the console verifies tokens exactly as the deployed
control plane does, so local and deployed behave the same.

**`--allow-runs` is off by default.** A console serving a queue has no business
starting runs: starting one reads repositories and spends money. Turn it on only
when you actually want to drive scans from the browser, and note that
`--run-max-calls` (not `--max-calls`) is the ceiling that then applies.

### Roles

The dev token grants **analyst + approver**. Those are different powers:
analyst covers the non-terminal states (investigating), approver covers the
terminal ones (closing a finding). `scanner` — the role that may spend budget —
is separate again, and is what `--allow-runs` gates.

---

## 2. The codescan UI (configure and run a pipeline)

This is the surface for **choosing models per task**, which the engagement
console deliberately does not do.

```bash
codescan serve --ai --live
```

Drop `--ai --live` for the offline demo against fixtures — no credentials
needed, useful for looking around the UI before wiring anything up.

Set `FOUNDRY_API_KEY` and `FOUNDRY_RESOURCE` first (plus `GITHUB_TOKEN` for a
live repo source). Then at <http://127.0.0.1:8000>:

1. **Config tab** — the model routing lives here. A default model and effort,
   then a per-task grid (dedup, enrichment, exploitability, threat_model,
   openhack) where each row takes its own provider, model, effort, and max
   tokens. The model list is populated by preflighting your Foundry resource's
   actual deployments; any deployment name can also be typed freely. Two toggles
   are worth understanding before a live run: **auto-route** silently moves a
   call up or down the tier ladder by difficulty, and **pin to deployments**
   preflights the resource at scan start and substitutes an undeployed model
   within its family rather than 404-ing mid-scan. Saving writes
   `config.overrides.json` (gitignored), so routing survives a restart.
2. **Scan bar** — enter repos as `owner/name`, tick **AI**, **live**, and
   **whitebox** as needed, then **Run scan**. Whitebox clones the repos and runs
   the built-in engine; it needs AI on and `git` available.
3. **Audit tab** — shows `scan.model_remapped` events, which is how you confirm
   whether deployment pinning actually substituted anything. Worth checking
   after the first live run rather than assuming your routing took effect.

If `CODESCAN_API_TOKEN` is set, every `/api/*` request needs it; visiting
`/?token=…` once sets a cookie so the browser's own calls carry it.

### One trap

Model families have per-model quirks on Foundry — `gpt-5.x` wants
`max_completion_tokens`, structured outputs are per model, Codestral does not
reliably terminate its JSON. The lowest-risk first live run routes everything to
Claude, then diversifies once that is green.

---

## Verifying UI changes

For changes to `codescan`'s `static/index.html`, verify in a browser against the
running dev server rather than by reading the diff. The preview dev server needs
the venv interpreter: point `.claude/launch.json`'s `runtimeExecutable` at
`.venv/Scripts/python.exe` temporarily, then revert it to `"python"` before
committing — the machine path must not be committed.

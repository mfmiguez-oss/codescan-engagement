---
description: Reduce LLM spend on an engagement run without cutting coverage — analyse cost drivers, apply the cheap model allocation, verify, and run the gate.
argument-hint: "[optional: a target scan size, e.g. 'scenarios 24 candidates 9 findings 30']"
---

You are tuning **codescan-engagement** (or a sibling like codescan-mcp) to run
at the lowest sensible LLM cost **without reducing coverage**. All models are
reached through Microsoft Foundry, which bills at standard first-party API rates.
Work through the steps below in order. Report findings as you go; make code
changes only where a step says to.

## 1. Map where the money goes (don't guess)

Every live call funnels through `Dispatcher.ask` (`src/engagement/dispatch.py`)
→ `provider.complete`. The only call sites above it are the driver
(`src/engagement/driver.py`: router, scenarios, triage) and the analysis engines
(`src/engagement/analysis.py`: `ChainEngine`, `PocEngine`). The cost model and
its N× multipliers live in `src/engagement/budget.py` and the driver:

- **Router** chunking (`router_chunk_obligations`, default 12) → many calls, but
  the ~170K-token prompt rides as a **cache prefix**, so it costs ~1.4× one
  call's *money* even across dozens of calls. Lowering the chunk size costs more
  *quota*, not more money.
- **Scenarios** — 1 per candidate, embeds the target file (cap
  `MAX_SOURCE_CHARS`). The bulk of the run.
- **Triage** — 1 per candidate.
- **Chains** — 1 per service. **PoC** — batched, 1 per 10 criticals.
- **Two-pass** (`--second-model`) **doubles the whole pipeline**; `expand_context`
  (default on) adds a 2nd call per inconclusive scenario.

Confirm these against the current code before recommending anything.

## 2. Apply the cheap model allocation

Spend on judgement, economise on volume. The CLI ships these as defaults
(`DEFAULT_*` in `src/engagement/cli.py`), shared across `run`/`preflight`/`plan`:

| Flag | Phase | Model | Tier |
|---|---|---|---|
| `--router-model` | router | `claude-opus-4-8` | frontier (½ the price of fable-5) |
| `--expert-model` | scenarios | `claude-opus-4-8` | frontier |
| `--triage-model` | triage | `claude-sonnet-4-6` | mid |
| `--chains-model` | chains | `claude-sonnet-4-6` | mid |
| `--analysis-model` | PoC (+ chains fallback) | `claude-haiku-4-5` | economy |
| `--effort` | phases that accept it | `low` | cheapest lever on spend + time |

Rules that must hold:
- **Never route everything through one frontier model.** A bare `--model` forces
  every phase (including triage/PoC) to frontier price.
- **Keep `Policy` strict.** Defaults live at the CLI layer only; the `Policy`
  dataclass keeps empty defaults and its "loud on omission" guard so library and
  test callers must still name a model. Do not move these onto `Policy`.
- **Chains is split from PoC on purpose** (cross-finding reasoning: hard but rare,
  so a mid tier costs almost nothing; PoC is the batch stage → economy).

## 3. Bound any unbounded prompt

The triage prompt (`vendor/openhack/src/openhack/triage.py`) inlines the full
scenario-result JSON with **no character cap** — the only unbounded prompt in the
pipeline. Cap it the way scenarios are capped (`MAX_SOURCE_CHARS`) so input
tokens per candidate can't blow up on a large finding set. Add a test.

## 4. Cut multipliers you aren't using

- Drop `--second-model` unless cross-vendor consensus is genuinely needed (it's 2×).
- Leave `--chains`/`--pocs` off unless the run needs the advisory appendix.
- Scope with `--expert` (repeatable) to shrink the scenario count — the strongest
  input-reduction knob.

## 5. Verify, then gate

- Run `engagement plan` at a realistic size (use `$ARGUMENTS` if given, else
  `--scenarios 24 --candidates 9 --findings 30 --services 2`). Confirm the
  per-phase deployments and projected dollars. Expect two informational tier
  warnings (triage on sonnet is one tier above mid; that's fine) — explain them,
  don't silence them.
- Run the full gate and keep it green:

  ```bash
  ruff check src tests
  mypy
  pytest -q
  ```

- **Docs in lockstep**: update the "Model per task" section of `README.md` in the
  same commit as any default or flag change.

## 6. Know the platform limits

- **The Batch API's 50% discount is not available on Foundry** — don't plan
  around it.
- Prompt caching is already implemented (router prefix + cache warming); verify
  `CacheReport` doesn't show prefixes offered-but-never-read before adding more.

Deliver the smallest change that lowers spend while coverage stays intact.
Report the projected before/after cost.

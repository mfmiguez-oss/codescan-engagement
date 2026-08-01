# codescan-engagement

Unattended driver for scenario-first whitebox security review.

It drives an **OpenHack workspace** to completion with no human in the loop,
spending a bounded budget and reporting honestly on what it did not reach. It
does not reimplement the methodology — recon, routing units, scenarios, proof
obligations and independent finding triage stay in the workspace, and so do the
integrity checks that make an unattended run defensible in the first place.

Architecture and rationale: [docs/DESIGN.md](docs/DESIGN.md).
Stages, contracts and dataflows: [docs/DATAFLOW.md](docs/DATAFLOW.md) — including
the [degradation matrix](docs/DATAFLOW.md#degradation-what-happens-when-an-input-is-missing),
which says what a run still means when a feed or a budget is missing.
Topology and cloud setup: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
Risk register: [docs/THREATMODEL.md](docs/THREATMODEL.md).
Framework conformance, dated: [docs/SECURITY_FRAMEWORKS.md](docs/SECURITY_FRAMEWORKS.md).

## Run it

The workspace it drives is **vendored** into `vendor/openhack`, so a checkout
installs into something that can actually scan — no sibling repository, no
private fetch at build time:

```bash
pip install -e ".[dev]" ./vendor/openhack

# Azure Foundry (default)
export FOUNDRY_RESOURCE=... FOUNDRY_API_KEY=...
engagement run acme run-001 --workspace ../OpenHack-main --model gpt-5-mini

# AWS Bedrock — same image, same command
export BEDROCK_REGION=us-east-1 BEDROCK_INFERENCE_GEO=us
engagement run acme run-001 --workspace ../OpenHack-main \
  --model anthropic.claude-opus-5 --max-calls 400
```

## What it replaces

Attended, a person stands at four points and says "go". Three of those are
scope and sanity checks the workspace already enforces in code. The fourth —
approving a recorded backlog — is a spend decision, and it lands at the only
moment where the cost of the expensive phase is already known:

```
cost = 1 router call + 1 per scenario + 1 per candidate
```

That gap is where the budget governor sits, with the same information the human
had. Over the ceiling, the backlog is processed in priority order and the
remainder is reported as `unfunded` — never silently dropped.

## What is enforced

- **Work not done is never reported as work that found nothing.** Every item
  ends `completed`, `parked`, `unfunded`, or `failed`, and only the first counts
  as clean. `reviewed_fraction` travels with every report.
- **Provenance is observed, not claimed.** The driver stamps the digest of the
  prompt it actually dispatched and a unique agent id per item; a model's own
  account of either is overwritten.
- **One context cannot serve a whole backlog.** The workspace rejects a repeated
  agent id, so per-scenario isolation survives automation by force rather than
  by good intentions.
- **`needs_context` earns one expanded re-attempt, then parks.** The model's own
  statement of what it lacked drives the expansion; files it names are resolved
  **inside the checkout only**, and anything refused is reported. Parked
  scenarios are written to `parked-scenarios.json`, not merely counted.
- **Credentials never reach the provider.** Credential shapes are redacted
  before every dispatch and restored in the answer — reversible, because a
  model that could only see a redacted line could never cite one, and the
  findings lost would be exactly the hardcoded-credential ones.
- **Every dispatch is recorded.** An append-only audit carries prompt digests,
  token counts and redaction counts — never prompt text, never model output, so
  the trail is safe to ship where the source under review is not.
- **Spend is refused before dispatch**, with bounded defaults.
- **Two configured providers is a refusal.** An unattended run has nobody to
  notice it picked the wrong bill.
- **Exit code 3 means incomplete.** A scheduler must be able to tell a
  half-reviewed backlog from a clean one without parsing prose.
- **A model annotates the queue and never extends it.** Chain and PoC output is
  narrowed against the ids of its own request; a chain left with fewer than two
  admissible findings is dropped as fabricated rather than repaired.
- **Unknown is never reported as supported.** A component no lifecycle feed
  covers is counted as unknown, because "we checked and it is fine" and "we did
  not check" produce an identical clean queue otherwise.
- **The SIEM exporter narrows and never widens.** It is a pure function of the
  audit trail, with detail keys allow-listed per event kind; an unclassified
  event ships its identity and none of its payload.

## Scoring the findings

```bash
engagement run acme run-001 --workspace ../OpenHack-main --model gpt-5-mini \
  --triage --feeds ./feeds --repo acme/app
```

Hands the run's SARIF to the triage backbone — dedup, KEV/EPSS enrichment,
explainable score, rank. The backbone is `engagement.backbone`, **part of this
package**: no extra to install, no credentials, no network. It was ported from
`triagekit` rather than depended on, because a private git reference put scoring
— and therefore lifecycle, chains, PoC drafts and the worklist — behind
credentials, and its absence degraded to a *warning*, so a run that could not
score looked like a run that found nothing worth scoring.

Fingerprinting and the weakness-synonym table are ported **verbatim**: a
fingerprint is a finding's identity, and a port that hashed differently would
orphan every analyst decision and every baseline at the moment of the switch.
`tests/test_backbone_conformance.py` holds the port byte-for-byte against the
original whenever `triagekit` happens to be installed beside it, and skips
cleanly when it is not.

Without feeds it still scores, and says so: an unexploited finding and an
unchecked one otherwise rank the same.

## Package lifecycle: deprecation, end of support, end of life

A CVE-shaped pipeline has one large blind spot. Every stage upstream keys on
*known vulnerabilities*, so a component that is merely **unmaintained** produces
no finding and reads as clean. It is not clean — it is the one exposure that
cannot be patched, because nobody is left to publish the patch.

```bash
engagement run acme run-001 --workspace ../OpenHack-main --model gpt-5-mini \
  --triage --feeds ./feeds --inventory ./sbom.json
```

The pass is deterministic and offline — a date comparison against
`<feeds>/lifecycle.json`, never a model call. Lifecycle is a fact about a
release calendar, and a question with a checkable answer should not be handed to
something that guesses. Three states are kept distinct because they carry
different obligations:

| State | What it means | What it costs you |
|---|---|---|
| `deprecated` | The maintainer marked it superseded | Migration signal; fixes may still arrive |
| `eos` | Standard support ended | Security fixes need an extended-support agreement — or never come |
| `eol` | End of life | No further updates of any kind. Replacement is the only remediation |

Two things follow, and the first is the one nothing else in the pipeline does:

- **An end-of-life component becomes a finding in its own right**, minted
  locally, with no CVE behind it.
- **A vulnerable component past end of life outranks a vulnerable one**, through
  a recorded adjustment that sits beside the backbone's score rather than
  overwriting it — `base_score` always recovers the original.

`--inventory` supplies components beyond those already on findings, which is the
only way the blind spot actually closes: a dependency list that arrives *through*
findings can never contain the package that produced none.

**Unknown is never reported as supported.** A component the feed does not cover
is recorded as `unknown` and counted, exactly as a missing KEV feed is. The two
mean opposite things and rank identically if conflated.

## Attack chains and PoC drafts

A ranked queue answers "which finding first?" but not the two questions a
responder asks next:

```bash
engagement run acme run-001 --workspace ../OpenHack-main --model gpt-5-mini \
  --triage --chains --pocs
```

`--chains` finds ordered sequences that combine into a worse outcome than any
one finding alone — one call per service, because a chain between components
that never talk is not a chain. `--pocs` drafts, per finding, what an operator
*would* do in a test environment, with the preconditions first: whether the path
is really open is decided there. Both write into the run folder — `chains.json`
and a readable `pocs.md` pack — and both are **advisory**. Nothing is executed,
and a failure costs its own artifact, never a finding.

They spend from the run's own ledger, so `--max-calls` still bounds the whole
engagement. The caps are bounds like any other and are reported, never silent:
chain discovery examines at most 60 findings per service and PoC drafting the
top 40 by risk, in batches of 10 so one over-long response cannot truncate every
draft in it. Findings past a cap are named in the summary — no PoC below means
*not attempted*, never *implausible*.

## The worklist

`queue.csv` is what an analyst actually works from, so it carries four things a
ranked list does not:

| Column group | Why |
|---|---|
| `repo`, `path`, `line` | **Where.** A finding without a location is a claim the reader has to go and re-find |
| `detected_by`, `corroboration` | **What found it.** Two independent sources agreeing is stronger than one asserting twice — and you cannot weigh that if you cannot see it |
| `merged_count` | **No duplicates.** One row per real issue; a row that absorbed three others says so, so nothing vanishes without a trace |
| `severity_delta`, `score_delta`, `movement_reason` | **What moved, and why** — lifecycle state, exploit intelligence, or new corroboration |

```bash
engagement run acme run-002 --workspace ../OpenHack-main --model claude-opus-5 \
  --triage --baseline ./state/acme.baseline.json
```

`--baseline` is what makes movement possible: the previous run's severities and
scores, rolled forward automatically. Without it every row reads `unknown`
rather than `new` — a first run has not established that anything is new, and
labelling a whole queue "new" trains an analyst to ignore the column exactly
when it starts to mean something. Merging keeps the **worse** of two readings;
disagreement is not a reason to report the milder one.

## Model per task: what to spend where

An unattended run makes every model choice on its own, so the choice is written
down where a human can audit it before the bill arrives:

```bash
engagement plan --model claude-opus-5 --analysis-model claude-haiku-4-5 \
  --scenarios 24 --candidates 9 --findings 30
```

The rule is **spend on judgement, economise on volume**, and the two are
anti-correlated here:

| Task | Tier | Volume | Why |
|---|---|---|---|
| `router` | frontier | 1 per run | Decides the whole backlog; a missed routing unit loses every finding it would have produced — and it costs one call |
| `scenarios` | frontier | 1 per scenario | Where vulnerabilities are actually found. A cheaper model does not make a cheaper run, it makes a run that finds less |
| `triage` | mid | 1 per candidate | Adjudicates against evidence the workspace re-validates anyway |
| `chains` | high | 1 per service | Hard reasoning, short prompt, few calls |
| `poc` | economy | 1 per 10 findings | Writing up a finding that is already established |

`plan` prints projected calls and dollars before dispatch, and warns when a
configured deployment sits below (or wastefully above) its task's tier. A
deployment with no published rate is reported as **unpriced** rather than
assigned a guessed one.

## Two detection passes, from two vendors

```bash
engagement run acme run-001 --workspace ../OpenHack-main \
  --expert-model claude-opus-5 --second-model gpt-5.6-luna --triage
```

**The driver drives both passes.** `--second-model` is all it takes: the driver
creates a sibling run (`run-001-p2`) against the same checkout, reviews the
whole backlog again with the second vendor's model, and consolidates the two
SARIFs. `--second-sarif` remains only as an override for a pass produced out of
band.

The second pass is a *separate run*, not a second sweep of the first. That is
forced by the methodology rather than chosen for convenience: the workspace
treats a scenario as finished once a result is recorded, so both passes writing
into one run would produce a single SARIF with no way to tell which pass found
what — which is precisely the signal the second pass exists to produce. Separate
runs also give each pass its own checkout, its own agent ids, and its own
context by construction.

Both passes spend from **one ledger**, so `--max-calls` bounds the engagement
rather than each pass separately. A second pass that could not run — budget
exhausted, run not creatable, pass failed — is **reported**, never silently
skipped: a queue built from one pass whose findings read as corroborated would
be worse than no second pass at all.

A second pass is only worth paying for if it can **disagree** with the first.
Two models from one vendor share training data, tokenizer lineage and refusal
behaviour, so they miss the same things in the same places — and a second pass
that agrees for structural reasons produces a corroboration count that reads
like evidence and is not. **Same-vendor pairs are refused**, not warned about;
`ENGAGEMENT_ALLOW_SINGLE_VENDOR=1` makes accepting a weaker pair a deliberate
choice. An unrecognised alias counts as its own vendor, so two unknowns are
never *assumed* independent.

Consolidation is the dedup that already existed: findings merge on fingerprint
and `corroboration` counts the passes that reported each one. A finding only one
pass saw is **kept** and reported as uncorroborated — not false, only
uncorroborated. Dropping it would be suppression dressed up as precision.

## All four score dimensions are populated

The scorer weights severity 30%, exploitability 35%, exposure 20%, chaining 15%.
The last two used to be zero, so 35% of the weight did nothing: every blended
score was dragged down, the KEV floor decided the ranking of every exploited
finding rather than the blend, and two findings that differ entirely — one on an
unauthenticated SAML endpoint, one behind three internal hops — scored the same.

Both are now filled from evidence the pipeline already produced:

- **exposure** — OpenHack's recon already walks the source for *request
  boundaries* (route registrations, webhook handlers, SAML/OIDC callbacks,
  upload endpoints) and records each with a path and a type. A finding in a
  boundary file is externally reachable. That fact was being thrown away.
- **chaining** — the chain-discovery stage was producing exactly the signal the
  dimension was named for, with nowhere to put it. A hub appearing in three
  chains now outranks a link in one, capped so overlapping chains cannot inflate
  a finding past its evidence.

Both are **recorded, reversible adjustments** like the lifecycle bump:
`base_score` subtracts every one of them, so the backbone's own score is always
recoverable. A path with no boundary is *not* penalised — recon only sees
boundaries it recognised, so absence is weak evidence, not proof of
unreachability.

## Determinism

`temperature` defaults to `0.0` — a queue that changes between identical runs
cannot be reviewed or regression-tested. But **sampling support is a per-family
fact, not a global setting**: Claude Opus 4.7 and later, Opus 5, Sonnet 5 and
Fable 5 removed `temperature`/`top_p`/`top_k` and reject them with a **400**. So
the parameter is added only where the family accepts it, decided in one place
(`models.sampling_for`) rather than at each dispatch site. Platform prefixes are
stripped first — Bedrock writes `anthropic.claude-opus-5` and cross-region
inference adds `us.`, and a match against the bare family name silently fails
without that, which is a hard call failure rather than a degraded answer.

Ordering is deterministic too: findings rank by score with the finding id as a
stable tie-break, chains and PoC drafts sort by score, and JSON artifacts are
written with sorted keys.

## KEV, from CISA

```bash
engagement fetch-kev --out ./feeds/kev.json
```

Fetched from CISA's published catalogue rather than a copy, because **a stale
KEV file is a suppression surface**: every CVE added since the copy was taken
scores as un-exploited, which is the one direction that produces a falsely calm
queue — silently, since nothing about an old file looks wrong. The catalogue's
own `catalogVersion` and `dateReleased` are cached with it, and anything older
than a fortnight is reported as stale.

## Snyk

Snyk answers the question the lifecycle pass most needs answered: **what is
actually installed**. A source-only review carries no dependency list, which is
precisely why an unmaintained package slips through.

```bash
snyk test --all-projects --json > snyk.json

engagement run acme run-001 --workspace ../OpenHack-main --model claude-opus-5 \
  --triage --feeds ./feeds --snyk-export ./snyk.json
```

The export path is offline and needs no credentials — the components join the
lifecycle check, and Snyk's package-manager names are mapped onto the feed's
ecosystems (`pip` → `pypi`, `gradle` → `maven`). A live pull against an
organisation is also supported; the token travels in an `Authorization` header
and never in a URL, so it cannot be captured by a proxy or access log that
records the path.

## Audit trails, and getting them into a SIEM

Every run writes an append-only trail beside itself. A SIEM is where it is
actually read, so it ships in the shapes collectors expect:

```bash
engagement run acme run-001 --workspace ../OpenHack-main --model gpt-5-mini \
  --siem ./out/engagement.ecs.json --siem-format ecs

engagement export-siem runs/acme/run-001/audit.jsonl \
  --out engagement.cef --format cef --run acme/run-001
```

`ecs` is Elastic Common Schema as JSON lines (Elastic natively; Splunk, Sentinel,
Chronicle and OpenSearch by field mapping), `cef` is ArcSight Common Event Format
for QRadar, ArcSight and syslog collectors, and `jsonl` passes the trail through
unchanged.

The rule governing the exporter is **narrowing, never widening**. The trail is
already safe to ship — prompt *digests*, token counts, redaction *counts*, never
prompt text, model output or a redacted value — and the exporter is a pure
function of it, adding nothing. Detail keys are additionally allow-listed per
event kind, and an event kind nobody has classified ships its identity with
**none** of its payload. Failing closed is the only safe default where the data
crosses into a system with broad read access and long retention. A run that left
work unreviewed is exported at a raised severity, so a correlation rule can find
the runs that mattered without parsing prose.

## Picking work back up, and looking at it

```bash
engagement run acme run-001 --workspace ../OpenHack-main --model gpt-5-mini \
  --resume-parked --report queue.html
```

`--resume-parked` re-attempts the scenarios a previous run could not conclude.
`--report` writes a self-contained HTML view — no CDN, no scripts — that leads
with the fraction of the backlog actually reviewed. It is read-only: validation
states belong to an authenticated principal, never to a page.

## Scaling across repositories

`claims.py` leases repos from a shared table using `FOR UPDATE SKIP LOCKED`, so
several hosts share one repo list with no orchestrator above them. An expired
lease returns its repo to the queue, and a repo that fails every attempt is
marked failed rather than leased forever.

## The control plane

```bash
pip install -e ".[api]"
export ENGAGEMENT_TENANT_ID=<tenant>
export ENGAGEMENT_JWKS_URI=https://login.microsoftonline.com/$ENGAGEMENT_TENANT_ID/discovery/v2.0/keys
export ENGAGEMENT_ISSUER=https://login.microsoftonline.com/$ENGAGEMENT_TENANT_ID/v2.0
export ENGAGEMENT_API_AUDIENCE=api://engagement
uvicorn engagement.asgi:app --port 8080
```

Verifies Entra (or any OIDC) tokens against the issuer's published keys and
enforces the three roles. `/healthz` is the only unauthenticated route.
Everything else is 401 without a verified token and 403 without the role —
both with no detail, because a caller learning which check failed learns how
close it is.

It **refuses to start** without an issuer and audience rather than starting
permissively, and `deployControlPlane` in the Bicep defaults to `false`: an
endpoint that accepts state changes should not appear by accident.

## The vendored workspace

`vendor/openhack` carries the expert manifests, prompt templates, schemas, and
the `openhack` package itself, pinned to the upstream commit recorded in
`vendor/openhack/vendor-manifest.json`. The container bakes it in, which is
what makes the image self-contained.

Vendoring buys reproducibility and pays for it in drift, so the drift is made
detectable rather than hoped away: `tests/test_vendor.py` fails if a vendored
file is edited in place, and — when an upstream checkout happens to sit beside
this repo — if the copy has fallen behind it. Refresh with:

```bash
python scripts/vendor_openhack.py ../OpenHack-main
```

Change the methodology upstream and re-vendor; never edit under `vendor/`.

## The image

```bash
docker build -f deploy/Dockerfile -t codescan-engagement .
docker run --rm codescan-engagement --help
```

455 MB on `python:3.12-slim`, running as uid 10001. It carries the driver, both
provider clients, the control plane, and the vendored workspace — so it can run
a scan on its own, with no private repository reached at build time.

## The gate

```bash
ruff check src tests
mypy
pytest -q
```

Offline, deterministic, no network, no API key. Provider request shapes are
asserted by building them, never by calling anything; the fake workspace in the
suite enforces the same prompt-digest and agent-id rules the real one does, so
the gate cannot pass while the driver quietly violates the methodology.

`tests/test_e2e.py` goes further and drives the **real** workspace — and, when
the image is built, the container — with scripted model answers. Judgement is
stubbed; nothing else is. Coverage validation, prompt-hash binding, evidence
re-read from the checkout and agent-id uniqueness all run for real, and each
can fail it. Both defects that reached a green suite lived in that gap: a
prompt digest hashed over decoded text rather than file bytes, and a container
whose command was never installed.

```bash
docker build -f deploy/Dockerfile -t codescan-engagement:ci .
pytest tests/test_e2e.py -q   # skips cleanly without the image
```

## Security posture

[docs/THREATMODEL.md](docs/THREATMODEL.md) carries 28 risks; every row marked
*mitigated* names a test, and `tests/test_invariants.py` fails the build if one
does not exist. [docs/SECURITY_FRAMEWORKS.md](docs/SECURITY_FRAMEWORKS.md)
gives dated per-framework verdicts across OWASP LLM Top 10, OWASP Top 10, ASVS
5.0, NIST AI RMF and MITRE ATLAS — with three honest verdicts, and no credit
taken for a control that is not run.

## Not yet

The analyst view is still read-only — the control plane accepts state changes
over HTTP, but the generated HTML does not call it. `PostgresClaimStore` is
unproven against a live database, the JWKS network hop is stubbed in the suite,
and there is no rate limiting (that belongs at the ingress — R25). The `triage` extra
resolves to a git reference rather than an index, so `--triage` needs network
and repository access and is deliberately not baked into the image. See the end
of [docs/DESIGN.md](docs/DESIGN.md).

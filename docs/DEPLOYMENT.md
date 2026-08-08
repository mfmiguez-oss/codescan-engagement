# Deployment

Azure is the default target. AWS is a supported peer, not an afterthought — the
portability is structural, and this document exists partly to keep it honest.

## What makes it portable

Exactly one module knows which cloud it is on: `providers.py`. The driver, the
budget governor, and the workspace adapter never learn. Everything else is
substrate:

| Concern | Azure | AWS | Portable because |
|---|---|---|---|
| Model inference | Microsoft Foundry | Bedrock (Converse) | `ModelProvider` protocol |
| Compute | Container Apps Jobs | ECS / EKS scheduled task | One OCI image, no cloud SDK in the entrypoint |
| Artifacts | Blob Storage | S3 | Written to a mount, not an SDK call |
| Secrets | Key Vault + Managed Identity | Secrets Manager + IAM role | Credentials arrive as environment or ambient identity |
| Identity | Entra ID | IAM Identity Center | Not yet consumed — see the gap below |
| Projection | Azure Database for PostgreSQL | RDS / Aurora Postgres | Same SQL |

The container never calls a cloud SDK to do its job. It reads and writes a
filesystem mount and makes one kind of outbound call, to a model endpoint. That
is what keeps the same image digest promotable across clouds without a rebuild.

## What is in the image

The image is self-contained for the job it does. It carries the driver, both
provider clients, the control plane, and the **vendored OpenHack workspace** —
expert manifests, prompt templates, schemas, and the package that enforces
them. It reaches no private repository at build time and needs no build-time
credentials.

Verified against the built image (455 MB, `python:3.12-slim` base): the CLI
runs, the workspace root resolves with all 12 experts, the control plane
imports, the process is uid 10001, and a complete scan — recon, router, expert,
triage, SARIF — runs inside the container.

Three consequences worth knowing before you run it:

- **`/workspace` is baked, not mounted.** It is `OPENHACK_ROOT`, and it holds
  the methodology. Mounting a volume over it shadows the expert manifests and
  leaves a container that starts and then has nothing to route to. The volumes
  are `/workspace/runs` (mutable per-run state) and `/artifacts` (exports).
- **`--triage` needs nothing extra.** The backbone was ported into the package
  as `engagement.backbone` (stdlib and pydantic only), so scoring, lifecycle,
  chains, PoC drafts and the worklist are all in the default image. This bullet
  used to say the opposite, from when triage resolved to a private git
  reference; there is no `triage` extra any more, and a derived image built to
  get it is doing nothing.
- **Bind-mounting a local repository needs `safe.directory`.** The container
  runs as uid 10001, so a host checkout mounted into it is owned by a different
  user and git refuses to clone from it (`detected dubious ownership`). Normal
  use clones from a URL and never hits this; if you do mount one for testing,
  add `git config --global --add safe.directory '*'` inside the container.

## The shape of the workload

Scanning is a **job**, not a service: it starts on a schedule, drives one run to
completion or to its budget, writes artifacts, and exits. It has no ingress and
no published port, which keeps it exposure-free regardless of what else runs.

The control plane is the opposite and is therefore opt-in. `deployControlPlane`
defaults to `false`, and the application refuses to start without an issuer and
audience — an endpoint that accepts state changes should not appear by accident,
and one that accepts every token on trust is worse than none at all.

## Azure

```bash
az deployment group create \
  --resource-group rg-codescan \
  --template-file deploy/azure/main.bicep \
  --parameters \
      namePrefix=csengage \
      image=<registry>.azurecr.io/codescan-engagement@sha256:<digest> \
      foundryResource=<foundry-resource-name> \
      modelDeployment=<deployment-name> \
      infrastructureSubnetId=<subnet-resource-id>
```

What the template does and why:

- **User-assigned managed identity for every data-plane call.** No API key is
  stored, so there is nothing to rotate or leak. `AZURE_CLIENT_ID` is passed so
  the SDK's default credential chain selects the right identity.
- **Storage with shared-key access disabled** and public network access turned
  off once a subnet is supplied. Source under review and its findings should
  not traverse a public endpoint.
- **`replicaRetryLimit: 0`.** A failed scan is not retried automatically,
  because the retry re-spends the model budget on the same broken input. Retry
  is a decision, not a default.
- **A three-hour replica timeout**, because a run is recon plus a router call
  plus one call per scenario, and a large backlog is legitimately slow.

Pin the image by digest rather than tag. A tag that moves under a scheduled job
is a silent change to what your estate is scanned by.

### Still to wire for a production estate

The template stops at the batch job on purpose. Before this is enterprise-grade
you also need:

- **An Entra app registration** exposing an API scope and publishing the three
  app roles the control plane maps (`Engagement.Scanner`, `Engagement.Analyst`,
  `Engagement.Approver`). The enforcement exists; the directory objects it reads
  are a deployment step and cannot be created from Bicep.
- **Private Endpoints** for storage and Postgres, so nothing crosses a public
  network.
- **Immutability policy** on the artifacts container — the audit trail should be
  write-once.
- **Postgres Flexible Server** for the projection, with the index and decision
  schemas from the platform.
- **Data residency review.** Model inference leaves your subscription boundary;
  confirm the Foundry region and retention posture satisfy your obligations.

## AWS

The same image, a different provider and substrate:

```bash
docker run --rm \
  -e ENGAGEMENT_PROVIDER=bedrock \
  -e BEDROCK_REGION=us-east-1 \
  -e BEDROCK_INFERENCE_GEO=us \
  -v "$PWD/workspace:/workspace" \
  codescan-engagement:local run acme run-001 --workspace /workspace \
    --router-model anthropic.claude-opus-5 \
    --expert-model anthropic.claude-opus-5 \
    --triage-model anthropic.claude-sonnet-5 \
    --chains-model anthropic.claude-sonnet-5 \
    --analysis-model anthropic.claude-haiku-4-5
```

**Name the deployments per task on Bedrock.** `ENGAGEMENT_MODEL` is a *fallback*
for a per-task flag that is unset, and on `run` those flags always carry a CLI
default — Foundry-style ids such as `claude-opus-4-8`, which a Bedrock account
does not serve. Preflight refuses the run rather than failing at dispatch, but
the cause reads as a missing deployment rather than as configuration that never
applied. See [MODELS.md §5](MODELS.md#5-how-a-deployment-is-chosen-in-order).

For a scheduled deployment: ECS Fargate task on an EventBridge schedule, an
IAM task role granting `bedrock:InvokeModel` and `bedrock:Converse` plus S3
write on the artifact bucket, S3 with Object Lock for artifacts, and RDS or
Aurora Postgres for the projection. No credential goes in the task definition —
botocore resolves the task role and signs with SigV4 at dispatch.

Cross-region inference profiles are handled by `BEDROCK_INFERENCE_GEO`: several
models are only invocable through a profile, so the `us.` / `eu.` / `apac.`
prefix is part of the model id. It is applied at most once, so an id that
already carries one is left alone.

A Terraform module is not included; the resource set is small and most
organisations will fold it into an existing landing zone rather than adopt a
standalone stack.

## Configuration

| Variable | Meaning |
|---|---|
| `ENGAGEMENT_PROVIDER` | `foundry` or `bedrock`. Required only when both are configured |
| `ENGAGEMENT_MODEL` | Fallback deployment for any phase whose per-task flag is unset. On `run`/`plan`/`preflight` those flags carry CLI defaults, so this reaches only `draft-poc` and `console` unless the flags are cleared |
| `FOUNDRY_RESOURCE` / `FOUNDRY_API_KEY` | Foundry resource and key (prefer managed identity) |
| `FOUNDRY_BASE_URL` | Override the OpenAI-compatible base |
| `BEDROCK_REGION` / `AWS_REGION` | Bedrock region; the marker that Bedrock is configured |
| `BEDROCK_INFERENCE_GEO` | `us` / `eu` / `apac` cross-region inference profile prefix |
| `ENGAGEMENT_MAX_CALLS` / `ENGAGEMENT_MAX_TOKENS` | Spend ceilings. `--max-calls` / `--max-tokens` override them; a malformed value is refused, never defaulted |
| `OPENHACK_ROOT` | Workspace root the driver operates on (baked at `/workspace`) |
| `ENGAGEMENT_JWKS_URI` / `ENGAGEMENT_ISSUER` / `ENGAGEMENT_API_AUDIENCE` | Control plane; it refuses to start without them |
| `ENGAGEMENT_TENANT_ID` | Rejects tokens issued for any other tenant |

Precedence is **flag > environment > bounded built-in**, and a value the
environment supplies but cannot be parsed stops the run rather than falling
back — an operator who configured a budget and silently got a different one is
the failure this ordering exists to prevent.

**Two configured providers is a refusal, not a default.** An unattended run has
nobody to notice it picked the wrong model set — or the wrong bill.

## Operating it

Exit codes are the interface for a scheduler:

| Code | Meaning | Reasonable response |
|---|---|---|
| 0 | Every scenario and candidate concluded | Nothing |
| 3 | Finished with work parked or unfunded | Review the report; consider raising the budget |
| 2 | Configuration refused before spending | Fix configuration; safe to re-run |
| 1 | The run failed | Investigate before re-running |

**Do not treat 3 as success.** It is the code that says the estate was only
partly reviewed, and a pipeline that maps it to green reintroduces exactly the
silence the design exists to prevent.

Budget sizing follows the cost model directly: one router call, one call per
scenario, one call per candidate. Size `--max-calls` from a representative
run's backlog, then add headroom for retries rather than guessing.

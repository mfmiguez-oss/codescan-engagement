# Security framework review

Assessment of **codescan-engagement as an AI system** against the security and
governance frameworks below. It is itself a defensive security tool; this
review asks how the package protects itself, the source it reads, and the
outputs it produces.

Assessed 2026-08-02.

Companion documents: [THREATMODEL.md](THREATMODEL.md) (risk register R1–R82),
[OUTPUTS.md](OUTPUTS.md) (every artifact a run produces, what it must not be
read as, and a threat model with a diagram for each),
[DATAFLOW.md](DATAFLOW.md) (trust boundaries, stage contracts, degradation
matrix), [DESIGN.md](DESIGN.md), [DEPLOYMENT.md](DEPLOYMENT.md).

## The frameworks reviewed

Links are to each framework's canonical home. The **version reviewed** column
is what this assessment was written against; where the upstream has since
moved, it says so, because a framework review that does not date itself is a
framework review nobody can trust a year later.

| Framework | Published by | Version reviewed | Where to read it |
|---|---|---|---|
| Top 10 for LLM Applications | OWASP GenAI Security Project | 2025 (`LLM01:2025`–`LLM10:2025`) | <https://genai.owasp.org/llm-top-10/> |
| Top 10 Web Application Security Risks | OWASP | 2025 | <https://owasp.org/Top10/> |
| Application Security Verification Standard (ASVS) | OWASP | 5.0.0 — assessed at **L1**, selected chapters | <https://owasp.org/www-project-application-security-verification-standard/> |
| AI Risk Management Framework | NIST | AI RMF 1.0 (`NIST.AI.100-1`) + Generative AI Profile (`NIST.AI.600-1`) | <https://www.nist.gov/itl/ai-risk-management-framework> |
| ATLAS — Adversarial Threat Landscape for AI Systems | MITRE | v4 — technique ids (`AML.Txxxx`) move between revisions | <https://atlas.mitre.org/> |
| AI Controls Matrix (AICM) | Cloud Security Alliance | v1 — **v1.1 is now out**; re-derive the domain mapping | <https://cloudsecurityalliance.org/artifacts/ai-controls-matrix> |
| CycloneDX | OWASP / Ecma TC54 (ECMA-424) | 1.6 — SBOM, VEX and ML-BOM are the parts that apply | <https://cyclonedx.org/> |
| GenAI Security Project | OWASP | umbrella; the agentic-AI guidance is held as a **gate**, not a gap | <https://genai.owasp.org/> |
| AI Exchange | OWASP | living document, lifecycle-split threat catalogue | <https://owaspai.org/> |
| Framework for Securing Generative AI | IBM | three pillars — secure the data, the model, the usage | <https://www.ibm.com/products/tutorials/ibm-framework-for-securing-generative-ai> |
| Secure AI Framework (SAIF) | Google | the **6-element** formulation; SAIF 2.0 has since restructured around 15 risk categories and agent security | <https://saif.google/> |
| Securing an AI-native SDLC | Anthropic | practitioner account, reviewed 2026-08-01 — practices rather than a control catalogue | <https://claude.com/blog/how-anthropic-secures-its-ai-native-software-development-lifecycle> |

Two are worth flagging as **stale against upstream**: the CSA matrix has
shipped v1.1 since this was written, and Google has restructured SAIF into a
2.0 with a different shape. Neither invalidates a verdict below — the gaps they
surface are architectural, not clause-specific — but the mappings should be
re-derived rather than assumed the next time this file is touched.

## How to read this

Three verdicts, meant exactly:

- **Enforced** — implemented *and* covered by a test in the gate; the test is
  named, and it has been run.
- **Partial** — implemented for some paths, or implemented but not operating.
- **Not yet** — designed, planned, or absent. No credit taken.
- **Out of scope** — genuinely not this package's job, said so rather than left
  blank to look like a gap.

A control that exists in the codebase but is never wired up is **Not yet**.
That distinction is the point of the exercise: it is what separates this
document from a marketing sheet. Every row below was checked against code, not
intent, and `tests/test_invariants.py` fails the build if an *Enforced* row
names a test that does not exist.

Scope note: this package drives a vendored OpenHack workspace. The
methodology's own integrity checks — coverage validation, evidence grounding,
schema conformance — are that project's invariants. They are exercised
end-to-end here by `tests/test_e2e.py`, but they are not claimed as this
package's controls.

## Architectural posture

Several structural choices *are* the controls, and they carry most of the
score:

- **Model output is data, never instructions.** Every answer is schema-checked
  by the recorder before anything is written, ids are allow-listed to the
  request, scalars are clamped and markup is stripped. Nothing in the package
  can turn a model answer into code: no `eval`, no `exec`, no `shell=True`.
- **Model input is data too, and reduced.** Source reaches the model inside
  delimited untrusted blocks under a directive-refusing system prompt, and
  passes through reversible redaction first — so credential *values* never
  leave, while the evidence that one was there survives for the finding to
  cite. The cached prompt prefix goes through the same redaction.
- **The model proposes; a person disposes.** `resolve_write` guarantees a human
  decision is never overwritten by a machine proposal, and terminal states are
  approver-only. Nothing is auto-remediated and the model executes nothing.
- **Deterministic backbone.** Parse, dedup, enrich, score, rank, lifecycle and
  export run with no model at all. An AI failure costs an appendix, never the
  queue.
- **Metered, and refused before dispatch.** One gateway counts every call,
  records it, and refuses it when the ceiling is spent — before the bytes leave.
- **Egress allow-listed from configuration only.** A host named anywhere in the
  material under review is unreachable by construction.
- **Bounded, and every bound reported.** Caps, budgets, feeds and thresholds all
  produce a warning naming what the result does *not* mean.

## OWASP Top 10 for LLM Applications (2025)

| Risk | Verdict | Evidence |
|---|---|---|
| LLM01 Prompt injection | Enforced | Delimited untrusted blocks under a directive-refusing system prompt in all three phases; `test_expansion_delimits_supplied_files_as_untrusted` |
| LLM02 Sensitive information disclosure | Enforced | Reversible credential redaction before every dispatch; `test_no_secret_reaches_the_provider`, `test_redaction_is_reversible_so_evidence_still_validates`, `test_no_prompt_text_or_model_output_is_recorded` |
| LLM03 Supply chain | Partial | The workspace is vendored and hash-pinned (`test_no_vendored_file_has_been_edited_in_place`), and the image is hermetic. Reviewed components are now checked for deprecation / end of support / end of life against a feed, with uncovered ones reported as unknown (`test_an_end_of_life_component_becomes_a_finding_with_no_cve_behind_it`, `test_a_component_the_feed_does_not_cover_is_unknown_not_supported`); still no lockfile or dependency audit of *this package's own* dependencies in CI |
| LLM04 Data & model poisoning | Not yet | Hosted models, no training. Nothing here defends the methodology against a poisoned upstream beyond the drift check |
| LLM05 Improper output handling | Enforced | No dynamic execution (`test_no_dynamic_execution_primitives_in_source`); model answers are schema-validated by the recorders before anything is written. Advisory output is narrowed the same way — ids allow-listed, scalars clamped, markup stripped (`test_a_chain_may_only_reference_findings_from_its_own_request`, `test_model_prose_cannot_carry_markup_into_the_pack`) |
| LLM06 Excessive agency | Enforced | Machine principals hold `scanner` only and cannot close findings; `test_a_machine_may_never_set_a_terminal_state`, `test_an_unattended_run_may_scan_but_not_adjudicate` |
| LLM07 System prompt leakage | Not yet | System prompts carry no secrets by design, but nothing tests that they never will |
| LLM08 Vector & embedding weaknesses | Not yet | Deliberately out of scope: no vector store, no embeddings |
| LLM09 Misinformation | Partial | Every finding passes independent triage and every citation is re-read from the checkout; no groundedness check on rationales |
| LLM10 Unbounded consumption | Enforced | Refuse-before-dispatch ceilings with bounded defaults; `test_call_ceiling_refuses_before_dispatch`, `test_token_ceiling_refuses_before_dispatch`, `test_default_ceiling_is_bounded_not_unlimited` |

## OWASP Top 10 Web Application Security Risks (2025)

| Risk | Verdict | Evidence |
|---|---|---|
| Broken access control | Enforced | Three roles with terminal states separated from investigation; `test_an_analyst_may_investigate_but_not_close`, `test_a_principal_cannot_act_across_tenants` |
| Identification & authentication failures | Enforced | OIDC verification with algorithms pinned in configuration; `test_an_algorithm_confusion_forgery_is_rejected`, `test_an_unsigned_token_is_rejected`, `test_an_expired_token_is_rejected` |
| Injection | Enforced | Parameterised SQL throughout the claim store; `test_the_claim_store_uses_no_string_interpolated_sql`. No shell invocation of model output |
| Security misconfiguration | Enforced | The control plane refuses to start without an issuer and audience, and is opt-in in the template; `test_the_control_plane_is_opt_in` |
| Software & data integrity failures | Enforced | Vendored methodology hash-pinned; deploy files cross-checked; `test_the_mirror_contains_nothing_the_manifest_does_not_track`, `test_the_image_installs_what_the_control_plane_command_needs` |
| Security logging & monitoring failures | Enforced | Append-only audit of every dispatch and outcome, exportable to a SIEM in ECS or CEF without widening what the trail discloses; `test_every_model_call_is_recorded`, `test_a_write_failure_is_an_error_not_a_warning`, `test_the_export_is_a_pure_function_of_the_trail`, `test_an_incomplete_run_is_exported_at_a_higher_severity_than_a_clean_one` |
| SSRF | Enforced | Outbound hosts are allow-listed from operator configuration only, checked at the one point bytes leave — so a host named anywhere in the material under review is unreachable by construction; `test_nothing_observed_can_widen_the_allowlist`, `test_the_provider_refuses_before_the_request_is_sent` |

## OWASP ASVS 5.0 (assessed at L1, selected chapters)

| Area | Verdict | Evidence |
|---|---|---|
| V1 Encoding & injection | Enforced | HTML escaped in the analyst view; parameterised SQL; `test_the_claim_store_uses_no_string_interpolated_sql` |
| V3 Session management | Not yet | Stateless bearer tokens only; no session surface |
| V5 Validation | Enforced | Strict models reject unknown fields at every boundary; `test_a_malformed_body_is_refused`, `test_an_unknown_state_is_refused` |
| V7 Error handling & logging | Enforced | Uniform opaque failures with the reason logged, not returned; append-only audit; `test_every_authentication_failure_looks_the_same_to_the_caller`, `test_a_corrupt_audit_line_is_an_error_not_a_skip` |
| V12 File handling | Enforced | The expansion reader is jailed to the checkout, against paths that come from model output; `test_a_path_outside_the_checkout_is_refused_and_reported` |
| V10 Coding practices / dependency currency | Partial | Reviewed components are checked against a lifecycle feed for deprecation, end of support and end of life, with a finding minted where no CVE exists and uncovered components reported as unknown; `test_an_end_of_life_component_becomes_a_finding_with_no_cve_behind_it`. Coverage is only as wide as the feed supplied |
| V14 Configuration | Partial | No secrets in the image or template; managed identity for data-plane calls; no secret scanning in CI |

## NIST AI RMF 1.0 + Generative AI Profile

| Function | Verdict | Evidence |
|---|---|---|
| Govern | Partial | Invariants documented and enforced by `tests/test_invariants.py`; no organisational policy layer |
| Map | Enforced | `docs/THREATMODEL.md` names assets, adversaries and per-risk mitigations, checked by `test_the_register_parses_and_is_not_empty` |
| Measure | Partial | Coverage is reported per run and travels with the queue (`test_coverage_is_the_first_thing_the_page_says`); no labelled-corpus benchmark in this package |
| Manage | Enforced | Human precedence with a verified identity; bounded spend; parked work persisted; `test_a_machine_never_overwrites_a_human_decision`, `test_the_parked_queue_is_written_not_merely_counted` |

## MITRE ATLAS (v4, attacker's view)

| Technique family | Verdict | Evidence |
|---|---|---|
| Prompt injection (AML.T0051) | Enforced | Delimited untrusted blocks and a directive-refusing system prompt; `test_expansion_delimits_supplied_files_as_untrusted` |
| Exfiltration via inference API | Enforced | Credentials redacted before dispatch; `test_no_secret_reaches_the_provider` |
| Denial of ML service / cost harvesting | Enforced | Refuse-before-dispatch ceilings; `test_call_ceiling_refuses_before_dispatch` |
| Model swap behind a deployment alias | Not yet | No benchmark in this package; the estate's regression gate lives in the triage backbone |

## Anthropic — securing an AI-native SDLC (assessed 2026-08-01)

Against the practices in [How Anthropic secures its AI-native software
development lifecycle](https://claude.com/blog/how-anthropic-secures-its-ai-native-software-development-lifecycle).
This package is one stage of an SDLC, not a whole one, so several rows are
**out of scope** rather than missing — marked as such rather than left blank to
look like gaps.

| Practice | Verdict | Evidence |
|---|---|---|
| Secure guidelines encoded for the generating agent | Enforced | `CLAUDE.md` plus the vendored expert manifests; the directive-refusing system prompt is applied in every phase; `test_expansion_delimits_supplied_files_as_untrusted` |
| Limit the blast radius (least agency) | Enforced | Machine principals hold `scanner` only and cannot set a terminal state; `test_an_unattended_run_may_scan_but_not_adjudicate` |
| Single-purpose identity per agent | Enforced | `identity.py`; a run may scan but not adjudicate, and the container runs as uid 10001 (`test_the_image_does_not_run_as_root`) |
| **Egress allowlisting to limit prompt-injection exfiltration** | **Enforced** | `egress.py`: an allowlist derived **only** from operator configuration, checked at the one point bytes leave; `test_nothing_observed_can_widen_the_allowlist` |
| Multiple specialised review agents with separate context windows | Enforced | Per-scenario subagent isolation with agent-id uniqueness enforced *across* passes; two-vendor detection (`test_agent_ids_stay_unique_across_passes`) |
| Agents that cannot share blind spots | Enforced | Same-vendor second passes are **refused**, not warned about; `test_two_passes_on_one_vendor_are_refused` |
| Agentic **and** deterministic scanning combined | Enforced | The deterministic backbone produces the ranked queue with no model at all; the AI stages annotate it; `test_scoring_is_available_without_any_optional_install` |
| Proof required before a finding is acted on | Partial | The workspace re-reads every citation from the checkout, and PoC drafts state preconditions — but a triage decision is not itself gated on a written proof |
| **Risk-weighted sampling of automated decisions** | **Enforced** | `governance.py`: a tier-driven fraction flagged for human review, deterministic per run; `test_sampling_is_stable_across_reruns` |
| **Risk-tiered automation** | **Enforced** | `RiskTier`; `critical` samples every decision, which is the same as not adjudicating unattended |
| **Shadow mode until an agent earns trust** | **Enforced** | A shadowed model's decisions are recorded and reported but do not adjudicate; `test_a_shadowed_models_decisions_do_not_count` |
| Logging with the reasoning behind each decision | Enforced | Append-only audit with prompt digests; `movement_reason`, `ScoreBreakdown`, and lifecycle/exposure/chaining deltas each recorded beside the score; `test_every_model_call_is_recorded` |
| Every agent action in a SIEM, for attribution | Enforced | `siem.py` (ECS/CEF), narrowing never widening; `test_a_detail_key_outside_the_allowlist_is_dropped_and_reported` |
| Invariant testing of critical properties | Enforced | `tests/test_invariants.py` plus `scripts/mutation_check.py`, which breaks the code in 25 places to prove the tests notice; `test_the_register_parses_and_is_not_empty` |
| Humans in the loop at leverage points | Enforced | Terminal states are human-only and identity-bound; sampling puts a human on a measured fraction of the rest; `test_a_machine_may_never_set_a_terminal_state` |
| Treat agents as an insider-threat class | Partial | Blocked egress and shadow decisions are audited and exported, but there is no alerting rule that fires on an out-of-alignment action |
| Vitals dashboard across runs | Not yet | Per-run reporting only; nothing aggregates across runs |
| Continuous DAST matched to deploy cadence | Out of scope | This package performs static, scenario-driven review; it does not deploy |
| Automated PSR at the planning stage | Out of scope | No design-document stage here |
| Bug bounty | Out of scope | An organisational programme, not a property of this package |

Two rows are worth stating plainly. **Egress allowlisting** closed the most
material gap: an agent that reads attacker-controlled source and then makes
network calls has an exfiltration path, and prompt injection does not need the
model to leak anything — it only needs a later stage to fetch a URL. The
allowlist is built from configuration only, so a host named anywhere in the
material under review is unreachable by construction.

And **sampling** answers the question an unattended run otherwise cannot: if no
automated decision is ever checked, there is no evidence the decisions are good
— only the absence of evidence that they are bad.

## Cloud Security Alliance AI Controls Matrix

Mapped by domain rather than control id.

| Domain | Verdict | Evidence and gaps |
|---|---|---|
| Application & Interface Security | Enforced | Strict models (`extra="forbid"`) at every boundary; schema-checked AI output; security headers and a deny-by-default CSP on the console routes; `test_the_policy_admits_no_other_origin` |
| Identity & Access Management | Enforced | OIDC verification with pinned algorithms, three roles, terminal states separated from investigation, tenant isolation; `test_an_analyst_may_investigate_but_not_close` |
| Logging & Monitoring | Partial | Append-only audit of every dispatch and outcome with digests, token and cache counts, exportable to a SIEM; `test_every_model_call_is_recorded`. No retention or rotation policy, no tamper-evidence, no alerting rule |
| Data Security & Privacy | Enforced | Secrets from environment or Key Vault only, never disk; reversible redaction before every dispatch including the cached prefix; `test_no_secret_reaches_the_provider`, `test_the_prefix_is_redacted_like_everything_else_that_leaves` |
| Threat & Vulnerability Management | Partial | Reviewed components checked against a lifecycle feed for EOL/EOS/deprecation; no dependency audit of *this package's own* dependencies in CI |
| Business Continuity & Resilience | Enforced | Resumable runs, per-item failure isolation, parked work persisted, a ceiling bounding the run; `test_the_parked_queue_is_written_not_merely_counted` |
| Model Security | Partial | Per-task allocation, pre-dispatch projection, a preflight that verifies every deployment exists before spending and **never substitutes one**, two-vendor detection, per-call telemetry; `test_two_passes_on_one_vendor_are_refused`, `test_the_report_carries_no_field_that_could_become_a_replacement`. No model provenance record, no approval workflow |
| Governance, Risk & Compliance | Partial | Threat model with a per-output section, this review, an enforced register; no AI inventory entry, no periodic review cadence |
| Interoperability & Portability | Enforced | SARIF in, SARIF/CSV/JSON/ECS/CEF out; `test_the_export_is_a_pure_function_of_the_trail` |

## OWASP CycloneDX

**Applicable, and the widest remaining gap.** The package consumes a Snyk
export to build the component inventory that closes the CVE blind spot, but it
neither ingests nor emits CycloneDX.

| Capability | Verdict | Evidence and gaps |
|---|---|---|
| Consume SBOM (CycloneDX / SPDX) | Not yet | Component inventory comes from `--inventory` JSON or a Snyk export; an SBOM would be the standard shape for the same input |
| Consume VEX / VDR | Not yet | Nothing reads another party's exploitability judgement |
| Emit VEX | Not yet | The package decides exploitability and records analyst dispositions — exactly what VEX exists to express — and publishes none of it |
| Produce an SBOM of itself | Not yet | The image ships no SBOM |
| ML-BOM / model cards | Not yet | The deployment serving each task is recorded per call in the audit trail, which is the material an ML-BOM would be built from |

Worth stating plainly: this is the framework where the package is most
asymmetric. It consumes others' component data and publishes none of its own
judgements in a standard vocabulary, so a downstream SBOM consumer re-raises
every CVE this queue already dismissed.

## OWASP GenAI Security Project

**Applicable as the umbrella**, and its best-known output — the LLM Top 10 — is
assessed above. Two further pieces are worth naming.

**Agentic AI threats and mitigations.** Held as a **gate**, not a gap. This
package drives a workspace unattended, which is agentic in the operational
sense, but the model itself has no tools: it is called, it returns
schema-constrained JSON, and nothing it produces is executed. Memory poisoning,
tool misuse and privilege compromise presuppose an autonomy that is
deliberately withheld — the driver stamps provenance, the model supplies
judgement only, and the workspace decides admissibility.

The line to watch is the PoC pack. It now **drafts a procedure** rather than
flagging availability, and that changes nothing today, because the draft is
prose in a file that no component reads back. The day a **PoC executor** lands,
this becomes the governing framework, because that is the first thing that
would run what a model wrote.

**Securing the AI supply chain.** Partial: the methodology is vendored and
hash-pinned (`test_no_vendored_file_has_been_edited_in_place`), the image is
hermetic, and a test forbids any git or URL dependency — but this package's own
dependencies are not audited in CI.

## OWASP AI Exchange

**Applicable, and the most granular of the catalogues.** Its lifecycle split
makes the scoping unusually clean.

| Threat group | Applicability | Verdict |
|---|---|---|
| **Development-time threats** (training-data poisoning, model theft) | **Mostly N/A** — nothing is trained and no weights are stored. Model supply chain stays in scope | Partial |
| **Threats through use** (evasion, prompt injection, model inversion, denial of service) | **Fully in scope** — this is where the package lives | Partial to Enforced |
| **Runtime application security** (the AI system as ordinary software) | In scope | Enforced — `test_no_dynamic_execution_primitives_in_source`, `test_the_claim_store_uses_no_string_interpolated_sql` |

Its named controls map onto work that exists:

| AI Exchange control | Implementation |
|---|---|
| Input segregation / prompt-input validation | Delimited untrusted blocks plus the data-not-instructions system prompt in every phase |
| Data minimization for model input | Reversible redaction at the dispatch choke point, applied to the prompt and the cached prefix alike |
| Rate limiting / consumption control | Refuse-before-dispatch ceilings on calls and tokens |
| Monitoring and logging of model use | `model_call` audit events with phase, deployment, digest, tokens and cache counts |
| Human oversight of AI decisions | `resolve_write` precedence — a machine proposal never overwrites a person |

Its unmet controls are the ones the other catalogues flag too: model
provenance, continuous evaluation of model performance, and alerting.

## IBM Framework for Securing Generative AI

| Pillar | Verdict | Evidence and gaps |
|---|---|---|
| **Secure the data** | Enforced | Reversible redaction before dispatch; egress allow-listed from configuration only; secrets never on disk; `test_no_secret_reaches_the_provider`, `test_nothing_observed_can_widen_the_allowlist` |
| **Secure the model** | Out of scope | Hosted models. No training, no weights, no fine-tuning; provider handling is contractual |
| **Secure the usage** | Enforced | Metered gateway, append-only audit, human precedence, risk-weighted sampling of automated decisions; `test_every_model_call_is_recorded`, `test_selection_is_uniform_at_the_configured_rate` |

The model pillar being out of scope is not a free pass: it moves the
provenance question to the operator, which [DEPLOYMENT.md](DEPLOYMENT.md)
states and the residuals below repeat.

## Google Secure AI Framework (SAIF)

Against the **6-element** formulation.

| Element | Verdict | Evidence and gaps |
|---|---|---|
| Expand strong security foundations to the AI ecosystem | Enforced | Egress allow-listing, non-root container, hermetic image, no dynamic execution; `test_no_dynamic_execution_primitives_in_source`, `test_the_image_does_not_run_as_root` |
| Extend detection and response to AI | Partial | Every call and outcome audited and exportable to a SIEM at a severity that distinguishes an incomplete run; no detection *rule* fires on an out-of-alignment action |
| Automate defences to keep pace with threats | Enforced | Guards run on every dispatch rather than on review: refuse, redact, allow-list, clamp, strip; `test_the_provider_refuses_before_the_request_is_sent` |
| Harmonise platform-level controls | Enforced | One dispatcher, one egress check, one overwrite rule, one place deciding sampling parameters; `test_a_family_that_removed_sampling_is_never_sent_temperature` |
| Adapt controls and create a feedback loop | Partial | Risk-weighted sampling puts a person on a measured fraction of automated decisions; nothing aggregates the result across runs into a calibration signal |
| Contextualise AI system risks in business processes | Partial | Risk tiers drive how much may go unreviewed; no organisational impact assessment |

No red-team exercise has been run against this package. That is the honest
answer to element two and it is not compensated for by the controls above.

## Consolidated gap register

| # | Gap | Frameworks touched | Status |
|---|---|---|---|
| F1 | No authentication on the machine surface until the control plane is deployed | OWASP A01/A07 · ASVS · AICM IAM · SAIF 4 | **Closed** — OIDC verification, three roles, tenant isolation, and a console that renders the server's answer rather than its own |
| F2 | Prompt injection mitigated at prompt level only | LLM01 · ATLAS AML.T0051 | Open — reduced; the structural guards (egress allow-list, no execution, schema-checked output) are what actually hold |
| F3 | No consumption control or per-call telemetry | LLM10 · ATLAS AML.T0029 · AI Exchange rate limiting · NIST MEASURE | **Closed** — refuse-before-dispatch ceilings, per-call audit, and a pre-dispatch spend projection |
| F4 | Undefined data boundary for model input | LLM02 · ATLAS AML.T0024 · IBM Data | **Closed** — reversible redaction on every dispatch path including the cached prefix |
| F5 | No detection-quality evaluation or drift regime | NIST MEASURE · AICM Model Security · LLM09 · SAIF 5 | Open — coverage is reported per run, but there is no labelled corpus in this package and so no quality bar |
| F6 | Audit retention, tamper-evidence and **alerting** | OWASP A09 · AICM Logging · SAIF 2 | Open — the trail is append-only and exportable; nothing fires on it |
| F11 | No rate limiting on the control plane | OWASP A04 · ASVS V11 · AICM Infra | **Closed in-process** — per-principal buckets, a smaller allowance on spending routes, authorization answered first. **Residual:** a multi-replica deployment still needs one at the ingress |
| F7 | No SBOM, VEX or ML-BOM | CycloneDX · AICM Model Security · LLM03 | Open — the queue holds exactly the judgements VEX exists to publish |
| F8 | No dependency audit of this package's own dependencies | LLM03 · ASVS V10 · AICM TVM | Open — reviewed components are lifecycle-checked; the package's own are not |
| F9 | Agents not treated as an insider-threat class | SAIF 2 · Anthropic SDLC | Open — blocked egress and shadow decisions are audited and exported, but no rule alerts on them |
| F10 | No cross-run vitals | NIST MEASURE · SAIF 5 | Open — per-run reporting only |

Remaining priority: **F6** (alerting is the cheap half and unblocks F9), then
F7 (VEX first — the judgements already exist), then F8, then F5. F5 is last
deliberately: a quality bar cannot be set until a real corpus has been scored,
and a regression guard without one measures nothing.

## Residuals the operator owns

- **Provider retention and data handling** are contractual. Foundry is governed
  by the Microsoft agreement and the resource's region; Bedrock by the AWS
  agreement. Redaction removes credential values, not source.
- **A cached prompt prefix persists on the provider's infrastructure** for the
  life of the cache entry. It is redacted, and it is still repository content
  held by a third party for longer than a single request.
- **Rate limiting across replicas.** The limiter bounds one process. Four
  replicas of a per-process limit is four times the limit — put a real one at
  the ingress before scaling out.
- **Who may start a scan.** `--allow-runs` makes the capability available; the
  directory decides who holds `scanner`, and this package enforces what the
  token asserts without being able to audit who granted it.
- **SIEM alerting rules and log retention** belong to the adopting
  organisation. This package exports; it does not alert.
- **The identity provider's own configuration** — who is granted
  `Engagement.Approver`, and how that is reviewed — is a directory question.
  This package enforces what the token asserts and cannot audit who issued it.
- **`--dev-token` is a development affordance.** It is refused off loopback and
  it is still an asserted identity; production means OIDC.
- **Branch protection, required reviews and CI secrets** are repository
  settings.

Dated: category names and technique ids move between revisions. Re-date this
file whenever a row changes.

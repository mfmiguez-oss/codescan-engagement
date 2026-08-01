# Framework conformance

Assessed 2026-08-01 against the versions named below. Three verdicts, meant
exactly:

- **Enforced** — implemented *and* covered by a test in the gate; the test is
  named, and it has been run.
- **Partial** — implemented for some paths, or implemented but not operating.
- **Not yet** — designed, planned, or absent. No credit taken.

A control that exists in the codebase but is never wired up is **Not yet**.
Every row below was checked against code, not intent, and
`tests/test_invariants.py` fails the build if an *Enforced* row names a test
that does not exist.

Scope note: this package drives a vendored OpenHack workspace. The
methodology's own integrity checks — coverage validation, evidence grounding,
schema conformance — are that project's invariants. They are exercised
end-to-end here by `tests/test_e2e.py`, but they are not claimed as this
package's controls.

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

## Others in scope of the design

| Framework | Verdict | Notes |
|---|---|---|
| CSA AI Controls Matrix | Partial | Control intents mapped informally via the register; no per-control matrix |
| CycloneDX 1.6 (SBOM/VEX) | Not yet | Neither consumed nor emitted; the image ships no SBOM |
| OWASP AI Exchange | Partial | Lifecycle threats considered in the register; no full catalogue walk |
| IBM Framework for Securing Generative AI | Partial | Data (redaction) and usage (metering, audit) pillars enforced; model pillar n/a (hosted) |
| Google SAIF | Partial | Expanded detection (audit log) and automated defences (guards); no red-team exercise |

Dated: category names and technique ids move between revisions. Re-date this
file whenever a row changes.

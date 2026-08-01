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
| SSRF | Not yet | The only outbound calls are to a configured model endpoint and a configured JWKS URI; neither is influenced by model output, but nothing tests that |

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

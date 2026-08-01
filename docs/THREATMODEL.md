# Threat model

`codescan-engagement` is an LLM application over hosted models that reads
untrusted source code, spends money unattended, and records judgements about
security findings. The assets are: **the source under review** and any
credentials inside it, **the integrity of the finding queue**, **the analysts'
decisions**, and **the operator's spend**.

The adversaries are: hostile text inside the repository under review (prompt
injection), a model that hallucinates or degrades, an unauthenticated party
reaching the control plane, and ordinary operational failure — a bound, a
budget, a crash — turning into silent under-review.

Status values: **mitigated** (enforced *and* covered by a named test in the
gate) or **open** (designed or absent; no credit taken). `tests/test_invariants.py`
contains a meta-test that fails if a row claims "mitigated" without naming a
test that exists.

## Risk register

| id | risk | mitigation | status | invariant test |
|---|---|---|---|---|
| R1 | Credentials in the source under review are sent to a third-party model | credential shapes redacted before dispatch, restored in the answer | mitigated | test_no_secret_reaches_the_provider |
| R2 | Redaction suppresses the hardcoded-credential findings it should surface | redaction is reversible; snippets restore before the recorder validates them | mitigated | test_redaction_is_reversible_so_evidence_still_validates |
| R3 | A run spends without limit because nobody is watching | one metered gateway, bounded defaults, refuse before dispatch | mitigated | test_call_ceiling_refuses_before_dispatch |
| R4 | Work not done is reported as work that found nothing | every item ends completed/parked/unfunded/failed; reviewed_fraction travels with the report | mitigated | test_budget_stops_dispatch_and_reports_the_rest_as_unfunded |
| R5 | A scenario nobody could conclude is counted as clean | needs_context is parked, persisted, and keeps the run out of exit 0 | mitigated | test_parked_scenarios_never_count_as_a_clean_run |
| R6 | Prompt injection from the repository under review | delimited untrusted blocks under a directive-refusing system prompt in every phase | mitigated | test_expansion_delimits_supplied_files_as_untrusted |
| R7 | A model steers the context expansion into reading files outside the checkout | requested paths resolved against the checkout and refused if they escape | mitigated | test_a_path_outside_the_checkout_is_refused_and_reported |
| R8 | One model context serves a whole backlog and is presented as independent reviews | unique agent id per dispatched item; the workspace rejects a repeat | mitigated | test_each_item_gets_its_own_agent_id_so_one_context_cannot_serve_all |
| R9 | A result is recorded against a prompt that was never dispatched | the digest is computed over the bytes the workspace rendered, not claimed by the model | mitigated | test_prompt_digest_hashes_bytes_not_decoded_text |
| R10 | A machine actor closes a finding | machine principals hold `scanner` only; terminal states are approver-only | mitigated | test_a_machine_may_never_set_a_terminal_state |
| R11 | A machine proposal overwrites a human decision | one `resolve_write` holds the rule; every store routes through it | mitigated | test_a_machine_never_overwrites_a_human_decision |
| R12 | An unauthenticated party changes a validation state | OIDC verification with pinned algorithms; fail-closed on every path | mitigated | test_health_is_the_only_unauthenticated_route |
| R13 | A forged token is accepted (algorithm confusion, `alg: none`) | algorithms come from configuration, never the token header | mitigated | test_an_algorithm_confusion_forgery_is_rejected |
| R14 | An error response tells an attacker which check it failed | every failure is 401/403 with no detail; the reason is logged, not returned | mitigated | test_every_authentication_failure_looks_the_same_to_the_caller |
| R15 | An analyst closes findings without a second pair of eyes | terminal states require the approver role, separate from analyst | mitigated | test_an_analyst_may_investigate_but_not_close |
| R16 | Nobody can say what an unattended run sent, to whom, or at what cost | append-only audit of every dispatch, with digests and token counts | mitigated | test_every_model_call_is_recorded |
| R17 | The audit trail itself leaks source or credentials | events carry digests and counts only; never prompt text or model output | mitigated | test_no_prompt_text_or_model_output_is_recorded |
| R18 | Model output reaches a dynamic execution primitive | no `eval`/`exec`/`shell=True` anywhere in the package | mitigated | test_no_dynamic_execution_primitives_in_source |
| R19 | Two hosts scan the same repository and double-spend | lease with `FOR UPDATE SKIP LOCKED`; an expired lease returns the repo | mitigated | test_two_workers_never_hold_the_same_repo |
| R20 | A repo that always fails is leased forever | bounded attempts, then marked failed | mitigated | test_a_repo_that_fails_every_time_is_failed_not_leased_forever |
| R21 | SQL injection at the claim store | parameterised statements throughout | mitigated | test_the_claim_store_uses_no_string_interpolated_sql |
| R22 | The vendored methodology drifts from upstream unnoticed | manifest of per-file hashes; drift and in-place edits fail the gate | mitigated | test_no_vendored_file_has_been_edited_in_place |
| R23 | The deployed image cannot do the job it builds cleanly for | deploy files cross-checked, and an end-to-end scan runs in the image | mitigated | test_the_image_installs_what_the_control_plane_command_needs |
| R24 | A scan runs with more privilege than reading source requires | the container runs as a non-root user | mitigated | test_the_image_does_not_run_as_root |
| R25 | A rate-limited or hostile caller exhausts the control plane | rate limiting at the ingress | open | — |
| R26 | The JWKS endpoint is unreachable or serves rotated keys mid-run | bounded key cache with refetch on unknown `kid` | open | — |
| R27 | An analyst acts on a queue without knowing how much was reviewed | coverage stated before any finding in the report | mitigated | test_coverage_is_the_first_thing_the_page_says |
| R28 | Secrets reach a log platform through the control plane's own logging | failures log the exception type, never the token | open | — |
| R29 | A model extends the queue by inventing findings through a chain | chain ids narrowed to the request; a chain under two admissible ids is dropped | mitigated | test_a_chain_may_only_reference_findings_from_its_own_request |
| R30 | A PoC is drafted against a finding nobody asked about | draft ids allow-listed against the batch | mitigated | test_a_poc_is_drafted_only_against_a_finding_in_its_request |
| R31 | Model prose carries markup into a rendered pack or web view | angle brackets stripped from every model-supplied string | mitigated | test_model_prose_cannot_carry_markup_into_the_pack |
| R32 | An advisory cap silently suppresses findings from the appendix | capped and unaffordable findings named in the summary and the pack | mitigated | test_findings_past_the_poc_cap_are_reported_not_silently_skipped |
| R33 | An advisory stage spends outside the run's ceiling | chains and PoC drafting meter through the run's own dispatcher and ledger | mitigated | test_analysis_spends_from_the_run_ledger |
| R34 | An unmaintained dependency reads as clean because it carries no CVE | lifecycle pass mints a finding for deprecated / EOS / EOL components | mitigated | test_an_end_of_life_component_becomes_a_finding_with_no_cve_behind_it |
| R35 | An unchecked component is reported as a supported one | uncovered components recorded as `unknown` and counted, never `supported` | mitigated | test_a_component_the_feed_does_not_cover_is_unknown_not_supported |
| R36 | End of support is reported as end of life, or the reverse | the two states are decided separately and ranked worst-first | mitigated | test_a_version_past_support_but_not_eol_is_end_of_support_not_end_of_life |
| R37 | A lifecycle adjustment silently rewrites the backbone's score | the delta is recorded alongside, so `base_score` always recovers the original | mitigated | test_the_adjustment_can_always_be_undone |
| R38 | Prompt text or model output reaches a SIEM through the exporter | export is a pure function of the trail, with detail keys allow-listed per kind | mitigated | test_a_detail_key_outside_the_allowlist_is_dropped_and_reported |
| R39 | A new event kind ships an unreviewed payload to a log platform | unclassified kinds export their identity and none of their detail | mitigated | test_an_unclassified_event_ships_its_identity_and_none_of_its_payload |
| R40 | A run that left work unreviewed is indistinguishable in the SIEM | incomplete runs exported at a raised severity | mitigated | test_an_incomplete_run_is_exported_at_a_higher_severity_than_a_clean_one |
| R41 | A determinism setting fails the call on models that removed sampling | sampling parameters sent only where the family accepts them, decided in one place | mitigated | test_a_family_that_removed_sampling_is_never_sent_temperature |
| R42 | A platform prefix hides the model family and the wrong parameters are sent | vendor and geo prefixes stripped before the family match | mitigated | test_a_platform_prefix_does_not_defeat_the_family_match |
| R43 | A stale KEV catalogue scores newly-exploited CVEs as un-exploited | catalogue fetched from CISA with its release date, and reported stale past a fortnight | mitigated | test_a_stale_catalogue_is_detectable |
| R44 | Duplicate rows inflate a queue, or a merge silently drops the worse reading | one row per identity, keeping the highest score, with the merge counted | mitigated | test_a_merge_keeps_the_worse_reading |
| R45 | A first run labels every finding new and trains analysts to ignore movement | no baseline reports `unknown`, never `new` | mitigated | test_a_first_run_reports_unknown_movement_not_new |
| R46 | Attacker-influenced text executes when the queue is opened in a spreadsheet | formula-leading cells neutralised on export | mitigated | test_a_hostile_title_cannot_execute_in_a_spreadsheet |
| R47 | An unattended run spends on a model nobody chose, at a rate nobody projected | per-task allocation with a pre-dispatch projection; unpriced deployments reported | mitigated | test_an_unpriced_deployment_is_reported_rather_than_guessed |
| R48 | A Snyk token is captured from a URL by a proxy or access log | credentials travel in an Authorization header only | mitigated | test_a_snyk_token_never_appears_in_a_url |

## What is deliberately out of scope

- **Model behaviour itself.** These are hosted models; there is no training,
  and no claim is made about what they will conclude. The controls bound what
  they are shown, what they can cause, and what is recorded.
- **The methodology's own integrity checks.** Coverage validation, evidence
  grounding, and schema conformance live in the vendored workspace and are
  exercised end-to-end by `tests/test_e2e.py`, but they are that project's
  invariants, not this one's to claim.

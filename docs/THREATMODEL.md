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
| R25 | A rate-limited or hostile caller exhausts the control plane | per-principal token buckets in the control plane, with a smaller allowance on spending routes; a fleet still needs one at the ingress | mitigated | test_a_caller_past_its_allowance_is_refused |
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
| R49 | Two same-vendor passes produce a corroboration count that is not evidence | vendor independence enforced before the run; refused, not warned | mitigated | test_two_passes_on_one_vendor_are_refused |
| R50 | A finding only one pass saw is dropped as unconfirmed | uncorroborated findings kept and reported as uncorroborated, not false | mitigated | test_a_finding_only_one_pass_saw_is_kept |
| R51 | An unrecognised deployment alias is assumed independent of another | unknown counts as its own vendor; two unknowns are refused | mitigated | test_two_unrecognised_aliases_are_treated_as_one_vendor |
| R52 | A score adjustment cannot be undone, so the score cannot be audited | every adjustment recorded beside the score; `base_score` recovers the original | mitigated | test_both_adjustments_together_stay_reversible |
| R53 | An unreachable finding ranks with an internet-facing one | exposure derived from recon's request boundaries | mitigated | test_a_finding_on_a_request_boundary_is_more_exposed_than_one_that_is_not |
| R54 | Overlapping chains inflate one finding past the evidence for it | chain contribution capped | mitigated | test_the_chaining_adjustment_is_capped |
| R55 | A second pass silently does not run, leaving a queue that reads as corroborated | every failure path appends a warning naming what the queue does not mean | mitigated | test_a_budget_exhausted_by_the_first_pass_reports_no_corroboration |
| R56 | Two passes share one context and are presented as independent reviews | separate runs; agent-id uniqueness enforced across passes, not only within one | mitigated | test_agent_ids_stay_unique_across_passes |
| R57 | A second pass silently reuses the first pass's model | the second run's policy overrides the expert deployment | mitigated | test_the_second_pass_uses_the_second_vendors_model |
| R58 | A second pass reviews a different checkout, so corroboration compares two things | the sibling run is created from the first run's own `run-config.yaml` | mitigated | test_a_second_pass_that_cannot_be_created_is_reported |
| R59 | An API key sits in plaintext on disk, readable by anything running as that user | secrets resolved by name from Key Vault via managed identity | mitigated | test_a_configured_vault_is_read_instead_of_the_environment |
| R60 | A vault silently falls back to a stale environment value, so rotation does nothing | a configured vault that fails is an error, never a fallback | mitigated | test_a_configured_vault_never_falls_back_to_the_environment |
| R61 | A secret value reaches a log, an error message or an artifact | failures name the vault and the secret name only; the plan prints no values | mitigated | test_a_failure_names_the_coordinates_and_never_the_value |
| R62 | The vault fetch is refused by this package's own egress allowlist | the vault host is derived from the same configuration that names the vault | mitigated | test_the_vault_host_is_on_the_egress_allowlist |
| R63 | An unattended run authorises its own exceptions to the critical-only rule, and the rule stops existing | `draft_poc` refuses a machine actor, derived from the subject and not the role set | mitigated | test_a_run_may_not_authorise_its_own_exception_to_the_critical_rule |
| R64 | An unauthenticated caller spends model budget through the drafting route | requesting a draft is authenticated and authorized exactly like a write, before any provider is built | mitigated | test_requesting_a_draft_without_a_credential_is_refused |
| R65 | A requested draft is an unbounded spend because a person asked for it | the batch cap and the run ledger apply to a request too, and the shortfall is reported | mitigated | test_a_request_is_metered_and_bounded_like_any_other_spend |
| R66 | A finding lifted into critical by enrichment is drafted against its pre-enrichment score and skipped | chaining is fed back inside `analyse`, before selection reads the score | mitigated | test_chain_membership_reaches_the_score_before_poc_selection_reads_it |
| R67 | Feeding chaining back twice double-counts and inflates a score | one place applies it; the caller no longer does | mitigated | test_chaining_is_applied_exactly_once |
| R68 | A finding below critical reads as one no PoC exists for | undrafted findings named, with the request path stated in the same warning | mitigated | test_findings_below_critical_are_named_and_pointed_at_the_request_path |
| R69 | A CLI-asserted operator identity is mistaken for a verified one | `operator()` carries `analyst` only and is displayed as unverified; terminal states stay behind the control plane | mitigated | test_a_cli_operator_may_ask_for_work_and_still_not_close_a_finding |
| R70 | A credential rides into a cached prompt prefix and persists on a third party's infrastructure | the prefix is redacted on the same path as every other byte that leaves | mitigated | test_the_prefix_is_redacted_like_everything_else_that_leaves |
| R71 | Hoisting content to make it cacheable changes what the model was asked | only the expert manifest moves; the instruction block stays with the header it refers to | mitigated | test_the_instruction_block_stays_with_the_header_it_refers_to |
| R72 | A cache prefix is silently dropped on a surface that cannot mark a breakpoint | folded into the system prompt instead, so the model sees the same prompt either way | mitigated | test_a_surface_without_cache_control_still_receives_the_prefix |
| R73 | Every call pays a cache write premium for an entry nothing ever reads | reads are counted from the provider's own numbers and a cache that never hits is a warning | mitigated | test_a_cache_offered_and_never_read_is_a_warning_not_a_zero |
| R74 | The console decides who may do what, and drifts from the server | the settable states are computed by the authorizing function and rendered; the server refuses regardless | mitigated | test_hiding_a_control_is_a_courtesy_and_the_server_still_refuses |
| R75 | A finding title from the repository under review executes in the analyst's browser | the page builds nodes and assigns text; nothing from the queue is written as markup | mitigated | test_the_page_never_writes_queue_data_as_markup |
| R76 | A development token becomes a network-reachable shared credential | `--dev-token` is refused unless the listener is bound to loopback | mitigated | test_a_shared_dev_token_is_refused_off_loopback |
| R77 | An access token is persisted where another page or a later session can reach it | held in a variable only; never in `localStorage`, never in a cookie | mitigated | test_the_token_is_never_put_in_persistent_storage |
| R78 | The console loads code from another origin | one self-contained document under a deny-by-default CSP | mitigated | test_the_policy_admits_no_other_origin |
| R79 | A missing deployment is silently replaced by an available one, changing the bill and the findings while every count looks healthy | preflight reports availability and never acts on it; no field pairs a missing model with a replacement | mitigated | test_the_report_carries_no_field_that_could_become_a_replacement |
| R80 | A provider that cannot list its deployments blocks every run | an empty listing means *unknown*, never *serves nothing*; an unchecked run proceeds and says so | mitigated | test_a_provider_that_cannot_answer_leaves_the_run_unchecked |
| R81 | A correctly configured cross-region profile id is refused as missing | deployments compared bare as well as exactly, so platform prefixes do not defeat the match | mitigated | test_a_platform_prefix_does_not_make_a_present_model_look_missing |
| R82 | A run discovers a missing deployment three phases in, having already spent what it took to get there | every deployment a run could reach — including the second pass — is checked before dispatch | mitigated | test_every_task_a_run_could_reach_is_checked |
| R83 | The rate limiter becomes an oracle for what a principal would be allowed to do | authorization is answered before the limit, so a forbidden caller is told 403 rather than 429 | mitigated | test_authorization_is_answered_before_the_limit |
| R84 | The limiter's own principal map grows without bound and becomes the exhaustion vector | the map is capped and evicts least-recently-seen entries | mitigated | test_the_principal_map_cannot_itself_become_the_exhaustion_vector |
| R85 | A caller raises its own spend ceiling by naming one in a run request | the request model is strict; budget and model come from the deployment | mitigated | test_a_run_request_cannot_smuggle_extra_arguments |
| R86 | An analyst who may close findings can also start scans | starting a run needs `scanner`, which is separate from the adjudication roles | mitigated | test_an_approver_who_cannot_scan_may_not_start_a_run |
| R87 | Two runs against one target race on the workspace and corrupt each other | one run per target at a time, refused with 409 rather than started | mitigated | test_two_runs_against_one_target_are_refused |
| R88 | A control plane that only serves a queue is also able to spend | starting runs is off unless the deployment passes `--allow-runs` | mitigated | test_a_deployment_that_did_not_enable_runs_refuses_them |
| R89 | A run id from a query string reads a `queue.json` outside the workspace | the resolved path is checked against the workspace root before it is used | mitigated | test_a_run_id_cannot_escape_the_workspace |
| R90 | A bulk state change is refused halfway, leaving the caller unable to say which half happened | authorized once before anything is written, and reported per finding | mitigated | test_a_bulk_change_is_authorized_once_before_anything_is_written |
| R91 | One bulk request becomes ten thousand writes | the fingerprint list is bounded and over-long requests are refused | mitigated | test_a_bulk_request_is_bounded |
| R92 | The vendored mirror claims a commit it was not built from, because it was vendored from a dirty checkout | the manifest records every uncommitted source path and the script warns that the pin will not reproduce | mitigated | test_the_manifest_records_whether_the_source_was_dirty |

## Threat models per output

Organised by artifact rather than by risk, and long enough to be its own
document: **[OUTPUTS.md](OUTPUTS.md)** describes everything a repo analysis
produces, who reads it, what it must not be read as, and the threat model for
each — with a diagram apiece.

The register above and that file answer different questions. This one asks
"what could go wrong in the pipeline"; that one asks "what may a reader of this
file safely conclude from it".

## What is deliberately out of scope

- **Model behaviour itself.** These are hosted models; there is no training,
  and no claim is made about what they will conclude. The controls bound what
  they are shown, what they can cause, and what is recorded.
- **The methodology's own integrity checks.** Coverage validation, evidence
  grounding, and schema conformance live in the vendored workspace and are
  exercised end-to-end by `tests/test_e2e.py`, but they are that project's
  invariants, not this one's to claim.

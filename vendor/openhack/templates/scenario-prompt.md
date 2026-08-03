# Scenario <scenario_id>

- Expert: `<expert>`
- Routing unit: `<routing_unit_id>`
- Recon item: `<recon_item_id>`
- Target path: `<target_path>`
- Priority: `<priority>`
- Routing rationale: <routing_rationale>
- Expected finding width: <expected_finding_width>
- Candidate policy: <candidate_policy>
- Result location: `<result_location>`
- Proof question: <proof_question>
- Evidence required: <evidence_required>
- Security invariant: <security_invariant>
- Required proof obligations: <proof_obligations>

## Instructions

Read the expert manifest, shared protocol, run config, routing unit, recon item,
and the target source before answering. The target file is embedded below under
`## Target Source`, with line numbers; if you have tools to open other files in
the checkout, use them for anything the embedded copy does not cover. Stay
inside this scenario unless same-root expansion or a cross-family handoff is
needed.

Review only what you have actually been shown. If the source you need is not in
this prompt and you cannot open it, that obligation is `needs_context` — not an
inference from the file name, the routing rationale, or what a file like this
usually contains. A plausible reconstruction is not evidence, and the recorder
will reject it.

If this prompt is part of an approved multi-scenario run, still answer this
scenario as an individual expert review. Do not use a bulk classification,
sampled sweep, or repeated template as a substitute for reading this prompt and
the relevant source. If you did not review this scenario, do not emit a finished
result for it.

Operate as a specialist for the assigned root-cause family, not as a generic
scanner. Use the expert manifest as a playbook: map the reachable entrypoint,
trace attacker control to the exact sink or boundary, inspect guards in the
context where they are consumed, check class-specific edge cases, and expand to
sibling parameters/endpoints/jobs that share the same root cause.

Do not stop after the first bug-shaped issue. A finding closes only the proof
obligation it proves vulnerable; it does not finish the scenario while other
central obligations remain unanswered. Answer every required proof obligation
listed above with `proven_safe`, `proven_vulnerable`, `not_applicable`, or
`needs_context`.

Evidence must be concrete enough for another reviewer to replay the reasoning
without guessing. Prefer exact files, functions, routes, line references,
configuration paths, data-flow steps, caller roles, preconditions, and final
security impact. Suspicious names, dangerous APIs, dependency folklore, and
framework reputation are only leads until tied to reachability and impact.

Do not treat delegated trust as proof. If an important guard is handled by a
framework, library, SDK, ORM, sanitizer, serializer, crypto primitive, cloud
policy, generated code, or deployment configuration, cite the exact locked
source/config/runtime behavior that enforces it. If you cannot inspect the
relevant dependency or generated artifact, mark that obligation `needs_context`
instead of treating it as safe.

When the scenario is promising but not yet proven, return `candidate` or
`needs_context` with the smallest missing facts. When a different root-cause
family owns the next step, create `candidate_queue_entries` instead of
stretching this expert beyond its ownership boundary.

Write JSON with the fields below. Each one names its JSON type, and the schema
enforces it: a field typed **array** is rejected when it arrives as a string,
and a field typed **string** is rejected when it arrives as a list.

<!-- fields: scenario-result-schema.json -->
- `scenario_id`: **string** — this scenario's id, as shown above
- `review_mode`: **string** — `per-scenario-subagent`
- `subagent_id`: **string** — a unique identifier for the one subagent that
  reviewed this scenario
- `scenario_prompt_sha256`: **string** — SHA-256 of this rendered `S*.md`
  prompt file
- `reviewed_files`: **array** of strings — source files this subagent actually
  read
- `status`: **string** — `verified`, `candidate`, `rejected`, or `needs_context`
- `expert`: **string** — the expert id shown above
- `summary`: **string** — your conclusion for the scenario, in prose
- `evidence`: **array** — at least one item, in the shape described below
- `proof_obligations`: **array** — one entry per required proof obligation, in
  the shape described below
- `surface_class_coverage`: **array** — one entry per surface class you checked
- `same_root_expansion`: **array** — one entry per sibling surface that shares
  this root cause, or `[]` when there are none
- `candidate_queue_entries`: **array** — one entry per lead handed to another
  expert, or `[]`
- `findings`: **array** of verified finding candidates for later independent
  triage
<!-- end fields -->

Prose belongs in the `summary` of an entry, not in place of the list — a
paragraph describing three sibling surfaces is not three entries, and the
recorder cannot turn it into them.

Each `proof_obligations` entry is an object with:

<!-- fields: scenario-result-schema.json#proof_obligations -->
- `id`: **string** — must match the scenario obligation id
- `status`: **string** — `proven_safe`, `proven_vulnerable`, `not_applicable`,
  or `needs_context`
- `summary`: **string** — short conclusion for that obligation
- `evidence`: **array** — source-line evidence for closed obligations; use an
  empty array only for `needs_context` and explain the missing context in
  `summary`
<!-- end fields -->

Every `evidence` item must cite a reviewed source file with `path`, `line`,
`snippet`, and `note`. The `snippet` must be copied from the cited source line;
the recorder and validator reject results whose snippets do not match the
source checkout. Where the source is embedded above, `line` is the number shown
to the left of the `|` and `snippet` is the text to the right of it, copied
exactly — do not include the number or the separator, and do not renumber.

Prefer width: one verified scenario may emit multiple finding candidates when distinct
parameters, endpoints, sinks, roles, or deployment paths are independently
vulnerable. Only put verified vulnerabilities in `findings`. Use
`candidate_queue_entries` for promising but unproven leads or work that belongs
to another expert.

`findings` must be empty unless `status` is `verified`. The recorder rejects the
whole result otherwise — a `candidate` or `needs_context` conclusion that also
carries findings is claiming both that it proved something and that it did not.
If you have a lead you could not prove, it is a `candidate_queue_entry`.

The scenario expert does not create final reports. `record-scenario-result`
stores these entries under `finding-candidates/`; the `finding-triage` agent
later decides whether each candidate is accepted, downgraded, duplicated,
rejected, or needs more context.

For each verified finding candidate, include enough context for both engineering and
non-technical review:

Every field below is **required**, and every one except `evidence` is a
**string**. This is the opposite of the result fields above: there, a list is
required and prose is rejected; here, prose is required and a list is rejected.
Write `attack_chain` and `preconditions` as prose — number the steps inside the
string if that reads better, but do not send an array.

<!-- fields: finding-schema.json -->
- `title`: **string** — `<severity> - <type of vuln> - <location>`
- `severity`: **string** — exactly one of `critical`, `high`, `medium`, `low`,
  `informational`, `unknown`, lowercase; no other word is accepted
- `target_path`: **string**
- `attacker_role`: **string**
- `preconditions`: **string**
- `non_technical_summary`: **string**
- `summary`: **string**
- `evidence`: **array**, same shape as the scenario-level `evidence` above
- `attack_chain`: **string**
- `example_attack`: **string**
- `impact`: **string**
- `impact_analysis`: **string**
- `attacker_use`: **string**
- `recommended_fix`: **string**
- `validation_notes`: **string**
<!-- end fields -->

Write the attack chain and example as controlled-test explanations: concrete
enough to understand exploitability, but avoid unnecessary live-target
weaponization when a conceptual proof is sufficient.

# vega-jurisdiction-sdk — Capabilities

This document inventories every real capability in the published code, why a policy-or-prompt-level approach structurally cannot provide it, where it is enforced in code, which test demonstrates it, and its honest limit.

## Capability inventory

### 1. Jurisdiction registration bound to a human commitment

| Aspect | Detail |
|--------|--------|
| **Capability** | A jurisdiction can only be registered when the device owner signs a human commitment for the exact identity (country code, name, three branch keys, voter roll). The protocol key commits to all four elements. |
| **Why policy/prompt cannot provide it** | A prompt or policy is a promise; nothing in the model's reasoning enforces that the human actually signed for this specific identity. The commitment is a cryptographic artifact verified on-chain before the registration event is written. |
| **Where enforced** | `protocol.py`: `Jurisdictions.register()` → `_v_register()` calls `commit.commit(REGISTER_ACTION, reg_params(p), signed, route="human")`. The jacket verifier checks the commitment exists on the chain with matching `action_hash`. |
| **Test** | `Registration.test_registration_needs_the_owners_commitment_for_exactly_this_identity` — a commitment signed for a different name is refused; a used commitment cannot be reused for another jurisdiction. |
| **Honest limit** | The human's private key must never touch the machine running the model. If the OS is compromised or the key is stolen, the guarantee collapses. The SDK does not manage key storage. |

### 2. Domain-separated Ed25519 signatures (kind binding)

| Aspect | Detail |
|--------|--------|
| **Capability** | A signature made for one action kind (position, veto_open, ballot, override, consent) can never verify as another kind. The kind is embedded inside the signed bytes. |
| **Why policy/prompt cannot provide it** | A model prompted to "only sign positions" can be coerced, confused, or hijacked into signing a ballot payload. Domain separation is a cryptographic property, not a behavioral one. |
| **Where enforced** | `signing.py`: `message(kind, payload)` prefixes `b"VEGA-JURIS-1|" + kind + b"|"`. `verify()` rejects unknown kinds. `Holder.sign()` uses the same `message()`. |
| **Test** | `Signing.test_a_signature_for_one_kind_never_verifies_as_another` — a "position" signature fails verification under "ballot", "veto_open", "override", "consent". |
| **Honest limit** | Relies on `cryptography` library's Ed25519 implementation and Python's memory safety. Not independently reviewed. Side channels not analyzed. |

### 3. Policy activation requires two branches approving identical text

| Aspect | Detail |
|--------|--------|
| **Capability** | A policy becomes active only when at least two different branches (executive, legislative, judicial) sign positions with the exact same rule digest (SHA-256 of canonical sorted rule list). Two branches approving different texts do not create a policy. |
| **Why policy/prompt cannot provide it** | A prompt saying "require two approvals" can be bypassed by a model that claims two approvals exist when they don't, or that treats similar texts as identical. The SDK enforces cryptographic equality of the rule digest. |
| **Where enforced** | `protocol.py`: `Jurisdictions._active()` groups positions by digest; returns active only if `len(ps) >= 2` for a digest. `rules_digest()` uses canonical JSON + SHA-256. |
| **Test** | `Policy.test_one_approval_is_not_a_policy_two_matching_approvals_are` and `Policy.test_two_branches_approving_different_texts_are_not_a_policy`. |
| **Honest limit** | Rules are opaque strings; the SDK does not interpret them. A branch could approve a rule it doesn't understand. No semantic review is built in. |

### 4. Position sequence numbers prevent replay

| Aspect | Detail |
|--------|--------|
| **Capability** | Each branch's position must have a strictly increasing sequence number. Replaying an old position (same or lower seq) is refused. |
| **Why policy/prompt cannot provide it** | A model can be tricked into accepting a replayed "approval" by presenting it as new. Sequence numbers are enforced by deterministic state machine logic, not by the model's memory. |
| **Where enforced** | `protocol.py`: `_v_position()` checks `p["seq"] > j["positions"].get(b, {"seq": 0})["seq"]`. |
| **Test** | `Policy.test_old_positions_cannot_be_replayed_and_numbers_must_rise` — seq 5 accepted, then 5, 4, 0, -1 all rejected. |
| **Honest limit** | If the chain is truncated and replayed from an earlier point, sequence numbers reset. The chain itself (custody) provides append-only integrity. |

### 5. People's Veto: 51% of registered roll (not ballots cast)

| Aspect | Detail |
|--------|--------|
| **Capability** | A veto passes when "for" ballots reach 51% of the *registered* voter roll, rounded up using integer arithmetic: `(51 * n + 99) // 100`. Not 51% of ballots cast. |
| **Why policy/prompt cannot provide it** | A prompt saying "majority wins" is ambiguous (majority of what?) and can be reinterpreted. The threshold is fixed in code with integer arithmetic, no floating point at the boundary. |
| **Where enforced** | `protocol.py`: `needed_for_veto(roll_size)` returns the integer threshold. `_v_ballot()` checks `len(v["for"]) >= need` to set `passed_seq`. |
| **Test** | `Veto.test_the_threshold_is_51_percent_of_the_registered_roll_rounded_up` — verifies thresholds for roll sizes 1, 2, 3, 10, 100, 101, 1000. |
| **Honest limit** | The voter roll is fixed at registration (updates not built). If the roll is captured at registration time, it cannot adapt to population changes. |

### 6. Only roll members can open vetoes or vote

| Aspect | Detail |
|--------|--------|
| **Capability** | `open_veto` requires `opener in j["roll"]`. `cast` requires `voter in j["roll"]`. Outsiders' signatures are rejected even if cryptographically valid. |
| **Why policy/prompt cannot provide it** | A model prompted to "only accept votes from authorized voters" has no cryptographic binding to the roll. The roll is a fixed, sorted list committed in the protocol key; membership is a deterministic check. |
| **Where enforced** | `protocol.py`: `_v_open()` checks `opener in j["roll"]`; `_v_ballot()` checks `voter in j["roll"]`. |
| **Test** | `Veto.test_only_the_roll_can_open_or_vote_and_ballots_cannot_be_forged_or_moved` — outsider keys rejected for both opening and voting. |
| **Honest limit** | Roll membership is public key equality. No revocation or key rotation built in. A compromised voter key can vote. |

### 7. Ballots are single-use per voter per phase

| Aspect | Detail |
|--------|--------|
| **Capability** | A voter can cast at most one "for" or "against" ballot while the veto is OPEN, and at most one "lift" ballot while the veto is PASSED. Changing one's mind is not allowed. |
| **Why policy/prompt cannot provide it** | A model can be persuaded to "let them vote again" or to ignore duplicate votes. The SDK tracks voted sets (`v["for"]`, `v["against"]`, `v["lift"]`) and rejects duplicates deterministically. |
| **Where enforced** | `protocol.py`: `_v_ballot()` checks `voter in v["for"] or voter in v["against"]` for for/against; `voter in v["lift"]` for lift. |
| **Test** | `Veto.test_against_ballots_do_not_move_the_count_and_each_voter_votes_once` — duplicate "for" rejected; "against" then "for" rejected. |
| **Honest limit** | Ballots are linkable to voter public keys (not secret). A voter cannot change their vote after casting. |

### 8. Veto window bounds (60 seconds to 90 days)

| Aspect | Detail |
|--------|--------|
| **Capability** | A veto's closing time must be 60–7,776,000 seconds (90 days) from the current time. Outside this range is refused. |
| **Why policy/prompt cannot provide it** | A model can be tricked into accepting a veto that closes in 1 second or never closes. Bounds are enforced by arithmetic on the injected clock, not by model judgment. |
| **Where enforced** | `protocol.py`: `_v_open()` checks `MIN_WINDOW <= closes - at <= MAX_WINDOW` where `MIN_WINDOW=60`, `MAX_WINDOW=90*86400`. |
| **Test** | `Veto.test_the_voting_window_is_bounded_and_only_one_veto_is_live_at_a_time` — 10s, -5s, 91 days all rejected. |
| **Honest limit** | The clock is caller-injected (`clock=time.time` default). A compromised clock breaks the window. No NTP or trusted time source built in. |

### 9. Only one live veto at a time per jurisdiction

| Aspect | Detail |
|--------|--------|
| **Capability** | While a veto is OPEN or PASSED (not resolved), no new veto can be opened for that jurisdiction. |
| **Why policy/prompt cannot provide it** | A model can be persuaded to "allow another veto" or lose track of state. The SDK checks `v["resolved"] is None and (v["passed_seq"] is not None or at < v["closes_at"])` for all existing vetoes. |
| **Where enforced** | `protocol.py`: `_v_open()` loops `j["vetoes"].values()` and refuses if any veto is unresolved and either passed or still open. |
| **Test** | `Veto.test_the_voting_window_is_bounded_and_only_one_veto_is_live_at_a_time` — second `open()` after first rejected. |
| **Honest limit** | A failed veto (window closed, not passed) allows a new one. This is by design. |

### 10. Veto resolution: three distinct paths

| Aspect | Detail |
|--------|--------|
| **Capability** | A passed veto can be lifted only by: (a) amendment — new active policy with different rule digest; (b) override — all three branches sign; (c) revote — 51% of roll cast "lift" ballots. |
| **Why policy/prompt cannot provide it** | A model can be tricked into accepting a fake resolution (e.g., "the veto is lifted" with no evidence). Each path requires cryptographic proof: new positions with matching digests, three branch signatures, or lift ballots from the roll. |
| **Where enforced** | `protocol.py`: `_v_position()` checks `act[0] != v["rules_at_pass"]` for amendment; `_v_override()` requires all 3 branch sigs over "override"; `_v_ballot()` for "lift" checks `len(v["lift"]) >= need` and `st == "PASSED"`. |
| **Test** | `Resolution.test_an_amendment_with_different_rules_lifts_it_the_same_rules_do_not`, `Resolution.test_an_override_needs_all_three_branches_and_real_signatures`, `Resolution.test_a_revote_needs_51_percent_to_lift_and_only_while_it_is_in_force`. |
| **Honest limit** | Amendment detection compares rule digests only. Semantically equivalent but textually different rules would not lift the veto. |

### 11. Kronos root: two-thirds member consent, two branches each, vetoed excluded

| Aspect | Detail |
|--------|--------|
| **Capability** | The Kronos root (hash over genesis + member protocol keys) can only be updated with consent from ≥2/3 of member jurisdictions, each providing signatures from ≥2 of its 3 branches. A jurisdiction with a veto in force cannot consent. |
| **Why policy/prompt cannot provide it** | A model prompted to "require supermajority" can be manipulated to accept fewer signatures or ignore vetoes. The threshold `(2 * n + 2) // 3`, the per-jurisdiction `len(good) >= 2`, and the veto exclusion are arithmetic checks on verified signatures. |
| **Where enforced** | `protocol.py`: `_v_root()` computes `need = (2 * len(members) + 2) // 3`; loops members, skips if `_in_force(j)`, counts `good` branches with valid "consent" signatures. |
| **Test** | `Kronos.test_two_thirds_of_the_members_each_with_two_branches_move_the_root`, `Kronos.test_a_jurisdiction_under_a_veto_cannot_consent`, `Kronos.test_too_few_jurisdictions_or_too_few_branches_do_not`. |
| **Honest limit** | Genesis is a 64-char hex provided by caller; no validation of its origin. Members list must be sorted unique registered codes. |

### 12. Gate: fail-closed decision function

| Aspect | Detail |
|--------|--------|
| **Capability** | `check(country, unknown="deny")` returns `allowed=True` only when: (1) jurisdiction is known, (2) an active policy exists (2+ branches same digest), (3) no veto is in force. Unknown jurisdictions denied by default. |
| **Why policy/prompt cannot provide it** | A model prompted to "check before acting" can be bypassed, confused, or made to return "allowed" without verification. The gate is a pure function of verified chain state; it has no discretion. |
| **Where enforced** | `protocol.py`: `Jurisdictions.check()` — unknown check, `_active()` for policy, `_in_force()` for veto. Returns dict with reasons. |
| **Test** | `Gate.test_unknown_jurisdictions_fail_closed_unless_the_caller_chooses_otherwise`, `Gate.test_an_active_policy_with_no_veto_allows_and_hands_back_the_rules`. |
| **Honest limit** | The gate only checks jurisdictional policy/veto state. It does not verify the action's content, the model's reasoning, or any other safety property. |

### 13. State reconstruction from chain with full signature re-verification

| Aspect | Detail |
|--------|--------|
| **Capability** | On initialization, `Jurisdictions.__init__` replays every `JURIS_*` chain event, re-verifying every signature. Forged or tampered entries are counted in `replay_rejected` and change nothing. |
| **Why policy/prompt cannot provide it** | A model's memory of "what happened" can be manipulated, truncated, or hallucinated. Replay is deterministic: the chain is the source of truth, and every signature is checked again. |
| **Where enforced** | `protocol.py`: `__init__` iterates `dag.content.entries()`, calls `_validate(kind, payload)()` for each, catches all exceptions and increments `replay_rejected`. |
| **Test** | `Durability.test_state_is_rebuilt_from_the_chain_with_every_signature_checked_again` — second instance matches first. `Durability.test_a_forged_entry_written_straight_into_the_chain_changes_nothing` — 4 forged entries → `replay_rejected=4`, state clean. |
| **Honest limit** | Replay only covers `JURIS_*` event kinds. Non-jurisdictional chain entries are ignored. If the custody DAG itself is corrupted, replay cannot recover. |

### 14. Write atomicity: verify → record → apply

| Aspect | Detail |
|--------|--------|
| **Capability** | Every write action validates first, then records to the chain, then applies to state. If `dag.record` fails (e.g., disk full), the state is not mutated and the sequence number is not burned. |
| **Why policy/prompt cannot provide it** | A model can "forget" to write, write twice, or apply without writing. The SDK enforces the order in `_commit()`: validate → `dag.record()` → `apply()`. |
| **Where enforced** | `protocol.py`: `_commit(kind, p)` calls `fn = _validate(kind, p)` (returns apply fn), then `dag.record(kind, p)`, then `fn()`. `DagError` caught → `JurisdictionRefused`, state unchanged. |
| **Test** | `Durability.test_if_the_chain_cannot_be_written_nothing_changes` — mocked `dag.record` raises on JURIS_* kinds; position refused; retry succeeds with same seq. |
| **Honest limit** | Atomicity relies on `dag.record` being atomic. If the DAG backend partially writes, consistency depends on the backend. |

### 15. Protocol key binds identity (code, name, branches, roll)

| Aspect | Detail |
|--------|--------|
| **Capability** | The protocol key is `SHA-256(canonical({v:1, code, name, branches, roll_root}))`. Any change to code, name, branch keys, or roll produces a different protocol key. |
| **Why policy/prompt cannot provide it** | A model can claim "this is the same jurisdiction" even if keys changed. The protocol key is a cryptographic commitment; equality is binary. |
| **Where enforced** | `protocol.py`: `protocol_key()` and `reg_params()` both compute the same canonical hash. Registration stores `pk` in `_j[country]["pk"]`. |
| **Test** | `Registration.test_the_protocol_key_changes_if_any_key_or_name_changes` — country, name, branch key, roll each change the key. |
| **Honest limit** | The protocol key is only as strong as SHA-256 and the canonical JSON encoding. No quantum resistance. |

## DKG + lattice integration (this repo's part in the family predictive loop)

Per ORGANISM_MAP.md, the predictive loop is:
```
custody records → librarian distils lessons → dkg-lattice builds knowledge graph (origin + licence per fact)
→ reasoning/galaxy forecast from lattice → harness pre-registers predicted paths
→ metacog gates completion on evidence → feed/galaxy show to human → human decides again
```

**vega-jurisdiction-sdk's role:** It provides the *jurisdictional floor* — the legal-minimum constraints that no custom constraint may drop below. The jurisdiction registry (this SDK) defines:
- Which jurisdictions exist (protocol keys)
- What policies are active in each (rules in force)
- Whether a veto is in force (pausing deployment)

Higher layers consume this via:
- `Jurisdictions.check(country)` — the gate that harness, two-gate, terminal, etc. call before allowing an action.
- `Jurisdictions.policy(country)` — returns active rules for reasoning/galaxy to forecast against.
- `Jurisdictions.protocol_key_of(country)` — stable identity for anchoring in dkg-lattice facts.
- `Jurisdictions.root` / `root_members` — Kronos root for cross-jurisdiction coordination.

**No direct imports** of dkg-lattice, reasoning, galaxy, harness, metacog, or feed from this SDK. Dependencies point down only (custody, jacket). Higher layers import this SDK, not vice versa.

## A category of its own: honest differentiation

| Claim | Basis in this design |
|-------|---------------------|
| **Authority held outside the model** | The human commitment (jacket) and branch/voter signatures (signing) are cryptographic artifacts the model never holds. The model cannot mint a commitment or forge a branch signature. |
| **Deterministic gate, no model in the loop** | `check()` is a pure function of verified chain state. No LLM call, no prompt, no heuristic. |
| **Pre-registered predicted paths (via harness)** | Harness (layer 6) calls `check()` before executing a predicted path. The jurisdiction SDK provides the ground truth the harness gates on. |
| **Single-use human commitments** | Each registration consumes a commitment for that exact identity. The jacket commitment is single-use by design. |
| **Chain-of-custody by default** | Every event (registration, position, veto, ballot, override, root update) is written to the custody DAG before state applies. Replay re-verifies all. |
| **Lattice-informed foresight** | The active policy rules (from `policy()`) and veto state (from `check()`) are facts the reasoning lattice can condition forecasts on. The jurisdiction SDK supplies the authoritative current state. |

**Every differentiation claim above is phrased as what THIS design does.** The argument "authority held outside the model cannot be replicated by prompt-level policy" follows from the architecture (WHITEPAPER.md §2): the signing key is physically separate from the model's runtime.
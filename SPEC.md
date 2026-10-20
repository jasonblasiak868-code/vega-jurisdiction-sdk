# vega-jurisdiction-sdk — Specification

Spec v1.0 — 2026-10-19 — describes the published reference implementation as tested; where this document and the source disagree, the source wins.

## 1. Purpose and scope

This specification covers the `vega_jurisdiction` package (modules `protocol` and `signing`). It defines:

- Jurisdiction registration under a device owner's human commitment.
- Three-branch key model (executive, legislative, judicial) with domain-separated Ed25519 signatures.
- Policy activation: two of three branches must approve the identical rule digest.
- The People's Veto: registered voters cast signed ballots; 51% of the registered roll passes a veto.
- Three veto resolution paths: amendment (new active policy with different rules), three-branch override, or revote (51% lift ballots).
- The Kronos root: a hash over genesis and member protocol keys, updatable only with two-thirds member consent (≥2 branches each), excluding vetoed jurisdictions.
- The gate: `check(country)` allows only when policy is active and no veto is in force; unknown jurisdictions denied by default.
- State reconstruction from the chain with full signature re-verification on every start.

Out of scope:
- Secret ballots (blind signatures, zero-knowledge proofs) — designed, not built.
- Voter roll updates — designed, not built.
- Rule interpretation or enforcement — rules are opaque strings for callers.
- Real government keys or legal advice.
- Key management for humans (holders generate keys in memory; the SDK does not persist private keys).

## 2. Vocabulary

| Term | Definition |
|------|------------|
| jurisdiction | A registered identity: country code, name, three branch public keys, voter roll. |
| branch | One of three government branches: executive, legislative, judicial. Each holds an Ed25519 key pair. |
| protocol key | SHA-256 identity of a jurisdiction registration (code, name, branch keys, roll root). Not derivable from code + date alone. |
| position | A branch's signed statement: sequence number, approve/deny, sorted unique rule list. |
| policy | The set of rules currently in force. Active when ≥2 branches approve the same rule digest. |
| rule digest | SHA-256 of the canonical JSON of the sorted rule list. |
| voter roll | The fixed, sorted list of registered voter public keys (1–20,000). |
| veto | A voter-initiated pause on deployment. Opened by a roll member with nonce and closing time. |
| ballot | A voter's signed choice: "for", "against", or "lift". One per voter per phase. |
| vote ID | SHA-256 of the canonical veto opening payload. |
| passed | A veto reaches 51% "for" ballots of the registered roll (rounded up: `(51 * n + 99) // 100`). |
| in force | A veto that has passed and not yet resolved. |
| amendment | A new active policy with a different rule digest than the one at veto pass. |
| override | All three branches sign an override; lifts veto without changing rules. |
| revote | 51% of the roll cast "lift" ballots while veto is in force. |
| Kronos root | SHA-256 over genesis + length-prefixed sorted protocol keys of member jurisdictions. |
| consent | A jurisdiction's agreement to a root update: signatures from ≥2 of its 3 branches over "consent" domain. |
| gate | `check(country)` — the fail-closed decision function. |

## 3. Components

### 3.1 `signing` module

**Role:** Domain-separated Ed25519 signing and verification so a signature for one action kind never verifies as another.

**Public interface:**
- `KINDS = ("position", "veto_open", "ballot", "override", "consent")`
- `SigningRefused(ValueError)` — raised on invalid kind or non-plain-data payload.
- `canonical(obj) -> bytes` — deterministic JSON (sorted keys, no whitespace, no NaN).
- `message(kind, payload) -> bytes` — `b"VEGA-JURIS-1|" + kind + b"|" + canonical(payload)`.
- `Holder` — generates Ed25519 key pair; `public` (hex); `sign(kind, payload) -> str` (hex signature).
- `verify(public_hex, kind, payload, sig_hex) -> bool` — never raises; False on any error.

**Behavior:**
- `canonical` rejects non-plain-data (objects, NaN) with `SigningRefused`.
- `message` rejects unknown kinds with `SigningRefused`.
- `verify` validates hex lengths (64- or 128-character hex), then verifies; any failure returns False.

**Invariants:**
- Domain separation: a signature over kind "position" never verifies under kind "ballot".
- Payload canonicalization is deterministic (sorted keys, fixed separators).
- Private keys never leave `Holder`; only public hex and signatures are exposed.

### 3.2 `protocol` module

**Role:** Jurisdictional protocol state machine — registration, positions, vetoes, root updates, and the gate.

**Public interface:**

Constants:
- `BRANCHES = ("executive", "legislative", "judicial")`
- `EVENT_KINDS = ("JURIS_REGISTERED", "JURIS_POSITION", "JURIS_VETO_OPENED", "JURIS_BALLOT", "JURIS_OVERRIDE", "JURIS_ROOT_UPDATED")`
- `CHOICES = ("for", "against", "lift")`
- Limits: `MAX_ROLL=20000`, `MAX_RULES=200`, `MAX_RULE_LEN=500`, `MIN_WINDOW=60`, `MAX_WINDOW=90*86400`, `MAX_VETOES=1000`.

Functions:
- `roll_root(roll) -> str` — SHA-256 of canonical sorted roll.
- `protocol_key(code, name, branches, rroot) -> str` — SHA-256 of canonical registration record.
- `needed_for_veto(roll_size) -> int` — 51% rounded up, integer arithmetic.
- `rules_digest(rules) -> str` — SHA-256 of canonical sorted rules.
- `kronos_root(genesis, protocol_keys) -> str` — length-prefixed SHA-256 over genesis + sorted keys.
- `reg_params(p) -> dict` — what the human commitment signs (country, name, protocol_key, branches, roll_root).
- `JurisdictionRefused(Exception)` — validation/refusal exception.

Class `Jurisdictions(commit, dag, clock=time.time)`:

State (rebuilt on init by replaying chain):
- `_j` — dict[country] → jurisdiction state (name, branches, roll, pk, positions, vetoes).
- `root` — current Kronos root (str or None).
- `root_members` — tuple of member country codes.
- `replay_rejected` — count of chain entries that failed re-verification.

Methods (write path — verify → record → apply):
- `register(country, name, branches, roll, signed) -> str` — returns protocol key.
- `submit_position(country, branch, seq, approved, rules, sig)` — records position.
- `open_veto(country, opener, nonce, closes_at, sig) -> str` — returns vote ID.
- `cast(country, vote_id, voter, choice, sig)` — records ballot.
- `override(country, vote_id, sigs)` — records override (sigs: dict[branch] → sig_hex).
- `update_root(prev_root, genesis, members, consents) -> str` — returns new root.

Methods (read path):
- `protocol_key_of(country) -> str`
- `policy(country) -> dict` — `{"active", "digest", "rules"}`
- `veto_status(country, vote_id) -> str` — "OPEN" | "PASSED" | "FAILED" | "RESOLVED:<reason>"
- `vetoes_in_force(country) -> list[str]`
- `check(country, unknown="deny") -> dict` — `{"allowed", "reasons", "rules"}`

**Behavior (guarantees on success):**
- Registration: only with valid human commitment for exact identity; protocol key commits to all four elements.
- Positions: sequence numbers strictly increase per branch; signature verified against branch key + "position" domain; rules sorted unique ≤200 items ≤500 chars each.
- Veto: opener on roll; window 60s–90d; only one live veto; vote ID = hash of opening payload.
- Ballots: voter on roll; signature over "ballot" domain; one per voter per phase; "for"/"against" only while OPEN; "lift" only while PASSED.
- Override: only while veto in force; requires all three branch signatures over "override" domain.
- Root update: prev_root match; genesis 64-char hex; members sorted unique registered; 2/3 members each with ≥2 branch signatures over "consent"; vetoed jurisdictions cannot consent.
- Gate: unknown → deny (unless `unknown="allow"`); requires active policy; requires no veto in force.
- Write atomicity: `_commit` validates, then `dag.record`, then applies; on record failure, state unchanged.
- Replay: `__init__` replays all chain events, re-verifying every signature; failures counted in `replay_rejected`, state unaffected.

**Failure behavior (fail-closed):**
- All validation functions raise `JurisdictionRefused` on any check failure.
- `verify` returns False (never raises) on any error.
- `check` returns `{"allowed": False, "reasons": [...], "rules": []}` — never raises for unknown/bad input.
- Chain write failure in `_commit` → `JurisdictionRefused`, state unchanged.
- Replay never mutates state from rejected entries.

**Invariants:**
- Protocol key binds code, name, branch keys, roll root — any change produces a different key.
- Rule lists have exactly one canonical form (sorted, unique).
- Voter roll sorted, unique, 1–20,000 keys; disjoint from branch keys.
- Position sequence numbers monotonically increase per branch (no replay).
- Veto threshold uses integer arithmetic (no floating point at boundary).
- Kronos root uses length-prefixed encoding (no concatenation ambiguity).
- State is purely a function of the verified chain (deterministic replay).

## 4. Guarantees and non-guarantees

### Guarantees

| Guarantee | Module | Test demonstrating |
|-----------|--------|-------------------|
| Domain separation: signature for kind A never verifies as kind B | signing | `Signing.test_a_signature_for_one_kind_never_verifies_as_another` |
| Canonical JSON is deterministic and rejects non-plain-data | signing | `Signing.test_payloads_must_be_plain_data` |
| Registration requires human commitment for exact identity | protocol | `Registration.test_registration_needs_the_owners_commitment_for_exactly_this_identity` |
| Protocol key changes if any key, name, or roll changes | protocol | `Registration.test_the_protocol_key_changes_if_any_key_or_name_changes` |
| Policy active only when ≥2 branches approve identical rule digest | protocol | `Policy.test_one_approval_is_not_a_policy_two_matching_approvals_are` |
| Two branches approving different texts ≠ policy | protocol | `Policy.test_two_branches_approving_different_texts_are_not_a_policy` |
| Veto threshold = 51% of registered roll, rounded up | protocol | `Veto.test_the_threshold_is_51_percent_of_the_registered_roll_rounded_up` |
| Only roll members can open vetoes or cast ballots | protocol | `Veto.test_only_the_roll_can_open_or_vote_and_ballots_cannot_be_forged_or_moved` |
| Ballots cannot be forged, moved, or replayed across jurisdictions | protocol | `Veto.test_a_ballot_cannot_be_moved_to_another_jurisdiction_or_world` |
| Override requires all three branch signatures | protocol | `Resolution.test_an_override_needs_all_three_branches_and_real_signatures` |
| Amendment lifts veto only if rules actually change | protocol | `Resolution.test_an_amendment_with_different_rules_lifts_it_the_same_rules_do_not` |
| Revote requires 51% lift ballots while veto in force | protocol | `Resolution.test_a_revote_needs_51_percent_to_lift_and_only_while_it_is_in_force` |
| Root update requires 2/3 members each with ≥2 branch signatures | protocol | `Kronos.test_two_thirds_of_the_members_each_with_two_branches_move_the_root` |
| Vetoed jurisdiction cannot consent to root update | protocol | `Kronos.test_a_jurisdiction_under_a_veto_cannot_consent` |
| Gate fails closed: unknown jurisdiction denied by default | protocol | `Gate.test_unknown_jurisdictions_fail_closed_unless_the_caller_chooses_otherwise` |
| Gate requires active policy and no veto in force | protocol | `Gate.test_an_active_policy_with_no_veto_allows_and_hands_back_the_rules` |
| State rebuilt from chain with full signature re-verification | protocol | `Durability.test_state_is_rebuilt_from_the_chain_with_every_signature_checked_again` |
| Forged chain entries change nothing (counted in replay_rejected) | protocol | `Durability.test_a_forged_entry_written_straight_into_the_chain_changes_nothing` |
| Failed chain write leaves state unchanged | protocol | `Durability.test_if_the_chain_cannot_be_written_nothing_changes` |

### Non-guarantees

| Non-guarantee | Explanation |
|---------------|-------------|
| Secret ballots | Ballots link to voter public key; blind signatures/ZKPs not built. |
| Voter roll updates | Roll fixed at registration; changing it requires new jurisdiction. |
| Rule interpretation | SDK treats rules as opaque strings; enforcement is caller's responsibility. |
| Legal validity | No real government keys included; nothing is legal advice. |
| Crypto expert review | Cryptography is plain software for clarity; not independently reviewed. |
| Production hardening | Reference implementation with tests; not hardened for production. |
| OS-level containment | Process-level only; no sandbox. |
| Key persistence | `Holder` keeps keys in memory; no secure storage or HSM integration. |
| Clock integrity | Uses injected `clock` callable; caller controls time source. |
| Availability | Chain write failures refuse the action; no retry or queuing built in. |

## 5. Failure modes

| Failure mode | Behavior | Test citing |
|--------------|----------|-------------|
| Tampered chain entry | Replay rejects it (`replay_rejected++`); state unchanged | `Durability.test_a_forged_entry_written_straight_into_the_chain_changes_nothing` |
| Missing commitment on registration | `JurisdictionRefused` before chain write | `Registration.test_registration_needs_the_owners_commitment_for_exactly_this_identity` |
| Expired/replayed position | Sequence number must exceed branch's last; old rejected | `Policy.test_old_positions_cannot_be_replayed_and_numbers_must_rise` |
| Forged branch signature | `verify` returns False → `JurisdictionRefused` | `Policy.test_forged_positions_are_refused` |
| Replayed veto opening | Nonce + opener hash = vote ID; duplicate rejected by shape check | `Veto.test_the_voting_window_is_bounded_and_only_one_veto_is_live_at_a_time` |
| Ballot after window closes | Status becomes "FAILED"; further ballots refused | `Veto.test_the_window_closes_and_a_failed_veto_lets_a_new_one_open` |
| Veto in force blocks gate | `check` returns `allowed=False, reasons=["veto_in_force"]` | `Veto.test_the_threshold_is_51_percent_of_the_registered_roll_rounded_up` |
| Corrupt record (bad sig) | Replay rejects; `replay_rejected` increments | `Durability.test_a_forged_entry_written_straight_into_the_chain_changes_nothing` |
| Chain write failure (disk full) | Action refused; state not mutated; sequence number not burned | `Durability.test_if_the_chain_cannot_be_written_nothing_changes` |
| Unknown jurisdiction at gate | `allowed=False, reasons=["unknown_jurisdiction"]` (default) | `Gate.test_unknown_jurisdictions_fail_closed_unless_the_caller_chooses_otherwise` |

## 6. Dependencies and layer rules

**Registry entry (verbatim from vega-umbrella-sdk):**
```python
"jurisdiction": {"layer": 1, "requires": ["custody", "jacket"]}
```

**Declared dependencies (pyproject.toml):**
- `cryptography>=42` — Ed25519 via `cryptography.hazmat.primitives.asymmetric.ed25519`.
- `vega-custody-sdk` — `vega_custody.dag.dag.Dag`, `vega_custody.ledger.backend_local.LocalBackend`, `vega_custody.ledger.ledger.Ledger`, `vega_custody.dag.dag.DagError`.
- `vega-governance-jacket-sdk` — `vega_jacket.humanauth`, `vega_jacket.commit.commit.Commit`, `vega_jacket.commit.commit.CommitRefused`, `vega_jacket.humanauth.human_signer`.

**Layer rules:** Dependencies point down only (layer 1 → layer 0 custody, layer 1 jacket). No up or sideways dependencies. The umbrella registry enforces no cycles and single ownership per concern.

## 7. Conformance

A third party can verify conformance by:

1. Installing the SDK and its dependencies (`pip install -e .` with `vega-custody-sdk` and `vega-governance-jacket-sdk` on PYTHONPATH).
2. Running the test suite: `PYTHONPATH=... py -3.12 tests/redteam_1_protocol.py` (39 tests).
3. All tests passing means:
   - The implementation matches this specification for the tested behaviors.
   - Fail-closed paths are exercised (mutations.py confirms each guard is necessary).
   - Replay integrity and chain atomicity hold under the test conditions.

**What passing does NOT mean:**
- The cryptography is independently reviewed or suitable for protecting real secrets.
- The implementation is production-hardened (it is a reference implementation).
- Uncovered code paths (e.g., roll updates, secret ballots) are correct — they are not built.
- Legal validity of any jurisdiction or policy created with this SDK.
- Absence of side-channel or implementation flaws in the `cryptography` library or Python runtime.
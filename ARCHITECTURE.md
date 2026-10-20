# vega-jurisdiction-sdk — Architecture

## 1. The organism (family picture)

The 16-layer Vega SDK stack (bottom = foundation). This repo is **layer 1: authority** (marked `>>> <<<`).

```
                 ┌──────────────────────────┐
                 │   THE HUMAN (the owner)  │  holds the only signing key;
                 │  authority starts here   │  spends it one action at a time
                 └────────────┬─────────────┘
                              v single-use signed commitments
 15 assemble   vega-umbrella-sdk        the family as one organism
 14 deliberate vega-council-sdk
               vega-galaxy-sdk
 13 watch      vega-governance-feed-sdk
 12 verify     vega-metacog-sdk
 11 reason     vega-reasoning-sdk
 10 observe    vega-trace-sdk
  9 interface  vega-terminal-sdk
  8 learn      vega-train-sdk
  7 knowledge  vega-dkg-lattice-sdk
  6 conduct    vega-harness-sdk
  5 memory     vega-librarian-sdk
  4 contain    vega-two-gate-sdk
  3 adapt      vega-pareah-sdk
  2 seal       vega-superproof-sdk
>>> 1 authority  vega-governance-jacket-sdk  human-only actions, single-use signed
               vega-jurisdiction-sdk        commitments, entry and exit gates
               (JURISDICTIONAL PROTOCOL)    three branches, People's Veto, Kronos
  0 record     vega-custody-sdk             capsules, DAG, hash-chained ledger,
                                          bounded processes — the foundation
```

**What the layers below provide:**
- **Layer 0 (custody):** Append-only DAG + ledger for recording every event; hash-chained integrity; `dag.record` and `dag.content.entries()` for replay.
- **Layer 1 jacket:** Human commitment primitive — `humanauth.Verifier`, `human_signer`, `Commit.commit(action, params, signed, route="human")` — ensures every jurisdiction registration is authorized by the device owner's key.

**Who above consumes this:**
- **Layer 2 (seal / superproof):** Can anchor sealing tiers to jurisdiction protocol keys.
- **Layer 3 (adapt / pareah):** Adapters may reference jurisdiction codes for routing.
- **Layer 4 (contain / two-gate):** Containment gates can call `check(country)` before allowing egress.
- **Layer 6 (conduct / harness):** Workflows can gate predicted paths on jurisdictional policy.
- **Layer 15 (umbrella):** Registry entry `"jurisdiction": {"layer": 1, "requires": ["custody", "jacket"]}` wires this SDK into the organism.

**One family, one organism:** every SDK owns exactly one concern and uses the owner of every other concern instead of growing its own copy.

## 2. Internal drawing: modules and flows

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           vega_jurisdiction                                 │
│  ┌──────────────────┐      ┌────────────────────────────────────────────┐  │
│  │    signing.py    │      │              protocol.py                   │  │
│  ├──────────────────┤      ├────────────────────────────────────────────┤  │
│  │ KINDS (5)        │      │ Jurisdictions(commit, dag, clock)          │  │
│  │ canonical()      │◀─────│   _j: dict[country] -> state               │  │
│  │ message()        │      │   root, root_members, replay_rejected      │  │
│  │ Holder           │      ├────────────────────────────────────────────┤  │
│  │   .public (hex)  │      │ WRITE PATH (verify -> record -> apply)     │  │
│  │   .sign()        │      │   register()                               │  │
│  │ verify()         │      │   submit_position()                        │  │
│  └────────┬─────────┘      │   open_veto()                              │  │
│           │               │   cast()                                   │  │
│           │ domain-sep    │   override()                               │  │
│           │ messages      │   update_root()                            │  │
│           ▼               │   _commit()  ──► dag.record() ──► apply()  │  │
│  ┌──────────────────┐     ├────────────────────────────────────────────┤  │
│  │  Authority flow  │     │ READ PATH                                  │  │
│  │  (human signs)   │     │   protocol_key_of()                        │  │
│  └────────┬─────────┘     │   policy()                                 │  │
│           │               │   veto_status()                            │  │
│           ▼               │   vetoes_in_force()                        │  │
│  ┌──────────────────┐     │   check()  ◀─── GATE (fail-closed)         │  │
│  │  Data/knowledge  │     └────────────────────────────────────────────┘  │
│  │  flow (up from   │              │                    ▲                │
│  │   custody chain) │              │                    │                │
│  └────────┬─────────┘              │                    │                │
│           │                        │                    │                │
│           ▼                        ▼                    │                │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                    vega_custody (layer 0)                          │  │
│  │  Dag  ──► entries()  ──► replay in Jurisdictions.__init__          │  │
│  │  Ledger ──► backend  ──► human commitment verification (jacket)    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Authority flow (down from human, never from model):**
```
human signs commitment for REGISTER_ACTION
        │
        ▼
jacket.Verifier checks commitment on chain
        │
        ▼
protocol.Jurisdictions.register() writes JURIS_REGISTERED
        │
        ▼
branch keys sign positions (kind="position")
        │
        ▼
2+ matching positions → active policy
        │
        ▼
voter signs veto_open (kind="veto_open")
        │
        ▼
voters sign ballots (kind="ballot")
        │
        ▼
51% "for" → veto PASSED → gate denies
        │
        ▼
resolution: amendment / override / revote
        │
        ▼
gate allows again
```

**Data/knowledge flow (up from record):**
```
dag.content.entries() (all JURIS_* kinds)
        │
        ▼
Jurisdictions.__init__ replay: verify every signature again
        │
        ▼
_j state rebuilt: policies, vetoes, Kronos root
        │
        ▼
read methods: policy(), veto_status(), check(), root, root_members
        │
        ▼
consumed by: two-gate (contain), harness (conduct), umbrella (assemble)
```

## 3. Mermaid version

```mermaid
graph TD
    A[Human Commitment\n(jacket)] --> B[Jurisdictions.register]
    B --> C[dag.record JURIS_REGISTERED]
    C --> D[_j state: country -> pk, branches, roll]
    
    E[Branch Holder] --> F[sign position]
    F --> G[submit_position]
    G --> H[dag.record JURIS_POSITION]
    H --> I[_active: 2+ same digest]
    
    J[Voter Holder] --> K[sign veto_open]
    K --> L[open_veto]
    L --> M[dag.record JURIS_VETO_OPENED]
    M --> N[vetoes[vid]: OPEN]
    
    J --> O[sign ballot]
    O --> P[cast]
    P --> Q[dag.record JURIS_BALLOT]
    Q --> R{for >= 51% roll?}
    R -->|yes| S[veto PASSED]
    R -->|no| T[veto stays OPEN]
    
    S --> U[gate.check denies]
    U --> V{resolution}
    V -->|amendment| W[new active policy\ndifferent digest]
    V -->|override| X[3 branch sigs\noverride]
    V -->|revote| Y[51% lift ballots]
    W --> Z[gate.check allows]
    X --> Z
    Y --> Z
    
    AA[Member Jurisdictions] --> AB[sign consent]
    AB --> AC[update_root]
    AC --> AD[dag.record JURIS_ROOT_UPDATED]
    AD --> AE[kronos_root updated]
    
    AF[dag.content.entries] --> AG[Jurisdictions.__init__ replay]
    AG --> AH[replay_rejected count]
    AG --> AI[_j state rebuilt]
    AI --> AJ[policy, veto_status, check]
```

## 4. Sequence: main scenario end to end

**Scenario:** A jurisdiction registers, activates a policy, faces a veto, resolves by amendment, and the gate allows again.

```
ACTOR              ACTION                          SDK CALL                          CHAIN EVENT
─────────────────────────────────────────────────────────────────────────────────────────────
Device Owner       decides identity                Jurisdictions.register()          JURIS_REGISTERED
  │                 (country, name, 3 branch       │  requires human commitment       │  commit_entry
  │                  pubkeys, voter roll)           │  for exact identity              │
  ▼                 signs commitment                │                                  │
Human signer       returns signed                  │                                  │
  │                 commitment                      │                                  │
  ▼                                                      │                                  │
Executive          signs position                  submit_position()                 JURIS_POSITION
  │                 (seq=1, approve, rules)        │  verify sig vs branch key        │  branch=exec
  ▼                                                      │  seq > last                     │
Legislative        signs position                  submit_position()                 JURIS_POSITION
  │                 (seq=1, approve, SAME rules)   │  2+ branches same digest         │  branch=leg
  ▼                                                      │  → policy ACTIVE                │
Voter 0            signs veto_open                 open_veto()                       JURIS_VETO_OPENED
  │                 (nonce, closes_at)             │  opener on roll                  │  vote_id = hash
  ▼                                                      │  window 60s-90d                │
Voters 0-5         sign "for" ballots              cast()                            JURIS_BALLOT (x6)
  │                 (vote_id, choice=for)          │  voter on roll                   │  each voter once
  ▼                                                      │  6 >= 51% of 10 = 6            │
                                                       │  → veto PASSED                 │
                                                       │                                  │
gate.check()                                                        check("XX")                     returns
  │                                                      │  veto_in_force → allowed=False  │  allowed=False
  ▼                                                      │                                  │  reasons=["veto"]
                                                       │                                  │
Executive          signs new position                submit_position()                 JURIS_POSITION
  │                 (seq=2, approve, NEW rules)      │  seq=2 > 1                      │  new digest
  ▼                                                      │                                  │
Legislative        signs new position                submit_position()                 JURIS_POSITION
  │                 (seq=2, approve, SAME NEW rules) │  2+ same NEW digest              │
  ▼                                                      │  → policy ACTIVE (new rules)   │
                                                       │  rules_at_pass != new digest     │
                                                       │  → veto RESOLVED:government_     │
                                                       │     amendment                    │
gate.check()                                                        check("XX")                     returns
  │                                                      │  policy active, no veto         │  allowed=True
  ▼                                                      │                                  │  rules=[new...]
Action proceeds                                                       │                                  │
```

## 5. Trust boundaries

| Boundary | What crosses | Enforcement |
|----------|--------------|-------------|
| Human → SDK | Human commitment (signed by owner's key) | `vega_jacket.humanauth.Verifier` + `Commit.commit` verifies commitment on chain before registration |
| Branch holder → SDK | Position signature (Ed25519, kind="position") | `signing.verify(branch_pub, "position", payload, sig)` — domain separation + branch key match |
| Voter → SDK | Veto open / ballot signatures | `signing.verify(voter_pub, "veto_open"/"ballot", payload, sig)` — roll membership checked |
| Branch holder → SDK | Override signatures (all 3 branches) | `signing.verify` for each branch over "override" domain; all 3 required |
| Member jurisdiction → SDK | Consent signatures (≥2 branches each) | `signing.verify` per branch over "consent" domain; 2/3 members; vetoed excluded |
| SDK → Custody (layer 0) | `dag.record(kind, payload)` | `Dag` appends to hash-chained log; `DagError` on failure → action refused, state unchanged |
| SDK → Jacket (layer 1) | `commit.commit(action, params, signed)` | `CommitRefused` if commitment invalid/missing → registration refused |
| Replay (startup) → State | Chain entries (all JURIS_* kinds) | `__init__` re-verifies every signature; failures counted in `replay_rejected`, state unaffected |
| Caller → Gate | `check(country, unknown="deny")` | Fail-closed: unknown → deny; requires active policy + no veto in force |

## 6. Fail-closed constraint points (computational workflow)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FAIL-CLOSED WORKFLOW                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  register()                                                                 │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ _check_reg_shape: country code format, name printable, 3 unique     │   │
│  │ branch hex64 keys, roll 1-20000 unique sorted hex64, disjoint       │   │
│  │ from branch keys. REJECT → JurisdictionRefused                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ commit.commit(REGISTER_ACTION, reg_params, signed):                 │   │
│  │   jacket verifies commitment on chain for EXACT identity.           │   │
│  │   REJECT → CommitRefused → JurisdictionRefused                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  _commit("JURIS_REGISTERED", p)  ──► dag.record() ──► apply()              │
│       │                              │              │                       │
│       │                        DagError?        │                       │
│       │                              YES             │                       │
│       │                              ▼              ▼                       │
│       │                     JurisdictionRefused   state updated           │
│       │                     (state UNCHANGED)       │                       │
│       ▼                                                                     │
│  submit_position()                                                         │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ _v_position: branch known, seq > last, rules valid,                │   │
│  │ verify(branch_pub, "position", signed, sig) → False? REJECT        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  _commit("JURIS_POSITION", p) ──► dag.record() ──► apply()                │
│       │                              (DagError → reject, state unchanged)  │
│       ▼                                                                     │
│  open_veto()                                                                │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ _v_open: opener in roll, nonce printable 8-64, window 60s-90d,      │   │
│  │ verify(opener, "veto_open", signed, sig), no other live veto.      │   │
│  │ REJECT → JurisdictionRefused                                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  cast()                                                                     │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ _v_ballot: voter in roll, choice in {for,against,lift},            │   │
│  │ verify(voter, "ballot", signed, sig), one per voter per phase,     │   │
│  │ "for"/"against" only if OPEN, "lift" only if PASSED.               │   │
│  │ REJECT → JurisdictionRefused                                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  override()                                                                 │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ _v_override: veto PASSED not resolved, sigs has all 3 branches,    │   │
│  │ verify(each_branch, "override", signed, sig) for all 3.            │   │
│  │ REJECT → JurisdictionRefused                                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  update_root()                                                              │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ _v_root: prev_root == current, genesis hex64, members sorted       │   │
│  │ unique registered, consents: 2/3 members each with ≥2 branch        │   │
│  │ verify(branch, "consent", payload, sig), vetoed jurisdictions       │   │
│  │ SKIPPED (cannot consent). REJECT → JurisdictionRefused             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  check(country, unknown="deny")                                             │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ unknown jurisdiction? → allowed=False, reasons=["unknown_          │   │
│  │ jurisdiction"] (unless unknown="allow")                            │   │
│  │ _active(j) → None? → reasons.append("policy_not_active")           │   │
│  │ _in_force(j) not empty? → reasons.append("veto_in_force")          │   │
│  │ allowed = (reasons == [])                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  Replay (Jurisdictions.__init__)                                            │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ For each chain entry: _validate(kind, payload)()                    │   │
│  │   Any exception (JurisdictionRefused, KeyError, TypeError,          │   │
│  │   ValueError, AttributeError) → replay_rejected++, state unchanged  │   │
│  │   Only fully valid entries apply.                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Custom constraints:** This version publishes no user-defined constraint hooks; constraints are fixed by the module and the jurisdiction floor. The governing rule: "User-defined constraints may be STRICTER than the legal minimum for the applicable jurisdiction, never looser. Jurisdictional legal minimums are defined by the jurisdiction registry (vega-jurisdiction-sdk); a custom constraint that would drop below a registered minimum is rejected at the gate."
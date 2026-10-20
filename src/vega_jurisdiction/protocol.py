"""protocol.py - jurisdictional protocol keys (filed concept: 64-068420, jurisdictional key termination and the People's Veto).

A JURISDICTION is registered once, by the device owner's human commitment, with:
  - three BRANCH public keys (executive, legislative, judicial); the private keys stay with the branches
  - a VOTER ROLL: the public keys of the registered voters
  - its PROTOCOL KEY: the SHA-256 identity of exactly that record (code, name, branch keys, roll). Not derivable from a code and a date: it commits to keys.
POLICY: each branch signs a position (a numbered statement: approve or not, over a sorted list of rules). A policy is ACTIVE when at least two different
  branches currently approve the SAME rules (same digest). Two branches approving different texts are not a policy.
PEOPLE'S VETO: a registered voter opens a veto (signed, with a closing time). Registered voters cast signed ballots, one each. The veto PASSES the moment
  'for' ballots reach 51% of the REGISTERED ROLL (not of the ballots cast); once passed, deployment in that jurisdiction is paused. It is lifted only by
  (a) an amendment: a later policy, active, with different rules than were in force when it passed; (b) an override signed by all three branches; or
  (c) a revote: 'lift' ballots from 51% of the roll.
GATE: check() allows only when the policy is active and no veto is in force. Unknown jurisdiction = refused unless the caller explicitly chooses 'allow'.
KRONOS ROOT: SHA-256 over the genesis and the participating protocol keys; it can be updated only with consent from at least two thirds of the member
  jurisdictions, each consent signed by at least two of its three branch keys, and a jurisdiction under a veto cannot consent (see kronos.py).
STATE: every event is verified, then written to the chain, then applied; on start the state is rebuilt by replaying the chain with every signature checked
  again, so a forged or tampered entry changes nothing (it is counted in replay_rejected).

HONEST LIMITS: ballots are signed with the voter's public key, so they are linkable to a key; a secret ballot needs blind signatures or zero-knowledge proofs and is NOT built.
The voter roll is fixed at registration (changing it means a new jurisdiction record: roll updates are not built). The SDK enforces the YES/NO of a policy; it
does not interpret what a rule means (a rule is text a human or another SDK acts on). Nothing here is legal advice and no real government's keys or rules ship with it."""
import hashlib
import re
import time

from vega_custody.dag.dag import DagError
from vega_jacket import humanauth
from vega_jacket.commit.commit import CommitRefused
from vega_jurisdiction import signing as S

REGISTER_ACTION = "register_jurisdiction"
BRANCHES = ("executive", "legislative", "judicial")
CODE = re.compile(r"^[A-Z0-9][A-Z0-9-]{1,15}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_ROLL = 20000
MAX_RULES = 200
MAX_RULE_LEN = 500
MIN_WINDOW, MAX_WINDOW = 60, 90 * 86400
MAX_VETOES = 1000
CHOICES = ("for", "against", "lift")
EVENT_KINDS = ("JURIS_REGISTERED", "JURIS_POSITION", "JURIS_VETO_OPENED", "JURIS_BALLOT", "JURIS_OVERRIDE", "JURIS_ROOT_UPDATED")


class JurisdictionRefused(Exception):
    pass


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def roll_root(roll) -> str:
    return _sha(S.canonical(sorted(roll)))


def protocol_key(code: str, name: str, branches: dict, rroot: str) -> str:
    return _sha(S.canonical({"v": 1, "code": code, "name": name, "branches": branches, "roll_root": rroot}))


def needed_for_veto(roll_size: int) -> int:
    """51% of the registered roll, rounded up, in whole-number arithmetic (no floating point at the edge)."""
    return (51 * roll_size + 99) // 100


def rules_digest(rules) -> str:
    return _sha(S.canonical(list(rules)))


def kronos_root(genesis: str, protocol_keys) -> str:
    """SHA-256 over the genesis and the participating protocol keys, length-prefixed and sorted, so no two different sets can produce the same bytes.
    (The filed text writes this as a plain concatenation; the length prefix is a safety change, the idea is the same.)"""
    ks = sorted(protocol_keys)
    h = hashlib.sha256()
    h.update(b"VEGA-KRONOS-ROOT-1\x00")
    for part in [genesis] + ks:
        b = part.encode("ascii")
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    h.update(len(ks).to_bytes(4, "big"))
    return h.hexdigest()


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_rules(rules):
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise JurisdictionRefused("rules must be a list of at most %d texts" % MAX_RULES)
    for r in rules:
        if not isinstance(r, str) or not r.strip() or len(r) > MAX_RULE_LEN or any(ord(c) < 32 for c in r):
            raise JurisdictionRefused("each rule is a plain text of 1 to %d characters" % MAX_RULE_LEN)
    if rules != sorted(set(rules)):
        raise JurisdictionRefused("rules must be unique and sorted, so there is only one way to write a given policy")


def _check_reg_shape(p):
    if not isinstance(p.get("country"), str) or not CODE.fullmatch(p["country"]):
        raise JurisdictionRefused("country code: capital letters, digits and '-', 2 to 16 characters")
    nm = p.get("name")
    if not isinstance(nm, str) or not 1 <= len(nm) <= 120 or not nm.isprintable():
        raise JurisdictionRefused("name is 1 to 120 printable characters")
    br = p.get("branches")
    if not isinstance(br, dict) or sorted(br) != sorted(BRANCHES) or not all(isinstance(v, str) and HEX64.fullmatch(v) for v in br.values()) or len(set(br.values())) != 3:
        raise JurisdictionRefused("exactly three different branch public keys: executive, legislative, judicial")
    roll = p.get("roll")
    if not isinstance(roll, list) or not 1 <= len(roll) <= MAX_ROLL or not all(isinstance(v, str) and HEX64.fullmatch(v) for v in roll) or roll != sorted(set(roll)):
        raise JurisdictionRefused("the voter roll is 1 to %d unique, sorted public keys" % MAX_ROLL)
    if set(roll) & set(br.values()):
        raise JurisdictionRefused("a branch key cannot also be on the voter roll")


def reg_params(p) -> dict:
    """What the device owner's commitment is signed over: the exact identity being registered."""
    return {"country": p["country"], "name": p["name"], "protocol_key": protocol_key(p["country"], p["name"], p["branches"], roll_root(p["roll"])),
            "branches": p["branches"], "roll_root": roll_root(p["roll"])}


class Jurisdictions:
    def __init__(self, commit, dag, clock=time.time):
        self.commit, self.dag, self._clock = commit, dag, clock
        self._j = {}
        self._seq = 0
        self.root = None
        self.root_members = ()
        self.replay_rejected = 0
        for e in dag.content.entries():
            if e["kind"] in EVENT_KINDS:
                try:
                    self._validate(e["kind"], e["payload"])()
                except (JurisdictionRefused, KeyError, TypeError, ValueError, AttributeError):
                    self.replay_rejected += 1

    # ---- the validation + application of one event (shared by live use and replay) -------------------------
    def _jur(self, code):
        j = self._j.get(code) if isinstance(code, str) else None
        if j is None:
            raise JurisdictionRefused("unknown jurisdiction")
        return j

    def _veto(self, j, vid):
        v = j["vetoes"].get(vid) if isinstance(vid, str) else None
        if v is None:
            raise JurisdictionRefused("unknown veto")
        return v

    @staticmethod
    def _active(j):
        """-> (digest, rules) of the policy in force, or None."""
        groups = {}
        for pos in j["positions"].values():
            if pos["approved"]:
                groups.setdefault(pos["digest"], []).append(pos)
        for digest, ps in groups.items():
            if len(ps) >= 2:
                return digest, ps[0]["rules"]
        return None

    @staticmethod
    def _in_force(j):
        return [vid for vid, v in j["vetoes"].items() if v["passed_seq"] is not None and v["resolved"] is None]

    def _status(self, v, at):
        if v["resolved"]:
            return "RESOLVED:" + v["resolved"]
        if v["passed_seq"] is not None:
            return "PASSED"
        return "OPEN" if at < v["closes_at"] else "FAILED"

    def _validate(self, kind, p):
        if not isinstance(p, dict):
            raise JurisdictionRefused("event is not an object")
        at = p.get("at")
        if not _is_int(at):
            raise JurisdictionRefused("event has no time")
        if kind == "JURIS_REGISTERED":
            return self._v_register(p)
        if kind == "JURIS_POSITION":
            return self._v_position(p)
        if kind == "JURIS_VETO_OPENED":
            return self._v_open(p, at)
        if kind == "JURIS_BALLOT":
            return self._v_ballot(p, at)
        if kind == "JURIS_OVERRIDE":
            return self._v_override(p)
        if kind == "JURIS_ROOT_UPDATED":
            return self._v_root(p)
        raise JurisdictionRefused("unknown event kind")

    def _v_register(self, p):
        _check_reg_shape(p)
        if p["country"] in self._j:
            raise JurisdictionRefused("jurisdiction already registered")
        ce = p.get("commit_entry")
        entry = self.dag.content.get(ce) if isinstance(ce, str) else None
        cm = entry["payload"].get("commitment") if entry and entry["kind"] == "COMMIT" else None
        if not isinstance(cm, dict) or cm.get("action") != REGISTER_ACTION or cm.get("action_hash") != humanauth.action_hash(reg_params(p)):
            raise JurisdictionRefused("no human commitment on the chain for exactly this registration")

        def apply():
            self._seq += 1
            self._j[p["country"]] = {"name": p["name"], "branches": dict(p["branches"]), "roll": frozenset(p["roll"]),
                                     "pk": protocol_key(p["country"], p["name"], p["branches"], roll_root(p["roll"])),
                                     "positions": {}, "vetoes": {}}
        return apply

    def _v_position(self, p):
        j = self._jur(p.get("country"))
        b = p.get("branch")
        if b not in BRANCHES:
            raise JurisdictionRefused("unknown branch")
        if not _is_int(p.get("seq")) or p["seq"] < 1 or p["seq"] <= j["positions"].get(b, {"seq": 0})["seq"]:
            raise JurisdictionRefused("a position's number must be higher than that branch's last one (no replay of an older position)")
        if not isinstance(p.get("approved"), bool):
            raise JurisdictionRefused("approved is true or false")
        _check_rules(p.get("rules"))
        signed = {"country": p["country"], "branch": b, "seq": p["seq"], "approved": p["approved"], "rules": p["rules"]}
        if not S.verify(j["branches"][b], "position", signed, p.get("sig")):
            raise JurisdictionRefused("not signed by that branch's key")

        def apply():
            self._seq += 1
            j["positions"][b] = {"seq": p["seq"], "approved": p["approved"], "rules": list(p["rules"]), "digest": rules_digest(p["rules"])}
            act = self._active(j)
            if act:
                for v in j["vetoes"].values():
                    if v["passed_seq"] is not None and v["resolved"] is None and act[0] != v["rules_at_pass"]:
                        v["resolved"] = "government_amendment"
        return apply

    def _v_open(self, p, at):
        j = self._jur(p.get("country"))
        op, nonce, closes = p.get("opener"), p.get("nonce"), p.get("closes_at")
        if op not in j["roll"]:
            raise JurisdictionRefused("only a registered voter can open a veto")
        if not isinstance(nonce, str) or not 8 <= len(nonce) <= 64 or not nonce.isprintable():
            raise JurisdictionRefused("nonce is 8 to 64 printable characters")
        if not _is_int(closes) or not MIN_WINDOW <= closes - at <= MAX_WINDOW:
            raise JurisdictionRefused("the voting window is between %d seconds and 90 days" % MIN_WINDOW)
        signed = {"country": p["country"], "opener": op, "nonce": nonce, "closes_at": closes}
        if not S.verify(op, "veto_open", signed, p.get("sig")):
            raise JurisdictionRefused("not signed by the opener's key")
        if len(j["vetoes"]) >= MAX_VETOES:
            raise JurisdictionRefused("too many vetoes recorded for this jurisdiction")
        for v in j["vetoes"].values():
            if v["resolved"] is None and (v["passed_seq"] is not None or at < v["closes_at"]):
                raise JurisdictionRefused("a veto is already open or in force")
        vid = _sha(S.canonical(signed))

        def apply():
            self._seq += 1
            act = self._active(j)
            j["vetoes"][vid] = {"opener": op, "closes_at": closes, "for": set(), "against": set(), "lift": set(), "passed_seq": None,
                                "resolved": None, "rules_at_pass": act[0] if act else None}
        return apply

    def _v_ballot(self, p, at):
        j = self._jur(p.get("country"))
        v = self._veto(j, p.get("vote_id"))
        voter, choice = p.get("voter"), p.get("choice")
        if choice not in CHOICES:
            raise JurisdictionRefused("choice is for, against or lift")
        if voter not in j["roll"]:
            raise JurisdictionRefused("not on the voter roll")
        signed = {"country": p["country"], "vote_id": p["vote_id"], "choice": choice, "voter": voter}
        if not S.verify(voter, "ballot", signed, p.get("sig")):
            raise JurisdictionRefused("not signed by that voter's key")
        st = self._status(v, at)
        if choice == "lift":
            if st != "PASSED":
                raise JurisdictionRefused("lift ballots are only for a veto that is in force")
            if voter in v["lift"]:
                raise JurisdictionRefused("this voter already voted to lift")
        else:
            if st != "OPEN":
                raise JurisdictionRefused("the veto is not open for ballots")
            if voter in v["for"] or voter in v["against"]:
                raise JurisdictionRefused("this voter already voted")
        need = needed_for_veto(len(j["roll"]))

        def apply():
            self._seq += 1
            v[choice].add(voter)
            if choice == "for" and len(v["for"]) >= need and v["passed_seq"] is None:
                v["passed_seq"] = self._seq
                act = self._active(j)
                v["rules_at_pass"] = act[0] if act else None
            if choice == "lift" and len(v["lift"]) >= need:
                v["resolved"] = "revote"
        return apply

    def _v_override(self, p):
        j = self._jur(p.get("country"))
        v = self._veto(j, p.get("vote_id"))
        if v["passed_seq"] is None or v["resolved"] is not None:
            raise JurisdictionRefused("only a veto in force can be overridden")
        sigs = p.get("sigs")
        signed = {"country": p["country"], "vote_id": p["vote_id"]}
        if not isinstance(sigs, dict) or sorted(sigs) != sorted(BRANCHES) or not all(S.verify(j["branches"][b], "override", signed, sigs[b]) for b in BRANCHES):
            raise JurisdictionRefused("an override needs the signatures of all three branches")

        def apply():
            self._seq += 1
            v["resolved"] = "supermajority_override"
        return apply

    def _root_payload(self, p):
        members = p.get("members")
        if not isinstance(members, list) or not 1 <= len(members) <= 500 or members != sorted(set(members)):
            raise JurisdictionRefused("members is a sorted list of unique country codes")
        return {"prev_root": p.get("prev_root"), "genesis": p.get("genesis"), "members": [[c, self._jur(c)["pk"]] for c in members]}

    def _v_root(self, p):
        if p.get("prev_root") != self.root:
            raise JurisdictionRefused("prev_root is not the current root (no replay, no fork)")
        if not isinstance(p.get("genesis"), str) or not HEX64.fullmatch(p["genesis"]):
            raise JurisdictionRefused("genesis is a 64-character hex hash")
        signed = self._root_payload(p)
        consents = p.get("consents")
        if not isinstance(consents, dict):
            raise JurisdictionRefused("consents are an object")
        ok = 0
        for code in p["members"]:
            j = self._j[code]
            if self._in_force(j):
                continue                                                 # a jurisdiction under a veto cannot consent
            cs = consents.get(code)
            if not isinstance(cs, dict):
                continue
            good = {b for b, sig in cs.items() if b in BRANCHES and S.verify(j["branches"][b], "consent", signed, sig)}
            if len(good) >= 2:
                ok += 1
        need = (2 * len(p["members"]) + 2) // 3
        if ok < need:
            raise JurisdictionRefused("not enough jurisdictions consented (%d of the %d needed)" % (ok, need))
        pks = [m[1] for m in signed["members"]]

        def apply():
            self._seq += 1
            self.root = kronos_root(p["genesis"], pks)
            self.root_members = tuple(p["members"])
        return apply

    def _commit(self, kind, p):
        """Verify, write to the chain, then apply. A chain that cannot be written changes nothing."""
        p = dict(p, at=int(self._clock()))
        fn = self._validate(kind, p)
        try:
            self.dag.record(kind, p)
        except DagError as exc:
            raise JurisdictionRefused("could not record the event: %s" % exc) from exc
        fn()
        return p

    # ---- public actions ----------------------------------------------------------------------------------
    def register(self, country, name, branches, roll, signed) -> str:
        """Needs the device owner's human commitment (jacket) for exactly this identity. Returns the protocol key."""
        p = {"country": country, "name": name, "branches": branches, "roll": roll}
        if not isinstance(roll, list):
            raise JurisdictionRefused("roll is a list")
        _check_reg_shape(p)
        if country in self._j:
            raise JurisdictionRefused("jurisdiction already registered")
        try:
            out = self.commit.commit(REGISTER_ACTION, reg_params(p), signed, route="human")
        except CommitRefused as exc:
            raise JurisdictionRefused("registration needs the owner's commitment: %s" % exc) from exc
        self._commit("JURIS_REGISTERED", dict(p, commit_entry=out["entry"]))
        return self._j[country]["pk"]

    def submit_position(self, country, branch, seq, approved, rules, sig):
        self._commit("JURIS_POSITION", {"country": country, "branch": branch, "seq": seq, "approved": approved, "rules": rules, "sig": sig})

    def open_veto(self, country, opener, nonce, closes_at, sig) -> str:
        p = {"country": country, "opener": opener, "nonce": nonce, "closes_at": closes_at, "sig": sig}
        self._commit("JURIS_VETO_OPENED", p)
        return _sha(S.canonical({k: p[k] for k in ("country", "opener", "nonce", "closes_at")}))

    def cast(self, country, vote_id, voter, choice, sig):
        self._commit("JURIS_BALLOT", {"country": country, "vote_id": vote_id, "voter": voter, "choice": choice, "sig": sig})

    def override(self, country, vote_id, sigs):
        self._commit("JURIS_OVERRIDE", {"country": country, "vote_id": vote_id, "sigs": sigs})

    def update_root(self, prev_root, genesis, members, consents) -> str:
        self._commit("JURIS_ROOT_UPDATED", {"prev_root": prev_root, "genesis": genesis, "members": members, "consents": consents})
        return self.root

    # ---- reading --------------------------------------------------------------------------------------------
    def protocol_key_of(self, country) -> str:
        return self._jur(country)["pk"]

    def policy(self, country) -> dict:
        act = self._active(self._jur(country))
        return {"active": act is not None, "digest": act[0] if act else None, "rules": list(act[1]) if act else []}

    def veto_status(self, country, vote_id) -> str:
        return self._status(self._veto(self._jur(country), vote_id), int(self._clock()))

    def vetoes_in_force(self, country) -> list:
        return self._in_force(self._jur(country))

    def check(self, country, unknown="deny") -> dict:
        """The gate. Fail closed: refuses unless the policy is active and no veto is in force. An unknown jurisdiction is refused unless the caller says unknown='allow'."""
        if unknown not in ("deny", "allow"):
            raise JurisdictionRefused("unknown is 'deny' or 'allow'")
        j = self._j.get(country) if isinstance(country, str) else None
        if j is None:
            return {"allowed": unknown == "allow", "reasons": ["unknown_jurisdiction"], "rules": []}
        reasons = []
        act = self._active(j)
        if act is None:
            reasons.append("policy_not_active")
        if self._in_force(j):
            reasons.append("veto_in_force")
        return {"allowed": not reasons, "reasons": reasons, "rules": list(act[1]) if act and not reasons else []}

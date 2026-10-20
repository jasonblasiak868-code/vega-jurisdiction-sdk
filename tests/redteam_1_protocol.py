"""Functional tests and attacks for the jurisdictional protocol keys."""
import pathlib
import tempfile
import unittest

from vega_custody.dag.dag import Dag, DagError
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_jacket import humanauth
from vega_jacket.commit.commit import Commit
from vega_jacket.humanauth import human_signer
from vega_jurisdiction import protocol as P
from vega_jurisdiction import signing as S

PW, DEV, SURF = "correct horse battery", "dev-t", "surf-t"
T0 = 1_800_000_000


class World:
    def __init__(self, voters=10, codes=("XX",)):
        self.blob, pub = human_signer.generate(PW)
        self.t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([self.t / "c.jsonl"], [self.t / "l.jsonl"])
        self.led = Ledger([LocalBackend(self.t / "led.jsonl")])
        self.commit = Commit(humanauth.Verifier(pub, DEV, SURF), self.led, self.dag)
        self.now = {"t": T0}
        self.clock = lambda: self.now["t"]
        self.J = P.Jurisdictions(self.commit, self.dag, clock=self.clock)
        self.h = {}                  # code -> {branch: Holder}
        self.voters = {}             # code -> [Holder]
        for c in codes:
            self.register(c, voters)

    def human(self, params, lease=300):
        return human_signer.sign(self.blob, PW, DEV, SURF, P.REGISTER_ACTION, params, lease)

    def register(self, code, voters=10, name="Testland"):
        br = {b: S.Holder() for b in P.BRANCHES}
        vs = [S.Holder() for _ in range(voters)]
        self.h[code], self.voters[code] = br, vs
        branches = {b: br[b].public for b in P.BRANCHES}
        roll = sorted(v.public for v in vs)
        params = P.reg_params({"country": code, "name": name, "branches": branches, "roll": roll})
        return self.J.register(code, name, branches, roll, self.human(params))

    def position(self, code, branch, seq, approved, rules, holder=None):
        rules = sorted(set(rules))
        signed = {"country": code, "branch": branch, "seq": seq, "approved": approved, "rules": rules}
        self.J.submit_position(code, branch, seq, approved, rules, (holder or self.h[code][branch]).sign("position", signed))

    def activate(self, code="XX", rules=("no autonomous release",)):
        self.position(code, "executive", 1, True, rules)
        self.position(code, "legislative", 1, True, rules)

    def open(self, code="XX", i=0, window=3600, nonce="nonce-0001"):
        v = self.voters[code][i]
        closes = self.now["t"] + window
        signed = {"country": code, "opener": v.public, "nonce": nonce, "closes_at": closes}
        return self.J.open_veto(code, v.public, nonce, closes, v.sign("veto_open", signed))

    def ballot(self, code, vid, i, choice):
        v = self.voters[code][i]
        self.J.cast(code, vid, v.public, choice, v.sign("ballot", {"country": code, "vote_id": vid, "choice": choice, "voter": v.public}))


class Registration(unittest.TestCase):
    def test_a_registered_jurisdiction_has_a_protocol_key_that_commits_to_its_keys(self):
        w = World(codes=())
        pk = w.register("XX")
        self.assertEqual(len(pk), 64)
        self.assertEqual(pk, w.J.protocol_key_of("XX"))
        self.assertNotEqual(pk, w.register("YY"))

    def test_the_protocol_key_changes_if_any_key_or_name_changes(self):
        br = {b: S.Holder().public for b in P.BRANCHES}
        roll = sorted(S.Holder().public for _ in range(3))
        base = P.protocol_key("XX", "N", br, P.roll_root(roll))
        for variant in (P.protocol_key("XY", "N", br, P.roll_root(roll)), P.protocol_key("XX", "M", br, P.roll_root(roll)),
                        P.protocol_key("XX", "N", dict(br, judicial=S.Holder().public), P.roll_root(roll)), P.protocol_key("XX", "N", br, P.roll_root(roll[:-1]))):
            self.assertNotEqual(base, variant)

    def test_registration_needs_the_owners_commitment_for_exactly_this_identity(self):
        w = World(codes=())
        br = {b: S.Holder().public for b in P.BRANCHES}
        roll = sorted(S.Holder().public for _ in range(3))
        good = P.reg_params({"country": "XX", "name": "N", "branches": br, "roll": roll})
        other = P.reg_params({"country": "XX", "name": "OTHER", "branches": br, "roll": roll})
        with self.assertRaises(P.JurisdictionRefused):
            w.J.register("XX", "N", br, roll, w.human(other))             # signed for a different identity
        with self.assertRaises(P.JurisdictionRefused):
            w.J.register("XX", "N", br, roll, {"nonce": "n", "expiry": T0, "signature": "00"})
        s = w.human(good)
        w.J.register("XX", "N", br, roll, s)
        with self.assertRaises(P.JurisdictionRefused):
            w.J.register("XX", "N", br, roll, s)                            # already registered
        with self.assertRaises(P.JurisdictionRefused):
            w.J.register("XZ", "N", br, roll, s)                            # a used commitment cannot be reused for another

    def test_malformed_registrations_are_refused(self):
        w = World(codes=())
        br = {b: S.Holder().public for b in P.BRANCHES}
        roll = sorted(S.Holder().public for _ in range(3))
        bad = [("x", "N", br, roll), ("XX" * 20, "N", br, roll), ("xx", "N", br, roll), ("XX", "", br, roll), ("XX", "N\x00", br, roll),
               ("XX", "N", dict(br, judicial=br["executive"]), roll), ("XX", "N", {"executive": br["executive"]}, roll),
               ("XX", "N", dict(br, king=S.Holder().public), roll), ("XX", "N", br, []), ("XX", "N", br, list(reversed(roll))),
               ("XX", "N", br, roll + roll[:1]), ("XX", "N", br, sorted(roll + [br["executive"]])), ("XX", "N", br, ["zz"]), ("XX", "N", br, "notalist")]
        for c, n, b, r in bad:
            try:
                s = w.human(P.reg_params({"country": c, "name": n, "branches": b, "roll": r}))      # the owner DID sign it: only the shape check can refuse
            except Exception:                                                                       # noqa: BLE001 - nonsense the owner could not even sign
                s = {"nonce": "n", "expiry": T0, "signature": "00"}
            with self.assertRaises(P.JurisdictionRefused, msg=repr((c, n))):
                w.J.register(c, n, b, r, s)
        self.assertEqual(w.J.check("XX")["reasons"], ["unknown_jurisdiction"])


class Policy(unittest.TestCase):
    def test_one_approval_is_not_a_policy_two_matching_approvals_are(self):
        w = World()
        w.position("XX", "executive", 1, True, ["a"])
        self.assertFalse(w.J.policy("XX")["active"])
        w.position("XX", "legislative", 1, True, ["a"])
        self.assertTrue(w.J.policy("XX")["active"])
        self.assertEqual(w.J.policy("XX")["rules"], ["a"])

    def test_two_branches_approving_different_texts_are_not_a_policy(self):
        w = World()
        w.position("XX", "executive", 1, True, ["a"])
        w.position("XX", "legislative", 1, True, ["b"])
        self.assertFalse(w.J.policy("XX")["active"])
        w.position("XX", "judicial", 1, True, ["a"])
        self.assertTrue(w.J.policy("XX")["active"])

    def test_a_branch_can_withdraw_and_a_branch_counts_once(self):
        w = World()
        w.activate()
        w.position("XX", "executive", 2, False, ["no autonomous release"])
        self.assertFalse(w.J.policy("XX")["active"])
        w.position("XX", "legislative", 2, True, ["no autonomous release"])      # the same branch again is still one approval
        self.assertFalse(w.J.policy("XX")["active"])

    def test_forged_positions_are_refused(self):
        w = World()
        wrong = S.Holder()
        with self.assertRaises(P.JurisdictionRefused):
            w.position("XX", "executive", 1, True, ["a"], holder=wrong)                 # not that branch's key
        with self.assertRaises(P.JurisdictionRefused):
            w.position("XX", "executive", 1, True, ["a"], holder=w.h["XX"]["judicial"])  # another branch's key
        sig = w.h["XX"]["executive"].sign("ballot", {"country": "XX", "branch": "executive", "seq": 1, "approved": True, "rules": ["a"]})
        with self.assertRaises(P.JurisdictionRefused):
            w.J.submit_position("XX", "executive", 1, True, ["a"], sig)                 # a signature of another kind
        good = w.h["XX"]["executive"].sign("position", {"country": "XX", "branch": "executive", "seq": 1, "approved": True, "rules": ["a"]})
        with self.assertRaises(P.JurisdictionRefused):
            w.J.submit_position("XX", "executive", 1, True, ["b"], good)                # signature does not cover these rules
        with self.assertRaises(P.JurisdictionRefused):
            w.J.submit_position("XX", "executive", 2, True, ["a"], good)                # nor this number
        self.assertFalse(w.J.policy("XX")["active"])

    def test_old_positions_cannot_be_replayed_and_numbers_must_rise(self):
        w = World()
        w.position("XX", "executive", 5, True, ["a"])
        for seq in (5, 4, 0, -1):
            with self.assertRaises(P.JurisdictionRefused):
                w.position("XX", "executive", seq, True, ["a"])
        for bad in (True, 1.5, "2", None):
            with self.assertRaises(P.JurisdictionRefused):
                w.J.submit_position("XX", "executive", bad, True, ["a"], "00" * 64)

    def test_rule_lists_have_one_way_to_be_written(self):
        w = World()
        h = w.h["XX"]["executive"]
        for rules in (["b", "a"], ["a", "a"], [""], ["x" * 501], ["bad\x00"], ["a"] * 300):
            sig = h.sign("position", {"country": "XX", "branch": "executive", "seq": 1, "approved": True, "rules": rules})
            with self.assertRaises(P.JurisdictionRefused, msg=repr(rules)[:30]):
                w.J.submit_position("XX", "executive", 1, True, rules, sig)
        for rules in ("text", [1], None):
            with self.assertRaises(P.JurisdictionRefused):
                w.J.submit_position("XX", "executive", 1, True, rules, "00" * 64)

    def test_unknown_jurisdiction_or_branch_is_refused(self):
        w = World()
        with self.assertRaises(P.JurisdictionRefused):
            w.J.submit_position("NOPE", "executive", 1, True, ["a"], "00" * 64)
        with self.assertRaises(P.JurisdictionRefused):
            w.J.submit_position("XX", "king", 1, True, ["a"], "00" * 64)


class Veto(unittest.TestCase):
    def setUp(self):
        self.w = World(voters=10)                 # 51% of 10 = 6
        self.w.activate()

    def test_the_threshold_is_51_percent_of_the_registered_roll_rounded_up(self):
        self.assertEqual([P.needed_for_veto(n) for n in (1, 2, 3, 10, 100, 101, 1000)], [1, 2, 2, 6, 51, 52, 510])
        w = self.w
        vid = w.open()
        for i in range(5):
            w.ballot("XX", vid, i, "for")
        self.assertEqual(w.J.veto_status("XX", vid), "OPEN")
        self.assertTrue(w.J.check("XX")["allowed"])
        w.ballot("XX", vid, 5, "for")
        self.assertEqual(w.J.veto_status("XX", vid), "PASSED")
        self.assertEqual(w.J.check("XX"), {"allowed": False, "reasons": ["veto_in_force"], "rules": []})

    def test_against_ballots_do_not_move_the_count_and_each_voter_votes_once(self):
        w = self.w
        vid = w.open()
        for i in range(9):
            w.ballot("XX", vid, i, "against")
        w.ballot("XX", vid, 9, "for")
        self.assertEqual(w.J.veto_status("XX", vid), "OPEN")
        with self.assertRaises(P.JurisdictionRefused):
            w.ballot("XX", vid, 9, "for")
        with self.assertRaises(P.JurisdictionRefused):
            w.ballot("XX", vid, 0, "for")                       # changed mind: not allowed

    def test_only_the_roll_can_open_or_vote_and_ballots_cannot_be_forged_or_moved(self):
        w = self.w
        outsider = S.Holder()
        signed = {"country": "XX", "opener": outsider.public, "nonce": "nonce-0001", "closes_at": T0 + 3600}
        with self.assertRaises(P.JurisdictionRefused):
            w.J.open_veto("XX", outsider.public, "nonce-0001", T0 + 3600, outsider.sign("veto_open", signed))
        vid = w.open()
        with self.assertRaises(P.JurisdictionRefused):
            w.J.cast("XX", vid, outsider.public, "for", outsider.sign("ballot", {"country": "XX", "vote_id": vid, "choice": "for", "voter": outsider.public}))
        v0, v1 = w.voters["XX"][0], w.voters["XX"][1]
        with self.assertRaises(P.JurisdictionRefused):
            w.J.cast("XX", vid, v1.public, "for", v0.sign("ballot", {"country": "XX", "vote_id": vid, "choice": "for", "voter": v1.public}))   # one voter signing as another
        with self.assertRaises(P.JurisdictionRefused):
            w.J.cast("XX", vid, v0.public, "against", v0.sign("ballot", {"country": "XX", "vote_id": vid, "choice": "for", "voter": v0.public}))  # signed 'for', sent as 'against'
        with self.assertRaises(P.JurisdictionRefused):
            w.J.cast("XX", vid, v0.public, "for", v0.sign("veto_open", {"country": "XX", "vote_id": vid, "choice": "for", "voter": v0.public}))   # wrong kind
        with self.assertRaises(P.JurisdictionRefused):
            w.J.cast("XX", "nosuchvote", v0.public, "for", "00" * 64)
        with self.assertRaises(P.JurisdictionRefused):
            w.J.cast("XX", vid, v0.public, "maybe", "00" * 64)

    def test_a_ballot_cannot_be_moved_to_another_jurisdiction_or_world(self):
        w = World(voters=10, codes=("XX", "YY"))
        w.activate("XX")
        w.activate("YY")
        vid = w.open("XX")
        v = w.voters["XX"][0]
        sig = v.sign("ballot", {"country": "XX", "vote_id": vid, "choice": "for", "voter": v.public})
        with self.assertRaises(P.JurisdictionRefused):
            w.J.cast("YY", vid, v.public, "for", sig)

    def test_the_window_closes_and_a_failed_veto_lets_a_new_one_open(self):
        w = self.w
        vid = w.open(window=3600)
        w.ballot("XX", vid, 0, "for")
        w.now["t"] += 3601
        self.assertEqual(w.J.veto_status("XX", vid), "FAILED")
        with self.assertRaises(P.JurisdictionRefused):
            w.ballot("XX", vid, 1, "for")                       # too late
        self.assertTrue(w.J.check("XX")["allowed"])
        w.open(nonce="nonce-0002")

    def test_the_voting_window_is_bounded_and_only_one_veto_is_live_at_a_time(self):
        w = self.w
        v = w.voters["XX"][0]
        for closes in (T0 + 10, T0 - 5, T0 + 91 * 86400):
            with self.assertRaises(P.JurisdictionRefused):
                w.J.open_veto("XX", v.public, "nonce-0001", closes, v.sign("veto_open", {"country": "XX", "opener": v.public, "nonce": "nonce-0001", "closes_at": closes}))
        for closes in ("x", True, None):
            with self.assertRaises(P.JurisdictionRefused):
                w.J.open_veto("XX", v.public, "nonce-0001", closes, "00" * 64)
        w.open()
        with self.assertRaises(P.JurisdictionRefused):
            w.open(nonce="nonce-0002")
        for n in ("short", "x" * 65, "bad\x00nonce!!"):
            with self.assertRaises(P.JurisdictionRefused):
                w.J.open_veto("XX", v.public, n, T0 + 3600, v.sign("veto_open", {"country": "XX", "opener": v.public, "nonce": n, "closes_at": T0 + 3600}))

    def test_a_jurisdiction_without_a_policy_is_refused_by_the_gate(self):
        w = World()
        self.assertEqual(w.J.check("XX"), {"allowed": False, "reasons": ["policy_not_active"], "rules": []})


class Resolution(unittest.TestCase):
    def setUp(self):
        self.w = World(voters=10)
        self.w.activate()
        self.vid = self.w.open()
        for i in range(6):
            self.w.ballot("XX", self.vid, i, "for")

    def test_an_amendment_with_different_rules_lifts_it_the_same_rules_do_not(self):
        w = self.w
        w.position("XX", "judicial", 1, True, ["no autonomous release"])              # a third branch approving the same text changes nothing
        self.assertEqual(w.J.veto_status("XX", self.vid), "PASSED")
        w.position("XX", "executive", 2, True, ["a different rule"])
        w.position("XX", "legislative", 2, True, ["a different rule"])
        self.assertEqual(w.J.veto_status("XX", self.vid), "RESOLVED:government_amendment")
        self.assertTrue(w.J.check("XX")["allowed"])

    def test_an_override_needs_all_three_branches_and_real_signatures(self):
        w = self.w
        h = w.h["XX"]
        body = {"country": "XX", "vote_id": self.vid}
        sigs = {b: h[b].sign("override", body) for b in P.BRANCHES}
        two = {b: sigs[b] for b in ("executive", "legislative")}
        with self.assertRaises(P.JurisdictionRefused):
            w.J.override("XX", self.vid, two)
        with self.assertRaises(P.JurisdictionRefused):
            w.J.override("XX", self.vid, dict(sigs, judicial=S.Holder().sign("override", body)))
        with self.assertRaises(P.JurisdictionRefused):
            w.J.override("XX", self.vid, dict(sigs, judicial=h["judicial"].sign("position", body)))
        with self.assertRaises(P.JurisdictionRefused):
            w.J.override("XX", self.vid, "all three")
        self.assertEqual(w.J.veto_status("XX", self.vid), "PASSED")
        w.J.override("XX", self.vid, sigs)
        self.assertEqual(w.J.veto_status("XX", self.vid), "RESOLVED:supermajority_override")
        with self.assertRaises(P.JurisdictionRefused):
            w.J.override("XX", self.vid, sigs)                                      # nothing left to override

    def test_a_revote_needs_51_percent_to_lift_and_only_while_it_is_in_force(self):
        w = self.w
        for i in range(5):
            w.ballot("XX", self.vid, i, "lift")
        self.assertEqual(w.J.veto_status("XX", self.vid), "PASSED")
        with self.assertRaises(P.JurisdictionRefused):
            w.ballot("XX", self.vid, 0, "lift")
        w.ballot("XX", self.vid, 5, "lift")
        self.assertEqual(w.J.veto_status("XX", self.vid), "RESOLVED:revote")
        w2 = World(voters=10)
        w2.activate()
        vid2 = w2.open()
        with self.assertRaises(P.JurisdictionRefused):
            w2.ballot("XX", vid2, 0, "lift")                                       # nothing is in force yet

    def test_for_ballots_are_refused_after_it_passed(self):
        with self.assertRaises(P.JurisdictionRefused):
            self.w.ballot("XX", self.vid, 7, "for")


class Gate(unittest.TestCase):
    def test_unknown_jurisdictions_fail_closed_unless_the_caller_chooses_otherwise(self):
        w = World()
        self.assertFalse(w.J.check("NOPE")["allowed"])
        self.assertTrue(w.J.check("NOPE", unknown="allow")["allowed"])
        for junk in (None, 5, [], {}, "", "xx"):
            self.assertFalse(w.J.check(junk)["allowed"])
        for bad in ("maybe", None, True):
            with self.assertRaises(P.JurisdictionRefused):
                w.J.check("XX", unknown=bad)

    def test_an_active_policy_with_no_veto_allows_and_hands_back_the_rules(self):
        w = World()
        w.activate(rules=("b rule", "a rule"))
        self.assertEqual(w.J.check("XX"), {"allowed": True, "reasons": [], "rules": ["a rule", "b rule"]})


class Kronos(unittest.TestCase):
    def setUp(self):
        self.w = World(voters=10, codes=("AA", "BB", "CC"))
        self.g = "ab" * 32

    def body(self, members, prev=None, g=None):
        return {"prev_root": prev, "genesis": g or self.g, "members": [[c, self.w.J.protocol_key_of(c)] for c in members]}

    def consents(self, members, prev=None, branches_per=2, g=None, only=None):
        body = self.body(members, prev, g)
        out = {}
        for c in members:
            if only is not None and c not in only:
                continue
            out[c] = {b: self.w.h[c][b].sign("consent", body) for b in P.BRANCHES[:branches_per]}
        return out

    def test_the_root_is_a_function_of_the_genesis_and_the_protocol_keys_only(self):
        pks = [self.w.J.protocol_key_of(c) for c in ("AA", "BB", "CC")]
        r = P.kronos_root(self.g, pks)
        self.assertEqual(r, P.kronos_root(self.g, list(reversed(pks))))
        self.assertNotEqual(r, P.kronos_root(self.g, pks[:2]))
        self.assertNotEqual(r, P.kronos_root("cd" * 32, pks))
        self.assertNotEqual(P.kronos_root(self.g, ["ab", "c"]), P.kronos_root(self.g, ["a", "bc"]))      # no concatenation ambiguity

    def test_two_thirds_of_the_members_each_with_two_branches_move_the_root(self):
        w, m = self.w, ["AA", "BB", "CC"]
        r = w.J.update_root(None, self.g, m, self.consents(m, only={"AA", "BB"}))
        self.assertEqual(r, w.J.root)
        self.assertEqual(r, P.kronos_root(self.g, [w.J.protocol_key_of(c) for c in m]))

    def test_too_few_jurisdictions_or_too_few_branches_do_not(self):
        w, m = self.w, ["AA", "BB", "CC"]
        with self.assertRaises(P.JurisdictionRefused):
            w.J.update_root(None, self.g, m, self.consents(m, only={"AA"}))
        with self.assertRaises(P.JurisdictionRefused):
            w.J.update_root(None, self.g, m, self.consents(m, branches_per=1))
        forged = self.consents(m)
        forged["AA"]["executive"] = S.Holder().sign("consent", self.body(m))
        forged["BB"]["executive"] = S.Holder().sign("consent", self.body(m))
        forged["CC"]["executive"] = S.Holder().sign("consent", self.body(m))
        with self.assertRaises(P.JurisdictionRefused):
            w.J.update_root(None, self.g, m, forged)
        self.assertIsNone(w.J.root)

    def test_consents_for_a_different_genesis_or_member_set_do_not_carry_over(self):
        w, m = self.w, ["AA", "BB", "CC"]
        with self.assertRaises(P.JurisdictionRefused):
            w.J.update_root(None, "cd" * 32, m, self.consents(m, g=self.g))
        with self.assertRaises(P.JurisdictionRefused):
            w.J.update_root(None, self.g, ["AA", "BB"], self.consents(m))

    def test_a_replay_or_a_fork_is_refused_and_the_chain_of_roots_continues(self):
        w, m = self.w, ["AA", "BB", "CC"]
        c = self.consents(m)
        r1 = w.J.update_root(None, self.g, m, c)
        with self.assertRaises(P.JurisdictionRefused):
            w.J.update_root(None, self.g, m, c)                                  # same update again
        g2 = "cd" * 32
        r2 = w.J.update_root(r1, g2, m, self.consents(m, prev=r1, g=g2))
        self.assertNotEqual(r1, r2)

    def test_a_jurisdiction_under_a_veto_cannot_consent(self):
        w, m = self.w, ["AA", "BB", "CC"]
        w.activate("AA")
        vid = w.open("AA", nonce="nonce-0001")
        for i in range(6):
            w.ballot("AA", vid, i, "for")
        with self.assertRaises(P.JurisdictionRefused):
            w.J.update_root(None, self.g, ["AA", "BB"], self.consents(["AA", "BB"]))        # AA frozen: only BB counts, 1 of the 2 needed
        self.assertIsNotNone(w.J.update_root(None, self.g, m, self.consents(m)))              # BB and CC are 2 of 3

    def test_members_must_be_sorted_unique_and_registered(self):
        w = self.w
        for bad in (["BB", "AA"], ["AA", "AA"], ["AA", "ZZ"], [], "AA", None):
            with self.assertRaises(P.JurisdictionRefused):
                w.J.update_root(None, self.g, bad, {})

    def test_bad_consent_shapes_are_refused_not_crashes(self):
        w, m = self.w, ["AA", "BB", "CC"]
        for bad in (None, "x", [], {"AA": "x", "BB": 5, "CC": None}):
            with self.assertRaises(P.JurisdictionRefused):
                w.J.update_root(None, self.g, m, bad)
        for g in (None, 5, "short", "z" * 64):
            with self.assertRaises(P.JurisdictionRefused):
                w.J.update_root(None, g, m, self.consents(m))


class Durability(unittest.TestCase):
    def test_state_is_rebuilt_from_the_chain_with_every_signature_checked_again(self):
        w = World(voters=10)
        w.activate()
        vid = w.open()
        for i in range(6):
            w.ballot("XX", vid, i, "for")
        w2 = P.Jurisdictions(w.commit, w.dag, clock=w.clock)
        self.assertEqual(w2.replay_rejected, 0)
        self.assertEqual(w2.check("XX"), w.J.check("XX"))
        self.assertEqual(w2.veto_status("XX", vid), "PASSED")
        self.assertEqual(w2.protocol_key_of("XX"), w.J.protocol_key_of("XX"))

    def test_a_forged_entry_written_straight_into_the_chain_changes_nothing(self):
        w = World()
        w.dag.record("JURIS_POSITION", {"country": "XX", "branch": "executive", "seq": 1, "approved": True, "rules": ["x"], "sig": "00" * 64, "at": T0})
        w.dag.record("JURIS_REGISTERED", {"country": "EVIL", "name": "n", "branches": {b: S.Holder().public for b in P.BRANCHES}, "roll": [S.Holder().public], "commit_entry": "nothing", "at": T0})
        w.dag.record("JURIS_BALLOT", {"country": "XX", "at": T0})
        w.dag.record("JURIS_ROOT_UPDATED", {"prev_root": None, "genesis": "ab" * 32, "members": ["XX"], "consents": {}, "at": T0})
        w2 = P.Jurisdictions(w.commit, w.dag, clock=w.clock)
        self.assertEqual(w2.replay_rejected, 4)
        self.assertFalse(w2.policy("XX")["active"])
        self.assertFalse(w2.check("EVIL")["allowed"])
        self.assertIsNone(w2.root)

    def test_a_registration_cannot_borrow_another_commitment_that_is_on_the_chain(self):
        w = World()
        entry = [e for e in w.dag.content.entries() if e["kind"] == "COMMIT"][0]["entry_hash"]
        br = {b: S.Holder().public for b in P.BRANCHES}
        w.dag.record("JURIS_REGISTERED", {"country": "EVIL", "name": "n", "branches": br, "roll": [S.Holder().public], "commit_entry": entry, "at": T0})
        self.assertEqual(P.Jurisdictions(w.commit, w.dag, clock=w.clock).replay_rejected, 1)

    def test_if_the_chain_cannot_be_written_nothing_changes(self):
        w = World()
        real = w.dag.record

        def failing(kind, payload, parents=None):
            if kind.startswith("JURIS_"):
                raise DagError("disk full")
            return real(kind, payload, parents)
        w.dag.record = failing
        with self.assertRaises(P.JurisdictionRefused):
            w.position("XX", "executive", 1, True, ["a"])
        w.dag.record = real
        w.position("XX", "executive", 1, True, ["a"])                                  # the refused one did not burn the number

    def test_the_chain_stays_intact(self):
        w = World()
        w.activate()
        self.assertTrue(w.dag.verify()[0])


class Signing(unittest.TestCase):
    def test_a_signature_for_one_kind_never_verifies_as_another(self):
        h = S.Holder()
        payload = {"a": 1}
        sig = h.sign("position", payload)
        self.assertTrue(S.verify(h.public, "position", payload, sig))
        for k in ("ballot", "veto_open", "override", "consent"):
            self.assertFalse(S.verify(h.public, k, payload, sig))
        self.assertFalse(S.verify(h.public, "position", {"a": 2}, sig))
        for junk in (None, 5, "", "zz" * 64, "00" * 63):
            self.assertFalse(S.verify(h.public, "position", payload, junk))
            self.assertFalse(S.verify(junk, "position", payload, sig))
        self.assertFalse(S.verify(h.public, "nonsense", payload, sig))
        self.assertFalse(S.verify(h.public, "position", {"a": float("nan")}, sig))

    def test_payloads_must_be_plain_data(self):
        with self.assertRaises(S.SigningRefused):
            S.canonical({"a": object()})
        with self.assertRaises(S.SigningRefused):
            S.message("nonsense", {})


if __name__ == "__main__":
    unittest.main()

"""Regression tests (2026-10-22): a signed veto_open names no time or sequence, and applying it wrote j['vetoes'][vid] without checking that vid already existed. After a
veto was resolved, anyone able to submit events could replay the original signed opening and bring the veto back."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redteam_1_protocol import World  # noqa: E402
from vega_jurisdiction import protocol as P  # noqa: E402


class VetoOpenReplay(unittest.TestCase):
    def test_a_resolved_veto_cannot_be_resurrected_by_replaying_its_opening(self):
        w = World(voters=10)
        w.activate()
        v = w.voters["XX"][0]
        closes = w.now["t"] + 30 * 86400
        signed = {"country": "XX", "opener": v.public, "nonce": "nonce-0001", "closes_at": closes}
        sig = v.sign("veto_open", signed)
        vid = w.J.open_veto("XX", v.public, "nonce-0001", closes, sig)
        for i in range(6):
            w.ballot("XX", vid, i, "for")
        h = w.h["XX"]
        w.J.override("XX", vid, {b: h[b].sign("override", {"country": "XX", "vote_id": vid}) for b in P.BRANCHES})
        self.assertEqual(w.J.veto_status("XX", vid), "RESOLVED:supermajority_override")
        with self.assertRaises(P.JurisdictionRefused):
            w.J.open_veto("XX", v.public, "nonce-0001", closes, sig)                # the very same signed opening, again
        self.assertEqual(w.J.veto_status("XX", vid), "RESOLVED:supermajority_override")
        self.assertTrue(w.J.check("XX")["allowed"])


if __name__ == "__main__":
    unittest.main()

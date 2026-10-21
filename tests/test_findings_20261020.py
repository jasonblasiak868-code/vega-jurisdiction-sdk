"""Regression tests (2026-10-20): an event was validated, then recorded, then applied as three separate steps, so concurrent calls could record two open vetoes (and duplicate
ballots) that the chain's own replay rules reject. The live state then differed from the state rebuilt from the chain after a restart."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redteam_1_protocol import World  # noqa: E402
from vega_jurisdiction import protocol as P  # noqa: E402


def race(n, fn):
    gate, out, lock = threading.Barrier(n), [], threading.Lock()

    def go(i):
        gate.wait()
        try:
            fn(i)
            r = "ok"
        except P.JurisdictionRefused:
            r = "refused"
        with lock:
            out.append(r)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    return sorted(out)


def slow_record(w, seconds=0.03):
    """Writing the chain takes a moment: widens the window between validating an event and applying it."""
    inner = w.J.dag.record

    class Slow:
        def __getattr__(self, k):
            return getattr(w.J.dag, k)

        def record(self, kind, payload, parents=None):
            time.sleep(seconds)
            return inner(kind, payload, parents)
    w.J.dag = Slow()


class LiveStateMatchesTheChain(unittest.TestCase):
    def test_two_voters_cannot_both_open_a_veto_at_once(self):
        for _ in range(3):
            w = World()
            w.activate()
            slow_record(w)
            self.assertEqual(race(2, lambda i: w.open(i=i, nonce="nonce-%04d" % i)), ["ok", "refused"])
            self.assertEqual(len(w.J._j["XX"]["vetoes"]), 1)

    def test_the_same_voter_cannot_have_two_ballots_recorded_at_once(self):
        w = World()
        w.activate()
        vid = w.open()
        slow_record(w)
        self.assertEqual(race(3, lambda i: w.ballot("XX", vid, 1, "for")), ["ok", "refused", "refused"])
        ballots = [e for e in w.dag.content.entries() if e["kind"] == "JURIS_BALLOT"]
        self.assertEqual(len(ballots), 1)

    def test_after_concurrent_use_a_restart_rebuilds_exactly_the_live_state(self):
        w = World()
        w.activate()
        slow_record(w)
        race(2, lambda i: w.open(i=i, nonce="nonce-%04d" % i))
        again = P.Jurisdictions(w.commit, w.dag, clock=w.clock)
        self.assertEqual(again.replay_rejected, 0)
        self.assertEqual(sorted(again._j["XX"]["vetoes"]), sorted(w.J._j["XX"]["vetoes"]))


if __name__ == "__main__":
    unittest.main()

# Changelog

## 2026-10-20: fixes found by a source read

These were found by reading the source against its own documentation after release, not by the earlier test and review passes. Each fix has a regression test in
`tests/test_findings_20261020.py` that failed before the fix, and each fix was checked by undoing it and confirming a test fails. Behaviour that changed is listed under "Changed".

### Fixed
- **Live state could differ from the state rebuilt from the chain.** Validating, recording and applying an event were three steps, so two voters could both open a veto and one voter could have two ballots recorded; replay after a restart rejected what the live object had accepted. They are now one step under a lock.

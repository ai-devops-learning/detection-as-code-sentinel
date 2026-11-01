---
title: Test detection rules against logs before deployment
labels:
  - phase-1
  - detection
  - testing
---

## Goal
No detection rule is deployed to Sentinel until its KQL has passed tests against both sample logs and real logs from the workspace.

## Tasks
- [ ] Define the test file format in `tests/detections/<rule>.test.yaml`: sample log rows, plus the number of results expected (one positive case and one negative case).
- [ ] Write `scripts/run_kql_tests.py` to run a rule's KQL against the sample rows using a `datatable(...)` in place of the real table.
- [ ] Add a check that compares the sample rows with the columns of a real event from the workspace (for example, a real `AzureActivity` row), so the test data matches reality.
- [ ] Add a test file for each existing rule in `detections/`.
- [ ] Run the tests in CI on every pull request and make the check required to merge.
- [ ] Make the deploy workflow run only after the tests pass, and fail the pipeline if any rule has no test file.
- [ ] Document how to write and run a rule test locally in the project README.

## Acceptance criteria
- Every rule in `detections/` has a test file with at least one case that matches and one that does not.
- A pull request with a rule that returns the wrong result in a test fails CI and cannot be merged.
- A rule with no test file fails the pipeline and is not deployed.
- Deployment only starts after the rule tests pass.

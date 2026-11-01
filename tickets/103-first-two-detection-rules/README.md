---
title: Build, deploy and fire two simple detection rules
labels:
  - phase-1
  - detection
---

## Goal
Take two very simple detection rules from idea to a real alert, using detection-as-code.

## Tasks
- [ ] Pick two simple rules that are easy to trigger on demand (for example: resource group deleted, role assignment created).
- [ ] Research how to deploy Sentinel analytics rules as code (YAML in Git, deployed through the Sentinel API).
- [ ] Write both rules as YAML + KQL in `detections/azure_activity/`.
- [ ] Write a test for each rule and run it against sample data.
- [ ] Deploy both rules through the pipeline.
- [ ] Trigger each rule for real (for example: delete a throwaway resource group in `rg-lab-targets`).
- [ ] Confirm each alert and incident appears in Sentinel, and save screenshots to `docs/evidence/phase-1/`.

## Acceptance criteria
- Both rules are in Git, tested, and deployed by the pipeline (not by hand in the portal).
- Each rule fires an alert from a real action in the lab.
- Re-running the deployment changes nothing.

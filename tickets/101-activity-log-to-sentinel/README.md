---
title: Connect Sentinel to the Defender portal and ingest the Azure Activity log
labels: [phase-0, infra]
---

## Tasks

- [ ] Connect the workspace to the Defender portal and make it the primary workspace
- [ ] Confirm **Microsoft Sentinel > Configuration > Automation** is visible
- [ ] Install the *Azure Activity* solution from the Content hub
- [ ] Create the `activity-to-sentinel` subscription diagnostic setting (Administrative, Security, Policy, Alert)
- [ ] Wait 10-15 minutes, then run the `AzureActivity` check query
- [ ] Save a screenshot of the results to `docs/evidence/phase-0/`

## Acceptance criteria

- [ ] The check query returns rows in the Azure portal
- [ ] The same query returns rows in the Defender portal (Advanced hunting)


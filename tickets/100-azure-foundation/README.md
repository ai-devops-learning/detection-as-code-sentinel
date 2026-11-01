---
title: Create Azure resource groups and the Sentinel workspace
labels: [phase-0, infra]
---

## Tasks

- [ ] Sign in with `az login` and select the lab subscription
- [ ] Create `rg-sentinel-lab` (workspace) and `rg-lab-targets` (things to break on purpose)
- [ ] Create the Log Analytics workspace `law-sentinel-lab`
- [ ] Enable Microsoft Sentinel on the workspace
- [ ] Copy `config/lab.env.example` to `config/lab.env` and fill in the IDs (git-ignored)

## Acceptance criteria

- [ ] Both resource groups exist in the chosen region
- [ ] The workspace shows Microsoft Sentinel as enabled
- [ ] No secrets or IDs are committed to the repository


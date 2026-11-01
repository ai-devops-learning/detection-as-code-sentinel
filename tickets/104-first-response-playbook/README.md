---
title: Build one playbook that responds to the first two detection rules
labels:
  - phase-2
  - soar
---

## Goal
When either rule from T-103 fires, a playbook runs on its own and takes a simple, safe action on the incident.

## Tasks
- [ ] Decide the first action. Start with the safest: add an incident comment and a tag. Consider notifying (Teams or email) next. Only consider revoking a user's sessions later, and only against a throwaway test user.
- [ ] Write the playbook request in `playbooks/<name>/prompt.md` (trigger, steps, safety check) and review it like code.
- [ ] Generate the playbook (Defender portal playbook generator, or a Logic App if the generator is unavailable) and read the generated code before enabling it.
- [ ] Add a scope check so it only acts on lab resources.
- [ ] Create the automation rule that runs the playbook for both detection rules, and record its settings in `playbooks/<name>/automation-rule.md`.
- [ ] Copy the final code and docs into `playbooks/<name>/` through a pull request.
- [ ] Trigger each detection rule for real and confirm the playbook runs and acts.
- [ ] Save screenshots (Activities tab, incident comments and tags) to `docs/evidence/phase-2/`.

## Acceptance criteria
- Firing either rule runs the playbook with no manual step.
- The incident shows the playbook's comment and tag.
- A resource outside the lab scope is left untouched and the playbook says why.
- The prompt, code, docs and automation rule settings are in Git.

---
description: Create a new ticket folder from a short description
argument-hint: What the ticket is about, in plain words
agent: agent
---

Create a new ticket from this description: ${input:description:What is the ticket about?}

Steps:

1. Read `tickets/_template/README.md` and copy its exact format: front matter with `title` and `labels`, then `## Goal` (one line), `## Tasks` (`- [ ]` checkboxes), `## Acceptance criteria` (plain bullets).
2. Read the other folders in `tickets/` and reuse their label names where they fit. Check the project README for context, and pick work that is not already covered by an existing ticket.
3. Get the id by running `python scripts/sync_tickets.py --next-id --repo <owner/repo>` (use `git remote get-url origin` for the repo). Never pick an id by hand and never reuse one.
4. Create `tickets/<id>-<short-kebab-slug>/README.md`.
5. Run `python scripts/sync_tickets.py --validate-only` and fix any error.
6. Show the ticket and stop. Do not commit or push. Pushing to `main` is what creates the GitHub issue.

Rules:

- Title: imperative, verb plus outcome, under 80 characters.
- Tasks: small, verifiable steps, roughly 4 to 8.
- Acceptance criteria: observable results, not activities.
- If the description is too vague to write acceptance criteria, ask one short question first.

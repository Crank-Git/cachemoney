# Contributing to cachemoney

This repo uses a two-branch integration model with pull requests on every path.

## Branch model

```
        feature / topic branches (short-lived)
                 │  PR #1
                 ▼
         ┌───────────────┐   PR #2
         │       dev      │───────────────►  main
         │  (integration) │                 (stable / release)
         └───────────────┘
```

- **`main`** — stable, release-ready branch. Never push directly. Always arrive via a PR from `dev`.
- **`dev`** — active integration branch. This is where feature work lands. It is the default branch.
- **feature branches** — short-lived branches forked off `dev`, each for one focused change.

## Workflow

1. Pull the latest `dev`:
   ```bash
   git fetch origin
   git switch dev
   git pull origin dev
   ```
2. Create a feature branch off `dev`:
   ```bash
   git switch -c <feature-name>
   ```
3. Commit your work (see [commit conventions](#commit-conventions)).
4. Push and open a PR **from `<feature-name>` into `dev`**:
   ```bash
   git push -u origin <feature-name>
   # then https://github.com/Crank-Git/cachemoney/pull/new/<feature-name>
   ```
5. Once the PR is merged into `dev`, open a second PR **from `dev` into `main`**
   and merge it with a **merge commit** (not squash) to promote the change to
   stable. A merge commit keeps `main` an ancestor of `dev`, so the next
   promotion only lists new commits; a squash would make `dev`'s history look
   unmerged every time.

## Branch protection

Both integration branches are protected:

- **`dev`** — a PR is required, at least one approval, conversation must be resolved.
- **`main`** — a PR is required (from `dev`), at least one approval, admin pushes are
  blocked, conversation must be resolved.

There is no direct push to either branch.

## Commit conventions

- Keep commits focused and atomic; one logical change per commit.
- Use a clear imperative subject line (e.g. `add DNS chunk resolver`).
- Reference an issue/PR number in the body when relevant.

## Before you push

- [ ] Branch created off `dev`, not `main`.
- [ ] Changes are focused and self-contained.
- [ ] Local `dev` is up to date.
- [ ] PR links any related issue.

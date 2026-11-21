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

Required status checks: `test` on `dev`; `build`, `format`, `test`, and `vet` on `main`.

## CI

`.github/workflows/test.yml` runs on every PR into `dev` or `main` and on every push to
them. Each job is a separate status check:

- **build**: `go build ./...`
- **format**: `gofmt -l` must print nothing.
- **vet**: `go vet ./...`
- **test**: `go test -race -coverprofile=coverage.out ./...` with `CACHEMONEY_REQUIRE_UNBOUND=1`,
  so the recursive-resolver test runs against a real Unbound. Total coverage must stay at
  70% or more.

Locally, the Unbound test is skipped if `unbound` isn't installed.

## Repository layout

```
pkg/objectstore/    content-addressed core: chunking, manifests, TXT/AAAA framing, verify
pkg/dnszone/        authoritative server (serve) + client resolver (fetch) over UDP/TCP
pkg/gitobj/         Git object model (commit/tree/blob hashing, graph walk)
pkg/gitdns/         publish/fetch Git object graphs over DNS
pkg/pkgindex/       package-file index model
pkg/mirror/         package index + file transport over DNS (the model for an apt/Nix mirror)
cmd/cachemoney/     CLI (`put`/`get` a local store, `serve` it, `serve-git` a repository, `fetch` over DNS)
cmd/git-remote-dns/ git remote helper for `git clone dns://<repo-or-sha>`
```

## Commit conventions

- Keep commits focused and atomic; one logical change per commit.
- Use a clear imperative subject line (e.g. `add DNS chunk resolver`).
- Reference an issue/PR number in the body when relevant.

## Before you push

- [ ] Branch created off `dev`, not `main`.
- [ ] Changes are focused and self-contained.
- [ ] Local `dev` is up to date.
- [ ] PR links any related issue.

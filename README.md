# cachemoney

**Content-addressed objects over DNS.** Objects (git commits/trees/blobs, packages,
arbitrary blobs) live at names derived from their own hash, resolvable with plain
DNS queries. Because the address *is* the content, caching is always correct, and
max TTLs turn every resolver on Earth into a free CDN.

## Why

- **Content-addressed data never changes → caching is always correct.** A resolver
  that fetched `<id>` once can serve it forever; the bytes can't drift.
- **Every resolver is a free CDN.** With long TTLs on immutable objects, a single
  origin is served by millions of cached copies.
- **Refs are the only mutable, short-TTL records.** `main.refs.<repo>` points at a
  commit; everything behind it is immutable.

## How addressing works

This uses the **variant** scheme (chunks named by their own hash, shared across
repos, with manifests):

```
<chunkid>.c.<zone>            # a chunk, addressed by the hash of its bytes
<id>.o.<zone>                 # a generic object's manifest
<gitsha>.g.<zone>             # a git object's manifest
main.refs.<repo>.<zone>       # mutable pointer → commit sha (short TTL)
```

A client walks the graph:

1. resolve `main.refs.<repo>` → commit sha
2. fetch the commit manifest `<gitsha>.g`
3. fetch the tree manifest, then each blob manifest + chunk
4. reassemble and verify every hash before trusting bytes

### Framing (current model)

- A SHA‑256 hash is 64 hex chars — too long for a 63‑char DNS label. We use
  **base32** (~51 chars) instead.
- Chunks fit a 1232‑byte UDP answer: **1024 B** raw TXT, **768 B** base64 TXT, or
  **15 B** per AAAA record (the 16th byte carries a sequence number so resolver
  reordering can't corrupt data).
- The manifest records each chunk's exact length, so decoders can trim padding
  before hashing.

### Cloning a repository over DNS (`git clone dns:<sha>`)

Git can clone a repository whose objects are served over DNS instead of HTTP,
SSH, or SFTP. On demand it spawns a `git-remote-dns` helper; you point the
helper at a DNS server and the zone to serve, and `git clone dns:<sha>`
resolves that commit and streams back the reachable objects.

```sh
# Client: clone by root commit SHA
GIT_REMOTE_DNS_ZONE=example.com \
GIT_REMOTE_DNS_SERVER=127.0.0.1:5300 \
git clone dns:0123456789abcdef0123456789abcdef01234567 https://example.com/repo.git

# Server: publish one repo's objects over DNS (see pkg/gitdns)
gitdns.Publish(server, "<root-sha>", func(sha string) ([]byte, error) {
	p := filepath.Join(repo, ".git", "objects", sha[:2], sha[2:])
	return os.ReadFile(p)
}, objectstore.TXT)
```

git launches the helper as `git-remote-dns <remote> dns://<sha>`. It answers:

- `list` — the commit SHA plus a HEAD symref to `refs/heads/main`.
- `fetch` — the reachable objects, materialized into git's object store via
  `git unpack-objects` (git's fetch path never consumes the pack the helper
  emits).

Configuration comes from the environment git passes to helpers:

| Env var | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GIT_REMOTE_DNS_ZONE` | yes | — | DNS zone to resolve against |
| `GIT_REMOTE_DNS_SERVER` | no | `127.0.0.1:5300` | Resolver host:port |
| `GIT_REMOTE_DNS_TRANSPORT` | no | `txt` | `txt` or `aaaa` |
| `GIT_REMOTE_DNS_TIMEOUT` | no | `5s` | Resolver timeout |

## Repository layout

```
pkg/objectstore/   content-addressed core: chunking, manifests, TXT/AAAA framing, verify
pkg/dnszone/       authoritative server (serve) + client resolver (fetch) over UDP/TCP
pkg/gitobj/        Git object model (commit/tree/blob hashing, graph walk)
pkg/gitdns/        publish/fetch Git object graphs over DNS
pkg/pkgindex/      package-file index model
pkg/mirror/        apt/Nix binary-cache mirror over DNS
cmd/cachemoney/    CLI (`put`/`get` a local store, `serve` an authoritative server, `fetch` over DNS)
.github/workflows/ CI (build, gofmt, unit + integration tests, vet, coverage)
```

## Development

Requires Go 1.27+.

```bash
go build ./...
go test -race -cover ./...
go vet ./...
```

CI runs on every PR and on push to `dev`/`main`: build, `gofmt`, unit +
integration tests (`-race`), vet, and a coverage gate.

## Branch model

Two-branch integration with a PR on every path:

```
feature ──► dev ──► main
(short)   (integration)  (stable)
```

- Feature branches fork off `dev`.
- PR #1: feature → `dev`. PR #2: `dev` → `main` (squash).
- Both `dev` and `main` are protected: PR required, CI must pass, admins cannot
  bypass.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full workflow.

## Status

All planned work is complete:

1. **Object store core** ✅ — chunking, manifests, TXT/AAAA framing, verification.
2. **Authoritative DNS layer** ✅ — in-memory nameserver (`serve`) and client resolver (`fetch`) over UDP/TCP.
3. **Client resolver** ✅ — walks the object graph over DNS with EDNS0 + TCP fallback for truncated answers.
4. **Git over DNS** ✅ — `gitobj` model and `gitdns` publish/fetch of Git object graphs.
5. **Package caches** ✅ — `pkgindex` model and `mirror` apt/Nix binary-cache mirror.

## Open questions

- Which TLD/zone hosts the records, and how contributors publish authoritatively.

## License

[MIT](./LICENSE)

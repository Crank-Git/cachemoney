# cachemoney

**Content-addressed objects over DNS.** Objects (git commits/trees/blobs, packages,
arbitrary blobs) live at names derived from their own hash, resolvable with plain
DNS queries. Because the address *is* the content, caching is always correct, and
long TTLs turn every resolver on Earth into a free CDN.

## Why

- **Content-addressed data never changes → caching is always correct.** A resolver
  that fetched `<id>` once can serve it forever; the bytes can't drift.
- **Every resolver is a free CDN.** With long TTLs on immutable objects, a single
  origin is served by millions of cached copies.
- **Refs are the only mutable, short-TTL records.** `<repo>.refs.<zone>` lists a
  repository's branches and tags; everything they point at is immutable.

## How addressing works

This uses the **variant** scheme (chunks named by their own hash, shared across
repos, with manifests):

```
<chunkid>.c.<zone>            # a chunk (≤ 512 B), addressed by the hash of its bytes
<id>.o.<zone>                 # a generic object's manifest, addressed by the manifest's hash
<gitsha>.g.<zone>             # a git object's manifest, addressed by its git SHA-1
<sha256>.f.<zone>             # a mirror file's (or index's) manifest, addressed by its sha256
<repo>.refs.<zone>            # a repository's ref list (mutable, 60 s TTL)
```

A client walks the graph:

1. resolve `<repo>.refs` → the branches, tags, and HEAD (or start from a commit
   SHA with `git clone dns://<sha>`)
2. fetch each commit's manifest at `<gitsha>.g`, then its chunks
3. fetch the tree, blobs, and parents the same way, many at once
4. verify every chunk hash, and every git object's SHA-1, before trusting bytes

### Framing

- A SHA‑256 hash is 64 hex chars — too long for a 63‑char DNS label. We use
  **base32** (52 chars) instead. Labels are matched case-insensitively.
- Every record holds at most **512 B** of payload, so every answer fits a
  1232‑byte EDNS buffer (DNS flag day 2020) for zones up to ~150 characters: a
  chunk is ~800 B as TXT (base64 in `<seq>:` strings) or ~1075 B as 35 AAAA
  records. Each AAAA record carries **15 B**; its first byte is a sequence
  number so resolver reordering can't corrupt data.
- AAAA payloads start with a 4‑byte length, so trailing padding is never
  mistaken for content.
- A manifest too large for one record is stored **indirectly**: the record holds
  a small manifest (`"indirect": true`) whose chunks reassemble to the real one,
  nested as needed (at most 16 levels). The object's manifest is still verified
  against its id.
- Records carry a one‑day TTL; negative answers are cached for 60 s.

The server answers as a standard authoritative server (SOA/NS at the apex,
NXDOMAIN, REFUSED outside the zone, EDNS0). The test suite runs it behind a real
Unbound resolver with 0x20 case randomization and QNAME minimization, including
serving objects from the resolver's cache with the origin shut down.

### Cloning a repository over DNS (`git clone dns://<repo>`)

Git can clone a repository whose objects are served over DNS instead of HTTP,
SSH, or SFTP. On demand it spawns a `git-remote-dns` helper; you point the
helper at a DNS server and the zone to serve, and `git clone dns://<repo>`
reads the repository's refs and streams back the reachable objects.

```sh
# Server: publish a repository's branches, tags, and history and serve them,
# re-reading the repository every 30 s (-refresh)
cachemoney serve-git -repo path/to/repo -name myrepo -zone example.com -addr 127.0.0.1:5300

# Client: clone by name (serve-git prints this command); later pulls fetch
# only new objects
export GIT_REMOTE_DNS_ZONE=example.com GIT_REMOTE_DNS_SERVER=127.0.0.1:5300
git clone dns://myrepo
git -C myrepo pull

# Or clone the history of one commit by SHA
git clone dns://0123456789abcdef0123456789abcdef01234567
```

`serve-git` publishes every branch and tag plus HEAD. Objects go out before
the ref list that points at them, so a client never sees a ref whose objects
are missing. A repository name is one lowercase DNS label.

**Trust.** Every object is verified by its SHA, but the ref list is not
content-addressed: which commit a branch names is only as trustworthy as the
DNS path that delivered it (see [Open questions](#open-questions)).

From Go, `gitdns.Publish(server, sha, fetch, transport)` publishes a graph given
a `fetch` that returns an object's raw, uncompressed bytes
(`"<type> <size>\x00<content>"`, as `git cat-file --batch` provides).

git launches the helper as `git-remote-dns <remote> dns://<repo-or-sha>`. It
answers:

- `list` — the repository's ref list as published (by SHA: that commit as
  `refs/heads/main` plus a HEAD symref to it).
- `fetch` — every object reachable from the requested refs that the local
  repository does not already have, materialized into git's object store via
  `git unpack-objects` (git's fetch path never consumes the pack the helper
  emits).

Configuration comes from the environment git passes to helpers:

| Env var | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GIT_REMOTE_DNS_ZONE` | yes | — | DNS zone to resolve against |
| `GIT_REMOTE_DNS_SERVER` | no | `127.0.0.1:5300` | Resolver host:port |
| `GIT_REMOTE_DNS_TRANSPORT` | no | `txt` | `txt` or `aaaa` |
| `GIT_REMOTE_DNS_TIMEOUT` | no | `5s` | Resolver timeout |
| `GIT_REMOTE_DNS_TRACE` | no | unset | Log the helper protocol to stderr |

## Repository layout

```
pkg/objectstore/   content-addressed core: chunking, manifests, TXT/AAAA framing, verify
pkg/dnszone/       authoritative server (serve) + client resolver (fetch) over UDP/TCP
pkg/gitobj/        Git object model (commit/tree/blob hashing, graph walk)
pkg/gitdns/        publish/fetch Git object graphs over DNS
pkg/pkgindex/      package-file index model
pkg/mirror/        package index + file transport over DNS (the model for an apt/Nix mirror)
cmd/cachemoney/    CLI (`put`/`get` a local store, `serve` it, `serve-git` a repository, `fetch` over DNS)
cmd/git-remote-dns/ git remote helper for `git clone dns://<sha>`
.github/workflows/ CI (build, gofmt, unit + integration tests incl. Unbound, vet, coverage)
```

## Development

Requires Go 1.27+.

```bash
go build ./...
go test -race -cover ./...
go vet ./...
```

CI runs on every PR and on push to `dev`/`main`: build, `gofmt`, unit +
integration tests (`-race`, including a recursive-resolver test against
Unbound), vet, and a coverage gate. Locally the Unbound test is skipped if
`unbound` is not installed.

## Branch model

Two-branch integration with a PR on every path:

```
feature ──► dev ──► main
(short)   (integration)  (stable)
```

- Feature branches fork off `dev`.
- PR #1: feature → `dev`. PR #2: `dev` → `main` (merge commit).
- Both `dev` and `main` are protected: PR required, CI must pass, admins cannot
  bypass.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full workflow.

## Status

All planned work is complete:

1. **Object store core** ✅ — chunking, manifests, TXT/AAAA framing, verification.
2. **Authoritative DNS layer** ✅ — in-memory nameserver (`serve`) and client resolver (`fetch`) over UDP/TCP.
3. **Client resolver** ✅ — walks the object graph over DNS with EDNS0 + TCP fallback for truncated answers.
4. **Git over DNS** ✅ — `gitobj` model, `gitdns` publish/fetch of Git object graphs, `serve-git`, and the `git-remote-dns` helper.
5. **Package caches** ✅ — `pkgindex` model and `mirror` index/file transport (no apt or Nix protocol front end yet).

## Open questions

- Which TLD/zone hosts the records, and how contributors publish authoritatively.
- Ref authenticity: refs are the one record not verified by hash. Signed ref
  lists or DNSSEC would let a client trust which commit a branch names.

## License

[MIT](./LICENSE)

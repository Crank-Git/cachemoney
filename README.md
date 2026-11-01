# cachemoney

**Content-addressed objects over DNS.** Objects (git commits/trees/blobs, packages,
arbitrary blobs) live at names derived from their own hash, resolvable with plain
DNS queries. Because the address *is* the content, caching is always correct, and
max TTLs turn every resolver on Earth into a free CDN.

> Research / prototype spike. The wire format and labels are a working model to
> iterate on — see [Open questions](#open-questions).

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

## Future work

- Parallel / concurrent fetch to keep latency down under many in-flight queries.
- DoH/DoT transports in addition to plain DNS.
- Resolver-side caching for hot objects.
- A `git-remote-dns` helper so `git clone` works over DNS.
- Which TLD/zone hosts the records, and how contributors publish authoritatively.

## Open questions

- Chunk size vs. UDP/EDNS limits; exact TXT vs. AAAA split.
- Which TLD/zone hosts the records, and how contributors publish authoritatively.
- Manifest serialization (JSON now; possibly CBOR later for size).

## License

[MIT](./LICENSE)

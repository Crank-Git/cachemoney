# Addressing and framing

cachemoney uses the **variant** scheme: chunks are named by their own hash and shared
across repositories, and every object has a manifest that lists its chunks.

## Names

```
<chunkid>.c.<zone>            # a chunk (≤ 512 B), addressed by the hash of its bytes
<id>.o.<zone>                 # a generic object's manifest, addressed by the manifest's hash
<gitsha>.g.<zone>             # a git object's manifest, addressed by its git SHA-1
<sha256>.f.<zone>             # a mirror file's (or index's) manifest, addressed by its sha256
<repo>.refs.<zone>            # a repository's ref list (mutable, 60 s TTL)
```

A client walks the graph:

1. Resolve `<repo>.refs` to get the branches, tags, and HEAD, or start from a commit
   SHA with `git clone dns://<sha>`.
2. Fetch each commit's manifest at `<gitsha>.g`, then its chunks.
3. Fetch the tree, blobs, and parents the same way, many at once.
4. Verify every chunk hash, and every git object's SHA-1, before trusting any bytes.

## Framing

- A SHA-256 hash is 64 hex characters, too long for a 63-character DNS label, so labels
  use **base32** (52 characters) instead. Labels match case-insensitively.
- Every record holds at most **512 B** of payload, so every answer fits a 1232-byte EDNS
  buffer for zones up to about 150 characters. A chunk is about 800 B as TXT (base64 in
  `<seq>:` strings) or about 1075 B as 35 AAAA records.
- Each AAAA record carries **15 B**. Its first byte is a sequence number, so resolver
  reordering can't corrupt data.
- AAAA payloads start with a 4-byte length, so trailing padding is never mistaken for
  content.
- A manifest too large for one record is stored **indirectly**: the record holds a small
  manifest (`"indirect": true`) whose chunks reassemble to the real one, nested as needed
  (at most 16 levels). The object's manifest is still verified against its id.
- Records carry a one-day TTL. Negative answers are cached for 60 s.

## The server

The server answers as a standard authoritative server: SOA and NS at the apex, NXDOMAIN,
REFUSED outside the zone, and EDNS0. The test suite runs it behind a real Unbound resolver
with 0x20 case randomization and QNAME minimization, including serving objects from the
resolver's cache with the origin shut down.

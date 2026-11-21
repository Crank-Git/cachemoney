# Git over DNS

`git clone dns://<repo>` works through the `git-remote-dns` remote helper. Git spawns it
on demand; you point it at a DNS server and zone with environment variables.

## Publishing

`cachemoney serve-git` publishes every branch and tag plus HEAD, and re-reads the
repository every 30 s (`-refresh`, 0 disables it). Objects go out before the ref list that
points at them, so a client never sees a ref whose objects are missing. A repository name
is one lowercase DNS label.

| Flag | Default | Purpose |
| --- | --- | --- |
| `-repo` | `.` | Path to the git repository to serve |
| `-name` | the repository directory name | Repository name clients clone by |
| `-zone` | `example.com` | Zone apex to serve |
| `-addr` | `127.0.0.1:5300` | Listen address |
| `-tr` | `txt` | Transport: `txt` or `aaaa` |
| `-ns` | `ns.<zone>` | Nameserver host for the zone's NS and SOA records |
| `-refresh` | `30s` | How often to re-read the repository and republish changed refs |

From Go, `gitdns.Publish(server, sha, fetch, transport)` publishes a graph given a `fetch`
that returns an object's raw, uncompressed bytes (`"<type> <size>\x00<content>"`, as
`git cat-file --batch` provides).

## The helper

Git launches the helper as `git-remote-dns <remote> dns://<repo-or-sha>`. It answers:

- `list`: the repository's ref list as published. For a SHA, that commit as
  `refs/heads/main` plus a HEAD symref to it.
- `fetch`: every object reachable from the requested refs that the local repository
  doesn't already have, written into git's object store with `git unpack-objects`. Git's
  fetch path never consumes the pack the helper emits.

Configuration comes from the environment git passes to helpers:

| Env var | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GIT_REMOTE_DNS_ZONE` | yes | none | DNS zone to resolve against |
| `GIT_REMOTE_DNS_SERVER` | no | `127.0.0.1:5300` | Resolver host:port |
| `GIT_REMOTE_DNS_TRANSPORT` | no | `txt` | `txt` or `aaaa` |
| `GIT_REMOTE_DNS_TIMEOUT` | no | `5s` | Resolver timeout |
| `GIT_REMOTE_DNS_TRACE` | no | unset | Log the helper protocol to stderr |

## Trust

Every object is verified by its SHA, but the ref list isn't content-addressed. Which
commit a branch names is only as trustworthy as the DNS path that delivered it. See
[open questions](open-questions.md).

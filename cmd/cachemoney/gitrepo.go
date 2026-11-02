package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/gitdns"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// serveGit publishes a local git repository's branches, tags, and HEAD, with
// every object they reach, and serves them over DNS until interrupted, so the
// repository can be cloned with `git clone dns://<name>` (or by commit SHA)
// through git-remote-dns. The repository is re-read every -refresh interval
// and changed refs are republished.
func serveGit(args []string) error {
	g, err := startGitServer(args)
	if err != nil {
		return err
	}
	defer g.srv.Shutdown()
	port := g.srv.Port()
	head, _ := g.refs.Lookup(g.refs.Head)
	if g.refs.Head == "" {
		head, _ = g.refs.Lookup("HEAD")
	}
	fmt.Printf("cachemoney: serving %s as %s (%d refs, HEAD %s) for %s on %s (port %d), transport=%s\n", g.cfg.repo, g.cfg.name, len(g.refs.Refs), head, g.cfg.zone, g.cfg.addr, port, g.cfg.tr)
	fmt.Printf("cachemoney: clone with\n  GIT_REMOTE_DNS_ZONE=%s GIT_REMOTE_DNS_SERVER=127.0.0.1:%d GIT_REMOTE_DNS_TRANSPORT=%s git clone dns://%s\n", g.cfg.zone, port, g.cfg.tr, g.cfg.name)
	fmt.Println("cachemoney: press Ctrl-C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	var tick <-chan time.Time
	if g.cfg.refresh > 0 {
		t := time.NewTicker(g.cfg.refresh)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-sig:
			return nil
		case <-tick:
			changed, err := g.refresh()
			if err != nil {
				fmt.Fprintln(os.Stderr, "cachemoney: refresh:", err)
			} else if changed {
				fmt.Printf("cachemoney: refs updated (%d refs)\n", len(g.refs.Refs))
			}
		}
	}
}

// gitServeConfig is the parsed serve-git command line.
type gitServeConfig struct {
	repo, name, zone, addr, tr, ns string
	refresh                        time.Duration
	transport                      objectstore.Transport
}

// gitServer is a running serve-git: the DNS server and the refs it last
// published.
type gitServer struct {
	cfg  gitServeConfig
	srv  *dnszone.Server
	refs *gitdns.RefList
}

// startGitServer parses the serve-git flags, publishes the repository's refs
// and objects into a new server, and starts it.
func startGitServer(args []string) (*gitServer, error) {
	var cfg gitServeConfig
	fs := flag.NewFlagSet("serve-git", flag.ContinueOnError)
	fs.StringVar(&cfg.repo, "repo", ".", "path to the git repository to serve")
	fs.StringVar(&cfg.name, "name", "", "repository name clients clone by (default: the repository directory name)")
	fs.StringVar(&cfg.zone, "zone", "example.com", "zone apex to serve")
	fs.StringVar(&cfg.addr, "addr", "127.0.0.1:5300", "listen address (host:port)")
	fs.StringVar(&cfg.tr, "tr", "txt", "transport: txt or aaaa")
	fs.StringVar(&cfg.ns, "ns", "", "nameserver host for the zone's NS and SOA records (default ns.<zone>)")
	fs.DurationVar(&cfg.refresh, "refresh", 30*time.Second, "how often to re-read the repository and republish changed refs (0 disables)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	var err error
	if cfg.transport, err = parseTransport(cfg.tr); err != nil {
		return nil, err
	}
	if cfg.name == "" {
		if cfg.name, err = defaultRepoName(cfg.repo); err != nil {
			return nil, err
		}
	}
	if !gitdns.ValidRepoName(cfg.name) {
		return nil, fmt.Errorf("serve-git: %q is not a valid repository name (one lowercase DNS label: a-z, 0-9, inner hyphens; not a 40-hex SHA)", cfg.name)
	}
	g := &gitServer{cfg: cfg, srv: dnszone.NewServer(dnszone.Zone(cfg.zone), 0)}
	if cfg.ns != "" {
		g.srv.SetNameserver(cfg.ns)
	}
	if _, err := g.refresh(); err != nil {
		return nil, err
	}
	if len(g.refs.Refs) == 0 {
		return nil, fmt.Errorf("serve-git: %s has no branches or tags to serve", cfg.repo)
	}
	if err := g.srv.Start(cfg.addr); err != nil {
		return nil, fmt.Errorf("serve-git: start: %w", err)
	}
	return g, nil
}

// refresh re-reads the repository's refs and, if they changed, publishes any
// new objects and then the new ref list. It reports whether the refs changed.
func (g *gitServer) refresh() (bool, error) {
	refs, err := readRefs(g.cfg.repo)
	if err != nil {
		return false, err
	}
	if g.refs != nil && bytes.Equal(refs.Marshal(), g.refs.Marshal()) {
		return false, nil
	}
	roots := make([]string, 0, len(refs.Refs))
	for _, r := range refs.Refs {
		roots = append(roots, r.SHA)
	}
	cf, err := openCatFile(g.cfg.repo)
	if err != nil {
		return false, err
	}
	pubErr := gitdns.PublishAll(g.srv, roots, cf.read, g.cfg.transport)
	if err := cf.Close(); pubErr == nil && err != nil {
		pubErr = fmt.Errorf("git cat-file: %w", err)
	}
	if pubErr != nil {
		return false, fmt.Errorf("serve-git: publish objects: %w", pubErr)
	}
	// Objects first, then the refs that point at them.
	if err := gitdns.PublishRefs(g.srv, g.cfg.name, refs, g.cfg.transport); err != nil {
		return false, fmt.Errorf("serve-git: publish refs: %w", err)
	}
	g.refs = refs
	return true, nil
}

// readRefs lists the repository's branches and tags and its HEAD: symbolic
// when it names a listed branch, otherwise (detached) the commit it is at.
func readRefs(repo string) (*gitdns.RefList, error) {
	out, err := gitOutput(repo, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags")
	if err != nil {
		return nil, err
	}
	refs := &gitdns.RefList{}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		sha, name, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("serve-git: unexpected for-each-ref line %q", line)
		}
		refs.Refs = append(refs.Refs, gitdns.Ref{Name: name, SHA: sha})
	}
	if target, err := gitOutput(repo, "symbolic-ref", "-q", "HEAD"); err == nil {
		if _, ok := refs.Lookup(target); ok {
			refs.Head = target
		}
	} else if sha, err := gitOutput(repo, "rev-parse", "--verify", "-q", "HEAD^{commit}"); err == nil {
		refs.Refs = append(refs.Refs, gitdns.Ref{Name: "HEAD", SHA: sha})
	}
	if err := refs.Validate(); err != nil {
		return nil, fmt.Errorf("serve-git: %w", err)
	}
	return refs, nil
}

// defaultRepoName derives a repository name from the repository's directory:
// lowercased, with runs of other characters turned into hyphens.
func defaultRepoName(repo string) (string, error) {
	top, err := gitOutput(repo, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range strings.ToLower(filepath.Base(top)) {
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
			b.WriteRune(c)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	name := strings.TrimRight(b.String(), "-")
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	return name, nil
}

// gitOutput runs git in repo and returns its trimmed stdout.
func gitOutput(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("serve-git: git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// catFile reads raw git objects, loose or packed, through one long-running
// `git cat-file --batch` process. It is not safe for concurrent use.
type catFile struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

// openCatFile starts `git cat-file --batch` in repo.
func openCatFile(repo string) (*catFile, error) {
	cmd := exec.Command("git", "-C", repo, "cat-file", "--batch")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("serve-git: start git cat-file: %w", err)
	}
	return &catFile{cmd: cmd, in: in, out: bufio.NewReader(out)}, nil
}

// read returns the canonical raw bytes of object sha: "<type> <size>\x00"
// followed by its content, the form gitobj.ReadObject hashes.
func (c *catFile) read(sha string) ([]byte, error) {
	if !isHexSHA1(sha) {
		return nil, fmt.Errorf("invalid object id %q", sha)
	}
	if _, err := fmt.Fprintf(c.in, "%s\n", sha); err != nil {
		return nil, err
	}
	header, err := c.out.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read cat-file header: %w", err)
	}
	fields := strings.Fields(header)
	if len(fields) == 2 && fields[1] == "missing" {
		return nil, fmt.Errorf("object %s missing from repository", sha)
	}
	if len(fields) != 3 || fields[0] != sha {
		return nil, fmt.Errorf("unexpected cat-file header %q", strings.TrimSpace(header))
	}
	size, err := strconv.Atoi(fields[2])
	if err != nil || size < 0 {
		return nil, fmt.Errorf("bad size in cat-file header %q", strings.TrimSpace(header))
	}
	prefix := fmt.Sprintf("%s %d\x00", fields[1], size)
	raw := make([]byte, len(prefix)+size+1)
	copy(raw, prefix)
	if _, err := io.ReadFull(c.out, raw[len(prefix):]); err != nil {
		return nil, fmt.Errorf("read object %s: %w", sha, err)
	}
	if raw[len(raw)-1] != '\n' {
		return nil, errors.New("cat-file output not newline-terminated")
	}
	return raw[:len(raw)-1], nil
}

// Close ends the cat-file process.
func (c *catFile) Close() error {
	_ = c.in.Close()
	return c.cmd.Wait()
}

// isHexSHA1 reports whether s is a 40-character lowercase hex SHA-1.
func isHexSHA1(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

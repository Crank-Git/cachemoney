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
	"strconv"
	"strings"
	"syscall"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/gitdns"
)

// serveGit publishes the object graph of a local git repository, rooted at a
// revision, and serves it over DNS until interrupted, so it can be cloned with
// `git clone dns://<sha>` through git-remote-dns.
func serveGit(args []string) error {
	srv, sha, cfg, err := startGitServer(args)
	if err != nil {
		return err
	}
	defer srv.Shutdown()
	port := srv.Port()
	fmt.Printf("cachemoney: serving %s at %s for %s on %s (port %d), transport=%s\n", cfg.repo, sha, cfg.zone, cfg.addr, port, cfg.tr)
	fmt.Printf("cachemoney: clone with\n  GIT_REMOTE_DNS_ZONE=%s GIT_REMOTE_DNS_SERVER=127.0.0.1:%d GIT_REMOTE_DNS_TRANSPORT=%s git clone dns://%s\n", cfg.zone, port, cfg.tr, sha)
	fmt.Println("cachemoney: press Ctrl-C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	return nil
}

// gitServeConfig is the parsed serve-git command line.
type gitServeConfig struct {
	repo, rev, zone, addr, tr, ns string
}

// startGitServer parses the serve-git flags, publishes the repository's graph
// into a new server, and starts it. It returns the running server and the
// commit SHA the revision resolved to.
func startGitServer(args []string) (*dnszone.Server, string, gitServeConfig, error) {
	var cfg gitServeConfig
	fs := flag.NewFlagSet("serve-git", flag.ContinueOnError)
	fs.StringVar(&cfg.repo, "repo", ".", "path to the git repository to serve")
	fs.StringVar(&cfg.rev, "rev", "HEAD", "revision whose history to serve")
	fs.StringVar(&cfg.zone, "zone", "example.com", "zone apex to serve")
	fs.StringVar(&cfg.addr, "addr", "127.0.0.1:5300", "listen address (host:port)")
	fs.StringVar(&cfg.tr, "tr", "txt", "transport: txt or aaaa")
	fs.StringVar(&cfg.ns, "ns", "", "nameserver host for the zone's NS and SOA records (default ns.<zone>)")
	if err := fs.Parse(args); err != nil {
		return nil, "", cfg, err
	}
	trv, err := parseTransport(cfg.tr)
	if err != nil {
		return nil, "", cfg, err
	}
	sha, err := resolveCommit(cfg.repo, cfg.rev)
	if err != nil {
		return nil, "", cfg, err
	}
	cf, err := openCatFile(cfg.repo)
	if err != nil {
		return nil, "", cfg, err
	}
	srv := dnszone.NewServer(dnszone.Zone(cfg.zone), 0)
	if cfg.ns != "" {
		srv.SetNameserver(cfg.ns)
	}
	pubErr := gitdns.Publish(srv, sha, cf.read, trv)
	if err := cf.Close(); pubErr == nil && err != nil {
		pubErr = fmt.Errorf("git cat-file: %w", err)
	}
	if pubErr != nil {
		return nil, "", cfg, fmt.Errorf("serve-git: publish %s: %w", sha, pubErr)
	}
	if err := srv.Start(cfg.addr); err != nil {
		return nil, "", cfg, fmt.Errorf("serve-git: start: %w", err)
	}
	return srv, sha, cfg, nil
}

// resolveCommit resolves rev in repo to the hex SHA-1 of a commit.
func resolveCommit(repo, rev string) (string, error) {
	cmd := exec.Command("git", "-C", repo, "rev-parse", "--verify", "--end-of-options", rev+"^{commit}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("serve-git: resolve %q in %s: %v: %s", rev, repo, err, strings.TrimSpace(stderr.String()))
	}
	sha := strings.TrimSpace(string(out))
	if !isHexSHA1(sha) {
		return "", fmt.Errorf("serve-git: %s is not a SHA-1 commit id (only SHA-1 repositories are supported)", sha)
	}
	return sha, nil
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

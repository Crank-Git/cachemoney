// Command git-remote-dns is a git-remote-helpers implementation that fetches
// Git object graphs from a cachemoney authoritative server over DNS. It lets a
// client run `git clone dns://<repo>` against a repository published with its
// refs (see `cachemoney serve-git`), or `git clone dns://<sha>` to clone the
// history of a single commit.
//
// The helper speaks the git remote-helpers protocol (see git-remote-helpers(7)):
// git drives it with a small line command language on stdin and reads the
// response on stdout. For fetching, the helper builds a packfile of the
// reachable objects and writes them into git's object store via `git
// unpack-objects` (the remote-helper "fetch" path never consumes the packfile
// the helper emits on stdout, so the objects must be installed directly).
//
// Configuration is read from GIT_REMOTE_DNS_* environment variables, which git
// passes through to the helper:
//
//	GIT_REMOTE_DNS_SERVER   server address (host:port), default 127.0.0.1:5300
//	GIT_REMOTE_DNS_ZONE     zone apex to query (required)
//	GIT_REMOTE_DNS_TRANSPORT transport: "txt" (default) or "aaaa"
//	GIT_REMOTE_DNS_TIMEOUT  per-query timeout, default 5s
//	GIT_REMOTE_DNS_TRACE    when set, log the protocol stream to stderr
package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/gitdns"
	"github.com/Crank-Git/cachemoney/pkg/gitobj"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// helper is a single git-remote-dns invocation: it knows what to serve (a
// repository by name, or one commit by SHA), the resolver used to fetch it
// over DNS, and the transport.
type helper struct {
	id        string // hex SHA-1 of the commit to serve, when cloning by SHA
	repo      string // repository name whose refs to serve, when cloning by name
	r         *dnszone.Resolver
	transport objectstore.Transport
	out       *bufio.Writer
}

// config holds the helper's environment-driven settings.
type config struct {
	server    string
	zone      string
	transport string
	timeout   string
}

func main() {
	os.Exit(runMain(os.Args))
}

// runMain drives the helper and returns the process exit code: 0 on success,
// 1 on error. Extracted from main so the error path is testable without calling
// os.Exit, which would terminate the test process.
func runMain(args []string) int {
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, "git-remote-dns:", err)
		return 1
	}
	return 0
}

// run parses the URL from git's arguments, applies the environment config, and
// drives the remote-helpers protocol loop. Git invokes the helper once with
// "git-remote-dns <repository> <url>" (args[1] is the repository name, e.g.
// "origin"; args[2] is the URL) and then drives it with a command stream on
// stdin; args[1] and args[2] are identical for a direct command-line URL.
func run(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: git-remote-dns <repository> <url> <command>")
	}
	rawURL := args[1]
	if len(args) >= 3 {
		rawURL = args[2]
	}
	h, err := newHelper(rawURL)
	if err != nil {
		return err
	}
	return h.run()
}

// trace writes a line to stderr for debugging the protocol stream. It is
// silent unless GIT_REMOTE_DNS_TRACE is set, so a normal clone prints nothing
// from the helper.
func trace(args ...any) {
	if os.Getenv("GIT_REMOTE_DNS_TRACE") == "" {
		return
	}
	fmt.Fprintln(os.Stderr, args...)
}

// newHelper parses the dns:<sha> URL and builds a configured helper.
func newHelper(rawURL string) (*helper, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	transport := objectstore.TXT
	switch strings.ToLower(cfg.transport) {
	case "", "txt":
		transport = objectstore.TXT
	case "aaaa", "aa":
		transport = objectstore.AAAA
	default:
		return nil, fmt.Errorf("invalid transport %q (want txt or aaaa)", cfg.transport)
	}

	target, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	var id, repo string
	if isSHA1(target) {
		id = target
	} else {
		repo = target
	}

	r := dnszone.NewResolver(cfg.server, dnszone.Zone(cfg.zone), mustDuration(cfg.timeout))
	r = r.WithObjectSuffix("g").WithConcurrency(0)

	return &helper{
		id:        id,
		repo:      repo,
		r:         r,
		transport: transport,
		out:       bufio.NewWriter(os.Stdout),
	}, nil
}

// parseURL extracts the clone target from a dns URL. Git invokes the helper
// with either "dns://<target>" (the :// form, which git routes to the helper
// when it cannot handle the transport natively) or "dns::<target>" (an
// explicit helper hint); a bare <target> is accepted too. The target is a
// 40-char hex commit SHA-1, or otherwise a repository name (one DNS label),
// returned lowercased since DNS names are case-insensitive.
func parseURL(rawURL string) (string, error) {
	url := strings.TrimSpace(rawURL)
	if i := strings.IndexByte(url, ':'); i >= 0 {
		url = url[i+1:]
	}
	// Drop the leading slashes of the :// form and the leading colon of the ::
	// form, leaving just the target.
	url = strings.ToLower(strings.TrimRight(strings.TrimLeft(url, "/:"), "/"))
	if isSHA1(url) || gitdns.ValidRepoName(url) {
		return url, nil
	}
	return "", fmt.Errorf("expected a 40-char hex commit SHA-1 or a repository name (one DNS label), got %q", url)
}

// isSHA1 reports whether s is 40 lowercase hex digits.
func isSHA1(s string) bool {
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

// loadConfig reads the helper's configuration from the environment, applying
// defaults for anything unset.
func loadConfig() (config, error) {
	cfg := config{
		server:    os.Getenv("GIT_REMOTE_DNS_SERVER"),
		zone:      os.Getenv("GIT_REMOTE_DNS_ZONE"),
		transport: os.Getenv("GIT_REMOTE_DNS_TRANSPORT"),
		timeout:   os.Getenv("GIT_REMOTE_DNS_TIMEOUT"),
	}
	if cfg.server == "" {
		cfg.server = "127.0.0.1:5300"
	}
	if cfg.zone == "" {
		return config{}, errors.New("GIT_REMOTE_DNS_ZONE is not set")
	}
	return cfg, nil
}

// environWithoutGitDir returns a copy of the current environment with all GIT_*
// variables removed. git spawns helpers with GIT_DIR (and sometimes GIT_OBJECT_*
// etc.) set; those would corrupt a fresh `git init`/`git pack-objects`, so we
// start from a clean slate when building our own throwaway repo.
func environWithoutGitDir() []string {
	out := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// mustDuration parses a Go duration string, returning 5s on empty or invalid
// input so a malformed timeout never breaks a clone.
func mustDuration(s string) time.Duration {
	if s == "" {
		return 5 * time.Second
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

// run reads commands from stdin and dispatches them, writing responses to out.
// The loop ends when stdin is closed by git.
func (h *helper) run() error {
	sc := bufio.NewReader(os.Stdin)
	for {
		line, err := sc.ReadString('\n')
		if len(line) > 0 {
			trace("<<", strings.TrimRight(line, "\r\n"))
			if err := h.dispatch(strings.TrimRight(line, "\r\n"), sc); err != nil {
				return err
			}
		}
		if err != nil {
			if err == io.EOF {
				trace(">> EOF")
				return nil
			}
			return err
		}
	}
}

// dispatch handles one command line and returns an error so the helper can
// exit non-zero (git treats a failed helper as a fatal clone error rather than
// waiting forever for a response). The fetch command's batch is terminated by
// a blank line, which the scanner reads here; the triggering line itself is a
// "fetch <sha> <ref>" line and must be included in the batch.
func (h *helper) dispatch(line string, sc *bufio.Reader) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	switch fields[0] {
	case "capabilities":
		fmt.Fprintln(h.out, "fetch")
		fmt.Fprintln(h.out) // capabilities end with a blank line
	case "list":
		if err := h.cmdList(h.out); err != nil {
			return err
		}
	case "fetch":
		shas := []string{}
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "fetch" {
			shas = append(shas, f[1])
		}
		shas = append(shas, h.readFetchBatch(sc)...)
		trace(">> fetch shas:", shas)
		if err := h.cmdFetch(shas, h.out); err != nil {
			trace(">> fetch error:", err)
			return err
		}
	}
	h.out.Flush()
	return nil
}

// readFetchBatch reads the fetch command's batch: a series of "fetch <sha>
// <ref>" lines terminated by a blank line. It returns the requested commit SHAs.
func (h *helper) readFetchBatch(sc *bufio.Reader) []string {
	var shas []string
	for {
		line, err := sc.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" || err != nil {
			break
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "fetch" {
			shas = append(shas, fields[1])
		}
		if err == io.EOF {
			break
		}
	}
	return shas
}

// cmdList advertises refs. Cloning by name, it fetches the repository's ref
// list from <repo>.refs.<zone>, which is already in the remote-helper list
// format, and emits it as is: every branch and tag plus HEAD. Cloning by SHA,
// it reports the commit as a single refs/heads/main branch and advertises HEAD
// as a symref to it ("@refs/heads/main HEAD"), so the clone's HEAD points at
// refs/heads/main rather than git's own default branch name.
func (h *helper) cmdList(w io.Writer) error {
	if h.repo != "" {
		refs, err := gitdns.FetchRefs(h.r, h.repo, h.transport)
		if err != nil {
			return err
		}
		if _, err := w.Write(refs.Marshal()); err != nil {
			return err
		}
		_, err = fmt.Fprintln(w)
		return err
	}
	fmt.Fprintf(w, "%s refs/heads/main\n", h.id)
	fmt.Fprintf(w, "@refs/heads/main HEAD\n")
	fmt.Fprintln(w)
	return nil
}

// cmdFetch walks the graph(s) reachable from the requested commits, unions them,
// and installs the resulting objects into git's object store. Per the git
// remote-helpers protocol, git drives the helper with a batch of "fetch <sha>\n"
// lines terminated by a blank line, and a single blank line signals that the
// batch is complete -- which is why the pack is installed before that final
// newline is emitted.
//
// All requested tips are walked in one pass, and objects already in the local
// repository are skipped with everything below them, so a fetch after new
// commits only downloads the new objects.
func (h *helper) cmdFetch(shas []string, w io.Writer) error {
	if len(shas) == 0 {
		return fmt.Errorf("fetch batch names no objects")
	}
	local, err := openLocalObjects()
	if err != nil {
		return err
	}
	merged, err := gitdns.FetchAll(h.r, shas, h.transport, local.has)
	if cerr := local.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	trace(">> fetched", len(merged), "objects")
	if len(merged) > 0 {
		if err := h.fetchInstall(merged); err != nil {
			return err
		}
	}
	// Tell git the fetch batch is complete.
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}
	return nil
}

// fetchInstall packs the fetched objects and installs them into git's object
// store.
func (h *helper) fetchInstall(merged map[string]*gitobj.Object) error {
	pack, err := h.buildPack(merged)
	if err != nil {
		return err
	}
	// The remote-helper "fetch" path (fetch_with_fetch in transport-helper.c)
	// reads only the protocol stream and never consumes the packfile the helper
	// emits on stdout, so a pack written there is orphaned and its objects never
	// reach the object store. Materialize the pack's objects directly into git's
	// object store instead: GIT_DIR is inherited from git and points at the
	// clone's .git, so `git unpack-objects` installs the loose objects there.
	return h.installObjects(pack)
}

// localObjects answers whether the repository git is fetching into (the
// inherited GIT_DIR) already holds an object, through one long-running
// `git cat-file --batch-check` process. It is not safe for concurrent use;
// gitobj.WalkAll calls it from one goroutine.
type localObjects struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
	err error
}

// openLocalObjects starts the batch-check process.
func openLocalObjects() (*localObjects, error) {
	cmd := exec.Command("git", "cat-file", "--batch-check=%(objectname)")
	cmd.Env = os.Environ() // keep the GIT_DIR git set for the fetch
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git cat-file --batch-check: %w", err)
	}
	return &localObjects{cmd: cmd, in: in, out: bufio.NewReader(out)}, nil
}

// has reports whether sha is present locally. On a read error it reports
// false (the object is fetched) and Close returns the error.
func (l *localObjects) has(sha string) bool {
	if l.err != nil {
		return false
	}
	if _, err := fmt.Fprintf(l.in, "%s\n", sha); err != nil {
		l.err = err
		return false
	}
	line, err := l.out.ReadString('\n')
	if err != nil {
		l.err = err
		return false
	}
	return strings.TrimSpace(line) == sha
}

// Close ends the batch-check process and reports any read error.
func (l *localObjects) Close() error {
	_ = l.in.Close()
	if err := l.cmd.Wait(); err != nil && l.err == nil {
		l.err = fmt.Errorf("git cat-file --batch-check: %w", err)
	}
	return l.err
}

// installObjects runs `git unpack-objects` to materialize the pack's objects
// into the object store selected by the GIT_DIR inherited from git.
func (h *helper) installObjects(pack []byte) error {
	var stdin bytes.Buffer
	stdin.Write(pack)
	var errb bytes.Buffer
	cmd := exec.Command("git", "unpack-objects", "-r")
	cmd.Env = os.Environ() // keep the GIT_DIR git set for the clone
	cmd.Stdin = &stdin
	cmd.Stdout = os.Stderr
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git unpack-objects: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// buildPack writes the objects as loose objects in a temporary object store and
// runs `git pack-objects` to produce a packfile containing them. Writing loose
// objects and delegating to git keeps the packfile format exact without
// reimplementing pack encoding.
func (h *helper) buildPack(objects map[string]*gitobj.Object) ([]byte, error) {
	tmp, err := os.MkdirTemp("", "git-remote-dns-")
	if err != nil {
		return nil, err
	}
	// The temporary repository only exists to run pack-objects; the pack is
	// returned in memory, so remove it on every path.
	defer os.RemoveAll(tmp)

	// git pack-objects requires a real git repository (a .git dir with a HEAD
	// file), not just an objects/ directory. Initialize one here.
	// git spawns helpers with GIT_DIR set in the environment; clearing it here
	// forces `git init` to create a fresh repo at tmp instead of reusing the
	// inherited GIT_DIR (which would leave us with only an objects/ dir).
	initCmd := exec.Command("git", "init", "-q", tmp)
	initCmd.Env = environWithoutGitDir()
	if err := initCmd.Run(); err != nil {
		return nil, fmt.Errorf("git init: %w", err)
	}
	storeDir := filepath.Join(tmp, ".git", "objects")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		return nil, err
	}
	_ = os.MkdirAll(filepath.Join(tmp, ".git", "objects", "pack"), 0o755)
	for sha, o := range objects {
		dir := filepath.Join(storeDir, sha[:2])
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(o.Raw); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, sha[2:]), buf.Bytes(), 0o644); err != nil {
			return nil, err
		}
	}

	var stdin bytes.Buffer
	for sha := range objects {
		stdin.WriteString(sha)
		stdin.WriteByte('\n')
	}
	var pack, errb bytes.Buffer
	cmd := exec.Command("git", "pack-objects", "--stdout")
	// git pack-objects needs both GIT_DIR (the .git repo) and GIT_OBJECT_DIRECTORY
	// (where the loose objects live) to avoid "not a git repository". Start from a
	// clean env so no inherited GIT_DIR leaks in, then set both explicitly.
	cmd.Env = append(environWithoutGitDir(), "GIT_DIR="+filepath.Join(tmp, ".git"), "GIT_OBJECT_DIRECTORY="+storeDir)
	cmd.Stdin = &stdin
	cmd.Stdout = &pack
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git pack-objects: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return pack.Bytes(), nil
}

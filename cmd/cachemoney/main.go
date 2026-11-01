// Command cachemoney is a local content-addressed store built on the objectstore
// package. It demonstrates the full put/resolve round-trip without a DNS layer:
// objects are addressed by their manifest hash and every chunk is verified on
// the way out.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "cachemoney:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: cachemoney <put|get> [flags]")
	}
	cmd, rest := args[0], args[1:]

	switch cmd {
	case "put":
		return put(rest)
	case "get":
		return get(rest)
	default:
		return fmt.Errorf("unknown command %q (want put or get)", cmd)
	}
}

func storePaths(store string) (manifests, chunks string) {
	return filepath.Join(store, "manifests"), filepath.Join(store, "chunks")
}

func put(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	store := fs.String("store", ".cachemoney", "store directory")
	out := fs.String("out", "", "write the object id here instead of stdout")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return errors.New("put: requires a file to store")
	}
	path := fs.Arg(0)

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	m, chunks := objectstore.Build(data)

	mDir, cDir := storePaths(*store)
	if err := os.MkdirAll(mDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(cDir, 0o755); err != nil {
		return err
	}
	mj, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(mDir, string(m.ID())+".json"), mj, 0o644); err != nil {
		return err
	}
	for i, id := range m.ChunkIDs {
		if err := os.WriteFile(filepath.Join(cDir, string(id)), chunks[i], 0o644); err != nil {
			return err
		}
	}

	fmt.Printf("object  %s\n", m.ID())
	fmt.Printf("chunks  %d\n", m.ChunkCount)
	fmt.Printf("bytes   %d\n", m.TotalSize)
	fmt.Printf("store   %s\n", *store)
	if *out != "" {
		return os.WriteFile(*out, []byte(m.ID()), 0o644)
	}
	return nil
}

func get(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	store := fs.String("store", ".cachemoney", "store directory")
	out := fs.String("out", "", "write reassembled bytes here (default stdout)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return errors.New("get: requires an object id")
	}
	id := objectstore.ObjectID(fs.Arg(0))

	mDir, cDir := storePaths(*store)
	raw, err := os.ReadFile(filepath.Join(mDir, string(id)+".json"))
	if err != nil {
		return fmt.Errorf("manifest %s: %w", id, err)
	}
	m, err := objectstore.UnmarshalManifest(raw)
	if err != nil {
		return err
	}

	chunks := make(map[objectstore.ObjectID][]byte, len(m.ChunkIDs))
	for _, cid := range m.ChunkIDs {
		b, err := os.ReadFile(filepath.Join(cDir, string(cid)))
		if err != nil {
			return fmt.Errorf("chunk %s: %w", cid, err)
		}
		chunks[cid] = b
	}
	got, err := objectstore.Reassemble(m, chunks)
	if err != nil {
		return err
	}

	if *out == "" {
		_, err = os.Stdout.Write(got)
		return err
	}
	return os.WriteFile(*out, got, 0o644)
}

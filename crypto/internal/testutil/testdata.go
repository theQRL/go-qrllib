package testutil

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ReadJSON reads a JSON test fixture from rootDir/name, falling back to name+".gz".
func ReadJSON[T any](t testing.TB, rootDir, name string) T {
	t.Helper()

	b, path := readFile(t, rootDir, name)
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("parse JSON %q: %v", path, err)
	}
	return out
}

func readFile(t testing.TB, rootDir, name string) ([]byte, string) {
	t.Helper()

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		t.Fatalf("open test fixture root %q: %v", rootDir, err)
	}
	defer func() { _ = root.Close() }()

	gzName := name
	if !strings.HasSuffix(gzName, ".gz") {
		var b []byte
		b, err = root.ReadFile(name)
		if err == nil {
			return b, filepath.Join(rootDir, name)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("read test fixture %q: %v", filepath.Join(rootDir, name), err)
		}
		gzName += ".gz"
	}

	f, err := root.Open(gzName)
	if err != nil {
		t.Fatalf("read test fixture %q: %v", filepath.Join(rootDir, name), err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("open compressed test fixture %q: %v", filepath.Join(rootDir, gzName), err)
	}
	defer func() { _ = gz.Close() }()

	b, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read compressed test fixture %q: %v", filepath.Join(rootDir, gzName), err)
	}
	return b, filepath.Join(rootDir, gzName)
}

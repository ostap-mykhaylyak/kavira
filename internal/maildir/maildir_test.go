package maildir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeliverCreatesLayoutAndMessage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mail")
	msg := []byte("Subject: hi\r\n\r\nbody\r\n")

	path, err := Deliver(dir, msg, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != filepath.Join(dir, "new") {
		t.Errorf("message not in new/: %s", path)
	}
	for _, sub := range []string{"cur", "new", "tmp"} {
		if st, err := os.Stat(filepath.Join(dir, sub)); err != nil || !st.IsDir() {
			t.Errorf("missing subdir %s", sub)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Errorf("content mismatch: %q", got)
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "tmp")); len(ents) != 0 {
		t.Error("tmp/ not empty after delivery")
	}
}

func TestDeliverUniqueNames(t *testing.T) {
	dir := t.TempDir()
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := Deliver(dir, []byte("x"), -1, -1)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(p)
		if seen[name] {
			t.Fatalf("duplicate name %s", name)
		}
		seen[name] = true
		if !strings.Contains(name, ".") {
			t.Errorf("unexpected name format %s", name)
		}
	}
}

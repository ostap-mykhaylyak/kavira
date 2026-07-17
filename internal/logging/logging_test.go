package logging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenWritesJSON(t *testing.T) {
	dir := t.TempDir()
	logs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	logs.Service.Info("starting", "version", "test", "pid", 42)
	if err := logs.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "kavira.log"))
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, b)
	}
	if rec["msg"] != "starting" || rec["version"] != "test" {
		t.Errorf("unexpected record: %v", rec)
	}
	if _, ok := rec["time"]; !ok {
		t.Error("record has no timestamp")
	}
}

func TestReopenAfterRotation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("logrotate-style rename of an open file is not possible on windows")
	}
	dir := t.TempDir()
	logs, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()

	path := filepath.Join(dir, "kavira.log")
	logs.Service.Info("before rotation")

	// Simulate logrotate: move the file away, then SIGHUP -> Reopen.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := logs.Reopen(); err != nil {
		t.Fatal(err)
	}
	logs.Service.Info("after rotation")

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "after rotation") {
		t.Errorf("new file missing post-rotation line: %s", b)
	}
	old, _ := os.ReadFile(path + ".1")
	if !strings.Contains(string(old), "before rotation") {
		t.Errorf("rotated file missing pre-rotation line: %s", old)
	}
}

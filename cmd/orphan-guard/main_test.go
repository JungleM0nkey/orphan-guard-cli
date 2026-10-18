package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIRejectsInvalidAndUnselectedCleanup(t *testing.T) {
	tests := [][]string{
		{"unknown"},
		{"scan", "--apply"},
		{"scan", "--profile", "App"},
		{"scan", "--min-age", "-1s"},
		{"scan", "extra"},
		{"clean", "--apply"},
		{"clean", "--pid", "not-a-pid"},
		{"clean", "--pid", "0"},
		{"clean", "--pid", "4294967296"},
		{"clean", "--pid", "123", "--apply"},
		{"clean", "--pid", "123", "--started-at", "yesterday", "--apply"},
		{"clean", "--started-at", "2026-10-18T12:00:00Z"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(args, &out, &errOut); code != 2 || errOut.Len() == 0 {
				t.Fatalf("exit=%d, stderr=%q; expected usage error", code, errOut.String())
			}
		})
	}
}

func TestCLIErrorIsMachineReadable(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"scan", "--unknown", "--json"}, &out, &errOut)
	var result struct {
		Error    string `json:"error"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal(errOut.Bytes(), &result); err != nil || code != 2 || result.ExitCode != 2 || result.Error == "" || out.Len() != 0 {
		t.Fatalf("exit=%d, stdout=%q, stderr=%q, parse error=%v", code, out.String(), errOut.String(), err)
	}
}

func TestCLIReportsMalformedConfigWithoutOverwriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"scan", "--config", path}, &out, &errOut); code != 1 {
		t.Fatalf("exit=%d, expected config error; stderr=%q", code, errOut.String())
	}
	data, _ := os.ReadFile(path)
	if string(data) != "{broken" {
		t.Fatalf("malformed config was overwritten: %q", data)
	}
}

func TestCLIInitializesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	var out, errOut bytes.Buffer
	if code := run([]string{"init", "--config", path, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("exit=%d, stderr=%q", code, errOut.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(out.Bytes()) {
		t.Fatalf("invalid JSON output: %q", out.String())
	}
}

func TestCLIHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"scan", "--help"}, {"version"}} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 0 || out.Len() == 0 || errOut.Len() != 0 {
			t.Fatalf("args=%v, exit=%d, stdout=%q, stderr=%q", args, code, out.String(), errOut.String())
		}
	}
}

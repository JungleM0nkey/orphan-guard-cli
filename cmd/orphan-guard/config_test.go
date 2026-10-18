package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRejectsUnsafeOrMalformedProfiles(t *testing.T) {
	tests := []string{
		`{`,
		`{}`,
		`{"profiles":null}`,
		`{"profiles":[]} {"profiles":[]}`,
		`{"profiles":[],"profilez":[]}`,
		`{"profiles":[{"name":"","indicator":{"mode":"blocklist"},"targets":["worker.exe"]}]}`,
		`{"profiles":[{"name":"A","enabled":"yes","indicator":{"mode":"blocklist"},"targets":["worker.exe"]}]}`,
		`{"profiles":[{"name":"A","indicator":{"mode":"unknown"},"targets":["worker.exe"]}]}`,
		`{"profiles":[{"name":"A","indicator":{"mode":"process","process":""},"targets":["worker.exe"]}]}`,
		`{"profiles":[{"name":"A","indicator":{"mode":"blocklist"},"targets":[]}]}`,
		`{"profiles":[{"name":"A","indicator":{"mode":"blocklist"},"targets":["C:\\worker.exe"]}]}`,
		`{"profiles":[{"name":"A","indicator":{"mode":"blocklist"},"targets":["*.exe"]}]}`,
		`{"profiles":[{"name":"A","indicator":{"mode":"blocklist"},"targets":["LSASS.exe"]}]}`,
		`{"profiles":[{"name":"A","indicator":{"mode":"blocklist"},"targets":["worker.exe"]},{"name":"a","indicator":{"mode":"blocklist"},"targets":["other.exe"]}]}`,
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := parseConfig([]byte(input)); err == nil {
				t.Fatal("unsafe or malformed config was accepted")
			}
		})
	}
}

func TestConfigPreservesTraySchema(t *testing.T) {
	c, err := parseConfig([]byte(`{"scan_interval_seconds":15,"profiles":[{"name":" App ","indicator":{"process":"app.exe"},"targets":["worker.exe"],"auto_kill":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Profiles) != 1 || c.Profiles[0].Name != "App" || c.Profiles[0].Indicator.Mode != "process" || !c.Profiles[0].AutoKill {
		t.Fatalf("profile was not read correctly: %+v", c)
	}
}

func TestInitNeverOverwritesExistingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initConfig(path); err == nil {
		t.Fatal("expected an error rather than overwriting existing config")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "keep me" {
		t.Fatalf("existing config was modified: %q, %v", got, err)
	}
}

func TestInitCreatesDisabledTrayProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := initConfig(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseConfig(data)
	if err != nil || len(c.Profiles) != 9 {
		t.Fatalf("invalid default profiles: %+v, %v", c, err)
	}
	for _, pr := range c.Profiles {
		if pr.Enabled == nil || *pr.Enabled || pr.AutoKill {
			t.Errorf("default profile is active: %+v", pr)
		}
	}
}

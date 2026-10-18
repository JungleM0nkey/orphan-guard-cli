package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProcessHelper(t *testing.T) {
	switch os.Getenv("ORPHAN_GUARD_TEST_HELPER") {
	case "sleep":
		for {
			time.Sleep(time.Hour)
		}
	case "orphan":
		child := helperCommand("sleep")
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println(child.Process.Pid)
		child.Process.Release()
		os.Exit(0)
	}
}

func helperCommand(mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	cmd.Env = append(os.Environ(), "ORPHAN_GUARD_TEST_HELPER="+mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func startFixture(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := helperCommand("sleep")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	return cmd
}

func snapshotProcess(t *testing.T, pid uint32) process {
	t.Helper()
	s, err := takeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range s.Processes {
		if p.PID == pid {
			return p
		}
	}
	t.Fatalf("process %d missing from snapshot", pid)
	return process{}
}

func TestWindowsSnapshotIdentifiesCurrentProcess(t *testing.T) {
	p := snapshotProcess(t, uint32(os.Getpid()))
	if p.StartedAt.IsZero() || p.Name == "" || p.MemoryBytes == 0 || p.ParentPID == 0 {
		t.Fatalf("incomplete process metadata: %+v", p)
	}
}

func TestWindowsRejectsChangedProcessIdentity(t *testing.T) {
	cmd := startFixture(t)
	p := snapshotProcess(t, uint32(cmd.Process.Pid))
	p.StartedAt = p.StartedAt.Add(100 * time.Nanosecond)
	if err := terminate(p); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("changed identity must be rejected, got %v", err)
	}
	snapshotProcess(t, uint32(cmd.Process.Pid))
}

func TestWindowsProfileCleanupDryRunAndApply(t *testing.T) {
	cmd := startFixture(t)
	p := snapshotProcess(t, uint32(cmd.Process.Pid))
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(config{Profiles: []profile{{Name: "Fixture", Indicator: indicator{Mode: "blocklist"}, Targets: []string{p.Name}, AutoKill: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"clean", "--config", path, "--profile", "Fixture", "--pid", strconv.Itoa(cmd.Process.Pid), "--min-age", "0", "--json"}
	var out, errOut bytes.Buffer
	if code := run(args, &out, &errOut); code != 0 {
		t.Fatalf("dry run exit=%d, stderr=%q", code, errOut.String())
	}
	var preview struct {
		Applied    bool        `json:"applied"`
		Candidates []candidate `json:"candidates"`
	}
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil || preview.Applied || len(preview.Candidates) != 1 || preview.Candidates[0].PID != p.PID {
		t.Fatalf("invalid preview: %q, %v", out.String(), err)
	}
	snapshotProcess(t, p.PID)
	out.Reset()
	errOut.Reset()
	staleArgs := append(append([]string{}, args...), "--started-at", p.StartedAt.Add(-time.Second).Format(time.RFC3339Nano), "--apply")
	if code := run(staleArgs, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "identity") {
		t.Fatalf("stale scan exit=%d, stderr=%q; expected identity rejection", code, errOut.String())
	}
	snapshotProcess(t, p.PID)
	out.Reset()
	errOut.Reset()
	args = append(args, "--started-at", p.StartedAt.Format(time.RFC3339Nano), "--apply")
	if code := run(args, &out, &errOut); code != 0 {
		t.Fatalf("apply exit=%d, stdout=%q, stderr=%q", code, out.String(), errOut.String())
	}
	var result struct {
		Applied bool `json:"applied"`
		Results []struct {
			PID    uint32 `json:"pid"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.Applied || len(result.Results) != 1 || result.Results[0].PID != p.PID || result.Results[0].Status != "terminated" {
		t.Fatalf("invalid cleanup result: %q, %v", out.String(), err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("terminated helper unexpectedly exited successfully")
	}
}

func TestWindowsRefusesPIDWithLiveParent(t *testing.T) {
	cmd := startFixture(t)
	p := snapshotProcess(t, uint32(cmd.Process.Pid))
	var out, errOut bytes.Buffer
	args := []string{"clean", "--pid", strconv.Itoa(cmd.Process.Pid), "--started-at", p.StartedAt.Format(time.RFC3339Nano), "--min-age", "0", "--apply"}
	if code := run(args, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "not an eligible candidate") {
		t.Fatalf("live-parent cleanup exit=%d, stderr=%q", code, errOut.String())
	}
	snapshotProcess(t, p.PID)
}

func TestWindowsDetectsAndCleansOwnedOrphan(t *testing.T) {
	output, err := helperCommand("orphan").Output()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	child, err := os.FindProcess(int(pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Kill(); child.Release() })
	p := snapshotProcess(t, uint32(pid))
	var out, errOut bytes.Buffer
	args := []string{"clean", "--pid", strconv.FormatUint(pid, 10), "--started-at", p.StartedAt.Format(time.RFC3339Nano), "--min-age", "0", "--apply", "--json"}
	if code := run(args, &out, &errOut); code != 0 || !strings.Contains(out.String(), `"terminated"`) {
		t.Fatalf("orphan cleanup exit=%d, stdout=%q, stderr=%q", code, out.String(), errOut.String())
	}
}

package main

import (
	"reflect"
	"testing"
	"time"
)

var fixtureNow = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func fixtureProcess(pid, parent uint32, name string) process {
	return process{PID: pid, ParentPID: parent, Name: name, StartedAt: fixtureNow.Add(-time.Hour), SessionID: 1}
}

func TestParentCandidateSafety(t *testing.T) {
	tests := []struct {
		name      string
		processes []process
		want      []uint32
		reason    string
	}{
		{"missing parent", []process{fixtureProcess(20, 19, "worker.exe")}, []uint32{20}, "parent_missing"},
		{"live parent", []process{fixtureProcess(19, 0, "owner.exe"), fixtureProcess(20, 19, "worker.exe")}, nil, ""},
		{"reused parent", []process{
			{PID: 19, Name: "replacement.exe", StartedAt: fixtureNow.Add(-time.Minute), SessionID: 1},
			fixtureProcess(20, 19, "worker.exe"),
		}, []uint32{20}, "parent_pid_reused"},
		{"inaccessible parent", []process{{PID: 19, Name: "owner.exe", SessionID: 1}, fixtureProcess(20, 19, "worker.exe")}, nil, ""},
		{"unverified target", []process{{PID: 20, ParentPID: 19, Name: "worker.exe", SessionID: 1}}, nil, ""},
		{"another session", []process{{PID: 20, ParentPID: 19, Name: "worker.exe", StartedAt: fixtureNow.Add(-time.Hour), SessionID: 2}}, nil, ""},
		{"recent target", []process{{PID: 20, ParentPID: 19, Name: "worker.exe", StartedAt: fixtureNow.Add(-time.Second), SessionID: 1}}, nil, ""},
		{"future timestamp", []process{{PID: 20, ParentPID: 19, Name: "worker.exe", StartedAt: fixtureNow.Add(time.Minute), SessionID: 1}}, nil, ""},
		{"protected OS process", []process{fixtureProcess(20, 19, "Explorer.EXE")}, nil, ""},
		{"protected server", []process{fixtureProcess(20, 19, "herdr.exe")}, nil, ""},
		{"protected agent", []process{fixtureProcess(20, 19, "codex.exe")}, nil, ""},
		{"own ancestor", []process{fixtureProcess(9, 8, "parent.exe"), fixtureProcess(10, 9, "orphan-guard.exe")}, nil, ""},
		{"parent cycle", []process{fixtureProcess(9, 10, "a.exe"), fixtureProcess(10, 9, "b.exe")}, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := snapshot{Processes: tt.processes, SelfPID: 10, SessionID: 1}
			got, err := findCandidates(s, nil, scanOptions{Now: fixtureNow, MinAge: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			var pids []uint32
			for _, c := range got {
				pids = append(pids, c.PID)
				if c.Reason != tt.reason {
					t.Errorf("reason = %q, want %q", c.Reason, tt.reason)
				}
			}
			if !reflect.DeepEqual(pids, tt.want) {
				t.Fatalf("candidate PIDs = %v, want %v", pids, tt.want)
			}
		})
	}
}

func TestProfileModes(t *testing.T) {
	disabled := false
	base := profile{Name: "App", Indicator: indicator{Process: "app.exe", Mode: "process"}, Targets: []string{"worker.exe"}}
	tests := []struct {
		name    string
		profile profile
		visible map[uint32]bool
		hasApp  bool
		want    int
	}{
		{"process present", base, nil, true, 0},
		{"process absent", base, nil, false, 1},
		{"window visible", profile{Name: "App", Indicator: indicator{Process: "APP.exe", Mode: "window"}, Targets: base.Targets}, map[uint32]bool{30: true}, true, 0},
		{"window absent", profile{Name: "App", Indicator: indicator{Process: "app.exe", Mode: "window"}, Targets: base.Targets}, map[uint32]bool{}, true, 1},
		{"blocklist ignores indicator", profile{Name: "App", Indicator: indicator{Mode: "blocklist"}, Targets: base.Targets}, nil, true, 1},
		{"disabled", profile{Name: "App", Enabled: &disabled, Indicator: indicator{Mode: "blocklist"}, Targets: base.Targets}, nil, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := snapshot{Processes: []process{fixtureProcess(20, 0, "WORKER.exe")}, Visible: tt.visible, SelfPID: 10, SessionID: 1}
			if tt.hasApp {
				s.Processes = append(s.Processes, fixtureProcess(30, 0, "app.exe"))
			}
			got, err := findCandidates(s, []profile{tt.profile}, scanOptions{Now: fixtureNow})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tt.want {
				t.Fatalf("got %d candidates, want %d", len(got), tt.want)
			}
			if len(got) > 0 && (got[0].PID != 20 || got[0].Profile != "App") {
				t.Fatalf("unexpected candidate: %+v", got[0])
			}
		})
	}
}

func TestOverlappingProfilesDoNotDuplicateProcesses(t *testing.T) {
	profiles := []profile{
		{Name: "A", Indicator: indicator{Mode: "blocklist"}, Targets: []string{"worker.exe"}},
		{Name: "B", Indicator: indicator{Mode: "blocklist"}, Targets: []string{"worker.exe"}},
	}
	s := snapshot{Processes: []process{fixtureProcess(20, 0, "worker.exe")}, SelfPID: 10, SessionID: 1}
	got, err := findCandidates(s, profiles, scanOptions{Now: fixtureNow})
	if err != nil || len(got) != 1 {
		t.Fatalf("candidates = %+v, err = %v; want one deduplicated process", got, err)
	}
	got, err = findCandidates(s, profiles, scanOptions{Now: fixtureNow, Profile: "b"})
	if err != nil || len(got) != 1 || got[0].Profile != "B" {
		t.Fatalf("filtered candidates = %+v, err = %v", got, err)
	}
}

func TestUnknownOrDisabledProfileIsAnError(t *testing.T) {
	disabled := false
	profiles := []profile{{Name: "Disabled", Enabled: &disabled}}
	for _, name := range []string{"Missing", "Disabled"} {
		if _, err := findCandidates(snapshot{}, profiles, scanOptions{Now: fixtureNow, Profile: name}); err == nil {
			t.Errorf("profile %q must return an error", name)
		}
	}
}

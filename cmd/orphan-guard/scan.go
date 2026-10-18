package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const unknownSessionID = ^uint32(0)

type process struct {
	PID         uint32    `json:"pid"`
	ParentPID   uint32    `json:"parent_pid"`
	Name        string    `json:"name"`
	StartedAt   time.Time `json:"started_at"`
	MemoryBytes uint64    `json:"memory_bytes"`
	SessionID   uint32    `json:"session_id"`
}

type snapshot struct {
	Processes []process
	Visible   map[uint32]bool
	SelfPID   uint32
	SessionID uint32
}

type indicator struct {
	Process string `json:"process"`
	Mode    string `json:"mode"`
}

type profile struct {
	Name      string    `json:"name"`
	Enabled   *bool     `json:"enabled,omitempty"`
	Indicator indicator `json:"indicator"`
	Targets   []string  `json:"targets"`
	AutoKill  bool      `json:"auto_kill,omitempty"`
}

type candidate struct {
	process
	Reason  string `json:"reason"`
	Profile string `json:"profile,omitempty"`
}

type scanOptions struct {
	Now     time.Time
	MinAge  time.Duration
	Profile string
}

func findCandidates(s snapshot, profiles []profile, opts scanOptions) ([]candidate, error) {
	if opts.Profile != "" {
		var selected *profile
		for i := range profiles {
			if strings.EqualFold(profiles[i].Name, opts.Profile) {
				selected = &profiles[i]
				break
			}
		}
		if selected == nil || (selected.Enabled != nil && !*selected.Enabled) {
			return nil, fmt.Errorf("profile %q does not exist or is disabled", opts.Profile)
		}
		profiles = []profile{*selected}
	}
	byPID := make(map[uint32]process, len(s.Processes))
	for _, p := range s.Processes {
		byPID[p.PID] = p
	}
	ancestors := map[uint32]bool{}
	for pid := s.SelfPID; pid != 0 && !ancestors[pid]; {
		ancestors[pid] = true
		p, exists := byPID[pid]
		if !exists {
			break
		}
		parent, exists := byPID[p.ParentPID]
		if !exists || (!p.StartedAt.IsZero() && parent.StartedAt.After(p.StartedAt)) {
			break
		}
		pid = p.ParentPID
	}
	eligible := func(p process) bool {
		return p.PID > 4 && !ancestors[p.PID] && !protectedName(p.Name) &&
			p.SessionID == s.SessionID && !p.StartedAt.IsZero() &&
			!p.StartedAt.After(opts.Now) && opts.Now.Sub(p.StartedAt) >= opts.MinAge
	}
	result := []candidate{}
	seen := map[uint32]bool{}
	if profiles == nil {
		for _, p := range s.Processes {
			if !eligible(p) || p.ParentPID == 0 {
				continue
			}
			parent, exists := byPID[p.ParentPID]
			reason := ""
			if !exists {
				reason = "parent_missing"
			} else if !parent.StartedAt.IsZero() && parent.StartedAt.After(p.StartedAt) {
				reason = "parent_pid_reused"
			}
			if reason != "" {
				result = append(result, candidate{process: p, Reason: reason})
			}
		}
	} else {
		for _, pr := range profiles {
			if pr.Enabled != nil && !*pr.Enabled {
				continue
			}
			mode := pr.Indicator.Mode
			if mode == "" {
				mode = "process"
			}
			if mode == "window" && s.Visible == nil {
				return nil, fmt.Errorf("cannot evaluate profile %q: visible windows unavailable", pr.Name)
			}
			running := false
			for _, p := range s.Processes {
				if mode == "blocklist" || !strings.EqualFold(p.Name, pr.Indicator.Process) {
					continue
				}
				if p.SessionID == unknownSessionID || p.SessionID == s.SessionID && (mode == "process" || s.Visible[p.PID]) {
					running = true
					break
				}
			}
			if running {
				continue
			}
			reason := map[string]string{"process": "profile_process_missing", "window": "profile_no_window", "blocklist": "profile_blocklist"}[mode]
			for _, p := range s.Processes {
				if !eligible(p) || seen[p.PID] {
					continue
				}
				for _, target := range pr.Targets {
					if strings.EqualFold(p.Name, target) {
						result = append(result, candidate{process: p, Reason: reason, Profile: pr.Name})
						seen[p.PID] = true
						break
					}
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, nil
}

func protectedName(name string) bool {
	switch strings.ToLower(name) {
	case "csrss.exe", "dwm.exe", "explorer.exe", "lsass.exe", "ntoskrnl.exe",
		"services.exe", "smss.exe", "svchost.exe", "system", "conhost.exe",
		"taskmgr.exe", "wininit.exe", "winlogon.exe", "registry", "secure system",
		"herdr.exe", "codex.exe", "claude.exe", "opencode.exe", "cline.exe",
		"node_repl.exe", "windowsterminal.exe", "openconsole.exe", "orphan-guard.exe":
		return true
	}
	return false
}

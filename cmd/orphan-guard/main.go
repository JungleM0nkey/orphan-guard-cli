package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

var version = "0.1.0-dev"

type cleanupResult struct {
	PID    uint32 `json:"pid"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type report struct {
	SchemaVersion int             `json:"schema_version"`
	Command       string          `json:"command"`
	Mode          string          `json:"mode"`
	ScannedAt     time.Time       `json:"scanned_at"`
	ProcessCount  int             `json:"process_count"`
	Candidates    []candidate     `json:"candidates"`
	Applied       bool            `json:"applied"`
	Results       []cleanupResult `json:"results"`
}

const usage = `OrphanGuard: inspect and deliberately clean up Windows process candidates.

Usage:
  orphan-guard scan [--config PATH] [--profile NAME] [--min-age 1m] [--json]
  orphan-guard clean [--config PATH] [--profile NAME] [--pid PID]
                    [--started-at RFC3339] [--min-age 1m] [--apply] [--json]
  orphan-guard init [--config config.json] [--json]
  orphan-guard version [--json]

Without --config, a scan finds processes whose parent is missing or reused.
With --config, a scan evaluates enabled window/process/blocklist profiles.
Clean previews by default. Applying requires --profile or --pid; a PID also
requires --started-at from the scan. A missing parent alone does not prove
that an application is abandoned. Only selected processes are terminated.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	jsonErrors := false
	for _, arg := range args {
		if arg == "--json" || arg == "--json=true" {
			jsonErrors = true
		}
	}
	command := args[0]
	if command != "scan" && command != "clean" && command != "init" && command != "version" {
		return fail(stderr, jsonErrors, 2, fmt.Errorf("unknown command %q; use --help", command))
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "write JSON reports and errors")
	var configPath, profileName, pidText, startedText string
	minAge := time.Minute
	apply := false
	if command != "version" {
		defaultPath := ""
		if command == "init" {
			defaultPath = "config.json"
		}
		fs.StringVar(&configPath, "config", defaultPath, "profile configuration file (explicit opt-in)")
	}
	if command == "scan" || command == "clean" {
		fs.StringVar(&profileName, "profile", "", "one enabled profile from --config")
		fs.DurationVar(&minAge, "min-age", time.Minute, "minimum process age")
	}
	if command == "clean" {
		fs.StringVar(&pidText, "pid", "", "select one candidate PID")
		fs.StringVar(&startedText, "started-at", "", "candidate started_at from a scan (required to apply a PID)")
		fs.BoolVar(&apply, "apply", false, "terminate selected candidates; otherwise preview")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return 0
		}
		return fail(stderr, jsonErrors, 2, err)
	}
	jsonErrors = *jsonOutput
	if fs.NArg() != 0 {
		return fail(stderr, jsonErrors, 2, errors.New("unexpected positional arguments"))
	}
	if command == "version" {
		var err error
		if *jsonOutput {
			err = writeJSON(stdout, map[string]string{"version": version})
		} else {
			_, err = fmt.Fprintln(stdout, "orphan-guard", version)
		}
		if err != nil {
			return fail(stderr, jsonErrors, 1, err)
		}
		return 0
	}
	if command == "init" {
		if err := initConfig(configPath); err != nil {
			return fail(stderr, jsonErrors, 1, err)
		}
		var err error
		if *jsonOutput {
			err = writeJSON(stdout, map[string]string{"config": configPath, "status": "created"})
		} else {
			_, err = fmt.Fprintf(stdout, "Created %s with all profiles disabled.\n", configPath)
		}
		if err != nil {
			return fail(stderr, jsonErrors, 1, err)
		}
		return 0
	}
	if minAge < 0 || (profileName != "" && configPath == "") {
		return fail(stderr, jsonErrors, 2, errors.New("--min-age must be nonnegative; --profile requires --config"))
	}
	var selectedPID uint32
	if pidText != "" {
		value, err := strconv.ParseUint(pidText, 10, 32)
		if err != nil || value <= 4 {
			return fail(stderr, jsonErrors, 2, errors.New("--pid must be an integer greater than 4"))
		}
		selectedPID = uint32(value)
	}
	var expectedStart time.Time
	if startedText != "" {
		var err error
		expectedStart, err = time.Parse(time.RFC3339Nano, startedText)
		if err != nil || expectedStart.IsZero() || selectedPID == 0 {
			return fail(stderr, jsonErrors, 2, errors.New("--started-at requires --pid and a valid RFC3339 timestamp"))
		}
	}
	if apply && (selectedPID == 0 && profileName == "" || selectedPID != 0 && expectedStart.IsZero()) {
		return fail(stderr, jsonErrors, 2, errors.New("--apply requires --profile or --pid with --started-at from a scan"))
	}
	var profiles []profile
	mode := "parent"
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return fail(stderr, jsonErrors, 1, err)
		}
		c, err := parseConfig(data)
		if err != nil {
			return fail(stderr, jsonErrors, 1, err)
		}
		profiles, mode = c.Profiles, "profiles"
	}
	s, err := takeSnapshot()
	if err != nil {
		return fail(stderr, jsonErrors, 1, err)
	}
	opts := scanOptions{Now: time.Now().UTC(), MinAge: minAge, Profile: profileName}
	candidates, err := findCandidates(s, profiles, opts)
	if err != nil {
		return fail(stderr, jsonErrors, 2, err)
	}
	if selectedPID != 0 {
		selected := []candidate{}
		for _, c := range candidates {
			if c.PID == selectedPID {
				if !expectedStart.IsZero() && !c.StartedAt.Equal(expectedStart) {
					return fail(stderr, jsonErrors, 1, errors.New("process identity changed since scan"))
				}
				selected = append(selected, c)
			}
		}
		if len(selected) == 0 {
			return fail(stderr, jsonErrors, 1, fmt.Errorf("PID %d is not an eligible candidate", selectedPID))
		}
		candidates = selected
	}
	r := report{SchemaVersion: 1, Command: command, Mode: mode, ScannedAt: opts.Now, ProcessCount: len(s.Processes), Candidates: candidates, Applied: apply, Results: []cleanupResult{}}
	exitCode := 0
	if apply {
		for _, c := range candidates {
			result := cleanCandidate(c, profiles, opts)
			if result.Error != "" {
				exitCode = 1
			}
			r.Results = append(r.Results, result)
		}
	}
	if err := writeReport(stdout, r, *jsonOutput); err != nil {
		return fail(stderr, jsonErrors, 1, err)
	}
	return exitCode
}

func cleanCandidate(c candidate, profiles []profile, opts scanOptions) cleanupResult {
	result := cleanupResult{PID: c.PID, Status: "failed"}
	fresh, err := takeSnapshot()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	opts.Now = time.Now().UTC()
	current, err := findCandidates(fresh, profiles, opts)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	for _, p := range current {
		if p.PID != c.PID || !p.StartedAt.Equal(c.StartedAt) || !strings.EqualFold(p.Name, c.Name) {
			continue
		}
		if err := terminate(c.process); errors.Is(err, errProcessExited) {
			result.Status = "exited"
		} else if err != nil {
			result.Error = err.Error()
		} else {
			result.Status = "terminated"
		}
		return result
	}
	result.Status = "skipped"
	result.Error = "process identity or eligibility changed; skipped"
	return result
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func fail(w io.Writer, jsonOutput bool, code int, err error) int {
	if jsonOutput {
		writeJSON(w, struct {
			Error    string `json:"error"`
			ExitCode int    `json:"exit_code"`
		}{err.Error(), code})
	} else {
		fmt.Fprintln(w, "orphan-guard:", err)
	}
	return code
}

func writeReport(w io.Writer, r report, jsonOutput bool) error {
	if jsonOutput {
		return writeJSON(w, r)
	}
	if r.Command == "clean" && !r.Applied {
		if _, err := fmt.Fprintln(w, "Dry run: no processes terminated. Use --apply with an explicit selection."); err != nil {
			return err
		}
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "PID\tPARENT\tNAME\tMEMORY MB\tSTARTED AT\tREASON\tPROFILE")
	for _, c := range r.Candidates {
		fmt.Fprintf(table, "%d\t%d\t%s\t%.1f\t%s\t%s\t%s\n", c.PID, c.ParentPID, c.Name, float64(c.MemoryBytes)/(1<<20), c.StartedAt.Format(time.RFC3339Nano), c.Reason, c.Profile)
	}
	for _, result := range r.Results {
		fmt.Fprintf(table, "%d\t%s\t%s\n", result.PID, result.Status, result.Error)
	}
	if err := table.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%d candidate(s) from %d processes in %s mode.\n", len(r.Candidates), r.ProcessCount, r.Mode)
	return err
}

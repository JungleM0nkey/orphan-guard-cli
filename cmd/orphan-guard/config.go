package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

//go:embed defaults.json
var defaultConfig []byte

type config struct {
	ScanIntervalSeconds float64   `json:"scan_interval_seconds,omitempty"`
	Profiles            []profile `json:"profiles"`
}

func parseConfig(data []byte) (config, error) {
	var c config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return c, errors.New("config must contain exactly one JSON object")
	}
	if c.Profiles == nil {
		return c, errors.New("config must contain a profiles array")
	}
	// A pointer alone cannot distinguish an omitted enabled flag from explicit null.
	var raw struct {
		Profiles []struct{ Enabled json.RawMessage }
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return c, fmt.Errorf("invalid config: %w", err)
	}
	names := map[string]bool{}
	for i := range c.Profiles {
		pr := &c.Profiles[i]
		if pr.Enabled == nil && len(raw.Profiles[i].Enabled) != 0 {
			return c, fmt.Errorf("profile %q: enabled must be a boolean, not null", pr.Name)
		}
		pr.Name = strings.TrimSpace(pr.Name)
		if pr.Name == "" || strings.IndexFunc(pr.Name, unicode.IsControl) >= 0 || names[strings.ToLower(pr.Name)] {
			return c, fmt.Errorf("invalid or duplicate profile name %q", pr.Name)
		}
		names[strings.ToLower(pr.Name)] = true
		if pr.Indicator.Mode == "" {
			pr.Indicator.Mode = "process"
		}
		switch pr.Indicator.Mode {
		case "process", "window":
			if !validProcessName(pr.Indicator.Process) {
				return c, fmt.Errorf("profile %q requires an indicator executable name", pr.Name)
			}
		case "blocklist":
		default:
			return c, fmt.Errorf("profile %q has unsupported indicator mode %q", pr.Name, pr.Indicator.Mode)
		}
		if len(pr.Targets) == 0 {
			return c, fmt.Errorf("profile %q requires at least one target", pr.Name)
		}
		for _, target := range pr.Targets {
			if !validProcessName(target) || protectedName(target) {
				return c, fmt.Errorf("profile %q has an invalid or protected target %q", pr.Name, target)
			}
		}
	}
	return c, nil
}

func initConfig(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(defaultConfig)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr, os.Remove(path))
	}
	return nil
}

func validProcessName(name string) bool {
	return name != "" && name != "." && name != ".." && strings.TrimSpace(name) == name &&
		!strings.ContainsAny(name, `\/:*?"<>|`) && strings.IndexFunc(name, unicode.IsControl) < 0
}

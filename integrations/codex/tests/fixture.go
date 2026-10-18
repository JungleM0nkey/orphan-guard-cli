package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	f, err := os.OpenFile(os.Getenv("ORPHAN_GUARD_FIXTURE_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	json.NewEncoder(f).Encode(map[string]any{"args": os.Args[1:], "pid": os.Getpid()})
	f.Close()
	if len(os.Args) != 3 || os.Args[1] != "scan" || os.Args[2] != "--json" {
		fmt.Fprintln(os.Stderr, "unexpected command")
		os.Exit(9)
	}
	switch os.Getenv("ORPHAN_GUARD_FIXTURE_MODE") {
	case "hang":
		time.Sleep(time.Hour)
	case "invalid":
		fmt.Println("fixture-secret: not JSON")
	case "error":
		fmt.Fprintln(os.Stderr, "fixture-secret: scanner failed")
		os.Exit(1)
	case "applied":
		fmt.Println(`{"schema_version":1,"command":"scan","mode":"parent","process_count":3,"candidates":[],"applied":true}`)
	default:
		fmt.Println(`{"schema_version":1,"command":"scan","mode":"parent","process_count":3,"candidates":[{"pid":20,"name":"worker.exe","started_at":"2026-10-18T12:00:00Z"}],"applied":false}`)
	}
}

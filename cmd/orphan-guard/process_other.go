//go:build !windows

package main

import "errors"

var errProcessExited = errors.New("process already exited")

func takeSnapshot() (snapshot, error) {
	return snapshot{}, errors.New("OrphanGuard process inspection requires Windows 10/11")
}

func terminate(process) error {
	return errors.New("OrphanGuard process cleanup requires Windows 10/11")
}

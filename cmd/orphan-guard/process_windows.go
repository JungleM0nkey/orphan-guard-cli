package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	processQueryLimitedInformation = 0x1000
	errorInvalidParameter          = syscall.Errno(87)
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	user32                = syscall.NewLazyDLL("user32.dll")
	queryFullProcessImage = kernel32.NewProc("QueryFullProcessImageNameW")
	processIDToSessionID  = kernel32.NewProc("ProcessIdToSessionId")
	getProcessMemoryInfo  = kernel32.NewProc("K32GetProcessMemoryInfo")
	enumWindows           = user32.NewProc("EnumWindows")
	isWindowVisible       = user32.NewProc("IsWindowVisible")
	getWindowTextLength   = user32.NewProc("GetWindowTextLengthW")
	getWindowThreadPID    = user32.NewProc("GetWindowThreadProcessId")
	visibleMu             sync.Mutex
	visiblePIDs           map[uint32]bool
	windowCallback        = syscall.NewCallback(collectVisibleWindow)
	errProcessExited      = errors.New("process already exited")
)

type memoryCounters struct {
	Size                  uint32
	PageFaultCount        uint32
	PeakWorkingSetSize    uintptr
	WorkingSetSize        uintptr
	QuotaPeakPagedPool    uintptr
	QuotaPagedPool        uintptr
	QuotaPeakNonPagedPool uintptr
	QuotaNonPagedPool     uintptr
	PagefileUsage         uintptr
	PeakPagefileUsage     uintptr
}

func takeSnapshot() (snapshot, error) {
	started := time.Now()
	s := snapshot{Processes: []process{}, SelfPID: uint32(os.Getpid())}
	var err error
	s.SessionID, err = sessionID(s.SelfPID)
	if err != nil {
		return s, err
	}
	h, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return s, fmt.Errorf("enumerate processes: %w", err)
	}
	defer syscall.CloseHandle(h)
	entry := syscall.ProcessEntry32{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = syscall.Process32First(h, &entry); err == nil; err = syscall.Process32Next(h, &entry) {
		p := process{PID: entry.ProcessID, ParentPID: entry.ParentProcessID, Name: syscall.UTF16ToString(entry.ExeFile[:]), SessionID: ^uint32(0)}
		if sid, sidErr := sessionID(p.PID); sidErr == nil {
			p.SessionID = sid
		}
		if handle, openErr := syscall.OpenProcess(processQueryLimitedInformation, false, p.PID); openErr == nil {
			created, timeErr := processStartTime(handle)
			name, nameErr := processName(handle)
			// A process born after enumeration began may have reused a snapshot PID.
			if timeErr == nil && nameErr == nil && strings.EqualFold(name, p.Name) && !created.After(started) {
				p.StartedAt = created
			}
			mem := memoryCounters{}
			mem.Size = uint32(unsafe.Sizeof(mem))
			if ok, _, _ := getProcessMemoryInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&mem)), uintptr(mem.Size)); ok != 0 {
				p.MemoryBytes = uint64(mem.WorkingSetSize)
			}
			syscall.CloseHandle(handle)
		}
		s.Processes = append(s.Processes, p)
	}
	if !errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
		return s, fmt.Errorf("enumerate processes: %w", err)
	}
	s.Visible, err = visibleWindows()
	return s, err
}

func terminate(p process) error {
	if p.PID <= 4 || p.PID == uint32(os.Getpid()) || protectedName(p.Name) || p.StartedAt.IsZero() {
		return errors.New("process is protected or its identity cannot be verified")
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation|syscall.PROCESS_TERMINATE|syscall.SYNCHRONIZE, false, p.PID)
	if errors.Is(err, errorInvalidParameter) {
		return errProcessExited
	}
	if err != nil {
		return fmt.Errorf("open process %d: %w", p.PID, err)
	}
	defer syscall.CloseHandle(h)
	created, err := processStartTime(h)
	if err != nil {
		return err
	}
	name, err := processName(h)
	if err != nil {
		return err
	}
	if !created.Equal(p.StartedAt) || !strings.EqualFold(name, p.Name) {
		return errors.New("process identity changed; refusing to terminate a reused PID")
	}
	sid, err := sessionID(p.PID)
	if err != nil {
		return err
	}
	ownSession, err := sessionID(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	if sid != ownSession || sid != p.SessionID {
		return errors.New("refusing to terminate a process in another session")
	}
	var exitCode uint32
	if err := syscall.GetExitCodeProcess(h, &exitCode); err != nil {
		return err
	}
	if exitCode != 259 { // STILL_ACTIVE
		return errProcessExited
	}
	if err := syscall.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate process %d: %w", p.PID, err)
	}
	state, err := syscall.WaitForSingleObject(h, 2000)
	if err != nil {
		return err
	}
	if state != syscall.WAIT_OBJECT_0 {
		return fmt.Errorf("process %d did not exit within two seconds", p.PID)
	}
	return nil
}

func sessionID(pid uint32) (uint32, error) {
	var sid uint32
	if ok, _, err := processIDToSessionID.Call(uintptr(pid), uintptr(unsafe.Pointer(&sid))); ok == 0 {
		return 0, fmt.Errorf("query process session: %w", err)
	}
	return sid, nil
}

func processStartTime(h syscall.Handle) (time.Time, error) {
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return time.Time{}, fmt.Errorf("query process creation time: %w", err)
	}
	return time.Unix(0, created.Nanoseconds()).UTC(), nil
}

func processName(h syscall.Handle) (string, error) {
	var path [32768]uint16
	size := uint32(len(path))
	if ok, _, err := queryFullProcessImage.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&size))); ok == 0 {
		return "", fmt.Errorf("query process executable: %w", err)
	}
	return filepath.Base(syscall.UTF16ToString(path[:size])), nil
}

func visibleWindows() (map[uint32]bool, error) {
	visibleMu.Lock()
	defer visibleMu.Unlock()
	visiblePIDs = make(map[uint32]bool)
	if ok, _, err := enumWindows.Call(windowCallback, 0); ok == 0 {
		visiblePIDs = nil
		return nil, fmt.Errorf("enumerate visible windows: %w", err)
	}
	result := visiblePIDs
	visiblePIDs = nil
	return result, nil
}

func collectVisibleWindow(hwnd, _ uintptr) uintptr {
	visible, _, _ := isWindowVisible.Call(hwnd)
	length, _, _ := getWindowTextLength.Call(hwnd)
	if visible != 0 && length != 0 {
		var pid uint32
		if threadID, _, _ := getWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&pid))); threadID != 0 {
			visiblePIDs[pid] = true
		}
	}
	return 1
}

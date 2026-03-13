package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const cgroupPath = "/sys/fs/cgroup/byway"

// CreateCgroup creates the byway cgroup directory.
// Returns the cgroup ID (inode number) used by nftables for matching.
func CreateCgroup() (uint64, error) {
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return 0, fmt.Errorf("creating cgroup: %w", err)
	}

	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		return 0, fmt.Errorf("stat cgroup: %w", err)
	}
	return stat.Ino, nil
}

// DestroyCgroup moves all PIDs back to the root cgroup and removes the byway cgroup.
func DestroyCgroup(logger *slog.Logger) error {
	pids, err := CgroupPIDs()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading cgroup PIDs: %w", err)
	}

	rootProcs := "/sys/fs/cgroup/cgroup.procs"
	for _, pid := range pids {
		data := []byte(strconv.FormatUint(uint64(pid), 10))
		if err := os.WriteFile(rootProcs, data, 0644); err != nil {
			// ESRCH = process already exited
			if !errors.Is(err, unix.ESRCH) {
				logger.Warn("moving PID to root cgroup", "pid", pid, "err", err)
			}
		}
	}

	if err := os.Remove(cgroupPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing cgroup: %w", err)
	}
	return nil
}

// MovePID writes a PID to the byway cgroup.
// Returns nil if the process has already exited.
func MovePID(pid uint32) error {
	data := []byte(strconv.FormatUint(uint64(pid), 10))
	err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), data, 0644)
	if err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	return nil
}

// isInBywayCgroup reports whether a process is already in the byway cgroup.
func isInBywayCgroup(pid uint32) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	// cgroup v2: single line "0::/byway\n"
	return strings.TrimSpace(string(data)) == "0::/byway"
}

// CgroupPIDs returns all PIDs currently in the byway cgroup.
func CgroupPIDs() ([]uint32, error) {
	data, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		return nil, err
	}

	var pids []uint32
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		pid, err := strconv.ParseUint(line, 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, uint32(pid))
	}
	return pids, nil
}

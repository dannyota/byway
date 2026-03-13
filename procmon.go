package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// Netlink connector constants.
	cnIdxProc = 0x1
	cnValProc = 0x1

	// Proc connector multicast operations.
	procCnMcastListen = 1
	procCnMcastIgnore = 2

	// Proc event types.
	procEventExec = 0x00000002
)

// ProcMon monitors process exec events and moves matching PIDs to the byway cgroup.
type ProcMon struct {
	apps   map[string]bool
	mu     sync.RWMutex
	logger *slog.Logger
}

func NewProcMon(apps []string, logger *slog.Logger) *ProcMon {
	return &ProcMon{
		apps:   appsToMap(apps),
		logger: logger,
	}
}

// UpdateApps replaces the app match list.
func (p *ProcMon) UpdateApps(apps []string) {
	m := appsToMap(apps)
	p.mu.Lock()
	p.apps = m
	p.mu.Unlock()
}

func appsToMap(apps []string) map[string]bool {
	m := make(map[string]bool, len(apps))
	for _, app := range apps {
		m[app] = true
	}
	return m
}

// ScanExisting walks /proc to find already-running processes that match configured apps.
func (p *ProcMon) ScanExisting() error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("reading /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		p.handleExec(uint32(pid))
	}
	return nil
}

// Run listens for process exec events via the netlink proc connector until ctx is cancelled.
// It scans existing processes after subscribing to avoid a gap where execs could be missed.
func (p *ProcMon) Run(ctx context.Context) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("creating netlink socket: %w", err)
	}
	defer unix.Close(sock)

	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: cnIdxProc,
		Pid:    0, // let kernel assign unique port ID
	}
	if err := unix.Bind(sock, sa); err != nil {
		return fmt.Errorf("binding netlink socket: %w", err)
	}

	// Increase receive buffer to 2 MiB to avoid ENOBUFS under heavy fork load.
	// SO_RCVBUFFORCE bypasses the sysctl net.core.rmem_max limit (requires CAP_NET_ADMIN).
	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 2*1024*1024); err != nil {
		p.logger.Warn("setting netlink receive buffer (falling back to default)", "err", err)
	}

	if err := p.subscribe(sock, procCnMcastListen); err != nil {
		return fmt.Errorf("subscribing to proc events: %w", err)
	}
	defer p.subscribe(sock, procCnMcastIgnore)

	// Scan after subscribing: any exec that happens after subscribe is
	// captured by the event stream, and any process that existed before
	// subscribe is captured by the scan. Duplicates are harmless (MovePID
	// is idempotent).
	if err := p.ScanExisting(); err != nil {
		p.logger.Warn("scanning existing processes", "err", err)
	}

	// Set a read timeout so we can check for context cancellation.
	tv := unix.Timeval{Sec: 0, Usec: 500_000} // 500ms
	if err := unix.SetsockoptTimeval(sock, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("setting socket timeout: %w", err)
	}

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, _, err := unix.Recvfrom(sock, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.ENOBUFS) {
				p.logger.Warn("netlink buffer overflow, some exec events may have been missed")
				continue
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			return fmt.Errorf("recvfrom: %w", err)
		}

		p.handleMessage(buf[:n])
	}
}

// subscribe sends a proc connector multicast listen/ignore message.
//
// Wire format (40 bytes total):
//
//	nlmsghdr  (16 bytes): len, type, flags, seq, pid
//	cn_msg    (20 bytes): cb_id.idx, cb_id.val, seq, ack, len, flags
//	data       (4 bytes): PROC_CN_MCAST_LISTEN or PROC_CN_MCAST_IGNORE
func (p *ProcMon) subscribe(sock int, op uint32) error {
	msg := make([]byte, 40)

	// nlmsghdr
	binary.NativeEndian.PutUint32(msg[0:4], 40)                    // nlmsg_len
	binary.NativeEndian.PutUint16(msg[4:6], unix.NLMSG_DONE)       // nlmsg_type
	binary.NativeEndian.PutUint16(msg[6:8], 0)                     // nlmsg_flags
	binary.NativeEndian.PutUint32(msg[8:12], 0)                    // nlmsg_seq
	binary.NativeEndian.PutUint32(msg[12:16], uint32(os.Getpid())) // nlmsg_pid

	// cn_msg
	binary.NativeEndian.PutUint32(msg[16:20], cnIdxProc) // cb_id.idx
	binary.NativeEndian.PutUint32(msg[20:24], cnValProc) // cb_id.val
	binary.NativeEndian.PutUint32(msg[24:28], 0)         // seq
	binary.NativeEndian.PutUint32(msg[28:32], 0)         // ack
	binary.NativeEndian.PutUint16(msg[32:34], 4)         // len (data = 4 bytes)
	binary.NativeEndian.PutUint16(msg[34:36], 0)         // flags

	// data
	binary.NativeEndian.PutUint32(msg[36:40], op)

	dest := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0}
	return unix.Sendto(sock, msg, 0, dest)
}

// handleMessage parses a netlink message containing a proc event.
//
// Wire format:
//
//	nlmsghdr       (16 bytes)
//	cn_msg         (20 bytes): header with cb_id, seq, ack, len, flags
//	proc_event_hdr (16 bytes): what, cpu, timestamp_ns
//	exec_event      (8 bytes): process_pid, process_tgid
func (p *ProcMon) handleMessage(data []byte) {
	// Minimum: nlmsghdr(16) + cn_msg(20) + proc_event_hdr(16) = 52
	if len(data) < 52 {
		return
	}

	// proc_event starts at offset 36 (16 + 20).
	evData := data[36:]
	what := binary.NativeEndian.Uint32(evData[0:4])
	if what != procEventExec {
		return
	}

	// exec_proc_event: process_pid(4) + process_tgid(4) at offset 16 from proc_event start.
	if len(evData) < 24 {
		return
	}
	tgid := binary.NativeEndian.Uint32(evData[20:24])
	p.handleExec(tgid)
}

func (p *ProcMon) handleExec(pid uint32) {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		// Process already exited or permission denied — expected race.
		return
	}

	p.mu.RLock()
	match := p.apps[exePath]
	p.mu.RUnlock()

	if match {
		if isInBywayCgroup(pid) {
			return
		}
		if err := MovePID(pid); err != nil {
			p.logger.Warn("moving PID to cgroup", "pid", pid, "exe", exePath, "err", err)
		} else {
			p.logger.Info("moved process to byway cgroup", "pid", pid, "exe", exePath)
		}
	}
}

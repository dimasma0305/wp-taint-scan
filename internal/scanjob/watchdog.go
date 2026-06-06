package scanjob

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// watchRSS polls the worker's resident-set size and kills it if it exceeds
// capMB. It returns a flag that is set true when the kill was triggered by the
// memory cap (as opposed to normal exit or context cancellation). capMB <= 0
// disables the watchdog. RSS is read from /proc on Linux; on other platforms
// the watchdog is a no-op and memory safety relies on -mem-limit-mb + timeout.
func watchRSS(ctx context.Context, cmd *exec.Cmd, capMB int) *atomic.Bool {
	killed := new(atomic.Bool)
	if capMB <= 0 || cmd.Process == nil {
		return killed
	}
	pid := cmd.Process.Pid
	capKB := int64(capMB) * 1024
	go func() {
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rss, ok := readRSSkB(pid)
				if !ok {
					return // process gone or /proc unavailable
				}
				if rss > capKB {
					killed.Store(true)
					_ = cmd.Process.Kill()
					return
				}
			}
		}
	}()
	return killed
}

// readRSSkB reads VmRSS (in kB) for pid from /proc. ok is false if unreadable.
func readRSSkB(pid int) (int64, bool) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return kb, true
				}
			}
		}
	}
	return 0, false
}

// Package host collects host metadata, privileges and clocks.
package host

import (
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Linux capability bit numbers.
const (
	CapSysPtrace = 19
	CapSysAdmin  = 21
	CapPerfmon   = 38
)

// Info is host metadata stored in the manifest.
type Info struct {
	Kernel         string `json:"kernel"`
	Machine        string `json:"machine"`
	PageSize       uint64 `json:"page_size"`
	EUID           int    `json:"euid"`
	CapEff         uint64 `json:"cap_eff"`
	PerfParanoid   *int   `json:"perf_event_paranoid,omitempty"`
	PtraceScope    *int   `json:"ptrace_scope,omitempty"`
	WallStart      string `json:"wall_start"`
	MonotonicStart int64  `json:"monotonic_start_ns"`
	Clock          string `json:"clock"`
}

// Collect gathers host Info.
func Collect() Info {
	var u unix.Utsname
	_ = unix.Uname(&u)
	return Info{
		Kernel:         unix.ByteSliceToString(u.Release[:]),
		Machine:        unix.ByteSliceToString(u.Machine[:]),
		PageSize:       uint64(os.Getpagesize()),
		EUID:           os.Geteuid(),
		CapEff:         capEff(),
		PerfParanoid:   readInt("/proc/sys/kernel/perf_event_paranoid"),
		PtraceScope:    readInt("/proc/sys/kernel/yama/ptrace_scope"),
		WallStart:      time.Now().UTC().Format(time.RFC3339Nano),
		MonotonicStart: Mono(),
		Clock:          "CLOCK_MONOTONIC",
	}
}

// HasCap reports whether capability bit c is effective (root counts).
func (i Info) HasCap(c uint) bool {
	return i.EUID == 0 || i.CapEff&(1<<c) != 0
}

// Mono returns CLOCK_MONOTONIC in ns; perf uses the same clock with -k.
func Mono() int64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano()
}

// FreeBytes returns bytes available to unprivileged users at path.
func FreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func capEff() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		v, ok := strings.CutPrefix(l, "CapEff:")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		return n
	}
	return 0
}

func readInt(path string) *int {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return nil
	}
	return &n
}

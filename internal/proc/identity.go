package proc

import (
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ErrPIDChanged means the PID now names a different process (or none).
var ErrPIDChanged = errors.New("target process exited or PID was reused")

// Identity pins a PID to one process instance.
type Identity struct {
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time_ticks"`
}

// StartTime reads field 22 of /proc/PID/stat (clock ticks since boot).
func StartTime(pid int) (uint64, error) {
	_, st, err := readStat(pid)
	return st, err
}

func readStat(pid int) (byte, uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, err
	}
	return ParseStat(string(b))
}

// ParseStat extracts state and starttime from stat content. comm may
// contain spaces and parens, so fields are counted after the last ')'.
func ParseStat(stat string) (byte, uint64, error) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, 0, fmt.Errorf("malformed stat")
	}

	// Fields after comm start at field 3 (state); starttime is field 22.
	f := strings.Fields(stat[i+1:])
	const idx = 22 - 3
	if len(f) <= idx {
		return 0, 0, fmt.Errorf("short stat")
	}
	st, err := strconv.ParseUint(f[idx], 10, 64)
	return f[0][0], st, err
}

// Pin records the current identity of pid.
func Pin(pid int) (Identity, error) {
	st, err := StartTime(pid)
	if err != nil {
		return Identity{}, err
	}
	return Identity{PID: pid, StartTime: st}, nil
}

// Check fails when the PID no longer names the pinned, live process.
func (id Identity) Check() error {
	state, st, err := readStat(id.PID)
	if err != nil || st != id.StartTime || state == 'Z' || state == 'X' {
		return ErrPIDChanged
	}
	return nil
}

// ExePath returns the exact executable image path of pid.
func ExePath(pid int) string { return fmt.Sprintf("/proc/%d/exe", pid) }

// HashFile returns hex sha256 of path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Binary describes the target executable.
type Binary struct {
	SHA256    string `json:"sha256"`
	GoVersion string `json:"go_version,omitempty"`
	Path      string `json:"path,omitempty"`
	Module    string `json:"module,omitempty"`
	DWARF     bool   `json:"dwarf"`
	Arch      string `json:"arch,omitempty"`
	Err       string `json:"error,omitempty"`
}

// InspectBinary reads hash, Go build info and DWARF presence of path.
func InspectBinary(path string) Binary {
	var b Binary
	var err error
	if b.SHA256, err = HashFile(path); err != nil {
		b.Err = err.Error()
		return b
	}

	if bi, err := buildinfo.ReadFile(path); err == nil {
		b.GoVersion = bi.GoVersion
		b.Path = bi.Path
		b.Module = bi.Main.Path
	} else {
		b.Err = "not a Go binary: " + err.Error()
	}

	f, err := elf.Open(path)
	if err != nil {
		return b
	}
	defer f.Close()
	b.Arch = f.Machine.String()
	b.DWARF = f.Section(".debug_info") != nil || f.Section(".zdebug_info") != nil
	return b
}

// MinGoMinor is the oldest Go 1.x minor release this tool supports.
const MinGoMinor = 22

// GoSupported reports whether goVersion ("go1.24.3") is supported.
func GoSupported(goVersion string) bool {
	v, ok := strings.CutPrefix(goVersion, "go1.")
	if !ok {
		return false
	}
	end := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if end >= 0 {
		v = v[:end]
	}
	n, err := strconv.Atoi(v)
	return err == nil && n >= MinGoMinor
}

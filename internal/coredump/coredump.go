// Package coredump captures a core with gcore and copies the exact executable.
package coredump

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/vrutkovs/golang-cold-memory/internal/proc"
)

// Names inside the output directory.
const (
	CorePrefix = "core"
	ExeName    = "exe"
)

// CorePath returns the gcore output path for pid.
func CorePath(dir string, pid int) string {
	return filepath.Join(dir, CorePrefix+"."+strconv.Itoa(pid))
}

// Capture runs gcore against pid. gcore attaches with ptrace and pauses
// the target while it dumps; callers must exclude this period from
// access classification. An existing core file is never overwritten.
func Capture(ctx context.Context, dir string, pid int) (string, []byte, error) {
	return capture(ctx, dir, pid, CorePrefix)
}

// CaptureStart saves a distinct first core, leaving the final core path free.
func CaptureStart(ctx context.Context, dir string, pid int) (string, []byte, error) {
	return capture(ctx, dir, pid, "core-start")
}

func capture(ctx context.Context, dir string, pid int, prefix string) (string, []byte, error) {
	gcore, err := exec.LookPath("gcore")
	if err != nil {
		return "", nil, fmt.Errorf("gcore (gdb) not installed")
	}
	out := filepath.Join(dir, prefix+"."+strconv.Itoa(pid))
	if _, err := os.Lstat(out); err == nil {
		return "", nil, fmt.Errorf("%s already exists; refusing to overwrite", out)
	}

	log, err := exec.CommandContext(ctx, gcore, "-o", filepath.Join(dir, prefix), strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return "", log, fmt.Errorf("gcore: %w", err)
	}
	if err := os.Chmod(out, 0o600); err != nil {
		return "", log, err
	}
	return out, log, nil
}

// CopyExe copies /proc/PID/exe to dir/exe (0600, no overwrite) and returns its sha256.
func CopyExe(dir string, pid int) (string, error) {
	src, err := os.Open(proc.ExePath(pid))
	if err != nil {
		return "", err
	}
	defer src.Close()

	dst, err := os.OpenFile(filepath.Join(dir, ExeName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, h), src); err != nil {
		dst.Close()
		return "", err
	}
	if err := dst.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Missing returns parts of rs not backed by file data in the core's PT_LOAD segments.
func Missing(corePath string, rs []proc.Range) ([]proc.Range, error) {
	f, err := elf.Open(corePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Type != elf.ET_CORE {
		return nil, fmt.Errorf("%s is not a core file", corePath)
	}

	var have []proc.Range
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Filesz > 0 {
			have = append(have, proc.Range{Start: p.Vaddr, End: p.Vaddr + p.Filesz})
		}
	}
	return proc.Subtract(rs, have), nil
}

// Package testutil starts the fixture target for integration tests.
package testutil

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Buf is an address range printed by the fixture.
type Buf struct {
	Addr uint64
	Size uint64
}

// Fixture is a running fixture process.
type Fixture struct {
	Cmd  *exec.Cmd
	Hot  Buf
	Idle []Buf
	Big  Buf
}

// StartFixture builds and starts testdata/fixture, waiting for "ready".
func StartFixture(t *testing.T, env []string, args ...string) *Fixture {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "fixture")
	bin := filepath.Join(t.TempDir(), "fixture")

	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	f := &Fixture{Cmd: cmd}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) == 1 && parts[0] == "ready" {
			return f
		}
		if len(parts) != 3 {
			continue
		}
		a, _ := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 64)
		n, _ := strconv.ParseUint(parts[2], 10, 64)
		b := Buf{a, n}
		switch parts[0] {
		case "hot":
			f.Hot = b
		case "idle":
			f.Idle = append(f.Idle, b)
		case "big":
			f.Big = b
		}
	}
	t.Fatal("fixture exited before ready")
	return nil
}

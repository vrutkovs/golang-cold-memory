package objects_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vrutkovs/golang-cold-memory/internal/coredump"
	"github.com/vrutkovs/golang-cold-memory/internal/objects"
	"github.com/vrutkovs/golang-cold-memory/internal/testutil"
	"github.com/vrutkovs/golang-cold-memory/internal/xdebug/gocore"
)

// captureFixture starts the fixture and dumps its core with the exact exe.
func captureFixture(t *testing.T, env []string, args ...string) (*testutil.Fixture, *gocore.Process) {
	t.Helper()
	if _, err := exec.LookPath("gcore"); err != nil {
		t.Skip("gcore not installed")
	}
	f := testutil.StartFixture(t, env, args...)
	dir := t.TempDir()
	pid := f.Cmd.Process.Pid

	if _, err := coredump.CopyExe(dir, pid); err != nil {
		t.Fatal(err)
	}
	core, log, err := coredump.Capture(context.Background(), dir, pid)
	if err != nil {
		t.Skipf("gcore failed (ptrace permission?): %v\n%s", err, log)
	}
	p, err := objects.Load(core, filepath.Join(dir, coredump.ExeName))
	if err != nil {
		t.Fatal(err)
	}
	return f, p
}

func within(b testutil.Buf, start, end uint64) bool {
	return start >= b.Addr && end <= b.Addr+b.Size
}

func TestAnalyzeFixture(t *testing.T) {
	f, p := captureFixture(t, nil, "-gc=true")

	label := func(start, end uint64) string {
		if within(f.Hot, start, end) {
			return objects.LabelObserved
		}
		for _, b := range f.Idle {
			if within(b, start, end) {
				return objects.LabelQuiet
			}
		}
		return objects.LabelUnknown
	}
	hotAddr := f.Hot.Addr + 100
	res, err := objects.Analyze(p, label, label, []uint64{hotAddr, 1}, objects.Options{MaxPaths: 50, TopObjects: 20})
	if err != nil {
		t.Fatal(err)
	}

	for _, d := range res.Diagnostics {
		if strings.Contains(d, "nil slot") {
			t.Errorf("mask should be built after GC: %s", d)
		}
	}

	var quiet int
	for _, o := range res.Listed {
		if o.Label != objects.LabelQuiet {
			continue
		}
		quiet++
		if o.SliceLen == nil || *o.SliceLen != 0 || *o.SliceCap != int64(f.Idle[0].Size) {
			t.Errorf("idle %#x: want slice len=0 cap=%d, got %v/%v", o.Addr, f.Idle[0].Size, o.SliceLen, o.SliceCap)
		}
		if len(o.Path) == 0 || !strings.HasPrefix(o.Path[0], "main.idle") {
			t.Errorf("idle %#x: unexpected path %v", o.Addr, o.Path)
		}
	}
	if quiet != len(f.Idle) {
		t.Errorf("quiet objects = %d, want %d", quiet, len(f.Idle))
	}

	foundBig := false
	for _, g := range res.ByType {
		foundBig = foundBig || strings.Contains(g.Key, "bigPtrs")
	}
	if !foundBig {
		t.Error("main.bigPtrs object not found")
	}

	if m := res.Matches[0]; m.Object == nil || m.Object.Addr != f.Hot.Addr || m.Offset != 100 {
		t.Errorf("hot sample match = %+v", m)
	}
	if res.Matches[1].Object != nil {
		t.Error("address 1 must not match an object")
	}
}

// Without any GC the on-demand mask slot is nil: report it, add no edges.
func TestOnDemandMaskNil(t *testing.T) {
	f, p := captureFixture(t, []string{"GOGC=off"}, "-gc=false")

	unknown := func(uint64, uint64) string { return objects.LabelUnknown }
	res, err := objects.Analyze(p, unknown, unknown, []uint64{f.Big.Addr}, objects.Options{MaxPaths: 5, TopObjects: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GraphPartial {
		t.Fatal("want incomplete pointer graph diagnostic")
	}
	found := false
	for _, d := range res.Diagnostics {
		found = found || strings.Contains(d, "nil slot")
	}
	if !found {
		t.Errorf("diagnostics lack nil-slot entry: %v", res.Diagnostics)
	}
	if m := res.Matches[0]; m.Object == nil || m.Object.Addr != f.Big.Addr {
		t.Errorf("big object match = %+v", m)
	}
}

func TestAllocSites(t *testing.T) {
	if _, err := exec.LookPath("gcore"); err != nil {
		t.Skip("gcore not installed")
	}
	f := testutil.StartFixture(t, []string{"GODEBUG=memprofilerate=1"})
	dir := t.TempDir()
	pid := f.Cmd.Process.Pid
	if _, err := coredump.CopyExe(dir, pid); err != nil {
		t.Fatal(err)
	}
	core, log, err := coredump.Capture(context.Background(), dir, pid)
	if err != nil {
		t.Skipf("gcore failed: %v\n%s", err, log)
	}
	exe := filepath.Join(dir, coredump.ExeName)
	p, err := objects.Load(core, exe)
	if err != nil {
		t.Fatal(err)
	}

	quiet := func(uint64, uint64) string { return objects.LabelQuiet }
	res, err := objects.Analyze(p, quiet, quiet, nil, objects.Options{MaxPaths: 20, TopObjects: 20, Sites: objects.NewSites(p)})
	if err != nil {
		t.Fatal(err)
	}
	if res.ProfileRate != 1 || res.Sampled == 0 {
		t.Fatalf("rate=%d sampled=%d", res.ProfileRate, res.Sampled)
	}

	counts := map[string]int{}
	for _, g := range res.BySite {
		if strings.HasPrefix(g.Key, "[8388608]uint8 ← ") {
			counts[strings.TrimPrefix(g.Key, "[8388608]uint8 ← ")] = g.Count
		}
	}
	var a, b int
	for site, n := range counts {
		switch {
		case strings.HasPrefix(site, "main.idleA (fixture/main.go:"):
			a = n
		case strings.HasPrefix(site, "main.idleB (fixture/main.go:"):
			b = n
		}
	}
	if a != len(f.Idle)/2 || b != len(f.Idle)/2 {
		t.Errorf("idle sites = %v", counts)
	}

	for _, o := range res.Listed {
		if strings.HasPrefix(o.Type, "[8388608]") && (o.Site == "" || len(o.Stack) == 0) {
			t.Errorf("listed idle %#x lacks site", o.Addr)
		}
	}
}

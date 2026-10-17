package report

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"

	"github.com/vrutkovs/golang-cold-memory/internal/analysis"
	"github.com/vrutkovs/golang-cold-memory/internal/coredump"
	"github.com/vrutkovs/golang-cold-memory/internal/damon"
	"github.com/vrutkovs/golang-cold-memory/internal/objects"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
	"github.com/vrutkovs/golang-cold-memory/internal/testutil"
)

const sec = int64(1e9)

func reportOpts() Options {
	return Options{
		Options:    analysis.Options{FreqRate: 0.5, FreqShare: 0.5, Top: 10, MaxMatches: 100},
		Objects:    true,
		MaxPaths:   50,
		TopObjects: 20,
	}
}

// writeRecording builds a recording from the live fixture with synthetic
// DAMON snapshots (hot buffer accessed, rest idle) and a real core.
func writeRecording(t *testing.T) (string, *testutil.Fixture) {
	t.Helper()
	if _, err := exec.LookPath("gcore"); err != nil {
		t.Skip("gcore not installed")
	}
	f := testutil.StartFixture(t, nil)
	pid := f.Cmd.Process.Pid
	page := uint64(os.Getpagesize())

	dir := filepath.Join(t.TempDir(), "rec")
	if err := store.CreateDir(dir); err != nil {
		t.Fatal(err)
	}
	id, _ := proc.Pin(pid)
	maps, err := proc.ReadMaps(pid)
	if err != nil {
		t.Fatal(err)
	}
	cands := proc.SelectCandidates(maps, 64)
	present, err := proc.Resident(pid, cands, page)
	if err != nil {
		t.Skipf("pagemap unreadable: %v", err)
	}

	hotLo := f.Hot.Addr &^ (page - 1)
	hotHi := (f.Hot.Addr + f.Hot.Size + page - 1) &^ (page - 1)
	var regs []damon.Region
	for _, c := range cands {
		if hotLo < c.Start || hotHi > c.End {
			regs = append(regs, damon.Region{Start: c.Start, End: c.End})
			continue
		}
		for _, r := range []damon.Region{{Start: c.Start, End: hotLo}, {Start: hotLo, End: hotHi, NrAccesses: 25}, {Start: hotHi, End: c.End}} {
			if r.End > r.Start {
				regs = append(regs, r)
			}
		}
	}

	write := func(name string, recs ...any) {
		j, err := store.CreateJSONL(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if _, err := j.Write(r); err != nil {
				t.Fatal(err)
			}
		}
		j.Close()
	}
	write(store.MapsFile, store.MapSnapshot{T: 0, Maps: maps}, store.MapSnapshot{T: 3 * sec, Maps: maps})
	write(store.ResidencyFile, store.ResidencySnapshot{T: 0, Present: present}, store.ResidencySnapshot{T: 3 * sec, Present: present})
	write(store.DAMONFile,
		store.DAMONSnapshot{T: 1 * sec, Regions: regs},
		store.DAMONSnapshot{T: 2 * sec, Regions: regs},
		store.DAMONSnapshot{T: 3 * sec, Regions: regs})
	write(store.PerfSamples, perfmem.Sample{TimeNS: 2 * sec, Addr: f.Hot.Addr + 64, Sym: "main.main", Op: "load"})

	exeSum, err := coredump.CopyExe(dir, pid)
	if err != nil {
		t.Fatal(err)
	}
	core, log, err := coredump.Capture(context.Background(), dir, pid)
	if err != nil {
		t.Skipf("gcore failed: %v\n%s", err, log)
	}

	m := &store.Manifest{
		Tool: "gocold", Status: store.StatusComplete, Target: id,
		Binary:     proc.InspectBinary(filepath.Join(dir, coredump.ExeName)),
		Settings:   store.Settings{AggrUS: 1e6, SampleUS: 20000, MapsIntervalNS: 10 * sec},
		Candidates: cands,
		DAMON:      &damon.Config{PID: pid, Ranges: cands},
		Capabilities: map[string]store.Capability{
			store.CapDAMON: {Available: true}, store.CapResidency: {Available: true},
			store.CapPerf: {Available: true}, store.CapCore: {Available: true},
		},
		Perf: store.Perf{Clock: perfmem.ClockMono},
		Core: store.Core{Path: filepath.Base(core), ExeSHA256: exeSum, StartNS: 4 * sec, FinalSnapshotNS: 3 * sec},
	}
	if err := store.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir, f
}

func TestReportEndToEnd(t *testing.T) {
	dir, f := writeRecording(t)
	r, err := Build(dir, reportOpts())
	if err != nil {
		t.Fatal(err)
	}
	if r.ObjectsErr != "" {
		t.Fatal(r.ObjectsErr)
	}

	hot := r.Regions[r.Find(f.Hot.Addr)]
	if hot.Label != analysis.Frequent {
		t.Errorf("hot region label = %s", hot.Label)
	}

	quiet := 0
	for _, o := range r.Objects.Listed {
		if o.Label == objects.LabelQuiet && o.SliceLen != nil && *o.SliceLen == 0 {
			quiet++
		}
	}
	if quiet != len(f.Idle) {
		t.Errorf("idle quiet objects = %d, want %d", quiet, len(f.Idle))
	}

	if len(r.SampleMatches) != 1 || r.SampleMatches[0].Object == nil || r.SampleMatches[0].Object.Addr != f.Hot.Addr {
		t.Fatalf("sample matches = %+v", r.SampleMatches)
	}
	if sm := r.SampleMatches[0]; sm.Object.Label != objects.LabelObserved || sm.CoreDelayNS != 2*sec {
		t.Errorf("match = %+v", sm)
	}

	var text, js bytes.Buffer
	r.Text(&text, 10)
	t.Log("\n" + text.String())
	if !strings.Contains(text.String(), "quiet candidate") {
		t.Errorf("text output:\n%s", text.String())
	}
	if err := r.JSON(&js); err != nil || !strings.Contains(js.String(), `"damon_snapshots"`) {
		t.Errorf("json err=%v", err)
	}
}

func TestReportRejectsMismatchedBinary(t *testing.T) {
	dir, _ := writeRecording(t)
	m, err := store.ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	m.Binary.SHA256 = strings.Repeat("0", 64)
	if err := store.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}

	r, err := Build(dir, reportOpts())
	if err != nil {
		t.Fatal(err)
	}
	if r.Objects != nil || !strings.Contains(r.ObjectsErr, "does not match") {
		t.Errorf("mismatch accepted: objects=%v err=%q", r.Objects != nil, r.ObjectsErr)
	}
}

func TestRegionOnlyReport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rec")
	if err := store.CreateDir(dir); err != nil {
		t.Fatal(err)
	}
	m := &store.Manifest{
		Status:   store.StatusComplete,
		Settings: store.Settings{AggrUS: 1e6, SampleUS: 20000},
		Capabilities: map[string]store.Capability{
			store.CapDAMON: {Available: false, Reason: "DAMON sysfs absent"},
			store.CapPerf:  {Available: false, Reason: "no PMU"},
		},
	}
	if err := store.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	r, err := Build(dir, reportOpts())
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	r.Text(&b, 5)
	if !strings.Contains(b.String(), "MISSING  DAMON sysfs absent") {
		t.Errorf("missing capability not stated:\n%s", b.String())
	}
}

var keep [][]byte

func TestPprofSection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rec")
	if err := store.CreateDir(dir); err != nil {
		t.Fatal(err)
	}
	runtime.MemProfileRate = 1
	for range 100 {
		keep = append(keep, make([]byte, 4096))
	}
	runtime.GC() // test process only: publishes profile data
	f, err := os.Create(filepath.Join(dir, store.PprofFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.Lookup("heap").WriteTo(f, 0); err != nil {
		t.Fatal(err)
	}
	f.Close()

	m := &store.Manifest{Status: store.StatusComplete, Settings: store.Settings{AggrUS: 1e6, SampleUS: 20000},
		Capabilities: map[string]store.Capability{store.CapPprof: {Available: true}}}
	if err := store.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	r, err := Build(dir, reportOpts())
	if err != nil {
		t.Fatal(err)
	}
	if r.PprofErr != "" || len(r.Pprof) == 0 {
		t.Errorf("pprof sites=%v err=%s", r.Pprof, r.PprofErr)
	}
}

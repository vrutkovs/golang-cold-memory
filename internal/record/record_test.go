package record_test

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vrutkovs/golang-cold-memory/internal/analysis"
	"github.com/vrutkovs/golang-cold-memory/internal/damon/damontest"
	"github.com/vrutkovs/golang-cold-memory/internal/objects"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/record"
	"github.com/vrutkovs/golang-cold-memory/internal/report"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
	"github.com/vrutkovs/golang-cold-memory/internal/testutil"
)

const aggr = 200 * time.Millisecond

func opts(pid int, out string, fs *damontest.FS) record.Options {
	return record.Options{
		PID: pid, Out: out, Duration: 2 * time.Second,
		SnapshotInterval: aggr, MapsInterval: 500 * time.Millisecond,
		SampleUS: 10000, AggrUS: uint64(aggr / time.Microsecond), UpdateUS: 1000000,
		MinRegions: 10, MaxRegions: 1000, MaxRanges: 64, MaxSnapshots: 100,
		NoPerf: true, DAMONFS: fs,
	}
}

func TestTrackDisappearancesRequiresObjects(t *testing.T) {
	o := opts(1, "unused", damontest.New("0"))
	o.TrackDisappearances = true
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "--objects") {
		t.Fatalf("expected --objects requirement, got %v", err)
	}
}

func TestTrackDisappearancesDiskEstimate(t *testing.T) {
	o := opts(1, "unused", damontest.New("0"))
	o.Objects = true
	maps := []proc.Mapping{{Rss: 1 << 20}}
	base := record.Estimate(o, maps, 1024)
	o.TrackDisappearances = true
	if extra := record.Estimate(o, maps, 1024) - base; extra < 1<<20 {
		t.Fatalf("second core reserved %d bytes, want at least 1 MiB", extra)
	}
}

// fakeKernel answers snapshots like DAMON: blocks one aggregation, hot buffer accessed.
func fakeKernel(t *testing.T, f *testutil.Fixture) *damontest.FS {
	maps, err := proc.ReadMaps(f.Cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	cands := proc.SelectCandidates(maps, 64)
	page := uint64(os.Getpagesize())
	lo, hi := f.Hot.Addr&^(page-1), (f.Hot.Addr+f.Hot.Size+page-1)&^(page-1)

	fs := damontest.New("0")
	fs.Tried = func() []damontest.Region {
		time.Sleep(aggr)
		var out []damontest.Region
		for _, c := range cands {
			if lo < c.Start || hi > c.End {
				out = append(out, damontest.Region{Start: c.Start, End: c.End})
				continue
			}
			for _, r := range []damontest.Region{{Start: c.Start, End: lo}, {Start: lo, End: hi, NrAccesses: 15}, {Start: hi, End: c.End}} {
				if r.End > r.Start {
					out = append(out, r)
				}
			}
		}
		return out
	}
	return fs
}

func TestRecordAndReport(t *testing.T) {
	if _, err := exec.LookPath("gcore"); err != nil {
		t.Skip("gcore not installed")
	}
	f := testutil.StartFixture(t, nil)
	fs := fakeKernel(t, f)
	out := filepath.Join(t.TempDir(), "rec")
	o := opts(f.Cmd.Process.Pid, out, fs)
	o.Objects = true

	if err := record.Run(context.Background(), o, io.Discard); err != nil {
		t.Fatal(err)
	}
	if fs.Get("kdamonds/nr_kdamonds") != "0" {
		t.Error("monitor not cleaned up")
	}

	m, err := store.ReadManifest(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != store.StatusComplete || !m.Capabilities[store.CapCore].Available {
		t.Fatalf("manifest = %+v", m)
	}
	if m.Core.FinalSnapshotNS == 0 || m.Core.StartNS < m.Core.FinalSnapshotNS {
		t.Errorf("core must follow final snapshot: %+v", m.Core)
	}

	st, _ := os.Stat(out)
	if st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode().Perm())
	}
	for _, name := range []string{store.ManifestFile, store.DAMONFile, m.Core.Path, "exe"} {
		if st, err := os.Stat(filepath.Join(out, name)); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode/err %v %v", name, st.Mode().Perm(), err)
		}
	}

	r, err := report.Build(out, report.Options{
		Options: analysis.Options{FreqRate: 0.25, FreqShare: 0.5, Top: 10, MaxMatches: 10},
		Objects: true, MaxPaths: 20, TopObjects: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.ObjectsErr != "" {
		t.Fatal(r.ObjectsErr)
	}
	if l := r.Regions[r.Find(f.Hot.Addr)].Label; l != analysis.Frequent {
		t.Errorf("hot label = %s", l)
	}
	quiet := 0
	for _, x := range r.Objects.Listed {
		if x.Label == objects.LabelQuiet && x.SliceLen != nil && *x.SliceLen == 0 {
			quiet++
		}
	}
	if quiet != len(f.Idle) {
		t.Errorf("quiet idle objects = %d, want %d", quiet, len(f.Idle))
	}
}

func TestTrackDisappearances(t *testing.T) {
	if _, err := exec.LookPath("gcore"); err != nil {
		t.Skip("gcore not installed")
	}
	f := testutil.StartFixture(t, nil)
	out := filepath.Join(t.TempDir(), "rec")
	o := opts(f.Cmd.Process.Pid, out, fakeKernel(t, f))
	o.Objects, o.TrackDisappearances = true, true
	if err := record.Run(context.Background(), o, io.Discard); err != nil {
		t.Fatal(err)
	}
	m, err := store.ReadManifest(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.StartCore == nil || m.StartCore.Path == "" || m.StartCore.EndNS >= m.Core.StartNS || m.Core.Path == "" {
		t.Fatalf("invalid core pair: start=%+v end=%+v", m.StartCore, m.Core)
	}
	for _, name := range []string{m.StartCore.Path, m.Core.Path} {
		st, err := os.Stat(filepath.Join(out, name))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("core %q: mode/err %v %v", name, st.Mode().Perm(), err)
		}
	}
	r, err := report.Build(out, report.Options{Options: analysis.Options{Top: 10}, Objects: true, TopObjects: 10})
	if err != nil {
		t.Fatal(err)
	}
	if r.DisappearancesErr != "" || r.ObjectsErr != "" {
		t.Fatalf("disappearances=%q objects=%q", r.DisappearancesErr, r.ObjectsErr)
	}
}

func TestRecordInterrupted(t *testing.T) {
	f := testutil.StartFixture(t, nil)
	fs := fakeKernel(t, f)
	out := filepath.Join(t.TempDir(), "rec")
	o := opts(f.Cmd.Process.Pid, out, fs)
	o.Objects = true

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	err := record.Run(ctx, o, io.Discard)
	if err == nil || !strings.Contains(err.Error(), store.StatusInterrupted) {
		t.Fatalf("want interrupted error, got %v", err)
	}
	if fs.Get("kdamonds/nr_kdamonds") != "0" {
		t.Error("monitor not cleaned up after interruption")
	}
	m, _ := store.ReadManifest(out)
	if m.Status != store.StatusInterrupted || m.Core.Path != "" {
		t.Errorf("manifest status=%s core=%q", m.Status, m.Core.Path)
	}
}

func TestRecordTargetExit(t *testing.T) {
	f := testutil.StartFixture(t, nil)
	fs := fakeKernel(t, f)
	out := filepath.Join(t.TempDir(), "rec")

	time.AfterFunc(500*time.Millisecond, func() { _ = f.Cmd.Process.Kill() })
	if err := record.Run(context.Background(), opts(f.Cmd.Process.Pid, out, fs), io.Discard); err == nil {
		t.Fatal("want error after target exit")
	}
	m, _ := store.ReadManifest(out)
	if m.Status != store.StatusIncomplete || len(m.Errors) == 0 {
		t.Errorf("manifest = %s %v", m.Status, m.Errors)
	}
	if fs.Get("kdamonds/nr_kdamonds") != "0" {
		t.Error("own monitor not cleaned up")
	}
}

func TestRecordOwnershipLost(t *testing.T) {
	f := testutil.StartFixture(t, nil)
	fs := fakeKernel(t, f)
	out := filepath.Join(t.TempDir(), "rec")

	time.AfterFunc(500*time.Millisecond, func() { fs.Set("kdamonds/0/pid", "1") })
	if err := record.Run(context.Background(), opts(f.Cmd.Process.Pid, out, fs), io.Discard); err == nil {
		t.Fatal("want error after ownership change")
	}
	if fs.Get("kdamonds/nr_kdamonds") != "1" || fs.Get("kdamonds/0/state") != "on" {
		t.Error("foreign monitor was touched")
	}
}

func TestRecordRefusesNonEmptyDir(t *testing.T) {
	f := testutil.StartFixture(t, nil)
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(out, 0o700)
	if err := record.Run(context.Background(), opts(f.Cmd.Process.Pid, out, damontest.New("0")), io.Discard); err == nil {
		t.Fatal("want refusal")
	}
	if _, err := os.Stat(filepath.Join(out, "keep")); err != nil {
		t.Error("pre-existing file removed")
	}
}

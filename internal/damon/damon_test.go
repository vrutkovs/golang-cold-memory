package damon_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vrutkovs/golang-cold-memory/internal/damon"
	"github.com/vrutkovs/golang-cold-memory/internal/damon/damontest"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
)

const (
	ctx = "kdamonds/0/contexts/0"
	tgt = ctx + "/targets/0"
)

func cfg() damon.Config {
	return damon.Config{PID: 77, Ranges: []proc.Range{{Start: 0x1000, End: 0x9000}, {Start: 0x20000, End: 0x30000}},
		SampleUS: 5000, AggrUS: 100000, UpdateUS: 1000000, MinRegions: 10, MaxRegions: 1000}
}

func TestRefuseExisting(t *testing.T) {
	f := damontest.New("1")
	if _, err := damon.Start(f, cfg()); !errors.Is(err, damon.ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	if len(f.Writes) != 0 {
		t.Errorf("touched existing monitor: %v", f.Writes)
	}
}

func TestLifecycle(t *testing.T) {
	f := damontest.New("0")
	var tried []damontest.Region
	f.Tried = func() []damontest.Region { return tried }

	m, err := damon.Start(f, cfg())
	if err != nil {
		t.Fatal(err)
	}
	if f.Get(ctx+"/operations") != "fvaddr" || f.Get(ctx+"/schemes/0/action") != "stat" {
		t.Error("expected fvaddr + stat scheme")
	}
	if f.Get(tgt+"/regions/1/start") != fmt.Sprint(0x20000) {
		t.Error("explicit regions not configured")
	}
	for _, w := range f.Writes {
		if strings.Contains(w, "pageout") || strings.Contains(w, "cold") {
			t.Errorf("forbidden DAMOS action written: %s", w)
		}
	}

	// Split/merge between snapshots is reported as-is.
	tried = []damontest.Region{{Start: 0x5000, End: 0x9000, Age: 3}, {Start: 0x1000, End: 0x5000, NrAccesses: 4, Age: 1}}
	regs, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 2 || regs[0].Start != 0x1000 || regs[0].NrAccesses != 4 {
		t.Errorf("regions = %+v", regs)
	}
	tried = []damontest.Region{{Start: 0x1000, End: 0x9000, NrAccesses: 1}}
	if regs, _ = m.Snapshot(); len(regs) != 1 {
		t.Errorf("merged regions = %+v", regs)
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if f.Get("kdamonds/nr_kdamonds") != "0" {
		t.Error("monitor not removed")
	}
}

func TestOwnershipLost(t *testing.T) {
	f := damontest.New("0")
	m, err := damon.Start(f, cfg())
	if err != nil {
		t.Fatal(err)
	}
	// Someone else restarted the kdamond.
	f.Set("kdamonds/0/pid", "9999")
	if _, err := m.Snapshot(); !errors.Is(err, damon.ErrOwnership) {
		t.Fatalf("want ErrOwnership, got %v", err)
	}

	n := len(f.Writes)
	if err := m.Close(); !errors.Is(err, damon.ErrOwnership) {
		t.Fatalf("want ErrOwnership on close, got %v", err)
	}
	if len(f.Writes) != n {
		t.Errorf("cleanup touched foreign monitor: %v", f.Writes[n:])
	}
}

func TestStartFailureCleansUp(t *testing.T) {
	f := damontest.New("0")
	f.FailOn = tgt + "/pid_target"
	if _, err := damon.Start(f, cfg()); err == nil {
		t.Fatal("want error")
	}
	if f.Get("kdamonds/nr_kdamonds") != "0" {
		t.Error("partially created monitor left behind")
	}
}

func TestProbe(t *testing.T) {
	if s := damon.Probe(&damontest.FS{Files: map[string]string{}}); s.Present {
		t.Error("absent sysfs reported present")
	}
	if s := damon.Probe(damontest.New("2")); !s.Readable || s.Existing != 2 {
		t.Errorf("probe = %+v", s)
	}
}

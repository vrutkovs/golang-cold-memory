package analysis

import (
	"slices"
	"testing"

	"github.com/vrutkovs/golang-cold-memory/internal/damon"
	"github.com/vrutkovs/golang-cold-memory/internal/objects"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
)

const sec = int64(1e9)

func rg(s, e uint64) proc.Range { return proc.Range{Start: s, End: e} }

func dr(s, e, acc, age uint64) damon.Region {
	return damon.Region{Start: s, End: e, NrAccesses: acc, Age: age}
}

func anon(start, end uint64) proc.Mapping {
	return proc.Mapping{Start: start, End: end, Perms: "rw-p"}
}

func baseInput() Input {
	m := &store.Manifest{
		Settings: store.Settings{AggrUS: 1e6, SampleUS: 20000, MapsIntervalNS: 10 * sec},
		DAMON:    &damon.Config{Ranges: []proc.Range{rg(0x10000, 0x50000)}},
		Capabilities: map[string]store.Capability{
			store.CapDAMON: {Available: true}, store.CapResidency: {Available: true}, store.CapPerf: {Available: true},
		},
		Perf: store.Perf{Clock: perfmem.ClockMono},
	}
	maps := []proc.Mapping{anon(0x10000, 0x50000)}
	return Input{
		M:    m,
		Maps: []store.MapSnapshot{{T: 0, Maps: maps}, {T: 3 * sec, Maps: maps}},
		Residency: []store.ResidencySnapshot{
			{T: 0, Present: []proc.Range{rg(0x10000, 0x48000)}},
			{T: 3 * sec, Present: []proc.Range{rg(0x10000, 0x48000)}},
		},
		// Regions split and merge between snapshots.
		DAMON: []store.DAMONSnapshot{
			{T: 1 * sec, Regions: []damon.Region{dr(0x10000, 0x30000, 10, 0), dr(0x30000, 0x50000, 0, 5)}},
			{T: 2 * sec, Regions: []damon.Region{dr(0x10000, 0x20000, 30, 0), dr(0x20000, 0x40000, 0, 1), dr(0x40000, 0x50000, 0, 6)}},
			{T: 3 * sec, Regions: []damon.Region{dr(0x10000, 0x20000, 40, 1), dr(0x20000, 0x50000, 0, 2)}},
		},
	}
}

func opts() Options {
	return Options{FreqRate: 0.5, FreqShare: 0.5, Top: 10, MaxMatches: 100}
}

type want struct {
	start, end uint64
	label      string
}

func check(t *testing.T, res *Result, ws []want) {
	t.Helper()
	if len(res.Regions) != len(ws) {
		t.Fatalf("regions = %+v", res.Regions)
	}
	for i, w := range ws {
		r := res.Regions[i]
		if r.Start != w.start || r.End != w.end || r.Label != w.label {
			t.Errorf("region %d = %#x-%#x %s %v, want %#x-%#x %s", i, r.Start, r.End, r.Label, r.Reasons, w.start, w.end, w.label)
		}
	}
}

func TestLabelsWithSplitMerge(t *testing.T) {
	res := Run(baseInput(), opts())
	check(t, res, []want{
		{0x10000, 0x20000, Frequent},
		{0x20000, 0x30000, Observed},
		{0x30000, 0x48000, Quiet},
		{0x48000, 0x50000, Unknown},
	})
	if !slices.Contains(res.Regions[3].Reasons, ReasonNotRes) {
		t.Errorf("non-resident reason missing: %v", res.Regions[3].Reasons)
	}
	if res.Totals.QuietBytes != 0x18000 || res.Totals.ObservedBytes != 0x20000 || res.Totals.UnknownBytes != 0x8000 {
		t.Errorf("totals = %+v", res.Totals)
	}
	if *res.Totals.CoveredResidentBytes != 0x38000 {
		t.Errorf("covered resident = %#x", *res.Totals.CoveredResidentBytes)
	}
	if r := res.Regions[1]; r.LatestAccessNS != 1*sec || r.LatestSource != "damon" {
		t.Errorf("latest access = %+v", r)
	}
}

func TestMappingGrowthUnobserved(t *testing.T) {
	in := baseInput()
	in.Maps[1].Maps = append(in.Maps[1].Maps, anon(0x60000, 0x70000))
	res := Run(in, opts())
	last := res.Regions[len(res.Regions)-1]
	if last.Start != 0x60000 || last.Label != Unknown || !slices.Contains(last.Reasons, ReasonNewMapping) {
		t.Errorf("new mapping = %+v", last)
	}
}

func TestUnmappedGapNotCounted(t *testing.T) {
	in := baseInput()
	// Mapping shrinks mid-run: the removed part is not quiet.
	in.Maps[1].Maps = []proc.Mapping{anon(0x10000, 0x40000)}
	res := Run(in, opts())
	for _, r := range res.Regions {
		if r.End > 0x40000 && r.Label == Quiet {
			t.Errorf("unmapped part labeled quiet: %+v", r)
		}
	}
}

func TestTimeGapsDisableQuiet(t *testing.T) {
	in := baseInput()
	in.DAMON[2].T = 6 * sec
	res := Run(in, opts())
	if len(res.Window.Gaps) != 1 {
		t.Fatalf("gaps = %+v", res.Window.Gaps)
	}
	if res.Totals.QuietBytes != 0 {
		t.Errorf("quiet with gaps: %+v", res.Regions)
	}
}

func TestPartialCoverage(t *testing.T) {
	in := baseInput()
	// Second snapshot misses the upper range.
	in.DAMON[1].Regions = in.DAMON[1].Regions[:2]
	res := Run(in, opts())
	for _, r := range res.Regions {
		if r.Start >= 0x40000 && r.Label == Quiet {
			t.Errorf("partially covered range quiet: %+v", r)
		}
	}
}

func TestResidencyUnknown(t *testing.T) {
	in := baseInput()
	in.M.Capabilities[store.CapResidency] = store.Capability{Available: false}
	res := Run(in, opts())
	if res.Totals.QuietBytes != 0 || res.Totals.ResidentBytes != nil || res.Totals.CoveredResidentBytes != nil {
		t.Errorf("residency unknown must disable quiet and resident totals: %+v", res.Totals)
	}
}

func TestNoDAMON(t *testing.T) {
	in := baseInput()
	in.DAMON = nil
	res := Run(in, opts())
	if res.Totals.UnknownBytes != 0x40000 {
		t.Errorf("all bytes must be unknown: %+v", res.Totals)
	}
}

func TestPerfOverlayAndObjectLabels(t *testing.T) {
	in := baseInput()
	in.Samples = []perfmem.Sample{
		{TimeNS: 2 * sec, Addr: 0x31000, Sym: "main.read"},
		{TimeNS: 2 * sec, Addr: 0x90000, Sym: "main.other"},
		{TimeNS: 9 * sec, Addr: 0x31000, Sym: "late"},
		{TimeNS: 2 * sec, Addr: 0, Sym: "noaddr"},
	}
	res := Run(in, opts())

	// A perf hit in a DAMON-quiet region is counted, not relabeled.
	q := res.Regions[2]
	if q.Label != Quiet || q.PerfSamples != 1 || q.LatestSource != "perf sample" {
		t.Errorf("quiet region overlay = %+v", q)
	}
	if res.Totals.PerfSamples != 2 || res.Totals.PerfOutside != 1 || len(res.Totals.PerfExcluded) != 2 {
		t.Errorf("perf totals = %+v", res.Totals)
	}

	cases := map[[2]uint64]string{
		{0x31000, 0x32000}: objects.LabelQuiet,
		{0x2f000, 0x31000}: objects.LabelMixed,
		{0x47000, 0x49000}: objects.LabelMixed, // quiet + non-resident
		{0x10000, 0x11000}: objects.LabelObserved,
		{0x80000, 0x81000}: objects.LabelUnknown,
	}
	for r, w := range cases {
		if got := res.Label(r[0], r[1]); got != w {
			t.Errorf("Label(%#x,%#x) = %s, want %s", r[0], r[1], got, w)
		}
	}
}

func TestPerfOnlyWindow(t *testing.T) {
	in := baseInput()
	in.DAMON = nil
	in.M.StartNS, in.M.EndNS = 0, 5*sec
	in.Samples = []perfmem.Sample{{TimeNS: 2 * sec, Addr: 0x31000}, {TimeNS: 7 * sec, Addr: 0x31000}}
	res := Run(in, opts())
	if res.Totals.PerfSamples != 1 {
		t.Errorf("perf-only window samples = %d", res.Totals.PerfSamples)
	}
	if res.Totals.QuietBytes != 0 {
		t.Error("perf absence must not create quiet candidates")
	}
}

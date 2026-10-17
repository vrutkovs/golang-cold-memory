package heatmap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vrutkovs/golang-cold-memory/internal/analysis"
	"github.com/vrutkovs/golang-cold-memory/internal/damon"
	"github.com/vrutkovs/golang-cold-memory/internal/host"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
)

const (
	sec  = int64(1e9)
	page = 0x1000
)

func dr(s, e, acc uint64) damon.Region { return damon.Region{Start: s, End: e, NrAccesses: acc} }

// fixture: monitored 0x10000-0x20000 over 4 snapshots (aggr 1s, 50 checks);
// 0x20000-0x24000 is mapped but never monitored.
func input(t *testing.T) Input {
	t.Helper()
	m := &store.Manifest{
		Host:     host.Info{PageSize: page},
		Settings: store.Settings{AggrUS: 1e6, SampleUS: 20000, MapsIntervalNS: 10 * sec},
		DAMON:    &damon.Config{Ranges: []proc.Range{{Start: 0x10000, End: 0x20000}}},
		Capabilities: map[string]store.Capability{
			store.CapDAMON: {Available: true}, store.CapResidency: {Available: true}, store.CapPerf: {Available: true},
		},
		Perf: store.Perf{Clock: perfmem.ClockMono},
	}
	maps := []proc.Mapping{{Start: 0x10000, End: 0x24000, Perms: "rw-p"}}
	in := analysis.Input{
		M:    m,
		Maps: []store.MapSnapshot{{T: 0, Maps: maps}, {T: 4 * sec, Maps: maps}},
		Residency: []store.ResidencySnapshot{
			{T: 0, Present: []proc.Range{{Start: 0x10000, End: 0x24000}}},
			{T: 4 * sec, Present: []proc.Range{{Start: 0x10000, End: 0x24000}}},
		},
		DAMON: []store.DAMONSnapshot{
			{T: 1 * sec, Regions: []damon.Region{dr(0x10000, 0x18000, 25), dr(0x18000, 0x20000, 0)}},
			// Split differs; upper half partly unmonitored this time.
			{T: 2 * sec, Regions: []damon.Region{dr(0x10000, 0x14000, 5), dr(0x14000, 0x1c000, 0)}},
			{T: 3 * sec, Regions: []damon.Region{dr(0x10000, 0x20000, 0)}},
			{T: 4 * sec, Regions: []damon.Region{dr(0x10000, 0x20000, 0)}},
		},
		Samples: []perfmem.Sample{
			{TimeNS: 2*sec + 500, Addr: 0x1e010},
			{TimeNS: 9 * sec, Addr: 0x1e010}, // outside window
		},
	}
	res := analysis.Run(in, analysis.Options{FreqRate: 0.5, FreqShare: 0.5, Top: 5, MaxMatches: 10})
	return Input{In: in, Res: res, Snaps: in.DAMON, Option: Options{MaxRows: 4, MaxCols: 10, MaxTypes: 5}}
}

func TestAddressGrid(t *testing.T) {
	h := Build(input(t))
	if h.BinBytes != 0x4000 || len(h.Columns) != 4 {
		t.Fatalf("bin=%#x cols=%d", h.BinBytes, len(h.Columns))
	}
	// 4 bins + 1 collapsed unmonitored row.
	if len(h.Rows) != 5 || h.Rows[4].Kind != KindUnmonitored || h.Rows[4].Bytes != 0x4000 {
		t.Fatalf("rows = %+v", h.Rows)
	}

	r0 := h.Rows[0]
	if r0.Rate[0] == nil || *r0.Rate[0] != 0.5 || LevelOf(*r0.Rate[0]) != 7 {
		t.Errorf("row0 col0 = %v", r0.Rate[0])
	}
	if *r0.Rate[1] != 0.1 || *r0.Rate[2] != 0 {
		t.Errorf("row0 = %v %v", *r0.Rate[1], *r0.Rate[2])
	}

	// Bin 0x1c000-0x20000 was unmonitored in snapshot 2: empty, not zero.
	r3 := h.Rows[3]
	if r3.Rate[1] != nil || r3.Rate[2] == nil || r3.Coverage[0] != 1 {
		t.Errorf("row3 rate=%v cov=%v", r3.Rate, r3.Coverage)
	}
	if r3.CoveredShare != 0.75 {
		t.Errorf("covered share = %v", r3.CoveredShare)
	}

	if u := h.Rows[4]; u.Rate[0] != nil || u.Label != "unknown" {
		t.Errorf("unmonitored row = %+v", u)
	}

	if r3.Perf[2] != 1 || r3.PerfTotal != 1 || !h.PerfPlaced {
		t.Errorf("perf placement = %v", r3.Perf)
	}
}

func TestColumnGroupingAndGaps(t *testing.T) {
	x := input(t)
	x.Snaps[3].T = 6 * sec // gap 3s..5s
	x.Option.MaxCols = 2
	h := Build(x)
	if len(h.Columns) != 2 || h.Columns[0].Snapshots != 2 || !h.Columns[1].GapBefore {
		t.Fatalf("columns = %+v", h.Columns)
	}
	// Grouped mean for row0, col0: (0.5 + 0.1)/2.
	if v := *h.Rows[0].Rate[0]; v < 0.2999 || v > 0.3001 {
		t.Errorf("grouped rate = %v", v)
	}
}

func TestTypeRowsAndEscaping(t *testing.T) {
	x := input(t)
	x.Types = map[string][]proc.Range{
		"<script>alert(1)</script>": {{Start: 0x10000, End: 0x11000}},
		"main.idle":                 {{Start: 0x18000, End: 0x1a000}, {Start: 0x1a000, End: 0x1c000}},
		"tiny":                      {{Start: 0x1f000, End: 0x1f010}},
	}
	x.Option.MaxTypes = 2
	h := Build(x)
	if len(h.TypeRows) != 2 || h.TypesOmitted != 1 || h.TypeRows[0].Key != "main.idle" {
		t.Fatalf("type rows = %+v omitted=%d", h.TypeRows, h.TypesOmitted)
	}
	if h.TypeRows[0].Bytes != 0x4000 || h.TypeRows[0].MaxRate != 0 {
		t.Errorf("main.idle = %+v", h.TypeRows[0])
	}

	var b bytes.Buffer
	if err := h.HTML(&b, Meta{PID: 1}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "address bin") {
		t.Error("stale address-bin header")
	}
	if strings.Contains(out, "<script>alert") || !strings.Contains(out, "&lt;script&gt;") {
		t.Error("type name not escaped")
	}
	for _, want := range []string{"not monitored (hatched)", "no access observed", "&gt; 30%", "perf sample(s) in cell", `class="c l7`, "main.idle"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
}

func TestTextGlyphs(t *testing.T) {
	h := Build(input(t))
	var b bytes.Buffer
	h.Text(&b)
	out := b.String()
	// Row 0: 0.5, 0.1, 0, 0 -> "75.."; unmonitored row -> "----".
	for _, want := range []string{"|75..|", "|----|", "|.-..|"} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
}

func TestPerfOnly(t *testing.T) {
	x := input(t)
	x.In.DAMON, x.Snaps = nil, nil
	x.In.M.StartNS, x.In.M.EndNS = 0, 4*sec
	x.Res = analysis.Run(x.In, analysis.Options{FreqRate: 0.5, FreqShare: 0.5})
	h := Build(x)
	if len(h.Columns) != 4 {
		t.Fatalf("columns = %d", len(h.Columns))
	}
	total := 0
	for _, r := range h.Rows {
		total += r.PerfTotal
		for _, v := range r.Rate {
			if v != nil {
				t.Fatal("perf-only cells must be unmonitored")
			}
		}
	}
	if total != 1 {
		t.Errorf("perf hits = %d", total)
	}
}

// Slivers left by snapshot reads are not gaps: the sample joins the next column.
func TestPerfSliver(t *testing.T) {
	x := input(t)
	x.Snaps[1].T = 2*sec + 100_000_000
	x.In.Samples = []perfmem.Sample{{TimeNS: sec + 50_000_000, Addr: 0x10010}}
	h := Build(x)
	if h.PerfInGaps != 0 || h.Rows[0].Perf[1] != 1 {
		t.Errorf("gaps=%d perf=%v", h.PerfInGaps, h.Rows[0].Perf)
	}
}

func TestHTMLWithoutTypes(t *testing.T) {
	var b bytes.Buffer
	if err := Build(input(t)).HTML(&b, Meta{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "Address space") || strings.Contains(out, "0x10000") || !strings.Contains(out, "--objects") {
		t.Error("address rows must not render; missing-core hint expected")
	}
}

func TestSiteRows(t *testing.T) {
	x := input(t)
	x.Sites = map[string][]proc.Range{
		"[]byte ← main.a (x/a.go:1)": {{Start: 0x10000, End: 0x11000}},
		"[]byte ← main.b (x/b.go:2)": {{Start: 0x18000, End: 0x19000}},
	}
	h := Build(x)
	if len(h.SiteRows) != 2 || h.SiteRows[0].Kind != KindSite {
		t.Fatalf("site rows = %+v", h.SiteRows)
	}
	if h.SiteRows[0].MaxRate == h.SiteRows[1].MaxRate {
		t.Error("sites of one type must keep separate rates")
	}
	var b bytes.Buffer
	if err := h.HTML(&b, Meta{}); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); !strings.Contains(out, "<th>allocation site</th>") || !strings.Contains(out, "main.b (x/b.go:2)") {
		t.Error("site table missing")
	}
}

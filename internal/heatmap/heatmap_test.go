package heatmap

import (
	"bytes"
	"encoding/json"
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

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

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

	if strings.Contains(mustJSON(t, h), `"perf"`) {
		t.Error("heatmap must not expose perf samples")
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

func TestNoCoreTimeTypeRows(t *testing.T) {
	x := input(t)
	h := Build(x)
	if strings.Contains(mustJSON(t, h), `"type_rows"`) {
		t.Error("heatmap must not expose core-time type rows")
	}

	var b bytes.Buffer
	if err := h.HTML(&b, Meta{PID: 1}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "address bin") {
		t.Error("stale address-bin header")
	}
	if strings.Contains(out, "Core-time object types") || strings.Contains(out, "perf sample") || strings.Contains(out, "perf hits") {
		t.Error("obsolete type table or perf samples rendered")
	}
	for _, want := range []string{"not monitored (hatched)", "no access observed", "&gt; 30%"} {
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
	if strings.Contains(out, "perf") || strings.Contains(out, "core-time type") {
		t.Error("obsolete heatmap details in text")
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
	for _, r := range h.Rows {
		for _, v := range r.Rate {
			if v != nil {
				t.Fatal("perf-only cells must be unmonitored")
			}
		}
	}
	if strings.Contains(mustJSON(t, h), `"perf"`) {
		t.Error("heatmap must not expose perf samples")
	}
}

func TestHTMLWithoutTypes(t *testing.T) {
	var b bytes.Buffer
	if err := Build(input(t)).HTML(&b, Meta{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "Address space") || strings.Contains(out, "0x10000") || strings.Contains(out, "--objects") {
		t.Error("address rows and missing-core hint must not render")
	}
}

func TestSiteRows(t *testing.T) {
	x := input(t)
	x.Sites = map[string][]proc.Range{
		"[]byte ← main.a (x/a.go:1)": {{Start: 0x10000, End: 0x11000}},
		"[]byte ← main.b (x/b.go:2)": {{Start: 0x18000, End: 0x19000}},
		"<script> ← main.c":          {{Start: 0x11000, End: 0x12000}},
	}
	h := Build(x)
	if len(h.SiteRows) != 3 || h.SiteRows[0].Kind != KindSite {
		t.Fatalf("site rows = %+v", h.SiteRows)
	}
	var rateA, rateB float64
	for _, row := range h.SiteRows {
		if strings.Contains(row.Key, "main.a") {
			rateA = row.MaxRate
		}
		if strings.Contains(row.Key, "main.b") {
			rateB = row.MaxRate
		}
	}
	if rateA == rateB {
		t.Error("sites of one type must keep separate rates")
	}
	var b bytes.Buffer
	if err := h.HTML(&b, Meta{}); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); !strings.Contains(out, "<th>allocation site</th>") || !strings.Contains(out, "main.b (x/b.go:2)") || strings.Contains(out, "<script> ←") || !strings.Contains(out, "&lt;script&gt;") {
		t.Error("site table missing")
	}
}

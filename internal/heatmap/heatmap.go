// Package heatmap builds address × time and type × time access heatmaps.
//
// Cells hold DAMON access rates (fraction of sampling checks that saw
// access per aggregation interval), byte-weighted over the covered part
// of the cell. Unmonitored cells stay empty instead of reading as zero.
// Perf sample counts are kept separately: absence of hits proves nothing.
package heatmap

import (
	"sort"

	"github.com/vrutkovs/golang-cold-memory/internal/analysis"
	"github.com/vrutkovs/golang-cold-memory/internal/objects"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
)

// Row kinds.
const (
	KindAddress     = "address"
	KindUnmonitored = "unmonitored"
	KindType        = "type"
	KindSite        = "site"
)

const (
	defaultPage = 4096
	nsPerSec    = int64(1e9)
)

// Options bound heatmap size.
type Options struct {
	MaxRows  int // address rows (monitored space is binned to fit)
	MaxCols  int // time columns (consecutive snapshots are grouped)
	MaxTypes int // core-time type rows, largest first
}

// Level is one legend class of access rate; Max is inclusive.
type Level struct {
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
	Name string  `json:"name"`
}

// Levels: 0 = covered without observed access, then increasing rates.
var Levels = []Level{
	{0, 0, "no access observed"},
	{0, 0.001, "≤ 0.1%"},
	{0.001, 0.003, "0.1–0.3%"},
	{0.003, 0.01, "0.3–1%"},
	{0.01, 0.03, "1–3%"},
	{0.03, 0.1, "3–10%"},
	{0.1, 0.3, "10–30%"},
	{0.3, 1, "> 30%"},
}

// LevelOf maps a rate to its Levels index.
func LevelOf(rate float64) int {
	if rate <= 0 {
		return 0
	}
	for i := 1; i < len(Levels); i++ {
		if rate <= Levels[i].Max {
			return i
		}
	}
	return len(Levels) - 1
}

// Column is a time bin of one or more consecutive DAMON snapshots.
type Column struct {
	StartNS   int64 `json:"start_ns"`
	EndNS     int64 `json:"end_ns"`
	Snapshots int   `json:"snapshots"`
	GapBefore bool  `json:"gap_before"`
}

// Row is one address bin or type; slices are indexed by column.
type Row struct {
	Kind         string       `json:"kind"`
	Key          string       `json:"key,omitempty"`
	Start        uint64       `json:"start"`
	End          uint64       `json:"end"`
	Bytes        uint64       `json:"bytes"`
	Label        string       `json:"label"`
	Rate         []*float64   `json:"rate"` // nil = not monitored
	Coverage     []float64    `json:"coverage"`
	Perf         []int        `json:"perf"`
	MeanRate     float64      `json:"mean_rate"`
	MaxRate      float64      `json:"max_rate"`
	PerfTotal    int          `json:"perf_total"`
	CoveredShare float64      `json:"covered_share"`
	ranges       []proc.Range // type rows: merged object ranges
}

// Heatmap is the full grid.
type Heatmap struct {
	Window       analysis.Window `json:"window"`
	Columns      []Column        `json:"columns"`
	BinBytes     uint64          `json:"bin_bytes"`
	Rows         []Row           `json:"rows"`
	TypeRows     []Row           `json:"type_rows,omitempty"`
	TypesOmitted int             `json:"types_omitted,omitempty"`
	SiteRows     []Row           `json:"site_rows,omitempty"`
	SitesOmitted int             `json:"sites_omitted,omitempty"`
	PerfPlaced   bool            `json:"perf_placed_in_time"`
	PerfInGaps   int             `json:"perf_samples_in_gaps,omitempty"`
	Levels       []Level         `json:"levels"`
	Notes        []string        `json:"notes,omitempty"`
}

// Input is everything Build needs.
type Input struct {
	In     analysis.Input
	Res    *analysis.Result
	Snaps  []store.DAMONSnapshot // window snapshots, time order
	Types  map[string][]proc.Range
	Sites  map[string][]proc.Range // sampled objects by "type ← site"
	Option Options
}

// Build computes the heatmap.
func Build(x Input) *Heatmap {
	m, res, o := x.In.M, x.Res, x.Option
	h := &Heatmap{Window: res.Window, Levels: Levels}
	page := m.Host.PageSize
	if page == 0 {
		page = defaultPage
	}

	colOf := h.columns(x.Snaps, res.Window, o.MaxCols)
	covered := coveredUnion(x.Snaps)
	space := regionSpan(res.Regions)
	monitored := proc.Intersect(space, covered)
	h.BinBytes = binSize(proc.TotalSize(monitored), o.MaxRows, page)
	h.Rows = addressRows(monitored, proc.Subtract(space, covered), h.BinBytes)

	maxChecks := float64(1)
	if m.Settings.SampleUS > 0 {
		maxChecks = float64(m.Settings.AggrUS) / float64(m.Settings.SampleUS)
	}
	for i := range h.Rows {
		r := &h.Rows[i]
		r.Label = res.Label(r.Start, r.End)
		h.fill(r, []proc.Range{{Start: r.Start, End: r.End}}, x.Snaps, colOf, maxChecks)
	}

	h.TypeRows, h.TypesOmitted = typeRows(x.Types, o.MaxTypes)
	for i := range h.TypeRows {
		r := &h.TypeRows[i]
		r.Label = typeLabel(res, r.ranges)
		h.fill(r, r.ranges, x.Snaps, colOf, maxChecks)
	}

	h.SiteRows, h.SitesOmitted = typeRows(x.Sites, o.MaxTypes)
	for i := range h.SiteRows {
		r := &h.SiteRows[i]
		r.Kind = KindSite
		r.Label = typeLabel(res, r.ranges)
		h.fill(r, r.ranges, x.Snaps, colOf, maxChecks)
	}

	h.overlayPerf(x.In.Samples, m.Perf.Clock == perfmem.ClockMono)
	if len(x.Snaps) == 0 {
		h.Notes = append(h.Notes, "no DAMON snapshots: cells unmonitored, perf hits only")
	}
	if len(h.TypeRows) > 0 {
		h.Notes = append(h.Notes, "type rows project core-time object placement over the whole window; addresses may have held other objects earlier")
	}
	return h
}

// columns groups snapshots into ≤ maxCols bins; returns snapshot→column.
// Without snapshots the window is split evenly (perf-only recordings).
func (h *Heatmap) columns(snaps []store.DAMONSnapshot, w analysis.Window, maxCols int) []int {
	maxCols = max(maxCols, 1)
	if len(snaps) == 0 {
		n := int(min(int64(maxCols), max((w.EndNS-w.StartNS)/nsPerSec, 1)))
		step := (w.EndNS - w.StartNS) / int64(n)
		for i := range n {
			h.Columns = append(h.Columns, Column{StartNS: w.StartNS + int64(i)*step, EndNS: w.StartNS + int64(i+1)*step})
		}
		return nil
	}

	per := (len(snaps) + maxCols - 1) / maxCols
	colOf := make([]int, len(snaps))
	for i, s := range snaps {
		c := i / per
		colOf[i] = c
		start := s.T - w.AggrNS
		if c == len(h.Columns) {
			gap := c > 0 && start > h.Columns[c-1].EndNS+w.AggrNS/2
			h.Columns = append(h.Columns, Column{StartNS: start, GapBefore: gap})
		}
		col := &h.Columns[c]
		col.EndNS = s.T
		col.Snapshots++
		if i > 0 && colOf[i-1] == c && start > snaps[i-1].T+w.AggrNS/2 {
			col.GapBefore = true // gap inside a grouped column
		}
	}
	return colOf
}

// fill computes per-column byte-weighted rates over rs.
func (h *Heatmap) fill(r *Row, rs []proc.Range, snaps []store.DAMONSnapshot, colOf []int, maxChecks float64) {
	n := len(h.Columns)
	r.Rate, r.Coverage, r.Perf = make([]*float64, n), make([]float64, n), make([]int, n)
	cov, sum := make([]float64, n), make([]float64, n)
	snapsIn := make([]int, n)
	for i, s := range snaps {
		c := colOf[i]
		snapsIn[c]++
		regs := s.Regions
		for _, x := range rs {
			j := sort.Search(len(regs), func(k int) bool { return regs[k].End > x.Start })
			for ; j < len(regs) && regs[j].Start < x.End; j++ {
				ov := float64(min(regs[j].End, x.End) - max(regs[j].Start, x.Start))
				rate := float64(regs[j].NrAccesses) / maxChecks
				cov[c] += ov
				sum[c] += rate * ov
				r.MaxRate = max(r.MaxRate, rate)
			}
		}
	}

	var totCov, totSum float64
	for c := range n {
		totCov += cov[c]
		totSum += sum[c]
		if cov[c] == 0 {
			continue
		}
		v := sum[c] / cov[c]
		r.Rate[c] = &v
		r.Coverage[c] = cov[c] / (float64(r.Bytes) * float64(snapsIn[c]))
	}
	if totCov > 0 {
		r.MeanRate = totSum / totCov
		r.CoveredShare = totCov / (float64(r.Bytes) * float64(len(snaps)))
	}
}

// overlayPerf counts samples per cell. Without a shared clock, samples
// cannot be placed in time and are left out of the grid.
func (h *Heatmap) overlayPerf(samples []perfmem.Sample, comparable bool) {
	h.PerfPlaced = comparable
	if len(samples) == 0 || len(h.Columns) == 0 {
		return
	}
	if !comparable {
		h.Notes = append(h.Notes, "perf clock differs from DAMON clock: perf hits not placed in the grid")
		return
	}

	for _, s := range samples {
		if s.Addr == 0 || s.TimeNS < h.Window.StartNS || s.TimeNS > h.Window.EndNS {
			continue
		}
		// Snapshot reads leave sub-interval slivers between columns; samples
		// there belong to the next column, like analysis gap detection.
		c := sort.Search(len(h.Columns), func(k int) bool { return h.Columns[k].EndNS >= s.TimeNS })
		if c == len(h.Columns) || s.TimeNS < h.Columns[c].StartNS-h.Window.AggrNS/2 {
			h.PerfInGaps++
			continue
		}
		if i := findRow(h.Rows, s.Addr); i >= 0 {
			h.Rows[i].Perf[c]++
			h.Rows[i].PerfTotal++
		}
		for _, rows := range [][]Row{h.TypeRows, h.SiteRows} {
			for i := range rows {
				if inRanges(rows[i].ranges, s.Addr) {
					rows[i].Perf[c]++
					rows[i].PerfTotal++
				}
			}
		}
	}
}

func coveredUnion(snaps []store.DAMONSnapshot) []proc.Range {
	var rs []proc.Range
	for _, s := range snaps {
		for _, r := range s.Regions {
			rs = append(rs, proc.Range{Start: r.Start, End: r.End})
		}
	}
	return proc.Normalize(rs)
}

func regionSpan(regs []analysis.Region) []proc.Range {
	rs := make([]proc.Range, len(regs))
	for i, r := range regs {
		rs[i] = proc.Range{Start: r.Start, End: r.End}
	}
	return proc.Normalize(rs)
}

// binSize spreads total bytes over maxRows, rounded up to whole pages.
func binSize(total uint64, maxRows int, page uint64) uint64 {
	per := (total + uint64(max(maxRows, 1)) - 1) / uint64(max(maxRows, 1))
	return max((per+page-1)/page*page, page)
}

// addressRows bins monitored space; each unmonitored range is one collapsed row.
func addressRows(monitored, unmonitored []proc.Range, bin uint64) []Row {
	var rows []Row
	for _, r := range monitored {
		for a := r.Start; a < r.End; a += bin {
			e := min(a+bin, r.End)
			rows = append(rows, Row{Kind: KindAddress, Start: a, End: e, Bytes: e - a})
		}
	}
	for _, r := range unmonitored {
		rows = append(rows, Row{Kind: KindUnmonitored, Start: r.Start, End: r.End, Bytes: r.Size()})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Start < rows[j].Start })
	return rows
}

// typeRows keeps the largest maxTypes types by bytes.
func typeRows(types map[string][]proc.Range, maxTypes int) ([]Row, int) {
	rows := make([]Row, 0, len(types))
	for k, rs := range types {
		rs = proc.Normalize(rs)
		if len(rs) == 0 {
			continue
		}
		rows = append(rows, Row{Kind: KindType, Key: k, Start: rs[0].Start, End: rs[len(rs)-1].End,
			Bytes: proc.TotalSize(rs), ranges: rs})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes != rows[j].Bytes {
			return rows[i].Bytes > rows[j].Bytes
		}
		return rows[i].Key < rows[j].Key
	})
	if len(rows) <= maxTypes {
		return rows, 0
	}
	return rows[:maxTypes], len(rows) - maxTypes
}

// typeLabel combines per-range labels like whole-object classification.
func typeLabel(res *analysis.Result, rs []proc.Range) string {
	seen := map[string]bool{}
	for _, r := range rs {
		seen[res.Label(r.Start, r.End)] = true
	}
	switch {
	case len(seen) == 1:
		for l := range seen {
			return l
		}
	case seen[objects.LabelQuiet] || seen[objects.LabelMixed]:
		return objects.LabelMixed
	case seen[objects.LabelObserved]:
		return objects.LabelObserved
	}
	return objects.LabelUnknown
}

func findRow(rows []Row, a uint64) int {
	i := sort.Search(len(rows), func(k int) bool { return rows[k].End > a })
	if i < len(rows) && rows[i].Start <= a {
		return i
	}
	return -1
}

func inRanges(rs []proc.Range, a uint64) bool {
	i := sort.Search(len(rs), func(k int) bool { return rs[k].End > a })
	return i < len(rs) && rs[i].Start <= a
}

// Package analysis turns raw DAMON/perf/maps evidence into labeled
// address intervals with stated coverage and uncertainty.
//
// Labels:
//   - observed-access: DAMON saw access in the window.
//   - frequently-accessed: rate >= threshold for >= share of snapshots.
//   - quiet-candidate: monitored in every snapshot without time gaps,
//     mapping-stable, resident throughout, and no access observed.
//   - unknown: anything else, with reasons.
//
// DAMON "age" is persistence of an access pattern, not last access.
package analysis

import (
	"sort"
	"strings"

	"github.com/vrutkovs/golang-cold-memory/internal/objects"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
)

// Labels.
const (
	Observed = "observed-access"
	Frequent = "frequently-accessed"
	Quiet    = "quiet-candidate"
	Unknown  = "unknown"
)

// Unknown reasons.
const (
	ReasonExcluded   = "excluded by --max-ranges bound"
	ReasonNewMapping = "mapped after monitoring started; unobserved"
	ReasonNoDAMON    = "no DAMON snapshots in window"
	ReasonPartial    = "DAMON coverage incomplete during window"
	ReasonTimeGaps   = "snapshot time gaps in window"
	ReasonMapChanged = "mapping changed during window"
	ReasonResUnknown = "residency unknown"
	ReasonNotRes     = "not resident throughout window (uncommitted, swapped or reclaimed)"
)

// Options select the window and thresholds.
type Options struct {
	FromNS     int64   // window start, offset from first snapshot coverage
	ToNS       int64   // window end offset; 0 = last snapshot
	FreqRate   float64 // fraction of DAMON sampling checks per aggregation
	FreqShare  float64 // fraction of snapshots at >= FreqRate
	Top        int
	MaxMatches int
}

// Input is a loaded recording.
type Input struct {
	M         *store.Manifest
	Maps      []store.MapSnapshot
	Residency []store.ResidencySnapshot
	DAMON     []store.DAMONSnapshot
	Samples   []perfmem.Sample
}

// Count is a named counter.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Region is a labeled, non-overlapping address interval.
type Region struct {
	Start             uint64   `json:"start"`
	End               uint64   `json:"end"`
	Label             string   `json:"label"`
	Reasons           []string `json:"reasons,omitempty"`
	AccessedSnapshots int      `json:"accessed_snapshots"`
	FrequentShare     float64  `json:"frequent_share"`
	MaxRate           float64  `json:"max_rate"`
	MeanRate          float64  `json:"mean_rate"`
	LatestAccessNS    int64    `json:"latest_observed_access_ns,omitempty"`
	LatestSource      string   `json:"latest_observed_access_source,omitempty"`
	LatestResolution  int64    `json:"latest_observed_access_resolution_ns,omitempty"`
	PerfSamples       int      `json:"perf_samples"`
	TopSymbols        []Count  `json:"top_symbols,omitempty"`
	ObjectBytes       int64    `json:"core_object_bytes,omitempty"`
}

// Size returns region length.
func (r Region) Size() uint64 { return r.End - r.Start }

// Gap is a time interval without DAMON coverage.
type Gap struct {
	FromNS int64 `json:"from_ns"`
	ToNS   int64 `json:"to_ns"`
}

// Window describes the analyzed interval.
type Window struct {
	StartNS   int64 `json:"start_ns"`
	EndNS     int64 `json:"end_ns"`
	Snapshots int   `json:"snapshots"`
	AggrNS    int64 `json:"aggr_ns"`
	SampleNS  int64 `json:"sample_ns"`
	Gaps      []Gap `json:"gaps,omitempty"`
}

// Totals are byte sums over non-overlapping regions.
type Totals struct {
	MappedBytes          uint64  `json:"mapped_candidate_bytes"`
	ObservedBytes        uint64  `json:"observed_access_bytes"`
	FrequentBytes        uint64  `json:"frequently_accessed_bytes"`
	QuietBytes           uint64  `json:"quiet_candidate_bytes"`
	UnknownBytes         uint64  `json:"unknown_bytes"`
	ResidentBytes        *uint64 `json:"resident_bytes,omitempty"`
	CoveredResidentBytes *uint64 `json:"covered_resident_bytes,omitempty"`
	PerfSamples          int     `json:"perf_samples_in_window"`
	PerfOutside          int     `json:"perf_samples_outside_candidates"`
	PerfExcluded         []Count `json:"perf_samples_excluded,omitempty"`
	PerfLost             uint64  `json:"perf_lost"`
}

// SampleRef is an in-window perf sample selected for object matching.
type SampleRef struct {
	TimeNS int64  `json:"t"`
	Addr   uint64 `json:"addr"`
	Sym    string `json:"sym"`
	Op     string `json:"op"`
}

// Result is the region-level analysis.
type Result struct {
	Window         Window      `json:"window"`
	Totals         Totals      `json:"totals"`
	Regions        []Region    `json:"regions"`
	TopCode        []Count     `json:"top_code_paths,omitempty"`
	PerfComparable bool        `json:"perf_times_comparable"`
	Notes          []string    `json:"notes,omitempty"`
	MatchSamples   []SampleRef `json:"-"`
}

// counters at one elementary interval.
type counters struct {
	cov, acc, freq   int
	u, s, m, r, init int
}

const (
	kCov = iota
	kAcc
	kFreq
	kU
	kS
	kM
	kR
	kInit
)

type event struct {
	pos   uint64
	kind  int
	delta int
}

// Run analyzes in.
func Run(in Input, o Options) *Result {
	m := in.M
	res := &Result{}
	aggr := int64(m.Settings.AggrUS) * 1000
	res.Window.AggrNS, res.Window.SampleNS = aggr, int64(m.Settings.SampleUS)*1000

	snaps := selectSnapshots(in.DAMON, aggr, o, &res.Window)
	if len(in.DAMON) == 0 {
		// Perf-only recording: the window is the recording span.
		res.Window.StartNS, res.Window.EndNS = m.StartNS+o.FromNS, m.EndNS
		if o.ToNS > 0 {
			res.Window.EndNS = m.StartNS + o.ToNS
		}
	}
	n := len(snaps)
	mapsSel := selectByTime(in.Maps, res.Window, m.Settings.MapsIntervalNS)
	resSel := selectByTime(in.Residency, res.Window, m.Settings.MapsIntervalNS)
	resKnown := m.Capabilities[store.CapResidency].Available && len(resSel) > 0

	var monitored []proc.Range
	if m.DAMON != nil {
		monitored = m.DAMON.Ranges
	}
	stable, union, initial := mappingSets(mapsSel, in.Maps)
	union = proc.Normalize(append(union, monitored...))
	resident := intersectAll(resSel)

	// Sweep all boundaries once; counters per elementary interval.
	maxChecks := float64(1)
	if m.Settings.SampleUS > 0 {
		maxChecks = float64(m.Settings.AggrUS) / float64(m.Settings.SampleUS)
	}
	var evs []event
	add := func(rs []proc.Range, k int) {
		for _, r := range rs {
			evs = append(evs, event{r.Start, k, 1}, event{r.End, k, -1})
		}
	}
	for _, s := range snaps {
		for _, r := range s.Regions {
			evs = append(evs, event{r.Start, kCov, 1}, event{r.End, kCov, -1})
			if r.NrAccesses > 0 {
				evs = append(evs, event{r.Start, kAcc, 1}, event{r.End, kAcc, -1})
			}
			if float64(r.NrAccesses)/maxChecks >= o.FreqRate {
				evs = append(evs, event{r.Start, kFreq, 1}, event{r.End, kFreq, -1})
			}
		}
	}
	add(union, kU)
	add(stable, kS)
	add(proc.Normalize(monitored), kM)
	add(resident, kR)
	add(initial, kInit)
	sort.Slice(evs, func(i, j int) bool { return evs[i].pos < evs[j].pos })

	var c counters
	gaps := len(res.Window.Gaps) > 0
	for i := 0; i < len(evs); {
		pos := evs[i].pos
		for ; i < len(evs) && evs[i].pos == pos; i++ {
			c.apply(evs[i])
		}
		if i == len(evs) {
			break
		}
		next := evs[i].pos
		if next == pos || (c.u == 0 && c.cov == 0 && c.m == 0) {
			continue
		}
		label, reasons := classify(c, n, gaps, resKnown, o.FreqShare)
		res.addInterval(pos, next, label, reasons)

		if resKnown && c.cov == n && n > 0 && !gaps && c.s > 0 && c.r > 0 {
			addPtr(&res.Totals.CoveredResidentBytes, next-pos)
		}
	}
	if resKnown {
		v := proc.TotalSize(resident)
		res.Totals.ResidentBytes = &v
		if res.Totals.CoveredResidentBytes == nil {
			res.Totals.CoveredResidentBytes = new(uint64)
		}
	} else {
		res.Notes = append(res.Notes, "residency unavailable: resident-byte totals omitted, quiet candidates impossible")
	}

	res.regionStats(snaps, maxChecks, o.FreqRate)
	res.overlayPerf(in, o)
	res.totals()
	if n > 0 && aggr > 0 {
		res.Notes = append(res.Notes, "DAMON samples one page per region per sampling interval; labels hold at region resolution")
	}
	return res
}

func (c *counters) apply(e event) {
	switch e.kind {
	case kCov:
		c.cov += e.delta
	case kAcc:
		c.acc += e.delta
	case kFreq:
		c.freq += e.delta
	case kU:
		c.u += e.delta
	case kS:
		c.s += e.delta
	case kM:
		c.m += e.delta
	case kR:
		c.r += e.delta
	case kInit:
		c.init += e.delta
	}
}

// classify labels one elementary interval.
func classify(c counters, n int, gaps, resKnown bool, share float64) (string, []string) {
	if c.acc > 0 {
		var caveats []string
		if c.cov < n {
			caveats = append(caveats, ReasonPartial)
		}
		if n > 0 && float64(c.freq)/float64(n) >= share {
			return Frequent, caveats
		}
		return Observed, caveats
	}

	var why []string
	switch {
	case c.m == 0 && c.init > 0:
		why = append(why, ReasonExcluded)
	case c.m == 0:
		why = append(why, ReasonNewMapping)
	case n == 0:
		why = append(why, ReasonNoDAMON)
	case c.cov < n:
		why = append(why, ReasonPartial)
	}
	if gaps {
		why = append(why, ReasonTimeGaps)
	}
	if c.s == 0 {
		why = append(why, ReasonMapChanged)
	}
	switch {
	case !resKnown:
		why = append(why, ReasonResUnknown)
	case c.r == 0:
		why = append(why, ReasonNotRes)
	}
	if len(why) == 0 {
		return Quiet, nil
	}
	return Unknown, why
}

// addInterval appends, merging with the previous region when identical.
func (res *Result) addInterval(lo, hi uint64, label string, reasons []string) {
	if n := len(res.Regions); n > 0 {
		p := &res.Regions[n-1]
		if p.End == lo && p.Label == label && strings.Join(p.Reasons, "|") == strings.Join(reasons, "|") {
			p.End = hi
			return
		}
	}
	res.Regions = append(res.Regions, Region{Start: lo, End: hi, Label: label, Reasons: reasons})
}

// selectSnapshots picks snapshots inside the window and records time gaps.
func selectSnapshots(all []store.DAMONSnapshot, aggr int64, o Options, w *Window) []store.DAMONSnapshot {
	if len(all) == 0 {
		return nil
	}
	origin := all[0].T - aggr
	from, to := origin+o.FromNS, all[len(all)-1].T
	if o.ToNS > 0 {
		to = origin + o.ToNS
	}
	slack := aggr / 2

	var out []store.DAMONSnapshot
	for _, s := range all {
		if s.T-aggr >= from-slack && s.T <= to {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		w.StartNS, w.EndNS = from, to
		return nil
	}

	w.StartNS, w.EndNS, w.Snapshots = out[0].T-aggr, out[len(out)-1].T, len(out)
	for i := 1; i < len(out); i++ {
		if out[i].T-aggr > out[i-1].T+slack {
			w.Gaps = append(w.Gaps, Gap{out[i-1].T, out[i].T - aggr})
		}
	}
	return out
}

type timed interface {
	store.MapSnapshot | store.ResidencySnapshot
}

func tOf[T timed](v T) int64 {
	switch x := any(v).(type) {
	case store.MapSnapshot:
		return x.T
	case store.ResidencySnapshot:
		return x.T
	}
	return 0
}

// selectByTime keeps snapshots taken within one interval of the window.
func selectByTime[T timed](all []T, w Window, interval int64) []T {
	var out []T
	for _, s := range all {
		t := tOf(s)
		if t >= w.StartNS-interval && t <= w.EndNS+interval {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

// mappingSets returns ranges candidate in every selected snapshot, in any,
// and in the first recorded snapshot.
func mappingSets(sel, all []store.MapSnapshot) (stable, union, initial []proc.Range) {
	for i, s := range sel {
		c := proc.CandidateRanges(s.Maps)
		union = append(union, c...)
		if i == 0 {
			stable = c
			continue
		}
		stable = proc.Intersect(stable, c)
	}
	if len(all) > 0 {
		initial = proc.CandidateRanges(all[0].Maps)
	}
	return proc.Normalize(stable), proc.Normalize(union), initial
}

func intersectAll(snaps []store.ResidencySnapshot) []proc.Range {
	if len(snaps) == 0 {
		return nil
	}
	out := proc.Normalize(snaps[0].Present)
	for _, s := range snaps[1:] {
		out = proc.Intersect(out, s.Present)
	}
	return out
}

// regionStats fills per-region DAMON statistics from overlapping regions.
func (res *Result) regionStats(snaps []store.DAMONSnapshot, maxChecks, freqRate float64) {
	for i := range res.Regions {
		r := &res.Regions[i]
		var rateSum float64
		var freq int
		for _, s := range snaps {
			rs := s.Regions
			j := sort.Search(len(rs), func(k int) bool { return rs[k].End > r.Start })
			var accessed, frequent bool
			var weighted float64
			for ; j < len(rs) && rs[j].Start < r.End; j++ {
				rate := float64(rs[j].NrAccesses) / maxChecks
				ov := min(rs[j].End, r.End) - max(rs[j].Start, r.Start)
				weighted += rate * float64(ov)
				r.MaxRate = max(r.MaxRate, rate)
				accessed = accessed || rs[j].NrAccesses > 0
				frequent = frequent || rate >= freqRate
			}
			rateSum += weighted / float64(r.Size())
			if accessed {
				r.AccessedSnapshots++
				r.LatestAccessNS, r.LatestSource, r.LatestResolution = s.T, "damon", res.Window.AggrNS
			}
			if frequent {
				freq++
			}
		}
		if len(snaps) > 0 {
			r.MeanRate = rateSum / float64(len(snaps))
			r.FrequentShare = float64(freq) / float64(len(snaps))
		}
	}
}

// overlayPerf counts window samples per region; absence of hits is not evidence of no access.
func (res *Result) overlayPerf(in Input, o Options) {
	m := in.M
	res.Totals.PerfLost = m.Perf.Summary.Lost
	if len(in.Samples) == 0 {
		return
	}
	res.PerfComparable = m.Perf.Clock == perfmem.ClockMono
	if !res.PerfComparable {
		res.Notes = append(res.Notes, "perf clock differs from DAMON clock: samples overlaid by address only")
	}

	excluded := map[string]int{}
	top := map[string]int{}
	perRegion := map[int]map[string]int{}
	for _, s := range in.Samples {
		if s.Addr == 0 {
			excluded["no data address"]++
			continue
		}
		if res.PerfComparable && (s.TimeNS < res.Window.StartNS || s.TimeNS > res.Window.EndNS) {
			excluded["outside window (incl. after final DAMON snapshot)"]++
			continue
		}
		res.Totals.PerfSamples++
		top[symOr(s.Sym)]++
		if len(res.MatchSamples) < o.MaxMatches {
			res.MatchSamples = append(res.MatchSamples, SampleRef{s.TimeNS, s.Addr, s.Sym, s.Op})
		}

		i := res.Find(s.Addr)
		if i < 0 {
			res.Totals.PerfOutside++
			continue
		}
		r := &res.Regions[i]
		r.PerfSamples++
		if perRegion[i] == nil {
			perRegion[i] = map[string]int{}
		}
		perRegion[i][symOr(s.Sym)]++
		if res.PerfComparable && s.TimeNS > r.LatestAccessNS {
			r.LatestAccessNS, r.LatestSource, r.LatestResolution = s.TimeNS, "perf sample", 0
		}
	}
	for i, syms := range perRegion {
		res.Regions[i].TopSymbols = topN(syms, 3)
	}
	res.TopCode = topN(top, o.Top)
	res.Totals.PerfExcluded = topN(excluded, len(excluded))
}

func (res *Result) totals() {
	for _, r := range res.Regions {
		sz := r.Size()
		res.Totals.MappedBytes += sz
		switch r.Label {
		case Observed:
			res.Totals.ObservedBytes += sz
		case Frequent:
			res.Totals.ObservedBytes += sz
			res.Totals.FrequentBytes += sz
		case Quiet:
			res.Totals.QuietBytes += sz
		default:
			res.Totals.UnknownBytes += sz
		}
	}
}

// Find returns the region index containing a, or -1.
func (res *Result) Find(a uint64) int {
	i := sort.Search(len(res.Regions), func(k int) bool { return res.Regions[k].End > a })
	if i < len(res.Regions) && res.Regions[i].Start <= a {
		return i
	}
	return -1
}

// Label classifies [start, end) for whole-object checks: quiet only when
// the entire range lies in contiguous quiet-candidate regions.
func (res *Result) Label(start, end uint64) string {
	return res.label(start, end, false)
}

// Visit is Label plus per-region core-object byte accounting.
func (res *Result) Visit(start, end uint64) string {
	return res.label(start, end, true)
}

func (res *Result) label(start, end uint64, account bool) string {
	var quiet, observed, unknown bool
	cur := start
	i := sort.Search(len(res.Regions), func(k int) bool { return res.Regions[k].End > start })
	for ; i < len(res.Regions) && res.Regions[i].Start < end; i++ {
		r := &res.Regions[i]
		if r.Start > cur {
			unknown = true
		}
		if account {
			r.ObjectBytes += int64(min(r.End, end) - max(r.Start, start))
		}
		switch r.Label {
		case Quiet:
			quiet = true
		case Observed, Frequent:
			observed = true
		default:
			unknown = true
		}
		cur = r.End
	}
	if cur < end {
		unknown = true
	}

	switch {
	case quiet && !observed && !unknown:
		return objects.LabelQuiet
	case quiet:
		return objects.LabelMixed
	case observed:
		return objects.LabelObserved
	}
	return objects.LabelUnknown
}

func addPtr(p **uint64, v uint64) {
	if *p == nil {
		*p = new(uint64)
	}
	**p += v
}

func symOr(s string) string {
	if s == "" {
		return "[unknown]"
	}
	return s
}

func topN(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

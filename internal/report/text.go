package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/vrutkovs/golang-cold-memory/internal/analysis"
	"github.com/vrutkovs/golang-cold-memory/internal/objects"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
)

// Text writes a human-readable report.
func (r *Report) Text(w io.Writer, top int) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

	p("recording %s  status=%s", r.Dir, r.Status)
	p("target    pid=%d start=%d %s sha256=%.16s kernel=%s page=%d",
		r.Target.PID, r.Target.StartTime, r.Binary.GoVersion, r.Binary.SHA256, r.Kernel, r.PageSize)
	for _, e := range r.Errors {
		p("error     %s", e)
	}

	win := r.Window
	gaps := "none"
	if len(win.Gaps) > 0 {
		gaps = fmt.Sprintf("%d (quiet labels disabled)", len(win.Gaps))
	}
	p("window    %s, %d DAMON snapshots (aggr %s, sample %s), time gaps: %s",
		dur(win.EndNS-win.StartNS), win.Snapshots, dur(win.AggrNS), dur(win.SampleNS), gaps)

	p("evidence")
	for _, name := range []string{store.CapDAMON, store.CapPerf, store.CapResidency, store.CapCore, store.CapPprof} {
		c, ok := r.Capabilities[name]
		state := "present"
		switch {
		case !ok:
			state, c.Reason = "MISSING", "not attempted"
		case !c.Available:
			state = "MISSING"
		}
		p("  %-10s %-8s %s", name, state, c.Reason)
	}

	t := r.Totals
	p("totals (non-overlapping intervals)")
	p("  mapped candidates   %s", human(t.MappedBytes))
	if t.ResidentBytes != nil {
		p("  resident            %s", human(*t.ResidentBytes))
		p("  covered resident    %s", human(*t.CoveredResidentBytes))
	} else {
		p("  resident            omitted (residency unknown)")
	}
	p("  observed access     %s (frequently accessed %s)", human(t.ObservedBytes), human(t.FrequentBytes))
	p("  quiet candidate     %s", human(t.QuietBytes))
	p("  unknown             %s", human(t.UnknownBytes))
	p("  perf samples        %d in window, %d outside candidates, %d lost", t.PerfSamples, t.PerfOutside, t.PerfLost)
	for _, e := range t.PerfExcluded {
		p("    excluded %-40s %d", e.Key, e.Count)
	}

	if len(r.TopCode) > 0 {
		p("top code paths (perf samples; absence is not evidence of no access)")
		for _, c := range r.TopCode {
			p("  %7d  %s", c.Count, c.Key)
		}
	}

	r.textRegions(p, top)
	r.textMap.Text(w)
	r.textObjects(p, top)
	r.textDisappearances(p, top)

	if len(r.Pprof) > 0 || r.PprofErr != "" {
		p("heap pprof (sampled allocation sites; separate context, not joined to addresses)")
		if r.PprofErr != "" {
			p("  error: %s", r.PprofErr)
		}
		for _, s := range r.Pprof {
			p("  %12s  %s", human(uint64(max(s.Bytes, 0))), s.Function)
		}
	}

	for _, n := range r.Notes {
		p("note      %s", n)
	}
}

// textDisappearances shows only changes in reachability across two core dumps.
func (r *Report) textDisappearances(p func(string, ...any), top int) {
	if r.DisappearancesErr != "" {
		p("possible disappearances unavailable: %s", r.DisappearancesErr)
		return
	}
	if !r.Settings.TrackDisappearances && r.DisappearedCount == 0 {
		return
	}
	p("possible disappearances: %d objects (%s); reachable at start core, absent at end core; times since start core, not proof of GC (address reuse can hide changes)",
		r.DisappearedCount, human(uint64(r.DisappearedBytes)))
	for i, x := range r.Disappearances {
		if i == top {
			break
		}
		p("  %#x %10s %-40s last seen %s, first absent %s", x.Addr, human(uint64(x.Bytes)), x.Type,
			dur(x.LastSeenNS-r.StartCoreNS), dur(x.FirstAbsentNS-r.StartCoreNS))
	}
}

func (r *Report) textRegions(p func(string, ...any), top int) {
	regs := append([]analysis.Region(nil), r.Regions...)
	sort.SliceStable(regs, func(i, j int) bool { return regs[i].Size() > regs[j].Size() })
	p("regions (largest %d of %d; full list in --json)", min(top, len(regs)), len(regs))
	for i, g := range regs {
		if i == top {
			break
		}
		latest := "-"
		if g.LatestAccessNS > 0 {
			latest = fmt.Sprintf("%s before end (%s)", dur(r.Window.EndNS-g.LatestAccessNS), g.LatestSource)
		}
		p("  %#x-%#x %10s %-19s rate max %.2f mean %.3f perf %d latest %s",
			g.Start, g.End, human(g.Size()), g.Label, g.MaxRate, g.MeanRate, g.PerfSamples, latest)
		if len(g.Reasons) > 0 {
			p("      reasons: %s", strings.Join(g.Reasons, "; "))
		}
		for _, s := range g.TopSymbols {
			p("      %5d  %s", s.Count, s.Key)
		}
	}
}

func (r *Report) textObjects(p func(string, ...any), top int) {
	if r.ObjectsErr != "" {
		p("objects   unavailable: %s", r.ObjectsErr)
		return
	}
	o := r.Objects
	if o == nil {
		return
	}
	p("objects at core time (%s; %d reachable, %s; core %s after final snapshot)",
		o.GoVersion, o.Objects, human(uint64(o.Bytes)), dur(r.CoreGapNS))
	if len(r.CoreMissing) > 0 {
		p("  core lacks %d candidate ranges; affected objects unknown", len(r.CoreMissing))
	}
	for _, d := range o.Diagnostics {
		p("  incomplete: %s", d)
	}

	p("  by type (bytes by label)")
	for i, g := range o.ByType {
		if i == top {
			break
		}
		p("    %10s %7d  %-40s %s", human(uint64(g.Bytes)), g.Count, g.Key, labels(g.Labels))
	}
	r.textSites(p, top)
	if len(o.ByOwner) > 0 {
		p("  quiet/mixed by owner (listed objects only)")
		for i, g := range o.ByOwner {
			if i == top {
				break
			}
			p("    %10s %7d  %s", human(uint64(g.Bytes)), g.Count, g.Key)
		}
	}
	for i, x := range o.Listed {
		if i == top {
			break
		}
		p("  %-15s %#x %10s %s", x.Label, x.Addr, human(uint64(x.Size)), x.Type)
		if x.SliceLen != nil {
			p("      slice len=%d cap=%d", *x.SliceLen, *x.SliceCap)
		}
		if len(x.Path) > 0 {
			p("      path: %s", strings.Join(x.Path, " → "))
		}
		for _, n := range x.Notes {
			p("      note: %s", n)
		}
	}

	matched := 0
	for _, m := range r.SampleMatches {
		if m.Object != nil {
			matched++
		}
	}
	p("  perf samples inside core-time objects: %d of %d (address reuse possible)", matched, len(r.SampleMatches))
}

// textSites lists sampled allocation sites, least-used first: rows with
// quiet bytes are candidates for allocations that are no longer used.
func (r *Report) textSites(p func(string, ...any), top int) {
	o := r.Objects
	rate := "unknown"
	if o.ProfileRate >= 0 {
		rate = fmt.Sprint(o.ProfileRate)
	}
	p("  by type and allocation site (memprofile-sampled: %d of %d objects, %s of %s; MemProfileRate=%s)",
		o.Sampled, o.Objects, human(uint64(o.SampledBytes)), human(uint64(o.Bytes)), rate)
	if o.Sampled == 0 {
		p("    no sampled objects. MemProfileRate=0 means the binary never links runtime.MemProfile (e.g. no net/http/pprof import);")
		p("    otherwise restart the target with GODEBUG=memprofilerate=N (lower N = more coverage, more overhead)")
		return
	}

	var rows []objects.Group
	for _, g := range o.BySite {
		if !strings.HasSuffix(g.Key, objects.NoSite) {
			rows = append(rows, g)
		}
	}
	idle := func(g objects.Group) int64 { return g.Labels[objects.LabelQuiet]*2 + g.Labels[objects.LabelMixed] }
	sort.SliceStable(rows, func(i, j int) bool { return idle(rows[i]) > idle(rows[j]) })
	typeWidth, siteWidth := len("type"), len("allocation site")
	for i, g := range rows {
		if i == top {
			break
		}
		typ, site, _ := strings.Cut(g.Key, " ← ")
		typeWidth = max(typeWidth, len(typ))
		siteWidth = max(siteWidth, len(site))
	}
	p("    %10s %5s  %-*s  %-*s  %s", "size", "count", typeWidth, "type", siteWidth, "allocation site", "bytes by label")
	for i, g := range rows {
		if i == top {
			break
		}
		typ, site, _ := strings.Cut(g.Key, " ← ")
		p("    %10s %5d  %-*s  %-*s  %s", human(uint64(g.Bytes)), g.Count, typeWidth, typ, siteWidth, site, labels(g.Labels))
	}
}

func labels(m map[string]int64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, human(uint64(m[k]))))
	}
	return strings.Join(parts, " ")
}

func human(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func dur(ns int64) string {
	return time.Duration(ns).Round(time.Millisecond).String()
}

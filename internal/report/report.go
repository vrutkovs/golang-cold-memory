// Package report analyzes a recording offline.
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/pprof/profile"

	"github.com/vrutkovs/golang-cold-memory/internal/analysis"
	"github.com/vrutkovs/golang-cold-memory/internal/coredump"
	"github.com/vrutkovs/golang-cold-memory/internal/heatmap"
	"github.com/vrutkovs/golang-cold-memory/internal/objects"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
)

// Options configure a report.
type Options struct {
	analysis.Options
	Objects    bool
	MaxPaths   int
	TopObjects int
	Heatmap    heatmap.Options
}

// textHeatmap bounds the terminal heatmap.
var textHeatmap = heatmap.Options{MaxRows: 24, MaxCols: 60, MaxTypes: 10}

// SampleMatch ties one in-window perf sample to a core-time object candidate.
type SampleMatch struct {
	analysis.SampleRef
	Object      *objects.Obj `json:"object,omitempty"`
	Offset      int64        `json:"offset,omitempty"`
	Reason      string       `json:"reason,omitempty"`
	CoreDelayNS int64        `json:"core_delay_ns,omitempty"`
	Confidence  string       `json:"confidence"`
}

// PprofSite is one sampled allocation site from an optional heap profile.
type PprofSite struct {
	Function string `json:"function"`
	Bytes    int64  `json:"inuse_bytes"`
}

// Report is the full offline result.
type Report struct {
	Dir          string                      `json:"dir"`
	Status       string                      `json:"status"`
	Errors       []string                    `json:"errors,omitempty"`
	Target       proc.Identity               `json:"target"`
	Binary       proc.Binary                 `json:"binary"`
	Kernel       string                      `json:"kernel"`
	PageSize     uint64                      `json:"page_size"`
	Settings     store.Settings              `json:"settings"`
	Capabilities map[string]store.Capability `json:"capabilities"`
	*analysis.Result
	DAMONSnapshots []store.DAMONSnapshot `json:"damon_snapshots"`
	SampleMatches  []SampleMatch         `json:"sample_matches,omitempty"`
	Objects        *objects.Result       `json:"objects,omitempty"`
	ObjectsErr     string                `json:"objects_error,omitempty"`
	CoreMissing    []proc.Range          `json:"core_missing_ranges,omitempty"`
	CoreGapNS      int64                 `json:"core_after_final_snapshot_ns,omitempty"`
	Pprof          []PprofSite           `json:"pprof_allocation_sites,omitempty"`
	PprofErr       string                `json:"pprof_error,omitempty"`
	Heatmap        *heatmap.Heatmap      `json:"heatmap"`

	textMap    *heatmap.Heatmap
	sites      map[string][]proc.Range      // sampled object ranges by type ← site
	quietSites map[uint64]map[string]uint64 // quiet region start → type/site → overlapping bytes
}

// addRange appends [start, end) to m[key], merging adjacent objects (e.g. one span).
func addRange(m map[string][]proc.Range, key string, start, end uint64) {
	rs := m[key]
	if n := len(rs); n > 0 && rs[n-1].End == start {
		rs[n-1].End = end
	} else {
		rs = append(rs, proc.Range{Start: start, End: end})
	}
	m[key] = rs
}

// Build loads dir and analyzes it.
func Build(dir string, o Options) (*Report, error) {
	m, err := store.ReadManifest(dir)
	if err != nil {
		return nil, fmt.Errorf("not a gocold recording: %w", err)
	}

	in := analysis.Input{M: m}
	var loadErrs []string
	load := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			loadErrs = append(loadErrs, err.Error())
		}
	}
	in.Maps, err = store.ReadJSONL[store.MapSnapshot](filepath.Join(dir, store.MapsFile))
	load(err)
	in.Residency, err = store.ReadJSONL[store.ResidencySnapshot](filepath.Join(dir, store.ResidencyFile))
	load(err)
	in.DAMON, err = store.ReadJSONL[store.DAMONSnapshot](filepath.Join(dir, store.DAMONFile))
	load(err)
	if m.Capabilities[store.CapPerf].Available {
		in.Samples, err = perfmem.ReadSamples(filepath.Join(dir, store.PerfSamples))
		load(err)
	}

	res := analysis.Run(in, o.Options)
	r := &Report{
		Dir: dir, Status: m.Status, Errors: append(m.Errors, loadErrs...),
		Target: m.Target, Binary: m.Binary, Kernel: m.Host.Kernel, PageSize: m.Host.PageSize,
		Settings: m.Settings, Capabilities: m.Capabilities, Result: res,
		CoreMissing: m.Core.Missing, CoreGapNS: m.Core.SnapshotGapNS,
	}
	for _, s := range in.DAMON {
		if s.T >= res.Window.StartNS && s.T <= res.Window.EndNS {
			r.DAMONSnapshots = append(r.DAMONSnapshots, s)
		}
	}
	if m.Status != store.StatusComplete {
		r.Notes = append(r.Notes, "recording status "+m.Status+": evidence is partial")
	}

	if o.Objects && m.Capabilities[store.CapCore].Available {
		r.objects(dir, m, o)
	}
	if m.Capabilities[store.CapPprof].Available {
		r.pprof(filepath.Join(dir, store.PprofFile), o.Top)
	}

	hm := heatmap.Input{In: in, Res: res, Snaps: r.DAMONSnapshots, Sites: r.sites, Option: o.Heatmap}
	r.Heatmap = heatmap.Build(hm)
	hm.Option = textHeatmap
	r.textMap = heatmap.Build(hm)
	return r, nil
}

func (r *Report) objects(dir string, m *store.Manifest, o Options) {
	exe := filepath.Join(dir, coredump.ExeName)
	sum, err := proc.HashFile(exe)
	if err != nil {
		r.ObjectsErr = err.Error()
		return
	}
	if sum != m.Binary.SHA256 || sum != m.Core.ExeSHA256 {
		r.ObjectsErr = "executable does not match recorded target binary; refusing binary/core pair"
		return
	}

	p, err := objects.Load(filepath.Join(dir, m.Core.Path), exe)
	if err != nil {
		r.ObjectsErr = err.Error()
		return
	}
	if p.BuildVersion() != m.Binary.GoVersion {
		r.ObjectsErr = fmt.Sprintf("core runtime %s != binary %s; refusing mismatched pair", p.BuildVersion(), m.Binary.GoVersion)
		return
	}

	addrs := make([]uint64, len(r.MatchSamples))
	for i, s := range r.MatchSamples {
		addrs[i] = s.Addr
	}
	r.sites = map[string][]proc.Range{}
	each := func(name, site string, start, end uint64) {
		if site != objects.NoSite {
			addRange(r.sites, objects.SiteKey(name, site), start, end)
		}
		r.addQuietOverlap(name, site, start, end)
	}
	res, err := objects.Analyze(p, r.Visit, r.Label, addrs, objects.Options{
		MaxPaths: o.MaxPaths, TopObjects: o.TopObjects, Sites: objects.NewSites(p), Each: each})
	if err != nil {
		r.ObjectsErr = err.Error()
		return
	}
	r.Objects = res

	for i, mt := range res.Matches {
		s := r.MatchSamples[i]
		sm := SampleMatch{SampleRef: s, Object: mt.Object, Offset: mt.Offset, Reason: mt.Reason, Confidence: "none"}
		if mt.Object != nil {
			// Address reuse between sample and core cannot be excluded.
			sm.Confidence = "core-time object candidate"
			if r.PerfComparable && m.Core.StartNS > 0 {
				sm.CoreDelayNS = m.Core.StartNS - s.TimeNS
			}
		}
		r.SampleMatches = append(r.SampleMatches, sm)
	}
}

// addQuietOverlap attributes only object bytes inside quiet regions, not whole objects.
func (r *Report) addQuietOverlap(name, site string, start, end uint64) {
	for i := sort.Search(len(r.Regions), func(i int) bool { return r.Regions[i].End > start }); i < len(r.Regions) && r.Regions[i].Start < end; i++ {
		region := r.Regions[i]
		if region.Label != analysis.Quiet {
			continue
		}
		if r.quietSites == nil {
			r.quietSites = make(map[uint64]map[string]uint64)
		}
		if r.quietSites[region.Start] == nil {
			r.quietSites[region.Start] = make(map[string]uint64)
		}
		r.quietSites[region.Start][objects.SiteKey(name, site)] += min(end, region.End) - max(start, region.Start)
	}
}

// pprof summarizes sampled allocation sites; never joined to addresses.
func (r *Report) pprof(path string, top int) {
	f, err := os.Open(path)
	if err != nil {
		r.PprofErr = err.Error()
		return
	}
	defer f.Close()
	p, err := profile.Parse(f)
	if err != nil {
		r.PprofErr = err.Error()
		return
	}

	idx := len(p.SampleType) - 1
	for i, st := range p.SampleType {
		if st.Type == "inuse_space" {
			idx = i
		}
	}
	sites := map[string]int64{}
	for _, s := range p.Sample {
		fn := "[unknown]"
		if len(s.Location) > 0 && len(s.Location[0].Line) > 0 && s.Location[0].Line[0].Function != nil {
			fn = s.Location[0].Line[0].Function.Name
		}
		sites[fn] += s.Value[idx]
	}
	for k, v := range sites {
		r.Pprof = append(r.Pprof, PprofSite{k, v})
	}
	sort.Slice(r.Pprof, func(i, j int) bool { return r.Pprof[i].Bytes > r.Pprof[j].Bytes })
	if len(r.Pprof) > top {
		r.Pprof = r.Pprof[:top]
	}
}

// WriteHTML writes the heatmap page to path (0600, never overwriting).
func (r *Report) WriteHTML(path string) error {
	m := heatmap.Meta{Dir: r.Dir, PID: r.Target.PID, GoVersion: r.Binary.GoVersion,
		Kernel: r.Kernel, QuietBytes: human(r.Totals.QuietBytes)}
	var quietRegions []analysis.Region
	for _, region := range r.Regions {
		if region.Label == analysis.Quiet {
			quietRegions = append(quietRegions, region)
		}
	}
	sort.Slice(quietRegions, func(i, j int) bool { return quietRegions[i].Size() > quietRegions[j].Size() })
	for _, region := range quietRegions {
		view := heatmap.QuietRegionView{
			Address: fmt.Sprintf("%#x–%#x", region.Start, region.End),
			Size:    human(region.Size()), CoreObjects: human(uint64(region.ObjectBytes)),
		}
		for key, bytes := range r.quietSites[region.Start] {
			view.Sites = append(view.Sites, heatmap.QuietSiteView{Key: key, Bytes: human(bytes)})
		}
		sort.Slice(view.Sites, func(i, j int) bool {
			return r.quietSites[region.Start][view.Sites[i].Key] > r.quietSites[region.Start][view.Sites[j].Key]
		})
		m.QuietRegions = append(m.QuietRegions, view)
	}
	if r.Objects != nil {
		m.HasCore = true
		var quiet int64
		for _, g := range r.Objects.ByType {
			quiet += g.Labels[objects.LabelQuiet]
		}
		m.QuietObjects = human(uint64(quiet))
	}
	return r.Heatmap.WriteHTML(path, m)
}

// JSON writes the full report.
func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

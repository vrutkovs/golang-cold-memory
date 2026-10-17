// Package record collects access evidence from a running Go process.
//
// It never forces GC, never changes target configuration and only cleans
// up the DAMON monitor it created.
package record

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vrutkovs/golang-cold-memory/internal/coredump"
	"github.com/vrutkovs/golang-cold-memory/internal/damon"
	"github.com/vrutkovs/golang-cold-memory/internal/host"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
)

// Tool is the manifest tool identifier.
const Tool = "gocold"

const (
	pprofTimeout  = 30 * time.Second
	pprofMaxBytes = 256 << 20
)

// Options configure a recording.
type Options struct {
	PID              int
	Duration         time.Duration
	Out              string
	Objects          bool
	SnapshotInterval time.Duration
	MapsInterval     time.Duration
	SampleUS         uint64
	AggrUS           uint64
	UpdateUS         uint64
	MinRegions       int
	MaxRegions       int
	MaxRanges        int
	MaxSnapshots     int
	PerfPeriod       int
	PerfMaxSize      uint64
	NoPerf           bool
	PprofURL         string
	DAMONRoot        string
	DAMONFS          damon.FS // overrides DAMONRoot (tests)
}

func (o Options) damonFS() damon.FS {
	if o.DAMONFS != nil {
		return o.DAMONFS
	}
	return damon.OSFS{Root: o.DAMONRoot}
}

// Settings converts options to manifest settings.
func (o Options) Settings() store.Settings {
	return store.Settings{
		DurationNS:         int64(o.Duration),
		SnapshotIntervalNS: int64(o.SnapshotInterval),
		MapsIntervalNS:     int64(o.MapsInterval),
		SampleUS:           o.SampleUS,
		AggrUS:             o.AggrUS,
		UpdateUS:           o.UpdateUS,
		MinRegions:         o.MinRegions,
		MaxRegions:         o.MaxRegions,
		MaxRanges:          o.MaxRanges,
		MaxSnapshots:       o.MaxSnapshots,
		PerfPeriod:         o.PerfPeriod,
		Objects:            o.Objects,
		PprofURL:           o.PprofURL,
	}
}

// Validate checks option bounds.
func (o Options) Validate() error {
	switch {
	case o.PID <= 0:
		return fmt.Errorf("--pid required")
	case o.Out == "":
		return fmt.Errorf("--out required")
	case o.Duration <= 0:
		return fmt.Errorf("--duration must be positive")
	case o.SampleUS == 0 || o.AggrUS < o.SampleUS:
		return fmt.Errorf("need 0 < sample interval <= aggregation interval")
	case o.SnapshotInterval < time.Duration(o.AggrUS)*time.Microsecond:
		return fmt.Errorf("--snapshot-interval must be >= aggregation interval")
	case o.MinRegions < 3 || o.MaxRegions < o.MinRegions:
		return fmt.Errorf("need 3 <= min regions <= max regions")
	case o.MaxRanges < 1 || o.MaxRanges*2 > o.MaxRegions:
		return fmt.Errorf("--max-ranges must be in [1, max-regions/2]")
	case o.MaxSnapshots < 1:
		return fmt.Errorf("--max-snapshots must be positive")
	}
	if o.PprofURL != "" {
		u, err := url.Parse(o.PprofURL)
		if err != nil {
			return err
		}
		if u.Query().Has("gc") {
			return fmt.Errorf("--pprof-url must not request gc (never force GC)")
		}
	}
	return nil
}

// Snapshots returns the bounded snapshot count for o.
func (o Options) Snapshots() int {
	return min(o.MaxSnapshots, int(o.Duration/o.SnapshotInterval)+1)
}

// Estimate bounds disk use in bytes for a recording.
func Estimate(o Options, maps []proc.Mapping, exeSize int64) uint64 {
	const (
		regionBytes  = 96
		mappingBytes = 160
		rangeBytes   = 48
	)
	var rss uint64
	for _, m := range maps {
		rss += m.Rss
	}
	mapsSnaps := uint64(o.Duration/o.MapsInterval) + 2

	est := uint64(o.Snapshots()) * uint64(o.MaxRegions) * regionBytes
	est += mapsSnaps * uint64(len(maps)) * mappingBytes
	est += mapsSnaps * uint64(o.MaxRanges) * rangeBytes * 64
	if !o.NoPerf {
		est += o.PerfMaxSize * 2 // perf.data + converted samples
	}
	if o.Objects {
		est += rss + rss/10 + uint64(exeSize)
	}
	return est
}

// Run records evidence; the manifest reflects partial results on failure.
func Run(ctx context.Context, o Options, log io.Writer) error {
	if err := o.Validate(); err != nil {
		return err
	}

	// Checks before anything changes.
	id, err := proc.Pin(o.PID)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	bin := proc.InspectBinary(proc.ExePath(o.PID))
	if bin.GoVersion == "" {
		return fmt.Errorf("target is not a readable Go binary: %s", bin.Err)
	}
	if !proc.GoSupported(bin.GoVersion) {
		return fmt.Errorf("unsupported Go runtime %s (need go1.%d+)", bin.GoVersion, proc.MinGoMinor)
	}
	if o.Objects && !bin.DWARF {
		return fmt.Errorf("--objects needs DWARF; binary is stripped")
	}
	maps, err := proc.ReadMaps(o.PID)
	if err != nil {
		return fmt.Errorf("read maps: %w", err)
	}
	cands := proc.SelectCandidates(maps, o.MaxRanges)
	if len(cands) == 0 {
		return fmt.Errorf("no writable anonymous ranges found")
	}

	damonOK := damon.Probe(o.damonFS()).Readable
	if !damonOK && (o.NoPerf || len(perfmem.ProbeEvents(ctx).Chosen) == 0) {
		return fmt.Errorf("neither DAMON nor perf memory sampling is available; see `gocold probe`")
	}

	if err := store.CreateDir(o.Out); err != nil {
		return err
	}
	exeSize := int64(0)
	if st, err := os.Stat(proc.ExePath(o.PID)); err == nil {
		exeSize = st.Size()
	}
	need := Estimate(o, maps, exeSize)
	free, err := host.FreeBytes(o.Out)
	if err != nil {
		return err
	}
	if free < need {
		return fmt.Errorf("need ~%d MiB free in %s, have %d MiB", need>>20, o.Out, free>>20)
	}

	r := &run{o: o, id: id, log: log, m: &store.Manifest{
		Tool:         Tool,
		Status:       store.StatusRunning,
		Target:       id,
		Binary:       bin,
		Host:         host.Collect(),
		Tools:        toolVersions(),
		Settings:     o.Settings(),
		Candidates:   cands,
		Capabilities: map[string]store.Capability{},
	}}
	r.m.StartNS = r.m.Host.MonotonicStart
	if err := r.save(); err != nil {
		return err
	}
	return r.run(ctx, cands)
}

type run struct {
	o   Options
	id  proc.Identity
	m   *store.Manifest
	log io.Writer

	maps, res, dmn *store.JSONL
	mon            *damon.Monitor
	perf           *perfmem.Recorder
	perfPath       string
	perfStopped    bool
	lastSnap       int64
}

func (r *run) save() error { return store.WriteManifest(r.o.Out, r.m) }

func (r *run) fail(err error) {
	r.m.Errors = append(r.m.Errors, err.Error())
	fmt.Fprintln(r.log, "error:", err)
}

func (r *run) capability(name string, ok bool, reason string) {
	r.m.Capabilities[name] = store.Capability{Available: ok, Reason: reason}
}

func (r *run) run(ctx context.Context, cands []proc.Range) (err error) {
	out := r.o.Out
	if r.maps, err = store.CreateJSONL(filepath.Join(out, store.MapsFile)); err != nil {
		return err
	}
	defer r.maps.Close()
	if r.res, err = store.CreateJSONL(filepath.Join(out, store.ResidencyFile)); err != nil {
		return err
	}
	defer r.res.Close()
	if r.dmn, err = store.CreateJSONL(filepath.Join(out, store.DAMONFile)); err != nil {
		return err
	}
	defer r.dmn.Close()

	// Cleanup runs on every exit path, including interruption.
	// Defers run in reverse: monitor -> perf stop -> perf convert -> manifest.
	defer func() {
		if r.m.Status == store.StatusRunning {
			r.m.Status = store.StatusIncomplete
		}
		if serr := r.save(); err == nil {
			err = serr
		}
	}()
	defer r.convertPerf(context.WithoutCancel(ctx))
	defer r.stopPerf()
	defer r.stopMonitor()

	r.sampleMaps(cands)
	r.startMonitor(cands)
	r.startPerf(ctx)
	if !r.m.Capabilities[store.CapDAMON].Available && !r.m.Capabilities[store.CapPerf].Available {
		return fmt.Errorf("could not start DAMON or perf: %s; %s",
			r.m.Capabilities[store.CapDAMON].Reason, r.m.Capabilities[store.CapPerf].Reason)
	}
	_ = r.save()

	status := r.loop(ctx, cands)
	r.m.EndNS = host.Mono()
	r.sampleMaps(cands)

	// Order: final DAMON snapshot (taken in loop) -> stop monitor -> stop perf
	// -> core -> slow perf conversion, keeping the core close to the snapshot.
	r.stopMonitor()
	r.stopPerf()
	r.m.Status = status
	_ = r.save()

	if status != store.StatusComplete {
		r.capability(store.CapCore, false, "not captured: run "+status)
		return fmt.Errorf("recording %s", status)
	}
	if r.o.Objects {
		r.captureCore(ctx, cands)
	} else {
		r.capability(store.CapCore, false, "not requested (--objects)")
	}
	r.convertPerf(context.WithoutCancel(ctx))
	if r.o.PprofURL != "" {
		r.fetchPprof(ctx)
	} else {
		r.capability(store.CapPprof, false, "no --pprof-url supplied")
	}
	return nil
}

// loop takes DAMON snapshots until duration, bound or failure.
func (r *run) loop(ctx context.Context, cands []proc.Range) string {
	deadline := time.Now().Add(r.o.Duration)
	nextMaps := time.Now().Add(r.o.MapsInterval)
	limit := r.o.Snapshots()

	for taken := 0; taken < limit; {
		tick := time.Now()
		if err := r.id.Check(); err != nil {
			r.fail(err)
			return store.StatusIncomplete
		}

		if r.mon != nil {
			regs, err := r.mon.Snapshot()
			if err != nil {
				r.fail(fmt.Errorf("DAMON snapshot: %w", err))
				if errors.Is(err, damon.ErrOwnership) {
					r.mon = nil // not ours anymore: never touch it
				}
				return store.StatusIncomplete
			}
			r.lastSnap = host.Mono()
			if _, err := r.dmn.Write(store.DAMONSnapshot{T: r.lastSnap, Regions: regs}); err != nil {
				r.fail(err)
				return store.StatusIncomplete
			}
		}
		taken++

		if time.Now().After(nextMaps) {
			r.sampleMaps(cands)
			nextMaps = time.Now().Add(r.o.MapsInterval)
		}
		if !time.Now().Before(deadline) {
			return store.StatusComplete
		}

		wait := time.Until(tick.Add(r.o.SnapshotInterval))
		if r.mon != nil {
			// Snapshot blocks until the next aggregation; don't add more delay.
			wait -= time.Duration(r.o.AggrUS) * time.Microsecond
		}
		select {
		case <-ctx.Done():
			return store.StatusInterrupted
		case <-time.After(max(wait, 0)):
		}
	}
	return store.StatusComplete
}

// sampleMaps saves smaps and resident pages of candidate ranges.
func (r *run) sampleMaps(cands []proc.Range) {
	t := host.Mono()
	maps, err := proc.ReadMaps(r.o.PID)
	if err != nil {
		r.fail(fmt.Errorf("read maps: %w", err))
		return
	}
	if _, err := r.maps.Write(store.MapSnapshot{T: t, Maps: maps}); err != nil {
		r.fail(err)
	}

	if c, ok := r.m.Capabilities[store.CapResidency]; ok && !c.Available {
		return
	}
	present, err := proc.Resident(r.o.PID, proc.Intersect(cands, proc.CandidateRanges(maps)), r.m.Host.PageSize)
	if err != nil {
		r.capability(store.CapResidency, false, "pagemap unreadable: "+err.Error())
		return
	}
	r.capability(store.CapResidency, true, "")
	if _, err := r.res.Write(store.ResidencySnapshot{T: t, Present: present}); err != nil {
		r.fail(err)
	}
}

func (r *run) startMonitor(cands []proc.Range) {
	fs := r.o.damonFS()
	st := damon.Probe(fs)
	if !st.Readable {
		r.capability(store.CapDAMON, false, st.Err)
		return
	}

	cfg := damon.Config{
		PID: r.o.PID, Ranges: cands,
		SampleUS: r.o.SampleUS, AggrUS: r.o.AggrUS, UpdateUS: r.o.UpdateUS,
		MinRegions: max(r.o.MinRegions, len(cands)), MaxRegions: r.o.MaxRegions,
	}
	mon, err := damon.Start(fs, cfg)
	if err != nil {
		r.capability(store.CapDAMON, false, err.Error())
		return
	}
	r.mon = mon
	r.m.DAMON = &cfg
	r.capability(store.CapDAMON, true, "")
}

func (r *run) stopMonitor() {
	if r.mon == nil {
		return
	}
	if err := r.mon.Close(); err != nil {
		r.fail(fmt.Errorf("DAMON cleanup: %w", err))
	}
	r.mon = nil
}

func (r *run) startPerf(ctx context.Context) {
	if r.o.NoPerf {
		r.capability(store.CapPerf, false, "disabled (--no-perf)")
		return
	}
	p := perfmem.ProbeEvents(ctx)
	if len(p.Chosen) == 0 {
		r.capability(store.CapPerf, false, "no memory-sampling PMU events: "+p.Err)
		return
	}

	r.perfPath = p.PerfPath
	out := filepath.Join(r.o.Out, store.PerfData)
	rec, err := perfmem.Start(p.PerfPath, r.o.PID, p.Chosen, r.o.PerfPeriod, r.o.PerfMaxSize, out)
	if err != nil {
		r.capability(store.CapPerf, false, err.Error())
		return
	}
	r.perf = rec
	r.m.Perf = store.Perf{Events: p.Chosen, Args: rec.Args, Clock: rec.Clock, StartNS: host.Mono()}
	r.capability(store.CapPerf, true, "")
}

// stopPerf flushes perf.data; conversion happens later in convertPerf.
func (r *run) stopPerf() {
	if r.perf == nil {
		return
	}
	log, err := r.perf.Stop()
	r.perf = nil
	r.perfStopped = true
	r.m.Perf.StopNS = host.Mono()
	r.m.Perf.Log = tail(log, 4096)
	if err != nil {
		r.fail(err)
	}
}

// convertPerf extracts samples once from a stopped recording.
func (r *run) convertPerf(ctx context.Context) {
	if !r.perfStopped {
		return
	}
	r.perfStopped = false

	_ = os.Chmod(filepath.Join(r.o.Out, store.PerfData), 0o600)
	sum := perfmem.Convert(ctx, r.perfPath, filepath.Join(r.o.Out, store.PerfData), filepath.Join(r.o.Out, store.PerfSamples))
	r.m.Perf.Summary = sum
	if sum.Err != "" {
		r.capability(store.CapPerf, false, sum.Err)
	}
}

// captureCore saves the exact executable and a core right after the final snapshot.
func (r *run) captureCore(ctx context.Context, cands []proc.Range) {
	c := &r.m.Core
	c.FinalSnapshotNS = r.lastSnap
	if err := r.id.Check(); err != nil {
		r.capability(store.CapCore, false, err.Error())
		return
	}

	sum, err := coredump.CopyExe(r.o.Out, r.o.PID)
	if err != nil {
		r.capability(store.CapCore, false, "copy exe: "+err.Error())
		return
	}
	c.ExeSHA256 = sum
	if sum != r.m.Binary.SHA256 {
		r.capability(store.CapCore, false, "executable changed during run")
		return
	}

	c.StartNS = host.Mono()
	path, log, err := coredump.Capture(ctx, r.o.Out, r.o.PID)
	c.EndNS = host.Mono()
	c.Log = tail(string(log), 4096)
	if r.lastSnap > 0 {
		c.SnapshotGapNS = c.StartNS - r.lastSnap
	}
	if err != nil {
		r.capability(store.CapCore, false, err.Error())
		return
	}
	if err := r.id.Check(); err != nil {
		r.capability(store.CapCore, false, "PID changed during core capture")
		return
	}
	c.Path = filepath.Base(path)

	if c.Missing, err = coredump.Missing(path, cands); err != nil {
		r.capability(store.CapCore, false, err.Error())
		return
	}
	r.capability(store.CapCore, true, "")
	fmt.Fprintf(r.log, "core: %s (%.1fs pause, %.2fs after final snapshot)\n", path,
		time.Duration(c.EndNS-c.StartNS).Seconds(), time.Duration(c.SnapshotGapNS).Seconds())
}

// fetchPprof saves an existing heap profile endpoint without forcing GC.
func (r *run) fetchPprof(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, pprofTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.o.PprofURL, nil)
	if err != nil {
		r.capability(store.CapPprof, false, err.Error())
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.capability(store.CapPprof, false, err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.capability(store.CapPprof, false, resp.Status)
		return
	}

	f, err := os.OpenFile(filepath.Join(r.o.Out, store.PprofFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		r.capability(store.CapPprof, false, err.Error())
		return
	}
	_, err = io.Copy(f, io.LimitReader(resp.Body, pprofMaxBytes))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		r.capability(store.CapPprof, false, err.Error())
		return
	}
	r.capability(store.CapPprof, true, "")
}

func toolVersions() map[string]string {
	v := map[string]string{"gocold-go": runtime.Version()}
	for name, args := range map[string][]string{"perf": {"--version"}, "gdb": {"--version"}} {
		out, err := exec.Command(name, args...).Output()
		if err != nil {
			continue
		}
		v[name] = strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	}
	return v
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

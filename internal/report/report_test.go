package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"

	"github.com/vrutkovs/golang-cold-memory/internal/analysis"
	"github.com/vrutkovs/golang-cold-memory/internal/coredump"
	"github.com/vrutkovs/golang-cold-memory/internal/damon"
	"github.com/vrutkovs/golang-cold-memory/internal/heatmap"
	"github.com/vrutkovs/golang-cold-memory/internal/objects"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/store"
	"github.com/vrutkovs/golang-cold-memory/internal/testutil"
)

const sec = int64(1e9)

func reportOpts() Options {
	return Options{
		Options:    analysis.Options{FreqRate: 0.5, FreqShare: 0.5, Top: 10, MaxMatches: 100},
		Objects:    true,
		MaxPaths:   50,
		TopObjects: 20,
		Heatmap:    heatmap.Options{MaxRows: 64, MaxCols: 30, MaxTypes: 10},
	}
}

func TestTextSitesColumns(t *testing.T) {
	r := &Report{Objects: &objects.Result{
		Objects: 2, Sampled: 2, Bytes: 8192, SampledBytes: 8192,
		BySite: []objects.Group{
			{Key: objects.SiteKey("[]byte", "main.alloc (x/a.go:1)"), Bytes: 4096, Count: 1},
			{Key: objects.SiteKey(strings.Repeat("X", 50), "main.long"), Bytes: 4096, Count: 1},
		},
	}}
	var out bytes.Buffer
	r.textSites(func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) })
	lines := strings.Split(out.String(), "\n")
	if len(lines) < 3 || !strings.Contains(lines[1], "type") || !strings.Contains(lines[1], "allocation site") {
		t.Fatalf("missing column headers: %q", out.String())
	}
	if !strings.Contains(lines[2], "[]byte") || !strings.Contains(lines[2], "main.alloc (x/a.go:1)") || strings.Contains(lines[2], " ← ") {
		t.Fatalf("type and site not separate columns: %q", out.String())
	}
	if strings.Index(lines[2], "main.alloc") != strings.Index(lines[3], "main.long") {
		t.Fatalf("allocation-site columns not aligned: %q", out.String())
	}
}

func TestReportOmitsDisappearances(t *testing.T) {
	var r Report
	legacy := `{"settings":{"track_disappearances":true},"possible_disappeared_count":1,"possible_disappearances":[{"addr":4096,"bytes":32,"type":"[]byte"}]}`
	if err := json.Unmarshal([]byte(legacy), &r); err != nil {
		t.Fatal(err)
	}
	r.Result, r.Heatmap, r.textMap = &analysis.Result{}, &heatmap.Heatmap{}, &heatmap.Heatmap{}

	var text, js bytes.Buffer
	r.Text(&text, 10)
	if err := r.JSON(&js); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "heatmap.html")
	if err := r.WriteHTML(path); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{text.String(), js.String(), string(html)} {
		if strings.Contains(output, "possible disappearances") || strings.Contains(output, "Possible disappearances") || strings.Contains(output, "possible_disappeared") {
			t.Fatalf("disappearance section leaked into report: %.200s", output)
		}
	}
}

func TestHTMLHighlightsQuietBytes(t *testing.T) {
	r := &Report{Result: &analysis.Result{Totals: analysis.Totals{QuietBytes: 4096}}, Heatmap: &heatmap.Heatmap{}}
	path := filepath.Join(t.TempDir(), "heatmap.html")
	if err := r.WriteHTML(path); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Quiet candidates") || !strings.Contains(string(html), "4.0 KiB") || !strings.Contains(string(html), "no access observed") {
		t.Fatalf("quiet evidence absent from HTML: %.600s", html)
	}
}

func TestHTMLHighlightsQuietObjects(t *testing.T) {
	r := &Report{Result: &analysis.Result{Totals: analysis.Totals{QuietBytes: 4096}}, Heatmap: &heatmap.Heatmap{},
		Objects: &objects.Result{ByType: []objects.Group{{Labels: map[string]int64{objects.LabelQuiet: 2048}}}}}
	path := filepath.Join(t.TempDir(), "heatmap.html")
	if err := r.WriteHTML(path); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Quiet objects") || !strings.Contains(string(html), "2.0 KiB") {
		t.Fatalf("fully quiet object evidence absent from HTML: %.600s", html)
	}
}

func TestHTMLListsQuietRegions(t *testing.T) {
	r := &Report{Result: &analysis.Result{
		Totals: analysis.Totals{QuietBytes: 4096},
		Regions: []analysis.Region{
			{Start: 0x1000, End: 0x2000, Label: analysis.Quiet, ObjectBytes: 2048},
			{Start: 0x3000, End: 0x4000, Label: analysis.Observed},
		},
	}, Heatmap: &heatmap.Heatmap{}, Objects: &objects.Result{}}
	path := filepath.Join(t.TempDir(), "heatmap.html")
	if err := r.WriteHTML(path); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "0x1000–0x2000") || !strings.Contains(string(html), "Core object overlap") || strings.Contains(string(html), "0x3000–0x4000") {
		t.Fatalf("quiet regions not isolated: %.600s", html)
	}
}

func TestHTMLQuietRegionSites(t *testing.T) {
	r := &Report{Result: &analysis.Result{
		Totals:  analysis.Totals{QuietBytes: 4096},
		Regions: []analysis.Region{{Start: 0x1000, End: 0x2000, Label: analysis.Quiet, ObjectBytes: 256}},
	}, Heatmap: &heatmap.Heatmap{SiteRows: []heatmap.Row{{Key: "sample ← pkg.fn"}}}, Objects: &objects.Result{}}
	r.quietSites = map[uint64]map[string]uint64{0x1000: {objects.SiteKey("<type>", "pkg.fn"): 128, objects.SiteKey("<type>", objects.NoSite): 128}}
	path := filepath.Join(t.TempDir(), "heatmap.html")
	if err := r.WriteHTML(path); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	if !strings.Contains(s, "&lt;type&gt;") || !strings.Contains(s, "pkg.fn") || !strings.Contains(s, objects.NoSite) || !strings.Contains(s, "overlap bytes") {
		t.Fatalf("quiet region attribution missing: %s", s)
	}
	if strings.Index(s, "Quiet regions (1)") <= strings.Index(s, "By type and allocation site") || strings.Contains(s, "<details open><summary>Quiet regions") {
		t.Fatal("quiet regions must follow allocation site heatmap, uncollapsed")
	}
}

func TestQuietRegionOverlapOnly(t *testing.T) {
	r := &Report{Result: &analysis.Result{Regions: []analysis.Region{
		{Start: 0x1000, End: 0x1100, Label: analysis.Quiet},
		{Start: 0x1100, End: 0x1200, Label: analysis.Observed},
		{Start: 0x1200, End: 0x1300, Label: analysis.Quiet},
	}}}
	r.addQuietOverlap("buffer", "pkg.alloc", 0x1080, 0x1280)
	key := objects.SiteKey("buffer", "pkg.alloc")
	if len(r.quietSites) != 2 || r.quietSites[0x1000][key] != 0x80 || r.quietSites[0x1200][key] != 0x80 {
		t.Fatalf("quiet overlap includes observed memory or omits quiet memory: %+v", r.quietSites)
	}
}

func TestQuietTotalsExcludeUnattributedMemory(t *testing.T) {
	r := &Report{Result: &analysis.Result{
		Totals: analysis.Totals{MappedBytes: 0x3000, QuietBytes: 0x3000},
		Regions: []analysis.Region{
			{Start: 0x1000, End: 0x2000, Label: analysis.Quiet},
			{Start: 0x2000, End: 0x3000, Label: analysis.Quiet, ObjectBytes: 0x400},
			{Start: 0x3000, End: 0x4000, Label: analysis.Quiet, ObjectBytes: 0x1000},
		},
	}, Heatmap: &heatmap.Heatmap{}, Objects: &objects.Result{}}
	r.textMap = &heatmap.Heatmap{}
	r.limitQuietToObjects()
	if r.Totals.QuietBytes != 0x1400 || r.Totals.UnknownBytes != 0x1c00 || r.Regions[0].Label != analysis.Unknown || r.Regions[1].Label != analysis.Quiet {
		t.Fatalf("unattributed memory counted as quiet: totals=%+v regions=%+v", r.Totals, r.Regions)
	}
	path := filepath.Join(t.TempDir(), "heatmap.html")
	if err := r.WriteHTML(path); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "0x1000–0x2000") || !strings.Contains(string(html), "5.0 KiB") {
		t.Fatalf("unattributed memory appears in quiet HTML: %s", html)
	}
	if !strings.Contains(string(html), "7.0 KiB excluded") {
		t.Fatal("HTML does not explain excluded quiet bytes")
	}
	var out bytes.Buffer
	r.Text(&out, 10)
	if !strings.Contains(out.String(), "7.0 KiB excluded") {
		t.Fatal("text report does not explain excluded quiet bytes")
	}
	var encoded bytes.Buffer
	if err := r.JSON(&encoded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encoded.String(), `"unattributed_quiet_bytes": 7168`) || !strings.Contains(encoded.String(), `"quiet_candidate_bytes": 5120`) {
		t.Fatalf("JSON counts excluded memory as quiet: %s", encoded.String())
	}
}

func TestQuietWithoutCoreIsUnverified(t *testing.T) {
	r := &Report{Result: &analysis.Result{Totals: analysis.Totals{MappedBytes: 0x1000, QuietBytes: 0x1000},
		Regions: []analysis.Region{{Start: 0x1000, End: 0x2000, Label: analysis.Quiet}}}}
	r.limitQuietToObjects()
	if r.Totals.QuietBytes != 0 || r.Regions[0].Label != analysis.Unknown {
		t.Fatalf("missing core cannot confirm Go object: %+v", r.Totals)
	}
}

// writeRecording builds a recording from the live fixture with synthetic
// DAMON snapshots (hot buffer accessed, rest idle) and a real core.
func writeRecording(t *testing.T) (string, *testutil.Fixture) {
	t.Helper()
	if _, err := exec.LookPath("gcore"); err != nil {
		t.Skip("gcore not installed")
	}
	f := testutil.StartFixture(t, nil)
	pid := f.Cmd.Process.Pid
	page := uint64(os.Getpagesize())

	dir := filepath.Join(t.TempDir(), "rec")
	if err := store.CreateDir(dir); err != nil {
		t.Fatal(err)
	}
	id, _ := proc.Pin(pid)
	maps, err := proc.ReadMaps(pid)
	if err != nil {
		t.Fatal(err)
	}
	cands := proc.SelectCandidates(maps, 64)
	present, err := proc.Resident(pid, cands, page)
	if err != nil {
		t.Skipf("pagemap unreadable: %v", err)
	}

	hotLo := f.Hot.Addr &^ (page - 1)
	hotHi := (f.Hot.Addr + f.Hot.Size + page - 1) &^ (page - 1)
	var regs []damon.Region
	for _, c := range cands {
		if hotLo < c.Start || hotHi > c.End {
			regs = append(regs, damon.Region{Start: c.Start, End: c.End})
			continue
		}
		for _, r := range []damon.Region{{Start: c.Start, End: hotLo}, {Start: hotLo, End: hotHi, NrAccesses: 25}, {Start: hotHi, End: c.End}} {
			if r.End > r.Start {
				regs = append(regs, r)
			}
		}
	}

	write := func(name string, recs ...any) {
		j, err := store.CreateJSONL(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if _, err := j.Write(r); err != nil {
				t.Fatal(err)
			}
		}
		j.Close()
	}
	write(store.MapsFile, store.MapSnapshot{T: 0, Maps: maps}, store.MapSnapshot{T: 3 * sec, Maps: maps})
	write(store.ResidencyFile, store.ResidencySnapshot{T: 0, Present: present}, store.ResidencySnapshot{T: 3 * sec, Present: present})
	write(store.DAMONFile,
		store.DAMONSnapshot{T: 1 * sec, Regions: regs},
		store.DAMONSnapshot{T: 2 * sec, Regions: regs},
		store.DAMONSnapshot{T: 3 * sec, Regions: regs})
	write(store.PerfSamples, perfmem.Sample{TimeNS: 2 * sec, Addr: f.Hot.Addr + 64, Sym: "main.main", Op: "load"})

	exeSum, err := coredump.CopyExe(dir, pid)
	if err != nil {
		t.Fatal(err)
	}
	core, log, err := coredump.Capture(context.Background(), dir, pid)
	if err != nil {
		t.Skipf("gcore failed: %v\n%s", err, log)
	}

	m := &store.Manifest{
		Tool: "gocold", Status: store.StatusComplete, Target: id,
		Binary:     proc.InspectBinary(filepath.Join(dir, coredump.ExeName)),
		Settings:   store.Settings{AggrUS: 1e6, SampleUS: 20000, MapsIntervalNS: 10 * sec},
		Candidates: cands,
		DAMON:      &damon.Config{PID: pid, Ranges: cands},
		Capabilities: map[string]store.Capability{
			store.CapDAMON: {Available: true}, store.CapResidency: {Available: true},
			store.CapPerf: {Available: true}, store.CapCore: {Available: true},
		},
		Perf: store.Perf{Clock: perfmem.ClockMono},
		Core: store.Core{Path: filepath.Base(core), ExeSHA256: exeSum, StartNS: 4 * sec, FinalSnapshotNS: 3 * sec},
	}
	if err := store.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir, f
}

func TestReportEndToEnd(t *testing.T) {
	dir, f := writeRecording(t)
	r, err := Build(dir, reportOpts())
	if err != nil {
		t.Fatal(err)
	}
	if r.ObjectsErr != "" {
		t.Fatal(r.ObjectsErr)
	}

	hot := r.Regions[r.Find(f.Hot.Addr)]
	if hot.Label != analysis.Frequent {
		t.Errorf("hot region label = %s", hot.Label)
	}

	quiet := 0
	for _, o := range r.Objects.Listed {
		if o.Label == objects.LabelQuiet && o.SliceLen != nil && *o.SliceLen == 0 {
			quiet++
		}
	}
	if quiet != len(f.Idle) {
		t.Errorf("idle quiet objects = %d, want %d", quiet, len(f.Idle))
	}

	if len(r.SampleMatches) != 1 || r.SampleMatches[0].Object == nil || r.SampleMatches[0].Object.Addr != f.Hot.Addr {
		t.Fatalf("sample matches = %+v", r.SampleMatches)
	}
	if sm := r.SampleMatches[0]; sm.Object.Label != objects.LabelObserved || sm.CoreDelayNS != 2*sec {
		t.Errorf("match = %+v", sm)
	}

	// Heatmap agrees with region analysis: hot buffer accessed.
	hm := r.Heatmap
	var hotMax float64
	for _, row := range hm.Rows {
		if row.Start <= f.Hot.Addr && f.Hot.Addr < row.End {
			hotMax = row.MaxRate
		}
	}
	if hotMax == 0 {
		t.Errorf("heatmap hot max=%v", hotMax)
	}
	htmlPath := filepath.Join(t.TempDir(), "hm.html")
	if err := r.WriteHTML(htmlPath); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteHTML(htmlPath); err == nil {
		t.Error("existing HTML overwritten")
	}

	var text, js bytes.Buffer
	r.Text(&text, 10)
	t.Log("\n" + text.String())
	if !strings.Contains(text.String(), "quiet candidate") {
		t.Errorf("text output:\n%s", text.String())
	}
	if !strings.Contains(text.String(), "heatmap (") {
		t.Error("text lacks heatmap")
	}
	if err := r.JSON(&js); err != nil || !strings.Contains(js.String(), `"damon_snapshots"`) || strings.Contains(js.String(), `"type_rows"`) {
		t.Errorf("json err=%v", err)
	}
}

func TestReportRejectsMismatchedBinary(t *testing.T) {
	dir, _ := writeRecording(t)
	m, err := store.ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	m.Binary.SHA256 = strings.Repeat("0", 64)
	if err := store.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}

	r, err := Build(dir, reportOpts())
	if err != nil {
		t.Fatal(err)
	}
	if r.Objects != nil || !strings.Contains(r.ObjectsErr, "does not match") {
		t.Errorf("mismatch accepted: objects=%v err=%q", r.Objects != nil, r.ObjectsErr)
	}
}

func TestRegionOnlyReport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rec")
	if err := store.CreateDir(dir); err != nil {
		t.Fatal(err)
	}
	m := &store.Manifest{
		Status:   store.StatusComplete,
		Settings: store.Settings{AggrUS: 1e6, SampleUS: 20000},
		Capabilities: map[string]store.Capability{
			store.CapDAMON: {Available: false, Reason: "DAMON sysfs absent"},
			store.CapPerf:  {Available: false, Reason: "no PMU"},
		},
	}
	if err := store.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	r, err := Build(dir, reportOpts())
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	r.Text(&b, 5)
	if !strings.Contains(b.String(), "MISSING  DAMON sysfs absent") {
		t.Errorf("missing capability not stated:\n%s", b.String())
	}
}

var keep [][]byte

func TestPprofSection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rec")
	if err := store.CreateDir(dir); err != nil {
		t.Fatal(err)
	}
	runtime.MemProfileRate = 1
	for range 100 {
		keep = append(keep, make([]byte, 4096))
	}
	runtime.GC() // test process only: publishes profile data
	f, err := os.Create(filepath.Join(dir, store.PprofFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.Lookup("heap").WriteTo(f, 0); err != nil {
		t.Fatal(err)
	}
	f.Close()

	m := &store.Manifest{Status: store.StatusComplete, Settings: store.Settings{AggrUS: 1e6, SampleUS: 20000},
		Capabilities: map[string]store.Capability{store.CapPprof: {Available: true}}}
	if err := store.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	r, err := Build(dir, reportOpts())
	if err != nil {
		t.Fatal(err)
	}
	if r.PprofErr != "" || len(r.Pprof) == 0 {
		t.Errorf("pprof sites=%v err=%s", r.Pprof, r.PprofErr)
	}
}

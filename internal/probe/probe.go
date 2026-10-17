// Package probe reports what a recording would need, without changing anything.
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/vrutkovs/golang-cold-memory/internal/damon"
	"github.com/vrutkovs/golang-cold-memory/internal/host"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
	"github.com/vrutkovs/golang-cold-memory/internal/record"
)

// Check is one prerequisite.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Report is the probe output.
type Report struct {
	Target         proc.Identity `json:"target"`
	Binary         proc.Binary   `json:"binary"`
	GoSupported    bool          `json:"go_supported"`
	Host           host.Info     `json:"host"`
	Mappings       int           `json:"mappings"`
	Candidates     []proc.Range  `json:"candidates"`
	CandidateBytes uint64        `json:"candidate_bytes"`
	CandidateRSS   uint64        `json:"candidate_rss_bytes"`
	DAMON          damon.Status  `json:"damon"`
	Perf           perfmem.Probe `json:"perf"`
	DiskEstimate   uint64        `json:"disk_estimate_bytes"`
	DiskFree       *uint64       `json:"disk_free_bytes,omitempty"`
	Checks         []Check       `json:"checks"`
}

// Run probes pid using record options for estimates.
func Run(ctx context.Context, o record.Options) (*Report, error) {
	id, err := proc.Pin(o.PID)
	if err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	r := &Report{Target: id, Host: host.Collect()}
	r.Binary = proc.InspectBinary(proc.ExePath(o.PID))
	r.GoSupported = proc.GoSupported(r.Binary.GoVersion)

	maps, err := proc.ReadMaps(o.PID)
	if err != nil {
		return nil, fmt.Errorf("read maps: %w", err)
	}
	r.Mappings = len(maps)
	r.Candidates = proc.SelectCandidates(maps, o.MaxRanges)
	r.CandidateBytes = proc.TotalSize(r.Candidates)
	for _, m := range maps {
		if len(proc.Intersect([]proc.Range{{Start: m.Start, End: m.End}}, r.Candidates)) > 0 {
			r.CandidateRSS += m.Rss
		}
	}

	r.DAMON = damon.Probe(damon.OSFS{Root: o.DAMONRoot})
	r.Perf = perfmem.ProbeEvents(ctx)

	var exeSize int64
	if st, err := os.Stat(proc.ExePath(o.PID)); err == nil {
		exeSize = st.Size()
	}
	r.DiskEstimate = record.Estimate(o, maps, exeSize)
	if o.Out != "" {
		if free, err := host.FreeBytes(dirOf(o.Out)); err == nil {
			r.DiskFree = &free
		}
	}

	_, pmErr := proc.Resident(o.PID, firstPage(r.Candidates, r.Host.PageSize), r.Host.PageSize)
	r.Checks = r.checks(pmErr)

	// PID reuse check after probing.
	if err := id.Check(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Report) checks(pmErr error) []Check {
	_, gcoreErr := exec.LookPath("gcore")
	add := func(cs []Check, name string, ok bool, detail string) []Check {
		return append(cs, Check{name, ok, detail})
	}

	var cs []Check
	cs = add(cs, "go-binary", r.Binary.GoVersion != "", r.Binary.GoVersion+" "+r.Binary.Err)
	cs = add(cs, "go-supported", r.GoSupported, fmt.Sprintf("need go1.%d+", proc.MinGoMinor))
	cs = add(cs, "dwarf (objects)", r.Binary.DWARF, "required for --objects")
	cs = add(cs, "candidates", len(r.Candidates) > 0, fmt.Sprintf("%d writable anonymous ranges", len(r.Candidates)))
	cs = add(cs, "damon-sysfs", r.DAMON.Present, r.DAMON.Err)
	cs = add(cs, "damon-access", r.DAMON.Readable && r.Host.HasCap(host.CapSysAdmin),
		"needs root/CAP_SYS_ADMIN on the host for DAMON sysfs")
	free := "unknown: sysfs unreadable"
	if r.DAMON.Readable {
		free = fmt.Sprintf("%d existing kdamonds; record never touches existing ones", r.DAMON.Existing)
	}
	cs = add(cs, "damon-free", r.DAMON.Readable && r.DAMON.Existing == 0, free)
	cs = add(cs, "perf-mem-events", len(r.Perf.Chosen) > 0, r.Perf.Err)

	paranoid := "unknown"
	if r.Host.PerfParanoid != nil {
		paranoid = fmt.Sprint(*r.Host.PerfParanoid)
	}
	perfOK := r.Host.HasCap(host.CapPerfmon) || r.Host.HasCap(host.CapSysAdmin) ||
		(r.Host.PerfParanoid != nil && *r.Host.PerfParanoid <= 1)
	cs = add(cs, "perf-permission", perfOK, "perf_event_paranoid="+paranoid+"; CAP_PERFMON or paranoid<=1 recommended")

	pmDetail := "present-page checks for quiet candidates"
	if pmErr != nil {
		pmDetail = pmErr.Error()
	}
	cs = add(cs, "pagemap", pmErr == nil, pmDetail)

	scope := "unknown"
	if r.Host.PtraceScope != nil {
		scope = fmt.Sprint(*r.Host.PtraceScope)
	}
	ptraceOK := r.Host.HasCap(host.CapSysPtrace) || (r.Host.PtraceScope != nil && *r.Host.PtraceScope == 0)
	cs = add(cs, "core: gcore", gcoreErr == nil, "gdb's gcore; pauses the target during dump")
	cs = add(cs, "core: ptrace", ptraceOK, "ptrace_scope="+scope+"; CAP_SYS_PTRACE otherwise")

	if r.DiskFree != nil {
		cs = add(cs, "disk", *r.DiskFree >= r.DiskEstimate, fmt.Sprintf("need ~%d MiB, free %d MiB", r.DiskEstimate>>20, *r.DiskFree>>20))
	}
	return cs
}

// Print writes a human-readable report.
func (r *Report) Print(w io.Writer) {
	fmt.Fprintf(w, "target    pid=%d start=%d\n", r.Target.PID, r.Target.StartTime)
	fmt.Fprintf(w, "binary    %s sha256=%s dwarf=%v arch=%s\n", r.Binary.GoVersion, r.Binary.SHA256, r.Binary.DWARF, r.Binary.Arch)
	fmt.Fprintf(w, "host      kernel=%s page=%d euid=%d\n", r.Host.Kernel, r.Host.PageSize, r.Host.EUID)
	fmt.Fprintf(w, "mappings  %d total, %d candidate ranges, %d MiB mapped, %d MiB RSS\n",
		r.Mappings, len(r.Candidates), r.CandidateBytes>>20, r.CandidateRSS>>20)
	for _, c := range r.Candidates {
		fmt.Fprintf(w, "          %#x-%#x %8d KiB\n", c.Start, c.End, c.Size()>>10)
	}
	fmt.Fprintf(w, "perf      events available=%v chosen=%v\n", r.Perf.Available, r.Perf.Chosen)
	fmt.Fprintf(w, "disk      estimate %d MiB\n", r.DiskEstimate>>20)
	fmt.Fprintln(w, "checks")
	for _, c := range r.Checks {
		mark := "ok  "
		if !c.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(w, "  [%s] %-18s %s\n", mark, c.Name, c.Detail)
	}
	fmt.Fprintln(w, "containers: pass the host PID, e.g. podman inspect CONTAINER --format '{{.State.Pid}}'")
}

// JSON writes r as indented JSON.
func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func firstPage(rs []proc.Range, page uint64) []proc.Range {
	if len(rs) == 0 {
		return nil
	}
	return []proc.Range{{Start: rs[0].Start, End: min(rs[0].End, rs[0].Start+page)}}
}

// dirOf returns path if it exists, else its parent (out dir may not exist yet).
func dirOf(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return filepath.Dir(path)
}

// Package perfmem drives `perf mem` sampling and converts results.
//
// A perf hit proves a sampled access at an address and time. Absence of
// hits proves nothing: sampling is sparse and loads may be latency-biased.
package perfmem

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// ClockMono is perf's -k value matching host.Mono timestamps.
	ClockMono = "CLOCK_MONOTONIC"
	// ClockLocal marks perf's default clock, not comparable to DAMON times.
	ClockLocal = "perf-local"

	startGrace = 700 * time.Millisecond
	stopGrace  = 15 * time.Second
)

// Probe is the result of `perf mem record -e list`.
type Probe struct {
	PerfPath  string   `json:"perf_path,omitempty"`
	Available []string `json:"available_events"`
	Chosen    []string `json:"chosen_events"`
	Err       string   `json:"error,omitempty"`
}

// ProbeEvents lists memory events supported by this host.
func ProbeEvents(ctx context.Context) Probe {
	var p Probe
	path, err := exec.LookPath("perf")
	if err != nil {
		p.Err = "perf not installed"
		return p
	}
	p.PerfPath = path

	out, err := exec.CommandContext(ctx, path, "mem", "record", "-e", "list").CombinedOutput()
	p.Available = ParseEventList(string(out))
	p.Chosen = ChooseEvents(p.Available)
	if len(p.Available) == 0 {
		p.Err = strings.TrimSpace(string(out))
		if p.Err == "" && err != nil {
			p.Err = err.Error()
		}
	}
	return p
}

// ParseEventList parses lines like "ldlat-loads  : available".
func ParseEventList(out string) []string {
	var evs []string
	for _, l := range strings.Split(out, "\n") {
		name, state, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(state) != "available" {
			continue
		}
		evs = append(evs, strings.TrimSpace(name))
	}
	return evs
}

// ChooseEvents prefers one combined load/store event, else one load and
// one store event, as reported by the probe (never hard-coded PMU names).
func ChooseEvents(avail []string) []string {
	var load, store string
	for _, e := range avail {
		l := strings.ToLower(e)
		switch {
		case strings.Contains(l, "ldst"):
			return []string{e}
		case load == "" && strings.Contains(l, "load"):
			load = e
		case store == "" && strings.Contains(l, "store"):
			store = e
		}
	}
	var out []string
	for _, e := range []string{load, store} {
		if e != "" {
			out = append(out, e)
		}
	}
	if len(out) == 0 && len(avail) > 0 {
		out = []string{avail[0]}
	}
	return out
}

// Recorder is a running PID-scoped perf mem record.
type Recorder struct {
	cmd    *exec.Cmd
	done   chan error
	stderr *bytes.Buffer
	Args   []string
	Clock  string
}

// Start runs `perf mem record` attached to pid, writing out.
// It retries without -k when the PMU rejects a custom clock.
func Start(perf string, pid int, events []string, period int, maxSize uint64, out string) (*Recorder, error) {
	r, err := start(perf, pid, events, period, maxSize, out, true)
	if err == nil {
		return r, nil
	}
	_ = os.Remove(out)
	r, err2 := start(perf, pid, events, period, maxSize, out, false)
	if err2 != nil {
		return nil, errors.Join(err, err2)
	}
	return r, nil
}

func start(perf string, pid int, events []string, period int, maxSize uint64, out string, mono bool) (*Recorder, error) {
	args := []string{"mem", "record"}
	for _, e := range events {
		args = append(args, "-e", e)
	}
	// Long forms only: perf mem owns short flags like -p (--phys-data);
	// unknown options pass through to perf record.
	// --data/--weight request data address and weight; --max-size bounds disk.
	args = append(args, "--data", "--weight",
		"--count="+strconv.Itoa(period),
		"--max-size="+strconv.FormatUint(maxSize>>10, 10)+"K",
		"--pid="+strconv.Itoa(pid),
		"--output="+out)
	clock := ClockLocal
	if mono {
		args = append(args, "--clockid="+ClockMono)
		clock = ClockMono
	}

	r := &Recorder{cmd: exec.Command(perf, args...), done: make(chan error, 1), stderr: &bytes.Buffer{}, Args: args, Clock: clock}
	r.cmd.Stderr = r.stderr
	r.cmd.Stdout = r.stderr
	if err := r.cmd.Start(); err != nil {
		return nil, err
	}
	go func() { r.done <- r.cmd.Wait() }()

	// perf exits quickly on unsupported options or permissions.
	select {
	case err := <-r.done:
		return nil, fmt.Errorf("perf exited early (%v): %s", err, strings.TrimSpace(r.stderr.String()))
	case <-time.After(startGrace):
		return r, nil
	}
}

// Stop interrupts perf so it flushes perf.data, killing after a grace period.
func (r *Recorder) Stop() (string, error) {
	_ = r.cmd.Process.Signal(syscall.SIGINT)
	select {
	case <-r.done:
	case <-time.After(stopGrace):
		_ = r.cmd.Process.Kill()
		<-r.done
		return r.stderr.String(), fmt.Errorf("perf did not stop; killed")
	}
	return r.stderr.String(), nil
}

// Sample is one memory sample.
type Sample struct {
	TimeNS int64  `json:"t"`
	Event  string `json:"ev"`
	Op     string `json:"op"`
	Addr   uint64 `json:"addr"`
	IP     uint64 `json:"ip"`
	Sym    string `json:"sym"`
	Weight uint64 `json:"w,omitempty"`
}

// Summary describes a converted perf recording.
type Summary struct {
	Samples     int               `json:"samples"`
	WithAddr    int               `json:"samples_with_addr"`
	Lost        uint64            `json:"lost"`
	SampleTypes map[string]string `json:"sample_types"`
	HasADDR     bool              `json:"has_addr"`
	HasWeight   bool              `json:"has_weight"`
	Err         string            `json:"error,omitempty"`
}

// Convert extracts samples from data into a JSONL file at dst.
func Convert(ctx context.Context, perf, data, dst string) Summary {
	s := Summary{SampleTypes: map[string]string{}}

	if out, err := exec.CommandContext(ctx, perf, "evlist", "-v", "-i", data).Output(); err == nil {
		s.SampleTypes = ParseSampleTypes(string(out))
	}
	for _, st := range s.SampleTypes {
		s.HasADDR = s.HasADDR || hasFlag(st, "ADDR")
		s.HasWeight = s.HasWeight || hasFlag(st, "WEIGHT") || hasFlag(st, "WEIGHT_STRUCT")
	}
	if out, err := exec.CommandContext(ctx, perf, "report", "--stats", "-i", data).CombinedOutput(); err == nil {
		s.Lost = ParseLost(string(out))
	}
	if !s.HasADDR {
		s.Err = "recorded sample_type lacks ADDR; data addresses unavailable"
		return s
	}

	fields := "time,event,addr,ip"
	if s.HasWeight {
		fields = "time,event,addr,weight,ip"
	}
	raw, err := exec.CommandContext(ctx, perf, "script", "-i", data, "--ns", "-F", fields).Output()
	if err != nil && s.HasWeight {
		s.HasWeight = false
		raw, err = exec.CommandContext(ctx, perf, "script", "-i", data, "--ns", "-F", "time,event,addr,ip").Output()
	}
	if err != nil {
		s.Err = "perf script: " + err.Error()
		return s
	}
	samples, err := ParseScript(string(raw), s.HasWeight)
	if err != nil {
		s.Err = err.Error()
		return s
	}

	// Symbols come from a second pass in identical sample order.
	if syms, err := exec.CommandContext(ctx, perf, "script", "-i", data, "-F", "ip,sym").Output(); err == nil {
		_ = AttachSymbols(samples, string(syms))
	}

	for _, x := range samples {
		if x.Addr != 0 {
			s.WithAddr++
		}
	}
	s.Samples = len(samples)
	if s.WithAddr == 0 {
		s.Err = "no samples carried a data address"
	}
	if err := writeJSONL(dst, samples); err != nil {
		s.Err = err.Error()
	}
	return s
}

// ParseSampleTypes maps event name to sample_type from `perf evlist -v`.
func ParseSampleTypes(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		name, rest, ok := strings.Cut(l, ": ")
		if !ok || strings.HasPrefix(name, "dummy") {
			continue
		}
		_, st, ok := strings.Cut(rest, "sample_type: ")
		if !ok {
			continue
		}
		if i := strings.Index(st, ","); i >= 0 {
			st = st[:i]
		}
		m[name] = strings.TrimSpace(st)
	}
	return m
}

func hasFlag(sampleType, flag string) bool {
	for _, f := range strings.Split(sampleType, "|") {
		if f == flag {
			return true
		}
	}
	return false
}

// ParseLost sums LOST/LOST_SAMPLES counts from `perf report --stats`.
func ParseLost(out string) uint64 {
	var n uint64
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || (f[0] != "LOST" && f[0] != "LOST_SAMPLES") || f[1] != "events:" {
			continue
		}
		v, _ := strconv.ParseUint(f[2], 10, 64)
		n += v
	}
	return n
}

// ParseScript parses `perf script --ns -F time,event,addr[,weight],ip` output.
func ParseScript(out string, weight bool) ([]Sample, error) {
	var res []Sample
	want := 4
	if weight {
		want = 5
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < want || !strings.HasSuffix(f[0], ":") {
			continue
		}
		t, err := parseTime(strings.TrimSuffix(f[0], ":"))
		if err != nil {
			return nil, err
		}
		ev := strings.TrimSuffix(f[1], ":")
		s := Sample{TimeNS: t, Event: ev, Op: opOf(ev)}
		if s.Addr, err = strconv.ParseUint(f[2], 16, 64); err != nil {
			return nil, fmt.Errorf("bad addr %q", f[2])
		}
		if weight {
			s.Weight, _ = strconv.ParseUint(f[3], 10, 64)
		}
		if s.IP, err = strconv.ParseUint(f[len(f)-1], 16, 64); err != nil {
			return nil, fmt.Errorf("bad ip %q", f[len(f)-1])
		}
		res = append(res, s)
	}
	return res, sc.Err()
}

// AttachSymbols zips `perf script -F ip,sym` lines onto samples by order.
func AttachSymbols(samples []Sample, out string) error {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != len(samples) {
		return fmt.Errorf("symbol pass returned %d lines for %d samples", len(lines), len(samples))
	}
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		if ip, err := strconv.ParseUint(f[0], 16, 64); err != nil || ip != samples[i].IP {
			return fmt.Errorf("symbol pass out of order at sample %d", i)
		}
		samples[i].Sym = strings.Join(f[1:], " ")
	}
	return nil
}

// parseTime converts "sec.nsec" to ns.
func parseTime(s string) (int64, error) {
	sec, frac, _ := strings.Cut(s, ".")
	a, err := strconv.ParseInt(sec, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad time %q", s)
	}
	frac = (frac + "000000000")[:9]
	b, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad time %q", s)
	}
	return a*int64(time.Second) + b, nil
}

func opOf(ev string) string {
	l := strings.ToLower(ev)
	switch {
	case strings.Contains(l, "ldst"):
		return "load/store"
	case strings.Contains(l, "store"):
		return "store"
	case strings.Contains(l, "load"):
		return "load"
	}
	return "unknown"
}

func writeJSONL(path string, samples []Sample) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, s := range samples {
		if err := enc.Encode(s); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadSamples loads a JSONL file written by Convert.
func ReadSamples(path string) ([]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Sample
	dec := json.NewDecoder(f)
	for dec.More() {
		var s Sample
		if err := dec.Decode(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

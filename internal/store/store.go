// Package store defines the on-disk recording format.
//
// Recordings may contain secrets (cores, addresses, symbols): directories
// are 0700, files 0600, nothing is overwritten or uploaded.
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vrutkovs/golang-cold-memory/internal/damon"
	"github.com/vrutkovs/golang-cold-memory/internal/host"
	"github.com/vrutkovs/golang-cold-memory/internal/perfmem"
	"github.com/vrutkovs/golang-cold-memory/internal/proc"
)

// File names inside a recording directory.
const (
	ManifestFile  = "manifest.json"
	MapsFile      = "maps.jsonl"
	ResidencyFile = "residency.jsonl"
	DAMONFile     = "damon.jsonl"
	PerfData      = "perf.data"
	PerfSamples   = "perf-samples.jsonl"
	PprofFile     = "heap.pprof"

	dirMode  = 0o700
	fileMode = 0o600
)

// Run status values.
const (
	StatusRunning     = "running"
	StatusComplete    = "complete"
	StatusInterrupted = "interrupted"
	StatusIncomplete  = "incomplete"
)

// Capability states whether an evidence source was collected.
type Capability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// Settings are the sampling settings of a run.
type Settings struct {
	DurationNS          int64  `json:"duration_ns"`
	SnapshotIntervalNS  int64  `json:"snapshot_interval_ns"`
	MapsIntervalNS      int64  `json:"maps_interval_ns"`
	SampleUS            uint64 `json:"sample_us"`
	AggrUS              uint64 `json:"aggr_us"`
	UpdateUS            uint64 `json:"update_us"`
	MinRegions          int    `json:"min_regions"`
	MaxRegions          int    `json:"max_regions"`
	MaxRanges           int    `json:"max_ranges"`
	MaxSnapshots        int    `json:"max_snapshots"`
	PerfPeriod          int    `json:"perf_period"`
	Objects             bool   `json:"objects"`
	TrackDisappearances bool   `json:"track_disappearances,omitempty"`
	PprofURL            string `json:"pprof_url,omitempty"`
}

// Perf records perf collection metadata.
type Perf struct {
	Events  []string        `json:"events,omitempty"`
	Args    []string        `json:"args,omitempty"`
	Clock   string          `json:"clock,omitempty"`
	StartNS int64           `json:"start_ns,omitempty"`
	StopNS  int64           `json:"stop_ns,omitempty"`
	Summary perfmem.Summary `json:"summary"`
	Log     string          `json:"log,omitempty"`
}

// Core records core capture metadata.
type Core struct {
	Path            string       `json:"path,omitempty"`
	ExeSHA256       string       `json:"exe_sha256,omitempty"`
	FinalSnapshotNS int64        `json:"final_snapshot_ns,omitempty"`
	StartNS         int64        `json:"start_ns,omitempty"`
	EndNS           int64        `json:"end_ns,omitempty"`
	SnapshotGapNS   int64        `json:"snapshot_gap_ns,omitempty"`
	Missing         []proc.Range `json:"missing_ranges,omitempty"`
	Log             string       `json:"log,omitempty"`
}

// Manifest describes one recording.
type Manifest struct {
	Tool         string                `json:"tool"`
	Status       string                `json:"status"`
	Errors       []string              `json:"errors,omitempty"`
	Target       proc.Identity         `json:"target"`
	Binary       proc.Binary           `json:"binary"`
	Host         host.Info             `json:"host"`
	Tools        map[string]string     `json:"tool_versions"`
	Settings     Settings              `json:"settings"`
	Candidates   []proc.Range          `json:"candidates"`
	DAMON        *damon.Config         `json:"damon,omitempty"`
	Capabilities map[string]Capability `json:"capabilities"`
	Perf         Perf                  `json:"perf"`
	Core         Core                  `json:"core"`
	StartCore    *Core                 `json:"start_core,omitempty"`
	StartNS      int64                 `json:"start_ns"`
	EndNS        int64                 `json:"end_ns"`
}

// Capability names.
const (
	CapDAMON     = "damon"
	CapPerf      = "perf"
	CapResidency = "residency"
	CapCore      = "core"
	CapPprof     = "pprof"
)

// MapSnapshot is /proc/PID/smaps at time T (CLOCK_MONOTONIC ns).
type MapSnapshot struct {
	T    int64          `json:"t"`
	Maps []proc.Mapping `json:"maps"`
}

// ResidencySnapshot lists present pages within candidates at T.
type ResidencySnapshot struct {
	T       int64        `json:"t"`
	Present []proc.Range `json:"present"`
}

// DAMONSnapshot is one raw DAMON tried_regions read completed at T.
type DAMONSnapshot struct {
	T       int64          `json:"t"`
	Regions []damon.Region `json:"regions"`
}

// CreateDir makes a private output dir; an existing dir must be empty and 0700.
func CreateDir(dir string) error {
	err := os.Mkdir(dir, dirMode)
	if err == nil {
		return os.Chmod(dir, dirMode)
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}

	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != dirMode {
		return fmt.Errorf("%s exists and is not a 0700 directory", dir)
	}
	es, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(es) > 0 {
		return fmt.Errorf("%s is not empty; refusing to mix recordings", dir)
	}
	return nil
}

// WriteManifest atomically replaces the manifest (0600).
func WriteManifest(dir string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ManifestFile+".tmp")
	if err := os.WriteFile(tmp, b, fileMode); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, ManifestFile))
}

// ReadManifest loads dir/manifest.json.
func ReadManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, err
	}
	var m Manifest
	return &m, json.Unmarshal(b, &m)
}

// JSONL appends records to a new 0600 file.
type JSONL struct {
	f *os.File
	w *bufio.Writer
}

// CreateJSONL creates a new file; existing files are never overwritten.
func CreateJSONL(path string) (*JSONL, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return nil, err
	}
	return &JSONL{f: f, w: bufio.NewWriter(f)}, nil
}

// Write appends one record and flushes so interrupted runs keep data.
func (j *JSONL) Write(v any) (int, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	b = append(b, '\n')
	if _, err := j.w.Write(b); err != nil {
		return 0, err
	}
	return len(b), j.w.Flush()
}

// Close flushes and closes the file.
func (j *JSONL) Close() error {
	if j == nil {
		return nil
	}
	if err := j.w.Flush(); err != nil {
		j.f.Close()
		return err
	}
	return j.f.Close()
}

// ReadJSONL decodes every record of path into a slice of T.
func ReadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []T
	dec := json.NewDecoder(bufio.NewReader(f))
	for dec.More() {
		var v T
		if err := dec.Decode(&v); err != nil {
			return out, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		out = append(out, v)
	}
	return out, nil
}

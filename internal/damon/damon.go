// Package damon drives one DAMON sysfs monitor owned by this process.
//
// Safety rules: never reuse, stop or reconfigure a kdamond this run did not
// create; only the DAMOS "stat" action is used (no pageout/cold); cleanup
// touches the monitor only while ownership still verifies.
package damon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vrutkovs/golang-cold-memory/internal/proc"
)

// DefaultRoot is the DAMON sysfs admin directory.
const DefaultRoot = "/sys/kernel/mm/damon/admin"

const (
	kd       = "kdamonds/0"
	ctxDir   = kd + "/contexts/0"
	tgtDir   = ctxDir + "/targets/0"
	schemeD  = ctxDir + "/schemes/0"
	ulongMax = "18446744073709551615"
	uintMax  = "4294967295"

	cmdOn      = "on"
	cmdOff     = "off"
	cmdTried   = "update_schemes_tried_regions"
	opsFVAddr  = "fvaddr"
	actionStat = "stat"
)

var (
	// ErrBusy means kdamonds already exist; this run will not touch them.
	ErrBusy = errors.New("DAMON already has kdamonds configured; refusing to touch another monitor")
	// ErrOwnership means the monitor created by this run was changed by someone else.
	ErrOwnership = errors.New("DAMON monitor ownership changed during run")
)

// FS abstracts sysfs access so tests can fake it.
type FS interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte) error
	ReadDir(name string) ([]string, error)
}

// OSFS is FS rooted at a real directory.
type OSFS struct{ Root string }

func (o OSFS) ReadFile(n string) ([]byte, error) { return os.ReadFile(filepath.Join(o.Root, n)) }

func (o OSFS) WriteFile(n string, d []byte) error {
	f, err := os.OpenFile(filepath.Join(o.Root, n), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.Write(d)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (o OSFS) ReadDir(n string) ([]string, error) {
	es, err := os.ReadDir(filepath.Join(o.Root, n))
	if err != nil {
		return nil, err
	}
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Name()
	}
	return out, nil
}

// Status describes DAMON sysfs availability.
type Status struct {
	Present  bool   `json:"present"`
	Readable bool   `json:"readable"`
	Existing int    `json:"existing_kdamonds"`
	Err      string `json:"error,omitempty"`
}

// Probe inspects DAMON sysfs without changing anything.
func Probe(fs FS) Status {
	var s Status
	b, err := fs.ReadFile("kdamonds/nr_kdamonds")
	if errors.Is(err, os.ErrNotExist) {
		s.Err = "DAMON sysfs absent (CONFIG_DAMON_SYSFS/CONFIG_DAMON_VADDR?)"
		return s
	}
	s.Present = true
	if err != nil {
		s.Err = err.Error()
		return s
	}
	s.Readable = true
	s.Existing, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	return s
}

// Config describes the monitor to create.
type Config struct {
	PID        int          `json:"pid"`
	Ranges     []proc.Range `json:"ranges"`
	SampleUS   uint64       `json:"sample_us"`
	AggrUS     uint64       `json:"aggr_us"`
	UpdateUS   uint64       `json:"update_us"`
	MinRegions int          `json:"min_regions"`
	MaxRegions int          `json:"max_regions"`
}

// Region is one DAMON monitoring region at snapshot time.
type Region struct {
	Start      uint64 `json:"start"`
	End        uint64 `json:"end"`
	NrAccesses uint64 `json:"nr_accesses"`
	Age        uint64 `json:"age"`
}

// Monitor is a kdamond created and owned by this run.
type Monitor struct {
	fs         FS
	pid        int
	kdamondPID string
	closed     bool
}

// Start creates kdamond 0 only when no kdamonds exist.
func Start(fs FS, c Config) (*Monitor, error) {
	if len(c.Ranges) == 0 {
		return nil, fmt.Errorf("no ranges to monitor")
	}
	nr, err := readInt(fs, "kdamonds/nr_kdamonds")
	if err != nil {
		return nil, err
	}
	if nr != 0 {
		return nil, ErrBusy
	}
	if err := write(fs, "kdamonds/nr_kdamonds", "1"); err != nil {
		return nil, err
	}

	m := &Monitor{fs: fs, pid: c.PID}
	if err := m.configure(c); err != nil {
		return nil, errors.Join(err, m.Close())
	}
	if err := write(fs, kd+"/state", cmdOn); err != nil {
		return nil, errors.Join(err, m.Close())
	}

	pid, err := fs.ReadFile(kd + "/pid")
	if err != nil {
		return nil, errors.Join(err, m.Close())
	}
	m.kdamondPID = strings.TrimSpace(string(pid))
	return m, nil
}

func (m *Monitor) configure(c Config) error {
	steps := [][2]string{
		{kd + "/contexts/nr_contexts", "1"},
		{ctxDir + "/operations", opsFVAddr},
		{ctxDir + "/monitoring_attrs/intervals/sample_us", u(c.SampleUS)},
		{ctxDir + "/monitoring_attrs/intervals/aggr_us", u(c.AggrUS)},
		{ctxDir + "/monitoring_attrs/intervals/update_us", u(c.UpdateUS)},
		// max first: kernel rejects min > max.
		{ctxDir + "/monitoring_attrs/nr_regions/max", strconv.Itoa(c.MaxRegions)},
		{ctxDir + "/monitoring_attrs/nr_regions/min", strconv.Itoa(c.MinRegions)},
		{ctxDir + "/targets/nr_targets", "1"},
		{tgtDir + "/pid_target", strconv.Itoa(c.PID)},
		{tgtDir + "/regions/nr_regions", strconv.Itoa(len(c.Ranges))},
	}
	for i, r := range c.Ranges {
		d := fmt.Sprintf("%s/regions/%d", tgtDir, i)
		steps = append(steps, [2]string{d + "/start", u(r.Start)}, [2]string{d + "/end", u(r.End)})
	}

	// A match-everything "stat" scheme exposes regions via tried_regions
	// without acting on memory.
	ap := schemeD + "/access_pattern"
	steps = append(steps,
		[2]string{ctxDir + "/schemes/nr_schemes", "1"},
		[2]string{schemeD + "/action", actionStat},
		[2]string{ap + "/sz/max", ulongMax},
		[2]string{ap + "/sz/min", "0"},
		[2]string{ap + "/nr_accesses/max", uintMax},
		[2]string{ap + "/nr_accesses/min", "0"},
		[2]string{ap + "/age/max", uintMax},
		[2]string{ap + "/age/min", "0"},
	)

	for _, s := range steps {
		if err := write(m.fs, s[0], s[1]); err != nil {
			return err
		}
	}
	return nil
}

// Verify confirms the monitor is still the one this run created.
func (m *Monitor) Verify() error {
	nr, err := readInt(m.fs, "kdamonds/nr_kdamonds")
	if err != nil || nr != 1 {
		return ErrOwnership
	}
	if m.kdamondPID != "" {
		pid, err := m.fs.ReadFile(kd + "/pid")
		if err != nil || strings.TrimSpace(string(pid)) != m.kdamondPID {
			return ErrOwnership
		}
	}
	tgt, err := readInt(m.fs, tgtDir+"/pid_target")
	if err != nil || tgt != m.pid {
		return ErrOwnership
	}
	return nil
}

// Snapshot refreshes and reads monitoring regions of the latest aggregation.
func (m *Monitor) Snapshot() ([]Region, error) {
	if err := m.Verify(); err != nil {
		return nil, err
	}
	if err := write(m.fs, kd+"/state", cmdTried); err != nil {
		return nil, err
	}

	dir := schemeD + "/tried_regions"
	names, err := m.fs.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var idx []int
	for _, n := range names {
		if i, err := strconv.Atoi(n); err == nil {
			idx = append(idx, i)
		}
	}
	sort.Ints(idx)

	out := make([]Region, 0, len(idx))
	for _, i := range idx {
		d := fmt.Sprintf("%s/%d/", dir, i)
		var r Region
		for _, f := range []struct {
			name string
			dst  *uint64
		}{{"start", &r.Start}, {"end", &r.End}, {"nr_accesses", &r.NrAccesses}, {"age", &r.Age}} {
			v, err := readUint(m.fs, d+f.name)
			if err != nil {
				return nil, err
			}
			*f.dst = v
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

// Close stops and removes the monitor if this run still owns it.
// Ownership loss returns ErrOwnership and leaves sysfs untouched.
func (m *Monitor) Close() error {
	if m == nil || m.closed {
		return nil
	}
	m.closed = true

	nr, err := readInt(m.fs, "kdamonds/nr_kdamonds")
	if err != nil {
		return err
	}
	if nr != 1 {
		return ErrOwnership
	}
	if m.kdamondPID != "" {
		if err := m.Verify(); err != nil {
			return err
		}
	}

	if st, _ := m.fs.ReadFile(kd + "/state"); strings.TrimSpace(string(st)) == cmdOn {
		if err := write(m.fs, kd+"/state", cmdOff); err != nil {
			return err
		}
	}
	return write(m.fs, "kdamonds/nr_kdamonds", "0")
}

func write(fs FS, name, v string) error {
	if err := fs.WriteFile(name, []byte(v)); err != nil {
		return fmt.Errorf("damon: write %s=%s: %w", name, v, err)
	}
	return nil
}

func readInt(fs FS, name string) (int, error) {
	b, err := fs.ReadFile(name)
	if err != nil {
		return 0, fmt.Errorf("damon: read %s: %w", name, err)
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func readUint(fs FS, name string) (uint64, error) {
	b, err := fs.ReadFile(name)
	if err != nil {
		return 0, fmt.Errorf("damon: read %s: %w", name, err)
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

func u(v uint64) string { return strconv.FormatUint(v, 10) }

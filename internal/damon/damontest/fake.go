// Package damontest fakes the DAMON sysfs behaviour gocold relies on.
package damontest

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

const (
	kd    = "kdamonds/0"
	tried = kd + "/contexts/0/schemes/0/tried_regions/"

	// KdamondPID is the pid reported once the fake monitor is on.
	KdamondPID = "4242"
)

// Region is one fake monitoring region.
type Region struct {
	Start, End, NrAccesses, Age uint64
}

// FS is an in-memory DAMON sysfs. Tried returns regions per snapshot request.
type FS struct {
	mu     sync.Mutex
	Files  map[string]string
	Writes []string
	FailOn string
	Tried  func() []Region
}

// New returns a fake with nr_kdamonds set to nr.
func New(nr string) *FS {
	return &FS{Files: map[string]string{"kdamonds/nr_kdamonds": nr}}
}

// Get returns a file value.
func (f *FS) Get(n string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Files[n]
}

// Set overwrites a file value (simulates another actor).
func (f *FS) Set(n, v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Files[n] = v
}

func (f *FS) ReadFile(n string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.Files[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(v + "\n"), nil
}

func (f *FS) WriteFile(n string, d []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := string(d)
	f.Writes = append(f.Writes, n+"="+v)
	if n == f.FailOn {
		return errors.New("injected")
	}

	switch {
	case n == "kdamonds/nr_kdamonds" && v == "1":
		f.Files[kd+"/state"], f.Files[kd+"/pid"] = "off", "-1"
	case n == "kdamonds/nr_kdamonds" && v == "0":
		f.drop("kdamonds/0/")
	case n == kd+"/state" && v == "on":
		f.Files[kd+"/pid"] = KdamondPID
	case n == kd+"/state" && v == "off":
		f.Files[kd+"/pid"] = "-1"
	case n == kd+"/state" && v == "update_schemes_tried_regions":
		f.drop(tried)
		f.Files[tried+"total_bytes"] = "0"
		if f.Tried == nil {
			return nil
		}
		for i, r := range f.Tried() {
			p := fmt.Sprintf("%s%d/", tried, i)
			f.Files[p+"start"] = fmt.Sprint(r.Start)
			f.Files[p+"end"] = fmt.Sprint(r.End)
			f.Files[p+"nr_accesses"] = fmt.Sprint(r.NrAccesses)
			f.Files[p+"age"] = fmt.Sprint(r.Age)
		}
		return nil
	}
	f.Files[n] = v
	return nil
}

func (f *FS) ReadDir(n string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	for k := range f.Files {
		if rest, ok := strings.CutPrefix(k, n+"/"); ok {
			seen[strings.SplitN(rest, "/", 2)[0]] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (f *FS) drop(prefix string) {
	for k := range f.Files {
		if strings.HasPrefix(k, prefix) {
			delete(f.Files, k)
		}
	}
}

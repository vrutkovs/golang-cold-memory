// Package proc reads target state from /proc.
package proc

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Mapping is one /proc/PID/maps entry, optionally with smaps counters.
type Mapping struct {
	Start  uint64 `json:"start"`
	End    uint64 `json:"end"`
	Perms  string `json:"perms"`
	Offset uint64 `json:"offset"`
	Inode  uint64 `json:"inode"`
	Path   string `json:"path,omitempty"`
	Rss    uint64 `json:"rss"`
	Swap   uint64 `json:"swap"`
}

// Size returns mapping length in bytes.
func (m Mapping) Size() uint64 { return m.End - m.Start }

// Writable reports a writable private mapping.
func (m Mapping) Writable() bool {
	return len(m.Perms) == 4 && m.Perms[1] == 'w' && m.Perms[3] == 'p'
}

// Anonymous reports a mapping without file backing.
// Pseudo paths such as [heap] count as anonymous, [stack]/[vvar]/... do not.
func (m Mapping) Anonymous() bool {
	if m.Inode != 0 {
		return false
	}
	return m.Path == "" || m.Path == "[heap]" || strings.HasPrefix(m.Path, "[anon:")
}

// ReadMaps parses /proc/PID/smaps (falls back to maps when smaps is unreadable).
func ReadMaps(pid int) ([]Mapping, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/smaps", pid))
	if err == nil {
		defer f.Close()
		return ParseSmaps(f)
	}

	f, err = os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseSmaps(f)
}

// ParseSmaps parses smaps or plain maps content.
func ParseSmaps(r io.Reader) ([]Mapping, error) {
	var out []Mapping
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Counter lines look like "Rss:   12 kB".
		if strings.HasSuffix(fields[0], ":") {
			if len(out) == 0 || len(fields) < 2 {
				continue
			}
			v, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				continue
			}
			cur := &out[len(out)-1]
			switch fields[0] {
			case "Rss:":
				cur.Rss = v * 1024
			case "Swap:":
				cur.Swap = v * 1024
			}
			continue
		}

		m, err := parseMapsLine(fields)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", line, err)
		}
		out = append(out, m)
	}
	return out, sc.Err()
}

// parseMapsLine parses "start-end perms offset dev inode [path]".
func parseMapsLine(f []string) (Mapping, error) {
	if len(f) < 5 {
		return Mapping{}, fmt.Errorf("short line")
	}
	lo, hi, ok := strings.Cut(f[0], "-")
	if !ok {
		return Mapping{}, fmt.Errorf("bad range")
	}

	var m Mapping
	var err error
	if m.Start, err = strconv.ParseUint(lo, 16, 64); err != nil {
		return m, err
	}
	if m.End, err = strconv.ParseUint(hi, 16, 64); err != nil {
		return m, err
	}
	m.Perms = f[1]
	if m.Offset, err = strconv.ParseUint(f[2], 16, 64); err != nil {
		return m, err
	}
	if m.Inode, err = strconv.ParseUint(f[4], 10, 64); err != nil {
		return m, err
	}
	if len(f) > 5 {
		m.Path = strings.Join(f[5:], " ")
	}
	return m, nil
}

// Range is a half-open virtual address interval [Start, End).
type Range struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// Size returns range length in bytes.
func (r Range) Size() uint64 { return r.End - r.Start }

// SelectCandidates returns writable private anonymous ranges, merging
// adjacent ones. When more than maxRanges remain, the largest by RSS win.
// Ranges are candidates only: nothing here proves they belong to the Go heap.
func SelectCandidates(maps []Mapping, maxRanges int) []Range {
	type cand struct {
		r   Range
		rss uint64
	}
	var cs []cand
	for _, m := range maps {
		if !m.Writable() || !m.Anonymous() || m.Size() == 0 {
			continue
		}
		if n := len(cs); n > 0 && cs[n-1].r.End == m.Start {
			cs[n-1].r.End = m.End
			cs[n-1].rss += m.Rss
			continue
		}
		cs = append(cs, cand{Range{m.Start, m.End}, m.Rss})
	}

	if maxRanges > 0 && len(cs) > maxRanges {
		sort.SliceStable(cs, func(i, j int) bool { return cs[i].rss > cs[j].rss })
		cs = cs[:maxRanges]
	}

	out := make([]Range, len(cs))
	for i, c := range cs {
		out[i] = c.r
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// CandidateRanges returns all writable anonymous ranges without bounding.
func CandidateRanges(maps []Mapping) []Range {
	return SelectCandidates(maps, 0)
}

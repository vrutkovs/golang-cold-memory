package proc

import "sort"

// Normalize sorts rs and merges overlapping or adjacent ranges.
func Normalize(rs []Range) []Range {
	c := make([]Range, 0, len(rs))
	for _, r := range rs {
		if r.End > r.Start {
			c = append(c, r)
		}
	}
	sort.Slice(c, func(i, j int) bool { return c[i].Start < c[j].Start })

	var out []Range
	for _, r := range c {
		if n := len(out); n > 0 && r.Start <= out[n-1].End {
			out[n-1].End = max(out[n-1].End, r.End)
			continue
		}
		out = append(out, r)
	}
	return out
}

// Subtract returns parts of a not covered by b.
func Subtract(a, b []Range) []Range {
	a, b = Normalize(a), Normalize(b)
	var out []Range
	j := 0
	for _, r := range a {
		cur := r.Start
		for j < len(b) && b[j].End <= cur {
			j++
		}
		for k := j; k < len(b) && b[k].Start < r.End; k++ {
			if b[k].Start > cur {
				out = append(out, Range{cur, b[k].Start})
			}
			cur = max(cur, b[k].End)
		}
		if cur < r.End {
			out = append(out, Range{cur, r.End})
		}
	}
	return out
}

// Intersect returns parts covered by both a and b.
func Intersect(a, b []Range) []Range {
	a, b = Normalize(a), Normalize(b)
	var out []Range
	for i, j := 0, 0; i < len(a) && j < len(b); {
		lo, hi := max(a[i].Start, b[j].Start), min(a[i].End, b[j].End)
		if lo < hi {
			out = append(out, Range{lo, hi})
		}
		if a[i].End < b[j].End {
			i++
		} else {
			j++
		}
	}
	return out
}

// TotalSize sums sizes of normalized rs.
func TotalSize(rs []Range) uint64 {
	var n uint64
	for _, r := range Normalize(rs) {
		n += r.Size()
	}
	return n
}

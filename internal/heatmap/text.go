package heatmap

import (
	"fmt"
	"io"
	"strings"
)

// Glyphs: '-' not monitored, '.' no access observed, '1'..'7' rate levels.
const (
	glyphNone = '-'
	glyphZero = '.'
)

// Glyph returns the text symbol of a cell.
func Glyph(rate *float64) byte {
	if rate == nil {
		return glyphNone
	}
	l := LevelOf(*rate)
	if l == 0 {
		return glyphZero
	}
	return byte('0' + l)
}

// Text writes a glyph grid; readable without color.
func (h *Heatmap) Text(w io.Writer) {
	if len(h.Columns) == 0 {
		return
	}
	span := float64(h.Window.EndNS-h.Window.StartNS) / float64(nsPerSec)
	fmt.Fprintf(w, "heatmap (%d cols over %.0fs, bin %s; - unmonitored, . no access, 1..7 rate levels)\n",
		len(h.Columns), span, human(h.BinBytes))

	var legend []string
	for i, l := range Levels[1:] {
		legend = append(legend, fmt.Sprintf("%d %s", i+1, l.Name))
	}
	fmt.Fprintf(w, "  levels: %s\n", strings.Join(legend, ", "))

	row := func(r Row, name string) {
		fmt.Fprintf(w, "  %-40.40s %9s %-15s |%s| perf %d\n", name, human(r.Bytes), r.Label, glyphs(r), r.PerfTotal)
	}

	// Small rows without access or perf hits are elided to keep the grid short.
	var elided int
	var elidedBytes uint64
	for _, r := range h.Rows {
		if r.Bytes < h.BinBytes/4 && r.MaxRate == 0 && r.PerfTotal == 0 {
			elided++
			elidedBytes += r.Bytes
			continue
		}
		row(r, fmt.Sprintf("%#x-%#x", r.Start, r.End))
	}
	if elided > 0 {
		fmt.Fprintf(w, "  (%d small rows without observed access or perf hits elided, %s; see --json/--html)\n", elided, human(elidedBytes))
	}
	if len(h.TypeRows) > 0 {
		fmt.Fprintln(w, "  by core-time type (placement projected over window):")
		for _, r := range h.TypeRows {
			row(r, r.Key)
		}
	}
}

func glyphs(r Row) string {
	var b strings.Builder
	for _, v := range r.Rate {
		b.WriteByte(Glyph(v))
	}
	return b.String()
}

func human(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

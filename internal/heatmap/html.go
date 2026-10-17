package heatmap

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"
)

// siteSep matches objects.SiteKey ("type ← site").
const siteSep = " ← "

// Meta is the recording context shown in the HTML header.
type Meta struct {
	Dir       string
	PID       int
	GoVersion string
	Kernel    string
}

type cellView struct {
	Class string
	Title string
}

type rowView struct {
	Name, Site, Kind, Label, Size string
	Start                         uint64
	Bytes                         uint64
	Mean, Max, Covered            float64
	Perf                          int
	Cells                         []cellView
}

type tableView struct {
	Site  bool // rows carry a separate allocation-site column
	Ticks []string
	Gaps  []bool
	Rows  []rowView
}

type pageView struct {
	Meta
	H      *Heatmap
	Span   string
	Types  tableView
	Sites  tableView
	Legend []cellView
}

// HTML writes a self-contained heatmap page. Profile-supplied names are
// escaped by html/template.
func (h *Heatmap) HTML(w io.Writer, m Meta) error {
	v := pageView{Meta: m, H: h, Span: fmt.Sprintf("%.1fs", float64(h.Window.EndNS-h.Window.StartNS)/float64(nsPerSec))}
	var ticks []string
	var gaps []bool
	for i, c := range h.Columns {
		gaps = append(gaps, c.GapBefore)
		t := ""
		if i%10 == 0 {
			t = fmt.Sprintf("%ds", (c.StartNS-h.Window.StartNS)/nsPerSec)
		}
		ticks = append(ticks, t)
	}
	v.Types = tableView{Ticks: ticks, Gaps: gaps}
	for _, r := range h.TypeRows {
		v.Types.Rows = append(v.Types.Rows, h.rowView(r, r.Key))
	}
	v.Sites = tableView{Site: true, Ticks: ticks, Gaps: gaps}
	for _, r := range h.SiteRows {
		typ, site, _ := strings.Cut(r.Key, siteSep)
		rv := h.rowView(r, typ)
		rv.Site = site
		v.Sites.Rows = append(v.Sites.Rows, rv)
	}
	v.Legend = append(v.Legend, cellView{"nc", "not monitored (hatched)"})
	for i, l := range Levels {
		v.Legend = append(v.Legend, cellView{fmt.Sprintf("l%d", i), fmt.Sprintf("%d: %s", i, l.Name)})
	}
	v.Legend = append(v.Legend,
		cellView{"l0 p", "partially monitored (dashed outline)"},
		cellView{"l0 h", "perf sample(s) in cell (blue dot)"})
	return pageTmpl.Execute(w, v)
}

// WriteHTML creates path (0600, never overwriting) with the heatmap.
func (h *Heatmap) WriteHTML(path string, m Meta) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := h.HTML(f, m); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (h *Heatmap) rowView(r Row, name string) rowView {
	rv := rowView{Name: name, Kind: r.Kind, Label: r.Label, Size: human(r.Bytes), Start: r.Start, Bytes: r.Bytes,
		Mean: r.MeanRate, Max: r.MaxRate, Covered: r.CoveredShare * 100, Perf: r.PerfTotal}
	for c, col := range h.Columns {
		t0 := float64(col.StartNS-h.Window.StartNS) / float64(nsPerSec)
		t1 := float64(col.EndNS-h.Window.StartNS) / float64(nsPerSec)
		cv := cellView{Class: "nc", Title: fmt.Sprintf("%s · %.0f–%.0fs · not monitored · perf %d", name, t0, t1, r.Perf[c])}
		if rate := r.Rate[c]; rate != nil {
			cv.Class = fmt.Sprintf("l%d", LevelOf(*rate))
			cv.Title = fmt.Sprintf("%s · %.0f–%.0fs · rate %.4f · monitored %.0f%% · perf %d",
				name, t0, t1, *rate, r.Coverage[c]*100, r.Perf[c])
			if r.Coverage[c] < 1 {
				cv.Class += " p"
			}
		}
		if r.Perf[c] > 0 {
			cv.Class += " h"
		}
		rv.Cells = append(rv.Cells, cv)
	}
	return rv
}

var pageTmpl = template.Must(template.New("heatmap").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>gocold heatmap pid {{.PID}}</title>
<style>
body{font:13px system-ui,sans-serif;margin:16px;color:#222}
table.hm{border-collapse:collapse;font:11px ui-monospace,monospace}
table.hm td,table.hm th{padding:0 4px;white-space:nowrap;text-align:right}
table.hm td.n{max-width:22em;overflow:hidden;text-overflow:ellipsis;direction:rtl;text-align:left}
table.hm td.c{width:7px;min-width:7px;height:11px;padding:0;border:0}
table.hm td.g{border-left:2px solid #c00}
table.hm th.t{padding:0;text-align:left;font-weight:normal;color:#666;overflow:visible;max-width:7px}
.nc{background:repeating-linear-gradient(45deg,#bbb 0 1px,#fff 1px 3px)}
.l0{background:#e8eef3}.l1{background:#fee8c8}.l2{background:#fdd49e}.l3{background:#fdbb84}
.l4{background:#fc8d59}.l5{background:#ef6548}.l6{background:#d7301f}.l7{background:#990000}
.p{outline:1px dashed #333;outline-offset:-1px}
.h{background-image:radial-gradient(circle,#0057b8 0 2px,transparent 2.5px)}
.nc.h{background:radial-gradient(circle,#0057b8 0 2px,transparent 2.5px),repeating-linear-gradient(45deg,#bbb 0 1px,#fff 1px 3px)}
.legend span.sw{display:inline-block;width:14px;height:12px;vertical-align:middle;margin:0 4px 0 12px;border:1px solid #999}
.note{color:#555;max-width:70em}
button{margin-right:6px}
tr:hover td.n{background:#ffd}
</style></head><body>
<h1>gocold access heatmap</h1>
<p>Recording <code>{{.Dir}}</code> · pid {{.PID}} · {{.GoVersion}} · kernel {{.Kernel}}<br>
Window {{.Span}}, {{len .H.Columns}} columns{{if .H.PerfInGaps}}, {{.H.PerfInGaps}} perf samples in time gaps{{end}}.</p>
<p class="note">Cell value = DAMON access rate: fraction of sampling checks that saw access per aggregation interval, byte-weighted over the monitored part of the cell (region resolution).
Blue dots mark sampled accesses; no dot is <em>not</em> evidence of no access. Red column borders mark time gaps. Hover a cell for numbers.</p>
{{range .H.Notes}}<p class="note">Note: {{.}}</p>{{end}}
<div class="legend" role="list" aria-label="legend">{{range .Legend}}<span role="listitem"><span class="sw {{.Class}}"></span>{{.Title}}</span>{{end}}</div>
<p>Sort rows: <button data-k="start">lowest address</button><button data-k="mean">mean rate</button><button data-k="max">max rate</button><button data-k="perf">perf hits</button><button data-k="bytes">size</button></p>
{{define "table"}}<table class="hm sortable">
<thead><tr><th>type</th>{{if .Site}}<th>allocation site</th>{{end}}<th>size</th><th>label</th><th>mean</th><th>max</th><th>monitored</th><th>perf</th>{{range $i, $t := $.Ticks}}<th class="t{{if index $.Gaps $i}} g{{end}}">{{$t}}</th>{{end}}</tr></thead>
<tbody>{{range .Rows}}<tr data-start="{{.Start}}" data-mean="{{.Mean}}" data-max="{{.Max}}" data-perf="{{.Perf}}" data-bytes="{{.Bytes}}">
<td class="n" title="{{.Name}}"><bdi>{{.Name}}</bdi></td>{{if $.Site}}<td class="n" title="{{.Site}}"><bdi>{{.Site}}</bdi></td>{{end}}<td>{{.Size}}</td><td>{{.Label}}</td><td>{{printf "%.4f" .Mean}}</td><td>{{printf "%.4f" .Max}}</td><td>{{printf "%.0f%%" .Covered}}</td><td>{{.Perf}}</td>
{{range $i, $c := .Cells}}<td class="c {{$c.Class}}{{if index $.Gaps $i}} g{{end}}" title="{{$c.Title}}"></td>{{end}}</tr>
{{end}}</tbody></table>{{end}}
{{if .Types.Rows}}<h2>Core-time object types</h2>
<p class="note">Rows aggregate objects of one type at core time. Their placement is projected over the whole window; earlier cells may describe other objects at the same addresses.{{if .H.TypesOmitted}} {{.H.TypesOmitted}} smaller types omitted.{{end}}</p>
{{template "table" .Types}}{{else}}<p class="note">No core-time object types: record with <code>--objects</code>. Address rows are in the text report and JSON.</p>{{end}}
{{if .Sites.Rows}}<h2>By type and allocation site</h2>
<p class="note">Only objects the runtime sampled for the heap profile carry an allocation stack (about one per <code>MemProfileRate</code> bytes allocated; large objects almost always). Unsampled objects are left out, so row sizes undercount. Site = first non-runtime frame; the full stack is in JSON (<code>alloc_stack</code>). A quiet row is a candidate for allocations that are no longer used, not proof.{{if .H.SitesOmitted}} {{.H.SitesOmitted}} smaller rows omitted.{{end}}</p>
{{template "table" .Sites}}{{end}}
<script>
document.querySelectorAll('button[data-k]').forEach(b=>b.onclick=()=>{
  const k=b.dataset.k, asc=k==='start';
  document.querySelectorAll('table.sortable tbody').forEach(tb=>{
    [...tb.rows].sort((x,y)=>(asc?1:-1)*(Number(x.dataset[k])-Number(y.dataset[k]))).forEach(r=>tb.appendChild(r));
  });
});
</script>
</body></html>
`))

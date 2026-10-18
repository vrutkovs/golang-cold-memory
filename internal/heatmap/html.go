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
	Dir           string
	PID           int
	GoVersion     string
	Kernel        string
	QuietBytes    string
	QuietExcluded string
	QuietObjects  string
	QuietRegions  []QuietRegionView
	HasCore       bool
}

// QuietRegionView lists monitored areas without observed access.
type QuietRegionView struct {
	Address     string
	Size        string
	CoreObjects string
	Sites       []QuietSiteView
}

// QuietSiteView attributes object overlap to type and allocation site.
type QuietSiteView struct {
	Key   string
	Bytes string
	Type  string
	Site  string
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
	v.Sites = tableView{Site: true, Ticks: ticks, Gaps: gaps}
	for _, r := range h.SiteRows {
		typ, site, _ := strings.Cut(r.Key, siteSep)
		rv := h.rowView(r, typ)
		rv.Site = site
		v.Sites.Rows = append(v.Sites.Rows, rv)
	}
	for i := range v.QuietRegions {
		for j := range v.QuietRegions[i].Sites {
			site := &v.QuietRegions[i].Sites[j]
			site.Type, site.Site, _ = strings.Cut(site.Key, siteSep)
		}
	}
	v.Legend = append(v.Legend, cellView{"nc", "not monitored (hatched)"})
	for i, l := range Levels {
		v.Legend = append(v.Legend, cellView{fmt.Sprintf("l%d", i), fmt.Sprintf("%d: %s", i, l.Name)})
	}
	v.Legend = append(v.Legend, cellView{"l0 p", "partially monitored (dashed outline)"})
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
		Mean: r.MeanRate, Max: r.MaxRate, Covered: r.CoveredShare * 100}
	for c, col := range h.Columns {
		t0 := float64(col.StartNS-h.Window.StartNS) / float64(nsPerSec)
		t1 := float64(col.EndNS-h.Window.StartNS) / float64(nsPerSec)
		cv := cellView{Class: "nc", Title: fmt.Sprintf("%s · %.0f–%.0fs · not monitored", name, t0, t1)}
		if rate := r.Rate[c]; rate != nil {
			cv.Class = fmt.Sprintf("l%d", LevelOf(*rate))
			cv.Title = fmt.Sprintf("%s · %.0f–%.0fs · rate %.4f · monitored %.0f%%",
				name, t0, t1, *rate, r.Coverage[c]*100)
			if r.Coverage[c] < 1 {
				cv.Class += " p"
			}
		}
		rv.Cells = append(rv.Cells, cv)
	}
	return rv
}

var pageTmpl = template.Must(template.New("heatmap").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gocold heatmap pid {{.PID}}</title>
<style>
:root{color-scheme:light;--bg:#f3f5f4;--surface:#fff;--ink:#192a30;--muted:#597077;--border:#dce5e3;--accent:#146a67;--accent-soft:#e5f3f0;--gap:#c54c39;--shadow:0 12px 36px rgba(21,55,58,.06)}
*{box-sizing:border-box}
body{font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:var(--bg);color:var(--ink)}
main{max-width:1480px;margin:auto;padding:32px clamp(16px,4vw,56px) 72px}
.report-header{background:linear-gradient(125deg,#16363c,#215e5c);color:#f8fbfa;padding:32px clamp(20px,4vw,48px);border-radius:18px;box-shadow:var(--shadow)}
.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:11px;font-weight:700;color:#a5dcd1}
h1{font-size:clamp(26px,3vw,38px);line-height:1.15;letter-spacing:-.035em;margin:10px 0 20px}
.meta{display:flex;flex-wrap:wrap;gap:8px 24px;color:#d8e8e5;margin:0;font-size:13px}
.meta code{color:inherit;overflow-wrap:anywhere}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px 24px;margin-top:20px;box-shadow:var(--shadow)}
h2{font-size:19px;letter-spacing:-.02em;margin:0 0 10px}
.note{color:var(--muted);max-width:85ch;margin:0 0 14px}
.note:last-child{margin-bottom:0}
.summary-value{font-size:clamp(28px,3vw,40px);font-weight:700;letter-spacing:-.04em;color:var(--accent);margin:0 0 6px}
details summary{cursor:pointer;font-weight:600;margin:14px 0}
.legend{display:flex;align-items:center;flex-wrap:wrap;gap:9px 16px;font-size:12px;color:var(--muted)}
.legend span[role=listitem]{display:inline-flex;align-items:center;gap:5px}
.legend span.sw{display:inline-block;width:15px;height:13px;flex:none;border:1px solid #a3b1b3;border-radius:3px}
.toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:16px 0}
.toolbar strong{font-size:12px;color:var(--muted);margin-right:4px}
button,input{font:inherit}
button{border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--ink);padding:6px 11px;cursor:pointer}
button:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-soft)}
button:focus-visible,input:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.filters{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
.filters label{display:grid;gap:5px;min-width:min(100%,220px);color:var(--muted);font-weight:600;font-size:12px}
.filters input{width:100%;padding:9px 11px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--ink)}
.filters input::placeholder{color:var(--muted);font-weight:400}
.table-scroll{overflow:auto;max-height:70vh;border:1px solid var(--border);border-radius:10px}
table.hm{border-collapse:separate;border-spacing:0;width:100%;min-width:max-content;font:12px/1.35 ui-monospace,SFMono-Regular,Consolas,monospace}
table.hm td,table.hm th{padding:8px 10px;white-space:nowrap;text-align:right;border-bottom:1px solid var(--border)}
table.hm thead th{position:sticky;top:0;background:var(--accent-soft);color:var(--ink);font-weight:650;z-index:1}
table.hm tbody tr:last-child td{border-bottom:0}
table.hm tbody tr:hover td:not(.c){background:var(--accent-soft)}
table.hm td.n{max-width:26em;text-align:left}
table.hm td.n bdi{display:block;max-width:26em;overflow-x:auto;scrollbar-width:thin}
table.hm td.n bdi:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
table.hm td.c{width:9px;min-width:9px;height:16px;padding:0;border:0}
table.hm td.g{border-left:2px solid var(--gap)}
table.hm th.t{padding:0;text-align:left;font-weight:normal;color:var(--muted);overflow:visible;max-width:9px}
table.hm th.t.tick{z-index:2}
table.hm th.t span{position:relative;white-space:nowrap}
.nc{background:repeating-linear-gradient(45deg,#bbb 0 1px,#fff 1px 3px)}
.l0{background:#e8eef3}.l1{background:#fee8c8}.l2{background:#fdd49e}.l3{background:#fdbb84}
.l4{background:#fc8d59}.l5{background:#ef6548}.l6{background:#d7301f}.l7{background:#990000}
.p{outline:1px dashed #333;outline-offset:-1px}
tr[hidden]{display:none}
@media(max-width:640px){main{padding:14px 12px 48px}.report-header{padding:24px 18px}.card{padding:16px}.table-scroll{max-height:65vh}}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#101d20;--surface:#192a2e;--ink:#e7f0ee;--muted:#abc1bf;--border:#345056;--accent:#83d9c6;--accent-soft:#244441;--shadow:none}.report-header{background:linear-gradient(125deg,#19383b,#24504d)}.nc{background:repeating-linear-gradient(45deg,#657477 0 1px,#26393c 1px 3px)}}
</style></head><body>
<main>
<header class="report-header"><div class="eyebrow">Memory access / Go process</div><h1>Access heatmap</h1>
<p class="meta"><span>Recording <code>{{.Dir}}</code></span><span>PID {{.PID}}</span><span>{{.GoVersion}}</span><span>Kernel {{.Kernel}}</span><span>Window {{.Span}} · {{len .H.Columns}} columns</span></p></header>
{{if .QuietBytes}}<section class="card" aria-label="Quiet candidates"><h2>Quiet candidates</h2><p class="summary-value">{{.QuietBytes}}</p>
<p class="note">Core-time reachable Go object bytes in monitored resident regions with no access observed. Candidates for inspection, not proof these allocations are unused.{{if .QuietExcluded}} {{.QuietExcluded}} excluded: no reachable Go object in final core; may have been freed or untracked.{{end}}</p>
{{if .QuietObjects}}<p><strong>Quiet objects:</strong> {{.QuietObjects}} fully inside quiet regions at core time. Count above can also include parts of objects active elsewhere.</p>{{end}}
</section>{{end}}
<section class="card" aria-label="Reading the heatmap"><p class="note">Cell color shows DAMON access rate: share of sampling checks that saw access, weighted by monitored bytes. Dashed outlines mean partial coverage. Red borders mark time gaps. Hover for values.</p>
{{range .H.Notes}}<p class="note">Note: {{.}}</p>{{end}}
<div class="legend" role="list" aria-label="legend">{{range .Legend}}<span role="listitem"><span class="sw {{.Class}}"></span>{{.Title}}</span>{{end}}</div></section>
{{define "table"}}<div class="table-scroll" role="region" aria-label="Heatmap table" tabindex="0"><table class="hm sortable">
<thead><tr><th>type</th>{{if .Site}}<th>allocation site</th>{{end}}<th>size</th><th>label</th><th>mean</th><th>max</th><th>monitored</th>{{range $i, $t := $.Ticks}}<th class="t{{if $t}} tick{{end}}{{if index $.Gaps $i}} g{{end}}">{{if $t}}<span>{{$t}}</span>{{end}}</th>{{end}}</tr></thead>
<tbody>{{range .Rows}}<tr data-type="{{.Name}}" data-site="{{.Site}}" data-start="{{.Start}}" data-mean="{{.Mean}}" data-max="{{.Max}}" data-bytes="{{.Bytes}}">
<td class="n" title="{{.Name}}"><bdi tabindex="0">{{.Name}}</bdi></td>{{if $.Site}}<td class="n" title="{{.Site}}"><bdi tabindex="0">{{.Site}}</bdi></td>{{end}}<td>{{.Size}}</td><td>{{.Label}}</td><td>{{printf "%.4f" .Mean}}</td><td>{{printf "%.4f" .Max}}</td><td>{{printf "%.0f%%" .Covered}}</td>
{{range $i, $c := .Cells}}<td class="c {{$c.Class}}{{if index $.Gaps $i}} g{{end}}" title="{{$c.Title}}"></td>{{end}}</tr>
{{end}}</tbody></table></div>{{end}}
{{if .Sites.Rows}}<section class="card"><h2>By type and allocation site</h2>
<p class="note">Only objects the runtime sampled for the heap profile carry an allocation stack (about one per <code>MemProfileRate</code> bytes allocated; large objects almost always). Unsampled objects are left out, so row sizes undercount. Site = first non-runtime frame; the full stack is in JSON (<code>alloc_stack</code>). A quiet row is a candidate for allocations that are no longer used, not proof.{{if .H.SitesOmitted}} {{.H.SitesOmitted}} smaller rows omitted.{{end}}</p>
<div class="toolbar" role="group" aria-label="Sort rows"><strong>Sort by</strong><button type="button" data-k="start">lowest address</button><button type="button" data-k="mean">mean rate</button><button type="button" data-k="max">max rate</button><button type="button" data-k="bytes">size</button></div>
<div class="filters"><label for="filter-type">Type<input id="filter-type" type="search" placeholder="Filter type"></label>
<label for="filter-site">Allocation site<input id="filter-site" type="search" placeholder="Filter site"></label></div>
{{template "table" .Sites}}</section>{{end}}
{{if .QuietRegions}}<section class="card" aria-label="Quiet regions"><h2>Quiet regions ({{len .QuietRegions}})</h2>
<p class="note">Only regions with reachable Go objects at core time; sorted by region size. Quiet total counts overlap bytes, not whole region sizes. Objects may be active elsewhere. Sites exist only for heap-profile-sampled objects.</p>
<div class="table-scroll" role="region" aria-label="Quiet regions table" tabindex="0"><table class="hm"><thead><tr><th>address range</th><th>region size</th>{{if .HasCore}}<th>Core object overlap</th><th>type</th><th>allocation site</th><th>overlap bytes</th>{{end}}</tr></thead><tbody>
{{range .QuietRegions}}{{ $region := . }}{{if .Sites}}{{range .Sites}}<tr><td class="n"><bdi tabindex="0">{{$region.Address}}</bdi></td><td>{{$region.Size}}</td>{{if $.HasCore}}<td>{{$region.CoreObjects}}</td><td class="n" title="{{.Type}}"><bdi tabindex="0">{{.Type}}</bdi></td><td class="n" title="{{.Site}}"><bdi tabindex="0">{{.Site}}</bdi></td><td>{{.Bytes}}</td>{{end}}</tr>{{end}}{{else}}<tr><td class="n"><bdi tabindex="0">{{.Address}}</bdi></td><td>{{.Size}}</td>{{if $.HasCore}}<td>{{.CoreObjects}}</td><td>—</td><td>—</td><td>—</td>{{end}}</tr>{{end}}{{end}}
</tbody></table></div></section>{{end}}
<script>
const typeFilter = document.getElementById('filter-type');
const siteFilter = document.getElementById('filter-site');
function filterRows() {
  const typ = typeFilter.value.toLocaleLowerCase(), site = siteFilter.value.toLocaleLowerCase();
  document.querySelectorAll('table.sortable tbody tr').forEach(row => {
    row.hidden = !row.dataset.type.toLocaleLowerCase().includes(typ) || !row.dataset.site.toLocaleLowerCase().includes(site);
  });
}
typeFilter?.addEventListener('input', filterRows);
siteFilter?.addEventListener('input', filterRows);
document.querySelectorAll('button[data-k]').forEach(b=>b.onclick=()=>{
  const k=b.dataset.k, asc=k==='start';
  document.querySelectorAll('table.sortable tbody').forEach(tb=>{
    [...tb.rows].sort((x,y)=>(asc?1:-1)*(Number(x.dataset[k])-Number(y.dataset[k]))).forEach(r=>tb.appendChild(r));
  });
});
</script>
</main></body></html>
`))

// Package objects maps core-time Go heap objects onto address labels.
//
// Objects are those reachable at core time. A sample address inside an
// object is only a candidate match: the address may have been reused
// between sample time and core time.
package objects

import (
	"fmt"
	"sort"

	"github.com/vrutkovs/golang-cold-memory/internal/xdebug/core"
	"github.com/vrutkovs/golang-cold-memory/internal/xdebug/gocore"
)

// Object labels.
const (
	LabelQuiet    = "quiet-candidate"
	LabelObserved = "observed-access"
	LabelMixed    = "mixed"
	LabelUnknown  = "unknown"
)

// Classifier labels [start, end) and may accumulate per-region stats.
type Classifier func(start, end uint64) string

// Options bound analysis cost.
type Options struct {
	MaxPaths   int // reference paths computed in total
	TopObjects int // quiet/mixed objects listed
}

// Group aggregates objects by type or owner.
type Group struct {
	Key    string           `json:"key"`
	Count  int              `json:"count"`
	Bytes  int64            `json:"bytes"`
	Labels map[string]int64 `json:"bytes_by_label"`
}

// Obj is one listed core-time object.
type Obj struct {
	Addr     uint64   `json:"addr"`
	Size     int64    `json:"size"`
	Type     string   `json:"type"`
	Label    string   `json:"label"`
	Path     []string `json:"path,omitempty"`
	Owner    string   `json:"owner,omitempty"`
	SliceLen *int64   `json:"slice_len,omitempty"`
	SliceCap *int64   `json:"slice_cap,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// Match ties a sample address to a core-time object candidate.
type Match struct {
	Addr   uint64 `json:"addr"`
	Object *Obj   `json:"object,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Result is the object analysis output.
type Result struct {
	GoVersion    string   `json:"go_version"`
	Objects      int      `json:"objects"`
	Bytes        int64    `json:"bytes"`
	ByType       []Group  `json:"by_type"`
	ByOwner      []Group  `json:"by_owner"`
	Listed       []Obj    `json:"listed_objects"`
	Matches      []Match  `json:"sample_matches"`
	Diagnostics  []string `json:"diagnostics,omitempty"`
	GraphPartial bool     `json:"pointer_graph_incomplete"`
	Warnings     []string `json:"core_warnings,omitempty"`
}

// Load opens the core with the exact executable.
func Load(corePath, exePath string) (p *gocore.Process, err error) {
	defer recoverErr(&err)
	c, err := core.Core(corePath, "", exePath)
	if err != nil {
		return nil, err
	}
	return gocore.Core(c)
}

// Analyze classifies every object, lists notable ones and matches sample addresses.
// visit is called once per object (may account bytes); label must be pure.
func Analyze(p *gocore.Process, visit, label Classifier, addrs []uint64, o Options) (res *Result, err error) {
	defer recoverErr(&err)
	res = &Result{GoVersion: p.BuildVersion(), Warnings: p.Process().Warnings()}

	byType := map[string]*Group{}
	var notable []gocore.Object
	labels := map[gocore.Object]string{}
	p.ForEachObject(func(x gocore.Object) bool {
		a, sz := uint64(p.Addr(x)), p.Size(x)
		l := visit(a, a+uint64(sz))
		name := typeName(p, x)
		res.Objects++
		res.Bytes += sz
		addTo(byType, name, sz, l)
		if l == LabelQuiet || l == LabelMixed {
			notable = append(notable, x)
			labels[x] = l
		}
		return true
	})
	res.ByType = sorted(byType)

	sort.Slice(notable, func(i, j int) bool { return p.Size(notable[i]) > p.Size(notable[j]) })
	if len(notable) > o.TopObjects {
		notable = notable[:o.TopObjects]
	}

	budget := o.MaxPaths
	byOwner := map[string]*Group{}
	for _, x := range notable {
		obj := describe(p, x, labels[x], &budget)
		res.Listed = append(res.Listed, obj)
		addTo(byOwner, ownerKey(obj), obj.Size, obj.Label)
	}
	res.ByOwner = sorted(byOwner)

	seen := map[gocore.Object]*Obj{}
	for _, a := range addrs {
		x, off := p.FindObject(core.Address(a))
		if x == 0 {
			res.Matches = append(res.Matches, Match{Addr: a, Reason: "not inside a reachable object at core time"})
			continue
		}
		obj, ok := seen[x]
		if !ok {
			ax := uint64(p.Addr(x))
			d := describe(p, x, label(ax, ax+uint64(p.Size(x))), &budget)
			obj = &d
			seen[x] = obj
		}
		res.Matches = append(res.Matches, Match{Addr: a, Object: obj, Offset: off})
	}

	res.Diagnostics = p.Diagnostics()
	res.GraphPartial = len(res.Diagnostics) > 0
	return res, nil
}

// describe builds Obj, spending one path from budget when available.
func describe(p *gocore.Process, x gocore.Object, label string, budget *int) Obj {
	o := Obj{Addr: uint64(p.Addr(x)), Size: p.Size(x), Type: typeName(p, x), Label: label}
	if *budget <= 0 {
		o.Notes = append(o.Notes, "path not computed (--max-paths budget)")
		return o
	}
	*budget--

	for r, path := range p.Reachable(x) {
		o.Owner = rootName(r)
		o.Path = renderPath(p, r, path)
		sliceInfo(p, r, path, &o)
		break
	}
	if o.Path == nil {
		o.Notes = append(o.Notes, "no root path found (pointer graph may be incomplete)")
	}
	return o
}

// sliceInfo reads len/cap when the last edge into x is a slice header.
func sliceInfo(p *gocore.Process, r *gocore.Root, path []gocore.Link, o *Obj) {
	last := path[len(path)-1]
	var t *gocore.Type
	var base core.Address
	off := last.SrcOff
	if len(path) == 1 {
		if !r.HasAddress() {
			return
		}
		t, base = r.Type, r.Addr()
	} else {
		parent := path[len(path)-2].Dst
		pt, _ := p.Type(parent)
		if pt == nil {
			return
		}
		t, base = pt, p.Addr(parent)
		off %= pt.Size
	}

	ft, foff := fieldAt(t, off)
	if ft == nil || ft.Kind != gocore.KindSlice || foff != 0 {
		return
	}
	mem := p.Process()
	ptr := mem.PtrSize()
	hdr := base.Add(last.SrcOff)
	if !mem.ReadableN(hdr, 3*ptr) {
		return
	}
	l, c := mem.ReadInt(hdr.Add(ptr)), mem.ReadInt(hdr.Add(2*ptr))
	o.SliceLen, o.SliceCap = &l, &c
	if l == 0 {
		o.Notes = append(o.Notes, "slice len=0 at core time: allocated spare capacity, not dead memory")
	}
}

// fieldAt returns the innermost type containing off and the offset within it.
func fieldAt(t *gocore.Type, off int64) (*gocore.Type, int64) {
	for t != nil {
		switch t.Kind {
		case gocore.KindArray:
			if t.Elem == nil || t.Elem.Size == 0 {
				return t, off
			}
			off %= t.Elem.Size
			t = t.Elem
		case gocore.KindStruct:
			var next *gocore.Type
			for _, f := range t.Fields {
				if f.Off <= off && off < f.Off+f.Type.Size {
					next, off = f.Type, off-f.Off
					break
				}
			}
			if next == nil {
				return nil, 0
			}
			t = next
		default:
			return t, off
		}
	}
	return nil, 0
}

func rootName(r *gocore.Root) string {
	if r.Frame == nil {
		return r.Name
	}
	return r.Frame.Func().Name() + "." + r.Name
}

func renderPath(p *gocore.Process, r *gocore.Root, path []gocore.Link) []string {
	out := []string{rootName(r) + typeFieldName(r.Type, path[0].SrcOff)}
	for i, l := range path {
		step := fmt.Sprintf("%x %s", p.Addr(l.Dst), typeName(p, l.Dst))
		if i+1 < len(path) {
			step += fieldName(p, l.Dst, path[i+1].SrcOff)
		}
		out = append(out, step)
	}
	return out
}

func ownerKey(o Obj) string {
	if o.Owner == "" {
		return "(path unknown)"
	}
	return o.Owner
}

func addTo(m map[string]*Group, key string, sz int64, label string) {
	g := m[key]
	if g == nil {
		g = &Group{Key: key, Labels: map[string]int64{}}
		m[key] = g
	}
	g.Count++
	g.Bytes += sz
	g.Labels[label] += sz
}

func sorted(m map[string]*Group) []Group {
	out := make([]Group, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// recoverErr converts analyzer panics (missing core pages, unsupported
// runtime layouts) into errors instead of guessing.
func recoverErr(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("core analysis failed: %v", r)
	}
}

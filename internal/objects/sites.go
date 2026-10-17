package objects

import (
	"debug/dwarf"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/vrutkovs/golang-cold-memory/internal/xdebug/core"
	"github.com/vrutkovs/golang-cold-memory/internal/xdebug/gocore"
)

// NoSite marks objects without a memprofile record.
const NoSite = "(not sampled)"

// maxStack bounds frames kept per listed object.
const maxStack = 8

// Sites resolves allocation stacks of sampled objects to file:line.
type Sites struct {
	p     *gocore.Process
	lines map[core.Address]string // return PC -> "dir/file.go:123"
	cache map[core.Address]string
}

// NewSites collects every sampled stack PC, then resolves them in one pass
// over the executable's DWARF line table. Without DWARF lines, frames
// resolve to function names only.
func NewSites(p *gocore.Process) *Sites {
	s := &Sites{p: p, lines: map[core.Address]string{}, cache: map[core.Address]string{}}

	var pcs []uint64
	seen := map[core.Address]bool{}
	p.ForEachObject(func(x gocore.Object) bool {
		for _, pc := range p.AllocStack(x) {
			if !seen[pc] {
				seen[pc] = true
				pcs = append(pcs, uint64(pc))
			}
		}
		return true
	})
	if len(pcs) == 0 {
		return s
	}
	slices.Sort(pcs)

	d, err := p.Process().DWARF()
	if err != nil {
		return s
	}
	base := p.Process().StaticBase()
	r := d.Reader()
	for {
		cu, err := r.Next()
		if err != nil || cu == nil {
			return s
		}
		if cu.Tag != dwarf.TagCompileUnit {
			r.SkipChildren()
			continue
		}
		lr, err := d.LineReader(cu)
		if err == nil && lr != nil {
			s.scan(lr, pcs, base)
		}
		r.SkipChildren()
	}
}

// scan maps each pc-1 (inside the call) to the line row covering it.
func (s *Sites) scan(lr *dwarf.LineReader, pcs []uint64, base uint64) {
	var prev dwarf.LineEntry
	var have bool
	var e dwarf.LineEntry
	for lr.Next(&e) == nil {
		if have && !prev.EndSequence && e.Address > prev.Address && prev.File != nil {
			lo, hi := prev.Address+base, e.Address+base
			i, _ := slices.BinarySearch(pcs, lo+1)
			for ; i < len(pcs) && pcs[i]-1 < hi; i++ {
				f := prev.File.Name
				s.lines[core.Address(pcs[i])] = fmt.Sprintf("%s/%s:%d", path.Base(path.Dir(f)), path.Base(f), prev.Line)
			}
		}
		prev, have = e, true
	}
}

// Of returns x's allocation site (first non-runtime frame) and the stack.
func (s *Sites) Of(x gocore.Object) (string, []string) {
	pcs := s.p.AllocStack(x)
	if len(pcs) == 0 {
		return NoSite, nil
	}

	var stack []string
	site := ""
	for _, pc := range pcs {
		f := s.frame(pc)
		if len(stack) < maxStack {
			stack = append(stack, f)
		}
		if site == "" && !runtimeFrame(f) {
			site = f
		}
	}
	if site == "" {
		site = runtimeSite(stack) // e.g. runtime.malg allocating a runtime.g
	}
	return site, stack
}

// frame names a return PC as "pkg.Func (dir/file.go:123)".
func (s *Sites) frame(pc core.Address) string {
	if f, ok := s.cache[pc]; ok {
		return f
	}

	// Return addresses point after the call; pc-1 lies inside it.
	name := fmt.Sprintf("%#x", uint64(pc))
	if fn := s.p.FindFunc(pc - 1); fn != nil {
		name = fn.Name()
	}
	if l, ok := s.lines[pc]; ok {
		name = fmt.Sprintf("%s (%s)", name, l)
	}
	s.cache[pc] = name
	return name
}

// mallocEntry lists runtime allocation entry points skipped when the
// whole stack is runtime-internal.
var mallocEntry = []string{"runtime.mallocgc", "runtime.newobject", "runtime.newarray", "runtime.make", "runtime.growslice", "runtime.rawstring", "runtime.rawbyteslice"}

func runtimeSite(stack []string) string {
	for _, f := range stack {
		if !slices.ContainsFunc(mallocEntry, func(p string) bool { return strings.HasPrefix(f, p) }) {
			return f
		}
	}
	return stack[0]
}

func runtimeFrame(f string) bool {
	return strings.HasPrefix(f, "runtime.") || strings.HasPrefix(f, "internal/runtime/")
}

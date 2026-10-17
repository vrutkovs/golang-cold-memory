// Local patch (gocold): on-demand GC mask support.

package gocore

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vrutkovs/golang-cold-memory/internal/xdebug/core"
)

// tflagGCMaskOnDemand is internal/abi.TFlagGCMaskOnDemand (Go 1.24+),
// used when DWARF lacks the constant.
const tflagGCMaskOnDemand = 1 << 4

// Diagnostics lists conditions that made the pointer graph incomplete.
func (p *Process) Diagnostics() []string {
	return p.diagnostics
}

func (p *Process) diag(format string, args ...any) {
	p.diagnostics = append(p.diagnostics, fmt.Sprintf(format, args...))
}

// ptrMask returns the pointer bitmap of the abi.Type in typ covering nptrs words.
//
// With TFlagGCMaskOnDemand set, GCData points to a slot holding the lazily
// built mask: dereference it exactly once. A nil slot or unreadable metadata
// returns ok=false; callers must then add no pointer edges for the type.
func (p *Process) ptrMask(typ region, nptrs int64) (core.Address, bool) {
	gcdata := typ.Field("GCData").Address()
	if p.onDemandMasks() && typ.Field("TFlag").Uint8()&p.onDemandFlag() != 0 {
		if gcdata == 0 || !p.proc.ReadableN(gcdata, p.proc.PtrSize()) {
			p.diagOnce(typ.a, "type %x: on-demand GC mask slot %x missing from core; pointer graph incomplete", typ.a, gcdata)
			return 0, false
		}
		gcdata = p.proc.ReadPtr(gcdata)
		if gcdata == 0 {
			p.diagOnce(typ.a, "type %x: on-demand GC mask not built yet (nil slot); pointer graph incomplete", typ.a)
			return 0, false
		}
	}

	if nptrs > 0 && !p.proc.ReadableN(gcdata, (nptrs+7)/8) {
		p.diagOnce(typ.a, "type %x: GC mask %x missing from core; pointer graph incomplete", typ.a, gcdata)
		return 0, false
	}
	return gcdata, true
}

func (p *Process) diagOnce(typ core.Address, format string, args ...any) {
	if p.diagSeen == nil {
		p.diagSeen = map[core.Address]bool{}
	}
	if p.diagSeen[typ] {
		return
	}
	p.diagSeen[typ] = true
	p.diag(format, args...)
}

func (p *Process) onDemandFlag() uint8 {
	if v, ok := p.rtConsts.find("internal/abi.TFlagGCMaskOnDemand"); ok {
		return uint8(v)
	}
	return tflagGCMaskOnDemand
}

// onDemandMasks reports whether the runtime may use on-demand masks (go1.24+).
func (p *Process) onDemandMasks() bool {
	if _, ok := p.rtConsts.find("internal/abi.TFlagGCMaskOnDemand"); ok {
		return true
	}
	return goMinor(p.buildVersion) >= 24
}

// goMinor parses "go1.24.3" or "go1.25rc1" into 24/25; unknown returns 0.
func goMinor(v string) int {
	v, ok := strings.CutPrefix(v, "go1.")
	if !ok {
		return 0
	}
	end := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if end >= 0 {
		v = v[:end]
	}
	n, _ := strconv.Atoi(v)
	return n
}

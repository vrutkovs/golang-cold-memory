// Local patch (gocold): allocation stacks of memprofile-sampled objects.

package gocore

import "github.com/vrutkovs/golang-cold-memory/internal/xdebug/core"

// maxProfStack bounds bucket stacks read from the core (runtime caps at 1024).
const maxProfStack = 1024

func (p *Process) noteProfile(obj, special core.Address) {
	if p.profiles == nil {
		p.profiles = map[core.Address]core.Address{}
	}
	p.profiles[obj] = special
}

// Sampled reports how many live objects carry a memprofile record.
func (p *Process) Sampled() int { return len(p.profiles) }

// AllocStack returns the allocation stack (return PCs, innermost first)
// that the runtime recorded when it sampled x for the heap profile.
// Only sampled objects (≈ one per MemProfileRate bytes) have one.
func (p *Process) AllocStack(x Object) []core.Address {
	sp, ok := p.profiles[core.Address(x)]
	if !ok {
		return nil
	}
	special, bucket := p.rtTypeByName["runtime.special"], p.rtTypeByName["runtime.bucket"]
	if special == nil || bucket == nil || bucket.field("nstk") == nil {
		p.diagOnce(0, "runtime.special/bucket types missing from DWARF; allocation sites unavailable")
		return nil
	}

	// specialprofile{special; b *bucket}: b follows special, pointer-aligned.
	ptr := p.proc.PtrSize()
	bAddr := sp.Add((special.Size + ptr - 1) / ptr * ptr)
	if !p.proc.ReadableN(bAddr, ptr) {
		return nil
	}
	b := p.proc.ReadPtr(bAddr)
	if b == 0 || !p.proc.ReadableN(b, bucket.Size) {
		return nil
	}

	// Stack words follow the bucket header (bucket.stk()).
	n := p.proc.ReadUintptr(b.Add(bucket.field("nstk").Off))
	if n == 0 || n > maxProfStack || !p.proc.ReadableN(b.Add(bucket.Size), int64(n)*ptr) {
		return nil
	}
	stk := make([]core.Address, n)
	for i := range stk {
		stk[i] = p.proc.ReadPtr(b.Add(bucket.Size + int64(i)*ptr))
	}
	return stk
}

// MemProfileRate returns runtime.MemProfileRate at core time, or -1.
func (p *Process) MemProfileRate() int64 {
	r, ok := p.rtGlobals["MemProfileRate"]
	if !ok {
		return -1
	}
	return r.Int()
}

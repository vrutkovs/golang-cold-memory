package proc

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	pagemapEntry     = 8
	pagemapPresent   = 1 << 63
	pagemapExclusive = 1 << 56
	pagemapPFNMask   = 1<<55 - 1

	// kpfZeroPage is KPF_ZERO_PAGE in /proc/kpageflags (covers the huge zero page too).
	kpfZeroPage = 1 << 24

	// pagemapChunk bounds memory per read (8 bytes per page).
	pagemapChunk = 64 * 1024
)

// Resident returns sub-ranges of rs backed by real RAM pages.
//
// Swapped and never-touched pages are excluded. So are shared zero-page
// mappings, which appear "present" after reads of untouched memory (e.g.
// by gcore via /proc/PID/mem) but use no RAM. Exclusively mapped pages are
// real; other pages count only when /proc/kpageflags proves they are not
// the zero page (needs root), otherwise they stay unverified.
func Resident(pid int, rs []Range, pageSize uint64) ([]Range, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/pagemap", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var kpf io.ReaderAt
	if k, err := os.Open("/proc/kpageflags"); err == nil {
		defer k.Close()
		kpf = k
	}
	return residentFrom(f, kpf, rs, pageSize)
}

func residentFrom(f, kpf io.ReaderAt, rs []Range, pageSize uint64) ([]Range, error) {
	var out []Range
	buf := make([]byte, pagemapChunk)
	zero := map[uint64]bool{}
	for _, r := range rs {
		last := (r.End + pageSize - 1) / pageSize
		for page := r.Start / pageSize; page < last; {
			n := min(last-page, uint64(len(buf)/pagemapEntry))
			b := buf[:n*pagemapEntry]
			if _, err := f.ReadAt(b, int64(page*pagemapEntry)); err != nil {
				return nil, fmt.Errorf("pagemap read at page %#x: %w", page, err)
			}

			for i := uint64(0); i < n; i++ {
				e := binary.LittleEndian.Uint64(b[i*pagemapEntry:])
				if !realPage(e, kpf, zero) {
					continue
				}
				addr := (page + i) * pageSize
				out = appendRange(out, Range{max(addr, r.Start), min(addr+pageSize, r.End)})
			}
			page += n
		}
	}
	return out, nil
}

// realPage reports a present pagemap entry that is provably not the zero page.
func realPage(e uint64, kpf io.ReaderAt, zero map[uint64]bool) bool {
	if e&pagemapPresent == 0 {
		return false
	}
	if e&pagemapExclusive != 0 {
		return true
	}
	pfn := e & pagemapPFNMask
	if pfn == 0 || kpf == nil {
		return false // PFN hidden without privileges: unverified
	}

	isZero, ok := zero[pfn]
	if !ok {
		var fb [8]byte
		if _, err := kpf.ReadAt(fb[:], int64(pfn*8)); err != nil {
			return false
		}
		isZero = binary.LittleEndian.Uint64(fb[:])&kpfZeroPage != 0
		zero[pfn] = isZero
	}
	return !isZero
}

// appendRange appends r, merging with the last range when contiguous.
func appendRange(rs []Range, r Range) []Range {
	if n := len(rs); n > 0 && rs[n-1].End == r.Start {
		rs[n-1].End = r.End
		return rs
	}
	return append(rs, r)
}

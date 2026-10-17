package proc

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	pagemapEntry   = 8
	pagemapPresent = 1 << 63

	// pagemapChunk bounds memory per read (8 bytes per page).
	pagemapChunk = 64 * 1024
)

// Resident returns sub-ranges of rs whose pages are present in RAM.
// Swapped and never-touched pages are excluded.
func Resident(pid int, rs []Range, pageSize uint64) ([]Range, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/pagemap", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return residentFrom(f, rs, pageSize)
}

func residentFrom(f io.ReaderAt, rs []Range, pageSize uint64) ([]Range, error) {
	var out []Range
	buf := make([]byte, pagemapChunk)
	for _, r := range rs {
		for page := r.Start / pageSize; page < (r.End+pageSize-1)/pageSize; {
			n := min((r.End+pageSize-1)/pageSize-page, uint64(len(buf)/pagemapEntry))
			b := buf[:n*pagemapEntry]
			if _, err := f.ReadAt(b, int64(page*pagemapEntry)); err != nil {
				return nil, fmt.Errorf("pagemap read at page %#x: %w", page, err)
			}

			for i := uint64(0); i < n; i++ {
				if binary.LittleEndian.Uint64(b[i*pagemapEntry:])&pagemapPresent == 0 {
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

// appendRange appends r, merging with the last range when contiguous.
func appendRange(rs []Range, r Range) []Range {
	if n := len(rs); n > 0 && rs[n-1].End == r.Start {
		rs[n-1].End = r.End
		return rs
	}
	return append(rs, r)
}

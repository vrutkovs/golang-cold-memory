// Fixture target: hot reads on a small buffer, large idle preallocated
// slices, and a type large enough for an on-demand GC mask (Go 1.24+).
// It has no profiler instrumentation.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"
)

const (
	hotSize  = 64 << 10
	idleSize = 8 << 20
	idleBufs = 8
	pageStep = 4096
)

// bigPtrs has 20000 pointer words (> 16384), forcing TFlagGCMaskOnDemand.
type bigPtrs struct{ p [20000]*int }

var (
	hot  []byte
	idle [][]byte
	big  *bigPtrs
	sink byte
)

func main() {
	gc := flag.Bool("gc", true, "run GC before ready (builds on-demand masks)")
	flag.Parse()

	hot = make([]byte, hotSize)
	for range idleBufs {
		b := make([]byte, idleSize)
		for i := 0; i < len(b); i += pageStep {
			b[i] = 1 // make resident
		}
		idle = append(idle, b[:0])
	}
	big = new(bigPtrs)
	big.p[0] = new(int)
	if *gc {
		runtime.GC()
	}

	fmt.Printf("hot %#x %d\n", uintptr(unsafe.Pointer(&hot[0])), hotSize)
	for _, b := range idle {
		fmt.Printf("idle %#x %d\n", uintptr(unsafe.Pointer(unsafe.SliceData(b))), idleSize)
	}
	fmt.Printf("big %#x %d\n", uintptr(unsafe.Pointer(big)), unsafe.Sizeof(*big))
	fmt.Println("ready")
	os.Stdout.Sync()

	for {
		for i := 0; i < len(hot); i += 64 {
			sink += hot[i]
		}
		time.Sleep(time.Millisecond)
	}
}

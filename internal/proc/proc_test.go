package proc

import (
	"bytes"
	"encoding/binary"
	"os"
	"reflect"
	"strings"
	"testing"
)

const smaps = `00400000-00500000 r-xp 00000000 08:01 1234 /usr/bin/app
Rss:                 100 kB
c000000000-c000400000 rw-p 00000000 00:00 0
Rss:                2048 kB
Swap:                  4 kB
c000400000-c000800000 rw-p 00000000 00:00 0
Rss:                   0 kB
7f0000000000-7f0000100000 rw-p 00000000 00:00 0 [stack]
7f0000200000-7f0000300000 rw-s 00000000 00:05 99 /dev/shm/x
7f0000400000-7f0000500000 ---p 00000000 00:00 0
7f0000600000-7f0000700000 rw-p 00000000 08:01 55 /usr/lib/libc.so
`

func TestParseAndSelect(t *testing.T) {
	maps, err := ParseSmaps(strings.NewReader(smaps))
	if err != nil {
		t.Fatal(err)
	}
	if len(maps) != 7 {
		t.Fatalf("got %d mappings", len(maps))
	}
	if maps[1].Rss != 2048*1024 || maps[1].Swap != 4*1024 {
		t.Errorf("smaps counters: %+v", maps[1])
	}

	// Adjacent anon rw-p ranges merge; stack, shared, PROT_NONE, file-backed excluded.
	got := SelectCandidates(maps, 0)
	want := []Range{{0xc000000000, 0xc000800000}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidates = %#v", got)
	}
}

func TestSelectBound(t *testing.T) {
	maps := []Mapping{
		{Start: 0x1000, End: 0x2000, Perms: "rw-p", Rss: 1},
		{Start: 0x3000, End: 0x4000, Perms: "rw-p", Rss: 100},
		{Start: 0x5000, End: 0x6000, Perms: "rw-p", Rss: 50},
	}
	got := SelectCandidates(maps, 2)
	want := []Range{{0x3000, 0x4000}, {0x5000, 0x6000}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bounded candidates = %#v", got)
	}
}

func TestParseStartTime(t *testing.T) {
	// comm with spaces and parens.
	stat := "1234 (my (odd) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 987654 1000 10"
	state, st, err := ParseStat(stat)
	if err != nil || st != 987654 || state != 'S' {
		t.Errorf("state=%c start=%d err=%v", state, st, err)
	}
	if _, _, err := ParseStat("garbage"); err == nil {
		t.Error("want error")
	}
}

func TestPinDetectsChange(t *testing.T) {
	id, err := Pin(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Check(); err != nil {
		t.Fatal(err)
	}
	id.StartTime++
	if err := id.Check(); err != ErrPIDChanged {
		t.Errorf("want ErrPIDChanged, got %v", err)
	}
}

func TestResidentFrom(t *testing.T) {
	const page = 4096
	// Pages 0..7: present at 1,2,3,6.
	var buf bytes.Buffer
	for i := range 8 {
		var v uint64
		if i == 1 || i == 2 || i == 3 || i == 6 {
			v = pagemapPresent
		}
		_ = binary.Write(&buf, binary.LittleEndian, v)
	}
	got, err := residentFrom(bytes.NewReader(buf.Bytes()), []Range{{0, 8 * page}}, page)
	if err != nil {
		t.Fatal(err)
	}
	want := []Range{{page, 4 * page}, {6 * page, 7 * page}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resident = %#v", got)
	}
}

func TestRangeOps(t *testing.T) {
	a := []Range{{0, 100}, {200, 300}}
	b := []Range{{50, 250}}
	if got := Subtract(a, b); !reflect.DeepEqual(got, []Range{{0, 50}, {250, 300}}) {
		t.Errorf("subtract = %v", got)
	}
	if got := Intersect(a, b); !reflect.DeepEqual(got, []Range{{50, 100}, {200, 250}}) {
		t.Errorf("intersect = %v", got)
	}
	if got := Normalize([]Range{{10, 20}, {0, 10}, {15, 30}}); !reflect.DeepEqual(got, []Range{{0, 30}}) {
		t.Errorf("normalize = %v", got)
	}
}

func TestGoSupported(t *testing.T) {
	for v, want := range map[string]bool{"go1.21.5": false, "go1.22.0": true, "go1.27.2": true, "go1.25rc1": true, "devel": false} {
		if GoSupported(v) != want {
			t.Errorf("GoSupported(%q) != %v", v, want)
		}
	}
}

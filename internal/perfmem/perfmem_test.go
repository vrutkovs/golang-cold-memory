package perfmem

import (
	"reflect"
	"testing"
)

func TestEventList(t *testing.T) {
	out := "ldlat-loads  : available\nldlat-stores : available\nload-store   : \n"
	got := ParseEventList(out)
	if !reflect.DeepEqual(got, []string{"ldlat-loads", "ldlat-stores"}) {
		t.Errorf("events = %v", got)
	}
	if c := ChooseEvents(got); !reflect.DeepEqual(c, []string{"ldlat-loads", "ldlat-stores"}) {
		t.Errorf("chosen = %v", c)
	}
	if c := ChooseEvents([]string{"spe-load", "mem-ldst"}); !reflect.DeepEqual(c, []string{"mem-ldst"}) {
		t.Errorf("ldst preferred, got %v", c)
	}
	if ParseEventList("failed: no PMU supports the memory events") != nil {
		t.Error("unsupported PMU must yield no events")
	}
}

func TestSampleTypes(t *testing.T) {
	out := `cpu/mem-loads,ldlat=30/P: type: 4, size: 136, config: 0x1cd, { sample_period, sample_freq }: 4000, sample_type: IP|TID|TIME|ADDR|ID|DATA_SRC|WEIGHT_STRUCT, read_format: ID
dummy:u: type: 1, sample_type: IP|TID|TIME|ID
`
	st := ParseSampleTypes(out)
	if len(st) != 1 || !hasFlag(st["cpu/mem-loads,ldlat=30/P"], "ADDR") {
		t.Errorf("sample types = %v", st)
	}

	// A recording that has samples but no ADDR field must be detected.
	noAddr := ParseSampleTypes("cycles:u: type: 0, sample_type: IP|TID|TIME, read_format: ID\n")
	if hasFlag(noAddr["cycles:u"], "ADDR") {
		t.Error("ADDR falsely detected")
	}
}

func TestParseScript(t *testing.T) {
	out := `453067.004858705: page-faults:u:     ffff8955c900   12     ffff8955c900
453067.004860746: cpu/mem-stores/P:     c000123456 0     4a1b2c
garbage line
`
	got, err := ParseScript(out, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("samples = %+v", got)
	}
	if got[0].TimeNS != 453067004858705 || got[0].Addr != 0xffff8955c900 || got[0].Weight != 12 {
		t.Errorf("sample 0 = %+v", got[0])
	}
	if got[1].Op != "store" || got[1].IP != 0x4a1b2c {
		t.Errorf("sample 1 = %+v", got[1])
	}

	syms := "ffff8955c900 _start\n4a1b2c main.(*cache).get\n"
	if err := AttachSymbols(got, syms); err != nil {
		t.Fatal(err)
	}
	if got[1].Sym != "main.(*cache).get" {
		t.Errorf("sym = %q", got[1].Sym)
	}
	if err := AttachSymbols(got, "1 x\n"); err == nil {
		t.Error("count mismatch must fail")
	}
}

func TestParseLost(t *testing.T) {
	out := "           LOST events:          3  ( 0.1%)\n   LOST_SAMPLES events:          2  ( 0.0%)\n    SAMPLE events:  1000\n"
	if n := ParseLost(out); n != 5 {
		t.Errorf("lost = %d", n)
	}
}

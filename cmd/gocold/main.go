// Command gocold measures memory access in a running Go process.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/vrutkovs/golang-cold-memory/internal/damon"
	"github.com/vrutkovs/golang-cold-memory/internal/probe"
	"github.com/vrutkovs/golang-cold-memory/internal/record"
	"github.com/vrutkovs/golang-cold-memory/internal/report"
)

const usage = `gocold: Go process memory-access profiler (Linux)

  gocold probe  --pid PID [--json]
  gocold record --pid PID --duration 60s --out DIR [--objects]
  gocold report DIR [--json]

PID is a host PID. Containers: podman inspect CONTAINER --format '{{.State.Pid}}'
Run "gocold <cmd> -h" for flags.
`

func main() {
	// Artifacts may hold secrets: everything this process creates is private.
	syscall.Umask(0o077)

	if runtime.GOOS != "linux" {
		fatal(errors.New("gocold requires Linux"))
	}
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "probe":
		err = runProbe(ctx, os.Args[2:])
	case "record":
		err = runRecord(ctx, os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

// recordFlags registers recording flags shared by probe (for estimates) and record.
// The returned func resolves duration-derived fields after Parse.
func recordFlags(fs *flag.FlagSet) (*record.Options, func()) {
	o := &record.Options{}
	var sample, aggr, update time.Duration
	var perfMaxMiB uint64
	fs.IntVar(&o.PID, "pid", 0, "host PID of target Go process")
	fs.DurationVar(&o.Duration, "duration", 60*time.Second, "observation window")
	fs.StringVar(&o.Out, "out", "", "private output directory (created 0700, must be new or empty)")
	fs.BoolVar(&o.Objects, "objects", false, "capture a core + exact executable at the end (pauses target; may contain secrets)")
	fs.BoolVar(&o.TrackDisappearances, "track-disappearances", false, "capture start and end cores to estimate object disappearance windows (requires --objects; pauses target twice)")
	fs.DurationVar(&o.SnapshotInterval, "snapshot-interval", 0, "DAMON snapshot interval (default = aggregation interval; larger leaves time gaps)")
	fs.DurationVar(&o.MapsInterval, "maps-interval", 10*time.Second, "mapping/residency recheck interval")
	fs.DurationVar(&sample, "sample", 20*time.Millisecond, "DAMON sampling interval")
	fs.DurationVar(&aggr, "aggr", time.Second, "DAMON aggregation interval")
	fs.DurationVar(&update, "update", time.Second, "DAMON update interval")
	fs.IntVar(&o.MinRegions, "min-regions", 10, "DAMON min regions")
	fs.IntVar(&o.MaxRegions, "max-regions", 1000, "DAMON max regions")
	fs.IntVar(&o.MaxRanges, "max-ranges", 64, "max candidate ranges monitored (largest RSS first)")
	fs.IntVar(&o.MaxSnapshots, "max-snapshots", 3600, "max DAMON snapshots saved")
	fs.IntVar(&o.PerfPeriod, "perf-period", 10000, "perf sample period (events per sample)")
	fs.Uint64Var(&perfMaxMiB, "perf-max-size", 256, "perf.data size cap, MiB")
	fs.BoolVar(&o.NoPerf, "no-perf", false, "skip perf memory sampling")
	fs.StringVar(&o.PprofURL, "pprof-url", "", "existing heap pprof endpoint to save (optional; gc param refused)")
	fs.StringVar(&o.DAMONRoot, "damon-root", damon.DefaultRoot, "DAMON sysfs admin dir")

	return o, func() {
		o.SampleUS = uint64(sample / time.Microsecond)
		o.AggrUS = uint64(aggr / time.Microsecond)
		o.UpdateUS = uint64(update / time.Microsecond)
		o.PerfMaxSize = perfMaxMiB << 20
		if o.SnapshotInterval == 0 {
			o.SnapshotInterval = aggr
		}
	}
}

func runProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	o, finish := recordFlags(fs)
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	finish()
	if o.PID <= 0 {
		return errors.New("--pid required")
	}

	r, err := probe.Run(ctx, *o)
	if err != nil {
		return err
	}
	if *asJSON {
		return r.JSON(os.Stdout)
	}
	r.Print(os.Stdout)
	return nil
}

func runRecord(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	o, finish := recordFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	finish()
	if err := record.Run(ctx, *o, os.Stderr); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "recorded to %s; analyze with: gocold report %s\n", o.Out, o.Out)
	if o.Objects {
		fmt.Fprintf(os.Stderr, "core dump may contain secrets; delete %s when done\n", o.Out)
	}
	return nil
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	var o report.Options
	var from, to time.Duration
	asJSON := fs.Bool("json", false, "JSON output")
	htmlOut := fs.String("html", "", "write self-contained HTML heatmap to this new file")
	fs.IntVar(&o.Heatmap.MaxRows, "heatmap-rows", 256, "heatmap address rows (monitored space is binned)")
	fs.IntVar(&o.Heatmap.MaxCols, "heatmap-cols", 120, "heatmap time columns (snapshots are grouped)")
	fs.IntVar(&o.Heatmap.MaxTypes, "heatmap-types", 40, "heatmap allocation-site rows, largest first")
	fs.DurationVar(&from, "from", 0, "window start, offset from first DAMON coverage")
	fs.DurationVar(&to, "to", 0, "window end offset (0 = last snapshot)")
	fs.Float64Var(&o.FreqRate, "freq-rate", 0.5, "frequent access: fraction of DAMON sampling checks per aggregation")
	fs.Float64Var(&o.FreqShare, "freq-share", 0.5, "frequent access: required fraction of snapshots")
	fs.IntVar(&o.Top, "top", 20, "rows per text section")
	fs.BoolVar(&o.Objects, "objects", true, "analyze core objects when a core exists")
	fs.IntVar(&o.MaxPaths, "max-paths", 100, "reference paths to compute")
	fs.IntVar(&o.TopObjects, "top-objects", 50, "quiet/mixed objects to list")
	fs.IntVar(&o.MaxMatches, "max-matches", 2000, "perf samples matched to objects")

	// Allow flags after DIR.
	var dir string
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		dir, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if dir == "" && fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	if dir == "" {
		return errors.New("usage: gocold report DIR [--json]")
	}
	o.FromNS, o.ToNS = int64(from), int64(to)

	r, err := report.Build(dir, o)
	if err != nil {
		return err
	}
	if *htmlOut != "" {
		if err := r.WriteHTML(*htmlOut); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "heatmap written to %s\n", *htmlOut)
	}
	if *asJSON {
		return r.JSON(os.Stdout)
	}
	r.Text(os.Stdout, o.Top)
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gocold:", err)
	os.Exit(1)
}

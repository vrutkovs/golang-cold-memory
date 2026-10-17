# gocold

`gocold` is a Linux CLI that measures memory access in a running Go process. It does not change application code. It reports address regions with evidence and uncertainty. It never claims that an object is dead or gives an exact last-access time.

Heap pprof shows sampled allocation sites. It is not an access sensor, so `gocold` keeps it in a separate section of the report.

## Build

```sh
go build -o gocold ./cmd/gocold
```

## Usage

```sh
gocold probe  --pid PID                                  # prerequisites; changes nothing
gocold record --pid PID --duration 60s --out DIR [--objects] [--pprof-url URL]
gocold report DIR [--json] [--from 10s --to 50s]
```

`PID` is a **host** PID. For a container, run:
`podman inspect CONTAINER --format '{{.State.Pid}}'`.

## Evidence sources

| Source | Needs | If missing |
|---|---|---|
| DAMON sysfs (`fvaddr`, explicit ranges, `stat` scheme only) | root/`CAP_SYS_ADMIN` on the host, and no existing kdamonds | Regions become `unknown`. |
| `perf mem` (PEBS / IBS / SPE, events picked by the probe) | a memory-sampling PMU and perf permission | No sample overlay. |
| `/proc/PID/pagemap` present bits (+ `/proc/kpageflags` to exclude zero-page mappings) | ptrace-read access; root for kpageflags | No resident totals and no quiet candidates. Without kpageflags, only exclusively mapped pages count as resident. |
| core (`gcore`) + exact `/proc/PID/exe` | `--objects`, ptrace, and DWARF in the binary | No object mapping. |

## Labels

- `observed-access`: DAMON saw access in the window.
- `frequently-accessed`: the rate was at least `--freq-rate` in at least `--freq-share` of the snapshots.
- `quiet-candidate`: monitored in every snapshot with no time gaps, mapping stable, resident the whole time, and no access observed.
- `unknown`: anything else. The report lists the reasons.

A perf hit inside the window changes its page from `quiet-candidate` to `observed-access`, because DAMON can miss sparse access at region resolution. This needs perf and DAMON to share a clock. A sample without a hit is not evidence that no access happened. A sample-to-object match is only a *core-time candidate* because the address can be reused. An object is `quiet-candidate` only if all of it lies in quiet regions. Otherwise it is `mixed` or `unknown`. A slice with `len=0` is still allocated spare capacity.

## Safety

- The output directory has mode 0700 and the files have mode 0600. Existing files are never overwritten or deleted. Nothing is uploaded.
- `record` never forces GC and never changes target settings. It refuses a `--pprof-url` that has a `gc` parameter.
- DAMON: `record` creates a monitor only when `nr_kdamonds` is 0. It cleans up only that monitor, including on errors and Ctrl-C. If a check shows the monitor was changed by someone else, `record` stops and leaves it alone. `record` never uses `pageout`/`cold` actions.
- `record` checks the PID start time on every tick. It stops if the target exits or the PID is reused.
- `record` checks free disk space before it starts. Snapshots, regions, ranges and `perf.data` size all have limits.
- Core capture is opt-in. It pauses the target. It runs after the final DAMON snapshot, so the pause is not part of the access window.

**Cleanup:** cores and profiles can contain secrets. Delete the directory when you are done: `rm -rf DIR`.

## Object analysis

`internal/xdebug` is a vendored and patched copy of `golang.org/x/debug` viewcore. The patch adds support for Go 1.24+ on-demand GC masks (`TFlagGCMaskOnDemand`). If metadata is missing, the pointer graph is marked as incomplete. See `internal/xdebug/README.md`.

## Demo: VictoriaMetrics on a CoreOS host

The host has no perf or gdb, so the tools run from a privileged container that shares the host PID namespace:

```sh
podman run -d --rm --name vm -p 8428:8428 docker.io/victoriametrics/victoria-metrics:v1.154.0
sudo podman run -d --name gocold-tools --privileged --pid=host --net=host \
  --security-opt label=disable -v /sys:/sys -v $PWD:/work registry.fedoraproject.org/fedora:44 sleep infinity
sudo podman exec gocold-tools dnf install -y perf gdb
testdata/vm-load.sh 60 &          # curl-based Prometheus text ingestion + queries
P=$(podman inspect vm --format '{{.State.Pid}}')
sudo podman exec gocold-tools /work/gocold record --pid $P --duration 90s --out /work/rec \
  --objects --pprof-url http://127.0.0.1:8428/debug/pprof/heap
sudo podman exec gocold-tools /work/gocold report /work/rec --to 38s    # busy window
sudo podman exec gocold-tools /work/gocold report /work/rec --from 45s  # idle window
sudo podman rm -f gocold-tools
```

## Tests

```sh
go test ./...
```

The integration tests use `testdata/fixture` (hot reads, eight idle 8 MiB slices with `len=0`, and a type with an on-demand mask), a fake DAMON sysfs, and a real `gcore` dump. They are skipped when `gcore`/ptrace is not available.

# KernelLens

A small Dear ImGui binary with one tab per kernel-observability interface,
plus standalone scripts that inject controlled faults to watch.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
./build/kernellens
```

C++20, OpenGL, GLFW/ImGui deps (fetched at configure time). Most tabs read
privileged interfaces (tracefs, perf events, eBPF) — run as root, or with
the matching capabilities / `perf_event_paranoid` relaxed.

## Source

| File | Tab | Tools/libraries |
|---|---|---|
| `proc.*` | `/proc` | direct reads of `/proc/meminfo`, `/proc/stat`, `/proc/<pid>/{statm,comm}` |
| `sys.*` | `/sys` | direct reads of `cpufreq/scaling_cur_freq`, `/sys/class/thermal` |
| `ftrace.*` | `ftrace` | tracefs: enables the `sched_process_exec` tracepoint, reads `trace_pipe` |
| `perf.*` | `perf` | shells out to `perf stat -x,`, parses its CSV |
| `bpf.*` | `eBPF` | forks `bpftrace` running a syscalls-by-process one-liner, reads its stdout |
| `main.cpp` | — | Dear ImGui + ImGui GLFW/OpenGL3 backends |

## Fault experiments (`experiments/`)

Standalone scripts, each a controlled fault around one piece of tooling,
reversible via a `trap` cleanup. Parameters are environment variables (see
each script's top).

| File | Tools | Fault |
|---|---|---|
| `systemd.sh` | `systemd-run`, cgroups | memory hog inside a scope with `MemoryMax`, so the OOM killer is contained to it |
| `iproute2.sh` | `ip` | blackholes a destination via `ip route add unreachable` |
| `netem.sh` | `tc`/netem | adds a netem qdisc: latency + packet loss on an interface |
| `tcpinfo.sh` | `nc`, `ss`/`TCP_INFO` | `SIGSTOP`s a TCP receiver to collapse its window, polls `TCP_INFO` via `ss -i` |
| `fio.sh` | `fio` | sustained random-write I/O |

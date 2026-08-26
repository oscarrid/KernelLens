// kernellens-agent: samples /proc, /sys and sock_diag on a fixed interval
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "bpf_probe.h"
#include "record.h"
#include "samplers.h"

using namespace kl;

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int) { g_stop = 1; }

// bpf_ktime_get_ns() is CLOCK_MONOTONIC; every record we write is CLOCK_REALTIME so that nodes can be laid on one timeline
static int64_t monotonic_to_realtime_offset() {
  struct timespec r, m;
  clock_gettime(CLOCK_REALTIME, &r);
  clock_gettime(CLOCK_MONOTONIC, &m);
  return ((int64_t)r.tv_sec - (int64_t)m.tv_sec) * 1000000000ll +
         ((int64_t)r.tv_nsec - (int64_t)m.tv_nsec);
}

static void usage() {
  fputs(
      "usage: kernellens-agent [options]\n"
      "  --out PATH          output file, - for stdout (default -)\n"
      "  --node NAME         node label (default hostname)\n"
      "  --interval-ms N     sampling interval (default 1000)\n"
      "  --duration-s N      stop after N seconds, 0 = until signalled (default 0)\n"
      "  --bpf-obj PATH      kernellens.bpf.o (default ./kernellens.bpf.o)\n"
      "  --offcpu-ms N       report run-queue waits over N ms (default 10)\n"
      "  --io-ms N           report block I/O over N ms (default 20)\n"
      "  --no-bpf            skip the eBPF probes\n",
      stderr);
}

int main(int argc, char** argv) {
  std::string out_path = "-", node, bpf_obj = "kernellens.bpf.o";
  long interval_ms = 1000, duration_s = 0, offcpu_ms = 10, io_ms = 20;
  bool use_bpf = true;

  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "--out") out_path = next();
    else if (a == "--node") node = next();
    else if (a == "--interval-ms") interval_ms = atol(next().c_str());
    else if (a == "--duration-s") duration_s = atol(next().c_str());
    else if (a == "--bpf-obj") bpf_obj = next();
    else if (a == "--offcpu-ms") offcpu_ms = atol(next().c_str());
    else if (a == "--io-ms") io_ms = atol(next().c_str());
    else if (a == "--no-bpf") use_bpf = false;
    else { usage(); return 2; }
  }
  if (interval_ms < 10) interval_ms = 10;
  if (node.empty()) {
    char h[256] = "unknown";
    gethostname(h, sizeof(h) - 1);
    node = h;
  }

  FILE* out = stdout;
  if (out_path != "-") {
    out = fopen(out_path.c_str(), "we");
    if (!out) {
      fprintf(stderr, "kernellens: cannot write %s: %s\n", out_path.c_str(), strerror(errno));
      return 1;
    }
  }

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  BpfProbe probe;
  int64_t boot_offset = monotonic_to_realtime_offset();
  if (use_bpf) {
    std::string err;
    if (!probe.start(bpf_obj, (uint64_t)offcpu_ms * 1000000ull, (uint64_t)io_ms * 1000000ull, err))
      fprintf(stderr, "kernellens: eBPF probes disabled: %s\n", err.c_str());
  }

  BpfSink sink = [&](const BpfEvt& e) {
    Rec r("bpf", (uint64_t)((int64_t)e.ts + boot_offset));
    r.node = node;
    r.s("probe", e.kind == 1 ? "offcpu" : "blockio");
    r.s("comm", std::string(e.comm, strnlen(e.comm, sizeof(e.comm))));
    r.n("pid", e.pid).n("delta_ms", (double)e.delta_ns / 1e6);
    r.n("aux", e.aux).n("err", (int32_t)e.err);
    emit(out, r);
  };

  const uint64_t t0 = now_ns();
  uint64_t deadline = t0;
  while (!g_stop) {
    uint64_t t = now_ns();
    std::vector<Rec> recs;
    sample_proc(t, recs);
    sample_net(t, recs);
    sample_hw(t, recs);
    for (auto& r : recs) {
      r.node = node;
      if (!r.t_ns) r.t_ns = t;
      emit(out, r);
    }
    fflush(out);

    deadline += (uint64_t)interval_ms * 1000000ull;
    if (duration_s > 0 && t - t0 >= (uint64_t)duration_s * 1000000000ull) break;

    // spend the gap draining the ring buffer rather than sleeping through it
    while (!g_stop) {
      uint64_t now = now_ns();
      if (now >= deadline) break;
      long wait_ms = (long)((deadline - now) / 1000000ull) + 1;
      if (wait_ms > 200) wait_ms = 200;
      if (probe.active()) {
        if (probe.poll((int)wait_ms, sink) > 0) fflush(out);
      } else {
        struct timespec ts = {wait_ms / 1000, (wait_ms % 1000) * 1000000};
        nanosleep(&ts, nullptr);
      }
    }
  }

  fflush(out);
  if (out != stdout) fclose(out);
  return 0;
}

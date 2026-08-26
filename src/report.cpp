// kernellens-report: reads the jsonl a run produced on every node, splits it into baseline / fault / recovery windows
#include <math.h>
#include <string.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "record.h"

using namespace kl;

namespace {

enum Win { BASE = 0, FAULT = 1, RECOV = 2, NWIN = 3 };

struct Stat {
  long n = 0;
  double sum = 0, sumsq = 0, mx = 0, mn = 0;
  void add(double v) {
    if (n == 0) { mx = mn = v; }
    else { mx = std::max(mx, v); mn = std::min(mn, v); }
    n++; sum += v; sumsq += v * v;
  }
  double mean() const { return n ? sum / n : 0.0; }
  double sd() const {
    if (n < 2) return 0.0;
    double m = mean(), var = sumsq / n - m * m;
    return var > 0 ? sqrt(var) : 0.0;
  }
};

struct Key {
  std::string node, kind, label, field;
  bool operator<(const Key& o) const {
    if (node != o.node) return node < o.node;
    if (kind != o.kind) return kind < o.kind;
    if (label != o.label) return label < o.label;
    return field < o.field;
  }
};

struct Mark {
  uint64_t t;
  std::string phase, fault, target, node;
  bool operator<(const Mark& o) const { return t < o.t; }
};

struct Event {  // an ebpf latency outlier worth naming in the report
  uint64_t t;
  std::string node, probe, comm;
  double delta_ms;
  long pid, err;
};

struct Run {
  std::map<Key, std::array<Stat, NWIN>> series;
  std::map<std::string, std::array<long, NWIN>> bpf_count;  // "node|probe"
  std::vector<Mark> marks;
  std::vector<Event> events;
  std::set<std::string> nodes;
  uint64_t t_min = 0, t_max = 0, f_start = 0, f_stop = 0;
  long lines = 0;
  int files = 0;
  uint64_t digest = 1469598103934665603ull;  // fnv-1a 64
  std::string fault = "unknown", target = "unknown";
};

const char* layer_of(const std::string& kind) {
  if (kind == "proc" || kind == "proctotal" || kind == "load") return "application";
  if (kind == "cpu" || kind == "mem" || kind == "psi" || kind == "disk" || kind == "fs" ||
      kind == "bpf")
    return "kernel";
  if (kind == "tcp" || kind == "conn" || kind == "tcpstack" || kind == "nic") return "network";
  return "hardware";
}

double win_secs(const Run& r, int w) {
  if (w == BASE) return (double)(r.f_start - r.t_min) / 1e9;
  if (w == FAULT) return (double)(r.f_stop - r.f_start) / 1e9;
  return r.t_max > r.f_stop ? (double)(r.t_max - r.f_stop) / 1e9 : 0.0;
}

// seconds relative to the start of the fault, which is the only anchor that
// means the same thing on every node.
double rel(const Run& r, uint64_t t) { return ((double)t - (double)r.f_start) / 1e9; }

void load(Run& r, const std::string& dir) {
  std::vector<Rec> recs;
  for (const auto& name : list_dir(dir, "")) {
    if (name.size() < 6 || name.compare(name.size() - 6, 6, ".jsonl") != 0) continue;
    std::string body = slurp(dir + "/" + name);
    if (body.empty()) continue;
    r.files++;
    for (unsigned char c : body) r.digest = (r.digest ^ c) * 1099511628211ull;
    for (const auto& ln : split_lines(body)) {
      Rec rec;
      if (!parse(ln, rec) || rec.t_ns == 0) continue;
      r.lines++;
      recs.push_back(std::move(rec));
    }
  }
  if (recs.empty()) return;

  r.t_min = r.t_max = recs[0].t_ns;
  for (const auto& rec : recs) {
    r.t_min = std::min(r.t_min, rec.t_ns);
    r.t_max = std::max(r.t_max, rec.t_ns);
    if (!rec.node.empty() && rec.kind != "mark") r.nodes.insert(rec.node);
  }

  for (const auto& rec : recs) {
    if (rec.kind != "mark") continue;
    Mark m{rec.t_ns, "", "", "", rec.node};
    for (const auto& kv : rec.f) {
      const std::string* s = std::get_if<std::string>(&kv.second);
      if (!s) continue;
      if (kv.first == "phase") m.phase = *s;
      else if (kv.first == "fault") m.fault = *s;
      else if (kv.first == "target") m.target = *s;
    }
    r.marks.push_back(m);
  }
  std::sort(r.marks.begin(), r.marks.end());

  bool have_start = false, have_stop = false;
  for (const auto& m : r.marks) {
    if (m.phase == "start" && !have_start) { r.f_start = m.t; have_start = true; }
    if (m.phase == "stop") { r.f_stop = m.t; have_stop = true; }
    if (!m.fault.empty()) r.fault = m.fault;
    if (!m.target.empty()) r.target = m.target;
  }
  // without markers, treat the first third as baseline so the report still works.
  if (!have_start) r.f_start = r.t_min + (r.t_max - r.t_min) / 3;
  if (!have_stop || r.f_stop < r.f_start) r.f_stop = r.t_max;

  for (const auto& rec : recs) {
    if (rec.kind == "mark") continue;
    int w = rec.t_ns < r.f_start ? BASE : (rec.t_ns <= r.f_stop ? FAULT : RECOV);

    std::string label;
    for (const auto& kv : rec.f)
      if (const std::string* s = std::get_if<std::string>(&kv.second)) { label = *s; break; }

    if (rec.kind == "bpf") {
      Event e{rec.t_ns, rec.node, label, "", 0, 0, 0};
      for (const auto& kv : rec.f) {
        if (const std::string* s = std::get_if<std::string>(&kv.second)) {
          if (kv.first == "comm") e.comm = *s;
        } else {
          double v = std::get<double>(kv.second);
          if (kv.first == "delta_ms") e.delta_ms = v;
          else if (kv.first == "pid") e.pid = (long)v;
          else if (kv.first == "err") e.err = (long)v;
        }
      }
      r.bpf_count[rec.node + "|" + e.probe][w]++;
      r.events.push_back(std::move(e));
    }

    for (const auto& kv : rec.f) {
      const double* v = std::get_if<double>(&kv.second);
      if (!v) continue;
      if (rec.kind == "proc" && kv.first == "pid") continue;  // an identifier, not a measurement
      r.series[Key{rec.node, rec.kind, label, kv.first}][w].add(*v);
    }
  }
}

double score_of(const Stat& b, const Stat& f) {
  if (b.n < 3 || f.n < 1) return 0.0;
  if (fabs(b.mean()) < 1e-9 && fabs(f.mean()) < 1e-9) return 0.0;
  double denom = std::max(std::max(b.sd(), 0.05 * fabs(b.mean())), 1e-9);
  return std::min(fabs(f.mean() - b.mean()) / denom, 999999.0);
}

// largest baseline-to-fault move among all series of this kind and field.
// label may be null to accept any label, or e.g. "cpu" to pin one psi resource.
bool pick(const Run& r, const std::string& kind, const std::string& field, const char* label,
          Key& out, double& base, double& fault) {
  bool found = false;
  double best = -1;
  for (const auto& kv : r.series) {
    if (kv.first.kind != kind || kv.first.field != field) continue;
    if (label && kv.first.label != label) continue;
    const Stat& b = kv.second[BASE];
    const Stat& f = kv.second[FAULT];
    if (f.n < 1) continue;
    double move = fabs(f.mean() - b.mean());
    if (move > best) { best = move; out = kv.first; base = b.mean(); fault = f.mean(); found = true; }
  }
  return found;
}

std::string ev(const Key& k, double b, double f, const char* unit) {
  char buf[256];
  std::string where = k.node + " " + k.kind + (k.label.empty() ? "" : "[" + k.label + "]") + "." +
                      k.field;
  snprintf(buf, sizeof(buf), "%s: %.3f -> %.3f %s", where.c_str(), b, f, unit);
  return buf;
}

double bpf_rate(const Run& r, const std::string& probe, int w) {
  long n = 0;
  for (const auto& kv : r.bpf_count)
    if (kv.first.size() > probe.size() &&
        kv.first.compare(kv.first.size() - probe.size(), probe.size(), probe) == 0)
      n += kv.second[w];
  double s = win_secs(r, w);
  return s > 0 ? n / s : 0.0;
}

void findings(FILE* o, const Run& r) {
  fputs("\n## Findings\n\n", o);
  int found = 0;
  Key k;
  double b, f;
  auto rule = [&](const char* title, const std::vector<std::string>& evid) {
    if (evid.empty()) return;
    ++found;
    fprintf(o, "%d. **%s**\n", found, title);
    for (const auto& e : evid) fprintf(o, "   - %s\n", e.c_str());
  };

  std::vector<std::string> e;
  if (pick(r, "psi", "some_avg10", "cpu", k, b, f) && f - b > 5)
    e.push_back(ev(k, b, f, "% stalled"));
  if (pick(r, "cpu", "cpu_steal", nullptr, k, b, f) && f - b > 5) e.push_back(ev(k, b, f, "% steal"));
  if (bpf_rate(r, "offcpu", FAULT) > 3 * bpf_rate(r, "offcpu", BASE) + 1)
    e.push_back("run-queue waits: " + std::to_string(bpf_rate(r, "offcpu", BASE)) + " -> " +
                std::to_string(bpf_rate(r, "offcpu", FAULT)) + " outliers/s");
  rule("CPU contention", e);

  e.clear();
  if (pick(r, "psi", "some_avg10", "memory", k, b, f) && f - b > 1)
    e.push_back(ev(k, b, f, "% stalled"));
  if (pick(r, "mem", "mem_avail_mb", nullptr, k, b, f) && b > 0 && f < 0.75 * b)
    e.push_back(ev(k, b, f, "MB available"));
  if (pick(r, "mem", "swap_used_mb", nullptr, k, b, f) && f - b > 64) e.push_back(ev(k, b, f, "MB swap"));
  rule("Memory pressure", e);

  e.clear();
  if (pick(r, "psi", "some_avg10", "io", k, b, f) && f - b > 5)
    e.push_back(ev(k, b, f, "% stalled"));
  if (pick(r, "disk", "await_ms", nullptr, k, b, f) && f - b > 5) e.push_back(ev(k, b, f, "ms await"));
  if (pick(r, "disk", "util_pct", nullptr, k, b, f) && f > 80) e.push_back(ev(k, b, f, "% utilised"));
  if (bpf_rate(r, "blockio", FAULT) > 2 * bpf_rate(r, "blockio", BASE) + 1)
    e.push_back("slow block I/O: " + std::to_string(bpf_rate(r, "blockio", BASE)) + " -> " +
                std::to_string(bpf_rate(r, "blockio", FAULT)) + " outliers/s");
  rule("Storage saturation", e);

  e.clear();
  if (pick(r, "fs", "used_pct", nullptr, k, b, f) && f >= 95) e.push_back(ev(k, b, f, "% used"));
  if (pick(r, "fs", "avail_mb", nullptr, k, b, f) && b > 0 && f < 0.5 * b) e.push_back(ev(k, b, f, "MB free"));
  rule("Filesystem exhaustion", e);

  e.clear();
  if (pick(r, "tcp", "rtt_ms_mean", nullptr, k, b, f) && f > 2 * b + 1) e.push_back(ev(k, b, f, "ms RTT"));
  if (pick(r, "tcp", "retrans_s", nullptr, k, b, f) && f - b > 0.5) e.push_back(ev(k, b, f, "retrans/s"));
  if (pick(r, "tcpstack", "retrans_s", nullptr, k, b, f) && f - b > 0.5)
    e.push_back(ev(k, b, f, "retrans segs/s"));
  if (pick(r, "nic", "tx_dropped_s", nullptr, k, b, f) && f - b > 0) e.push_back(ev(k, b, f, "tx drops/s"));
  rule("Network degradation", e);

  e.clear();
  if (pick(r, "throttle", "throttle_s", nullptr, k, b, f) && f > 0) e.push_back(ev(k, b, f, "throttles/s"));
  if (pick(r, "edac", "ce_count", nullptr, k, b, f) && f > b) e.push_back(ev(k, b, f, "corrected errors"));
  if (pick(r, "thermal", "temp_c", nullptr, k, b, f) && f - b > 10) e.push_back(ev(k, b, f, "degC"));
  rule("Hardware anomaly", e);

  if (!found) fputs("No rule fired: nothing moved far enough from its baseline.\n", o);
}

void movers(FILE* o, const Run& r, const char* layer, size_t limit) {
  struct Row { double score; Key k; double b, f; };
  std::vector<Row> rows;
  for (const auto& kv : r.series) {
    if (layer && strcmp(layer_of(kv.first.kind), layer) != 0) continue;
    double s = score_of(kv.second[BASE], kv.second[FAULT]);
    if (s <= 0.5) continue;
    rows.push_back({s, kv.first, kv.second[BASE].mean(), kv.second[FAULT].mean()});
  }
  std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
    if (a.score != b.score) return a.score > b.score;
    return a.k < b.k;  // deterministic tie-break
  });
  if (rows.empty()) {
    fputs("_no series moved significantly_\n", o);
    return;
  }
  fputs("| node | metric | baseline | fault | recovery | change | score |\n", o);
  fputs("|---|---|---:|---:|---:|---:|---:|\n", o);
  for (size_t i = 0; i < rows.size() && i < limit; i++) {
    const Row& w = rows[i];
    const auto& st = r.series.at(w.k);
    std::string metric = w.k.kind + (w.k.label.empty() ? "" : "[" + w.k.label + "]") + "." + w.k.field;
    char change[32];
    if (fabs(w.b) > 1e-9) snprintf(change, sizeof(change), "%+.1f%%", (w.f - w.b) / fabs(w.b) * 100.0);
    else snprintf(change, sizeof(change), "%+.3f", w.f - w.b);
    fprintf(o, "| %s | %s | %.3f | %.3f | %.3f | %s | %.1f |\n", w.k.node.c_str(), metric.c_str(),
            w.b, w.f, st[RECOV].mean(), change, w.score);
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::string dir, out_path = "-";
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "-o" && i + 1 < argc) out_path = argv[++i];
    else if (dir.empty()) dir = a;
    else { fputs("usage: kernellens-report <run-dir> [-o report.md]\n", stderr); return 2; }
  }
  if (dir.empty()) {
    fputs("usage: kernellens-report <run-dir> [-o report.md]\n", stderr);
    return 2;
  }

  Run r;
  load(r, dir);
  if (r.lines == 0) {
    fprintf(stderr, "kernellens-report: no records found in %s\n", dir.c_str());
    return 1;
  }

  FILE* o = stdout;
  if (out_path != "-") {
    o = fopen(out_path.c_str(), "w");
    if (!o) { fprintf(stderr, "cannot write %s\n", out_path.c_str()); return 1; }
  }

  fputs("# KernelLens incident report\n\n", o);
  fprintf(o, "- fault: **%s** on **%s**\n", r.fault.c_str(), r.target.c_str());
  std::string nodes;
  for (const auto& n : r.nodes) nodes += (nodes.empty() ? "" : ", ") + n;
  fprintf(o, "- nodes: %s\n", nodes.c_str());
  fprintf(o, "- input: %ld records from %d files, digest %016llx\n", r.lines, r.files,
          (unsigned long long)r.digest);
  fprintf(o, "- windows (s, relative to fault start): baseline %.1f..%.1f, fault %.1f..%.1f, "
             "recovery %.1f..%.1f\n",
          rel(r, r.t_min), rel(r, r.f_start), rel(r, r.f_start), rel(r, r.f_stop), rel(r, r.f_stop),
          rel(r, r.t_max));
  fprintf(o, "- series tracked: %zu\n", r.series.size());

  findings(o, r);

  fputs("\n## Timeline\n\n", o);
  if (r.marks.empty()) {
    fputs("_no injector markers; windows were split at one third of the run_\n", o);
  } else {
    fputs("| t (s) | node | phase | fault | target |\n|---:|---|---|---|---|\n", o);
    for (const auto& m : r.marks)
      fprintf(o, "| %+.3f | %s | %s | %s | %s |\n", rel(r, m.t), m.node.c_str(), m.phase.c_str(),
              m.fault.c_str(), m.target.c_str());
  }

  fputs("\n## Top movers\n\n", o);
  movers(o, r, nullptr, 20);

  for (const char* layer : {"application", "kernel", "network", "hardware"}) {
    fprintf(o, "\n### %s layer\n\n", layer);
    movers(o, r, layer, 8);
  }

  fputs("\n## Kernel latency outliers (eBPF)\n\n", o);
  if (r.bpf_count.empty()) {
    fputs("_no eBPF events in this run_\n", o);
  } else {
    fputs("| node/probe | baseline /s | fault /s | recovery /s |\n|---|---:|---:|---:|\n", o);
    for (const auto& kv : r.bpf_count)
      fprintf(o, "| %s | %.2f | %.2f | %.2f |\n", kv.first.c_str(),
              win_secs(r, BASE) > 0 ? kv.second[BASE] / win_secs(r, BASE) : 0.0,
              win_secs(r, FAULT) > 0 ? kv.second[FAULT] / win_secs(r, FAULT) : 0.0,
              win_secs(r, RECOV) > 0 ? kv.second[RECOV] / win_secs(r, RECOV) : 0.0);

    std::vector<const Event*> worst;
    for (const auto& e : r.events)
      if (e.t >= r.f_start && e.t <= r.f_stop) worst.push_back(&e);
    std::sort(worst.begin(), worst.end(), [](const Event* a, const Event* b) {
      if (a->delta_ms != b->delta_ms) return a->delta_ms > b->delta_ms;
      if (a->t != b->t) return a->t < b->t;
      return a->pid < b->pid;
    });
    if (!worst.empty()) {
      fputs("\n| t (s) | node | probe | comm | pid | latency (ms) | err |\n"
            "|---:|---|---|---|---:|---:|---:|\n", o);
      for (size_t i = 0; i < worst.size() && i < 12; i++) {
        const Event* e = worst[i];
        fprintf(o, "| %+.3f | %s | %s | %s | %ld | %.3f | %ld |\n", rel(r, e->t), e->node.c_str(),
                e->probe.c_str(), e->comm.c_str(), e->pid, e->delta_ms, e->err);
      }
    }
  }

  fputs("\n", o);
  if (o != stdout) fclose(o);
  return 0;
}

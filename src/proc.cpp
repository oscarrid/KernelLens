// processes, memory, filesystems, block devices and psi, read from /proc and /sys.
#include <ctype.h>
#include <stdlib.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <string>

#include "samplers.h"

namespace kl {
namespace {

std::map<std::string, double> g_prev;  // last raw counter value, keyed by series
uint64_t g_last_ns = 0;

// per-second rate of a monotonic counter. returns 0 across a counter reset.
double rate(const std::string& key, double cur, double dt) {
  auto it = g_prev.find(key);
  double r = 0;
  if (it != g_prev.end() && cur >= it->second && dt > 0) r = (cur - it->second) / dt;
  g_prev[key] = cur;
  return r;
}

double delta(const std::string& key, double cur) {
  auto it = g_prev.find(key);
  double d = (it != g_prev.end() && cur >= it->second) ? cur - it->second : 0;
  g_prev[key] = cur;
  return d;
}

std::map<std::string, double> meminfo() {
  std::map<std::string, double> m;
  for (const auto& ln : split_lines(slurp("/proc/meminfo"))) {
    auto f = fields(ln);
    if (f.size() < 2) continue;
    std::string k = f[0];
    if (!k.empty() && k.back() == ':') k.pop_back();
    m[k] = num(f[1]);  // kB
  }
  return m;
}

// /proc/pressure/{cpu,io,memory}: "some avg10=0.00 avg60=0.00 avg300=0.00 total=0"
void psi(uint64_t t, std::vector<Rec>& out) {
  for (const char* res : {"cpu", "io", "memory"}) {
    std::string body = slurp(std::string("/proc/pressure/") + res);
    if (body.empty()) continue;
    Rec r("psi", t);
    r.s("resource", res);
    bool any = false;
    for (const auto& ln : split_lines(body)) {
      auto f = fields(ln);
      if (f.size() < 2) continue;
      for (const auto& tok : f) {
        if (tok.compare(0, 6, "avg10=") == 0) {
          r.n((f[0] + "_avg10").c_str(), num(tok.substr(6)));
          any = true;
        }
      }
    }
    if (any) out.push_back(std::move(r));
  }
}

void cpu_and_load(uint64_t t, double dt, std::vector<Rec>& out) {
  static const char* kNames[] = {"user", "nice",   "system",  "idle",
                                 "iowait", "irq", "softirq", "steal"};
  Rec r("cpu", t);
  bool have = false;
  for (const auto& ln : split_lines(slurp("/proc/stat"))) {
    auto f = fields(ln);
    if (f.empty()) continue;
    if (f[0] == "cpu" && f.size() >= 9) {
      double d[8], tot = 0;
      for (int i = 0; i < 8; i++) {
        d[i] = delta(std::string("cpu:") + kNames[i], num(f[i + 1]));
        tot += d[i];
      }
      if (tot > 0 && dt > 0) {
        for (int i = 0; i < 8; i++)
          r.n((std::string("cpu_") + kNames[i]).c_str(), d[i] / tot * 100.0);
        have = true;
      }
    } else if (f[0] == "ctxt" && f.size() >= 2) {
      r.n("ctxt_s", rate("ctxt", num(f[1]), dt));
    } else if (f[0] == "procs_running" && f.size() >= 2) {
      r.n("procs_running", num(f[1]));
    } else if (f[0] == "procs_blocked" && f.size() >= 2) {
      r.n("procs_blocked", num(f[1]));
    }
  }
  if (have) out.push_back(std::move(r));

  auto la = fields(slurp("/proc/loadavg"));
  if (la.size() >= 3) {
    Rec l("load", t);
    l.n("load1", num(la[0])).n("load5", num(la[1]));
    out.push_back(std::move(l));
  }
}

void memory(uint64_t t, std::vector<Rec>& out) {
  auto m = meminfo();
  if (m.count("MemTotal") == 0 || m["MemTotal"] <= 0) return;
  double total = m["MemTotal"];
  double avail = m.count("MemAvailable") ? m["MemAvailable"] : m["MemFree"];
  Rec r("mem", t);
  r.n("mem_total_mb", total / 1024.0);
  r.n("mem_avail_mb", avail / 1024.0);
  r.n("mem_used_pct", (total - avail) / total * 100.0);
  r.n("dirty_mb", m["Dirty"] / 1024.0);
  r.n("writeback_mb", m["Writeback"] / 1024.0);
  if (m.count("SwapTotal")) r.n("swap_used_mb", (m["SwapTotal"] - m["SwapFree"]) / 1024.0);
  out.push_back(std::move(r));
}

// /proc/diskstats, restricted to whole disks (those that have a /sys/block entry).
void disks(uint64_t t, double dt, std::vector<Rec>& out) {
  if (dt <= 0) return;
  for (const auto& ln : split_lines(slurp("/proc/diskstats"))) {
    auto f = fields(ln);
    if (f.size() < 14) continue;
    const std::string& dev = f[2];
    if (slurp("/sys/block/" + dev + "/dev").empty()) continue;
    double rd = rate("d:" + dev + ":rd", num(f[3]), dt);
    double wr = rate("d:" + dev + ":wr", num(f[7]), dt);
    double rsec = rate("d:" + dev + ":rsec", num(f[5]), dt);
    double wsec = rate("d:" + dev + ":wsec", num(f[9]), dt);
    double svc_ms = delta("d:" + dev + ":rms", num(f[6])) + delta("d:" + dev + ":wms", num(f[10]));
    double busy_ms = delta("d:" + dev + ":ioms", num(f[12]));
    double ios = (rd + wr) * dt;
    Rec r("disk", t);
    r.s("dev", dev);
    r.n("rd_iops", rd).n("wr_iops", wr);
    r.n("rd_mbps", rsec * 512.0 / 1048576.0).n("wr_mbps", wsec * 512.0 / 1048576.0);
    r.n("await_ms", ios > 0 ? svc_ms / ios : 0.0);
    r.n("util_pct", std::min(100.0, busy_ms / (dt * 1000.0) * 100.0));
    r.n("inflight", num(f[11]));
    out.push_back(std::move(r));
  }
}

void filesystems(uint64_t t, std::vector<Rec>& out) {
  std::map<std::string, std::string> mounts;  // mountpoint -> fstype, sorted
  for (const auto& ln : split_lines(slurp("/proc/self/mounts"))) {
    auto f = fields(ln);
    if (f.size() < 3) continue;
    if (f[0][0] != '/' && f[2] != "tmpfs") continue;
    mounts[f[1]] = f[2];
  }
  for (const auto& mf : mounts) {
    struct statvfs s;
    if (statvfs(mf.first.c_str(), &s) != 0 || s.f_blocks == 0) continue;
    double frsize = s.f_frsize ? (double)s.f_frsize : (double)s.f_bsize;
    Rec r("fs", t);
    r.s("mount", mf.first).s("fstype", mf.second);
    r.n("used_pct", (double)(s.f_blocks - s.f_bfree) / (double)s.f_blocks * 100.0);
    r.n("avail_mb", (double)s.f_bavail * frsize / 1048576.0);
    if (s.f_files > 0)
      r.n("inode_used_pct", (double)(s.f_files - s.f_ffree) / (double)s.f_files * 100.0);
    out.push_back(std::move(r));
  }
}

// top processes by cpu. in /proc/<pid>/stat the comm field can contain spaces
// and parentheses, so parsing resumes after the last close paren.
void processes(uint64_t t, double dt, std::vector<Rec>& out) {
  struct P {
    double cpu, rss_pages, majflt, threads;
    int pid;
    std::string comm;
  };
  std::vector<P> ps;
  std::map<std::string, double> live;
  double page_kb = (double)(sysconf(_SC_PAGESIZE) / 1024);
  double hz = (double)sysconf(_SC_CLK_TCK);
  int nproc_total = 0;

  for (const auto& name : list_dir("/proc", "")) {
    if (!isdigit((unsigned char)name[0])) continue;
    ++nproc_total;
    std::string st = slurp("/proc/" + name + "/stat");
    size_t lp = st.find('(');
    size_t rp = st.rfind(')');
    if (lp == std::string::npos || rp == std::string::npos || rp < lp) continue;
    std::string comm = st.substr(lp + 1, rp - lp - 1);
    auto f = fields(st.substr(rp + 1));
    if (f.size() < 22) continue;  // f[0] is field 3 (state); rss is field 24
    double cpu_ticks = num(f[11]) + num(f[12]);
    std::string key = "p:" + name;
    auto it = g_prev.find(key);
    double cpu_pct = 0;
    if (it != g_prev.end() && cpu_ticks >= it->second && dt > 0)
      cpu_pct = (cpu_ticks - it->second) / hz / dt * 100.0;
    live[key] = cpu_ticks;
    ps.push_back({cpu_pct, num(f[21]), num(f[9]), num(f[17]), atoi(name.c_str()), comm});
  }
  // forget processes that exited, so the counter cache cannot grow without bound.
  for (auto it = g_prev.begin(); it != g_prev.end();) {
    if (it->first.compare(0, 2, "p:") == 0 && live.count(it->first) == 0) it = g_prev.erase(it);
    else ++it;
  }
  for (const auto& kv : live) g_prev[kv.first] = kv.second;

  Rec tot("proctotal", t);
  tot.n("processes", nproc_total);
  out.push_back(std::move(tot));
  if (dt <= 0) return;

  std::sort(ps.begin(), ps.end(), [](const P& a, const P& b) {
    if (a.cpu != b.cpu) return a.cpu > b.cpu;
    return a.pid < b.pid;  // deterministic tie-break
  });
  for (size_t i = 0; i < ps.size() && i < 6; i++) {
    Rec r("proc", t);
    r.s("comm", ps[i].comm);
    r.n("pid", ps[i].pid).n("cpu_pct", ps[i].cpu);
    r.n("rss_mb", ps[i].rss_pages * page_kb / 1024.0);
    r.n("majflt", ps[i].majflt).n("threads", ps[i].threads);
    out.push_back(std::move(r));
  }
}

}  // namespace

void sample_proc(uint64_t t, std::vector<Rec>& out) {
  double dt = g_last_ns ? (double)(t - g_last_ns) / 1e9 : 0.0;
  g_last_ns = t;
  cpu_and_load(t, dt, out);
  memory(t, out);
  psi(t, out);
  disks(t, dt, out);
  filesystems(t, out);
  processes(t, dt, out);
}

}  // namespace kl

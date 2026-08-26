// hardware-adjacent counters exposed through sysfs
#include <ctype.h>

#include <algorithm>
#include <map>
#include <string>

#include "samplers.h"

namespace kl {
namespace {

std::map<std::string, double> g_prev;
uint64_t g_last_ns = 0;

double rate(const std::string& key, double cur, double dt) {
  auto it = g_prev.find(key);
  double r = 0;
  if (it != g_prev.end() && cur >= it->second && dt > 0) r = (cur - it->second) / dt;
  g_prev[key] = cur;
  return r;
}

std::string trim(std::string s) {
  while (!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
  return s;
}

bool all_digits(const std::string& s) {
  if (s.empty()) return false;
  for (char c : s)
    if (!isdigit((unsigned char)c)) return false;
  return true;
}

void thermal(uint64_t t, std::vector<Rec>& out) {
  const std::string base = "/sys/class/thermal/";
  for (const auto& z : list_dir(base, "thermal_zone")) {
    std::string temp = trim(slurp(base + z + "/temp"));
    if (temp.empty()) continue;
    Rec r("thermal", t);
    r.s("zone", trim(slurp(base + z + "/type")) + "/" + z);
    r.n("temp_c", num(temp) / 1000.0);
    out.push_back(std::move(r));
  }
}

void cpufreq_and_throttle(uint64_t t, double dt, std::vector<Rec>& out) {
  const std::string base = "/sys/devices/system/cpu/";
  double sum = 0, hi = 0, lo = 1e18, n = 0, throttle = 0;
  bool have_throttle = false;
  for (const auto& c : list_dir(base, "cpu")) {
    if (!all_digits(c.substr(3))) continue;  // skip cpuidle, cpufreq, cpulist...
    std::string f = trim(slurp(base + c + "/cpufreq/scaling_cur_freq"));
    if (!f.empty()) {
      double mhz = num(f) / 1000.0;
      sum += mhz;
      hi = std::max(hi, mhz);
      lo = std::min(lo, mhz);
      n++;
    }
    for (const char* which : {"core_throttle_count", "package_throttle_count"}) {
      std::string v = trim(slurp(base + c + "/thermal_throttle/" + which));
      if (v.empty()) continue;
      throttle += num(v);
      have_throttle = true;
    }
  }
  if (n > 0) {
    Rec r("cpufreq", t);
    r.n("mhz_mean", sum / n).n("mhz_max", hi).n("mhz_min", lo);
    out.push_back(std::move(r));
  }
  if (have_throttle) {
    Rec r("throttle", t);
    r.n("throttle_total", throttle);
    r.n("throttle_s", rate("throttle", throttle, dt));
    out.push_back(std::move(r));
  }
}

void nics(uint64_t t, double dt, std::vector<Rec>& out) {
  if (dt <= 0) return;
  const std::string base = "/sys/class/net/";
  for (const auto& dev : list_dir(base, "")) {
    if (dev == "lo") continue;
    std::string st = base + dev + "/statistics/";
    if (slurp(st + "rx_bytes").empty()) continue;
    Rec r("nic", t);
    r.s("iface", dev);
    r.n("rx_mbps", rate("n:" + dev + ":rxb", num(slurp(st + "rx_bytes")), dt) / 131072.0);
    r.n("tx_mbps", rate("n:" + dev + ":txb", num(slurp(st + "tx_bytes")), dt) / 131072.0);
    r.n("rx_dropped_s", rate("n:" + dev + ":rxd", num(slurp(st + "rx_dropped")), dt));
    r.n("tx_dropped_s", rate("n:" + dev + ":txd", num(slurp(st + "tx_dropped")), dt));
    r.n("rx_errors_s", rate("n:" + dev + ":rxe", num(slurp(st + "rx_errors")), dt));
    r.n("tx_errors_s", rate("n:" + dev + ":txe", num(slurp(st + "tx_errors")), dt));
    out.push_back(std::move(r));
  }
}

void edac(uint64_t t, std::vector<Rec>& out) {
  const std::string base = "/sys/devices/system/edac/mc/";
  for (const auto& mc : list_dir(base, "mc")) {
    std::string ce = trim(slurp(base + mc + "/ce_count"));
    std::string ue = trim(slurp(base + mc + "/ue_count"));
    if (ce.empty() && ue.empty()) continue;
    Rec r("edac", t);
    r.s("controller", mc);
    r.n("ce_count", num(ce)).n("ue_count", num(ue));
    out.push_back(std::move(r));
  }
}

}  // namespace

void sample_hw(uint64_t t, std::vector<Rec>& out) {
  double dt = g_last_ns ? (double)(t - g_last_ns) / 1e9 : 0.0;
  g_last_ns = t;
  thermal(t, out);
  cpufreq_and_throttle(t, dt, out);
  nics(t, dt, out);
  edac(t, out);
}

}  // namespace kl

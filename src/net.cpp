// tcp connection state
#include <arpa/inet.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <string>

#include "samplers.h"

namespace kl {
namespace {

struct Conn {
  std::string peer;
  uint16_t sport = 0, dport = 0;
  uint8_t state = 0;
  struct tcp_info ti;
};

std::map<std::string, double> g_prev;
uint64_t g_last_ns = 0;

double rate(const std::string& key, double cur, double dt) {
  auto it = g_prev.find(key);
  double r = 0;
  if (it != g_prev.end() && cur >= it->second && dt > 0) r = (cur - it->second) / dt;
  g_prev[key] = cur;
  return r;
}

void dump(int family, std::vector<Conn>& out) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
  if (fd < 0) return;
  struct {
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 r;
  } req;
  memset(&req, 0, sizeof(req));
  req.nlh.nlmsg_len = sizeof(req);
  req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nlh.nlmsg_seq = 1;
  req.r.sdiag_family = (uint8_t)family;
  req.r.sdiag_protocol = IPPROTO_TCP;
  req.r.idiag_ext = 1 << (INET_DIAG_INFO - 1);
  req.r.idiag_states = ~0U;
  if (send(fd, &req, sizeof(req), 0) < 0) {
    close(fd);
    return;
  }

  char buf[16384];
  bool done = false;
  while (!done) {
    ssize_t got = recv(fd, buf, sizeof(buf), 0);
    if (got <= 0) break;
    unsigned int len = (unsigned int)got;
    for (struct nlmsghdr* h = (struct nlmsghdr*)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
      if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) {
        done = true;
        break;
      }
      struct inet_diag_msg* m = (struct inet_diag_msg*)NLMSG_DATA(h);
      Conn c;
      memset(&c.ti, 0, sizeof(c.ti));
      c.state = m->idiag_state;
      c.sport = ntohs(m->id.idiag_sport);
      c.dport = ntohs(m->id.idiag_dport);
      char ip[INET6_ADDRSTRLEN] = "?";
      inet_ntop(family, m->id.idiag_dst, ip, sizeof(ip));
      c.peer = ip;
      int rlen = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof(*m)));
      for (struct rtattr* a = (struct rtattr*)(m + 1); RTA_OK(a, rlen); a = RTA_NEXT(a, rlen)) {
        if (a->rta_type != INET_DIAG_INFO) continue;
        // older kernels return a shorter tcp_info than we were compiled against.
        size_t n = std::min((size_t)RTA_PAYLOAD(a), sizeof(c.ti));
        memcpy(&c.ti, RTA_DATA(a), n);
      }
      out.push_back(std::move(c));
    }
  }
  close(fd);
}

// the "Tcp:" line of /proc/net/snmp, for stack-wide retransmit and segment counters.
void snmp(uint64_t t, double dt, std::vector<Rec>& out) {
  if (dt <= 0) return;
  auto lines = split_lines(slurp("/proc/net/snmp"));
  for (size_t i = 0; i + 1 < lines.size(); i++) {
    if (lines[i].compare(0, 4, "Tcp:") != 0) continue;
    auto hdr = fields(lines[i]);
    auto val = fields(lines[i + 1]);
    if (val.empty() || val[0] != "Tcp:" || hdr.size() != val.size()) continue;
    Rec r("tcpstack", t);
    bool any = false;
    for (size_t j = 1; j < hdr.size(); j++) {
      if (hdr[j] == "RetransSegs") { r.n("retrans_s", rate("snmp:rt", num(val[j]), dt)); any = true; }
      else if (hdr[j] == "InSegs") { r.n("in_segs_s", rate("snmp:in", num(val[j]), dt)); any = true; }
      else if (hdr[j] == "OutSegs") { r.n("out_segs_s", rate("snmp:out", num(val[j]), dt)); any = true; }
      else if (hdr[j] == "AttemptFails") { r.n("attempt_fails_s", rate("snmp:af", num(val[j]), dt)); any = true; }
      else if (hdr[j] == "CurrEstab") { r.n("curr_estab", num(val[j])); any = true; }
    }
    if (any) out.push_back(std::move(r));
    break;
  }
}

}  // namespace

void sample_net(uint64_t t, std::vector<Rec>& out) {
  double dt = g_last_ns ? (double)(t - g_last_ns) / 1e9 : 0.0;
  g_last_ns = t;

  std::vector<Conn> conns;
  dump(AF_INET, conns);
  dump(AF_INET6, conns);

  double n_est = 0, rtt_sum = 0, rtt_max = 0, retrans = 0, lost = 0, rto_max = 0;
  double cwnd_min = 1e18;
  for (const auto& c : conns) {
    if (c.state != TCP_ESTABLISHED) continue;
    n_est++;
    double rtt_ms = c.ti.tcpi_rtt / 1000.0;
    rtt_sum += rtt_ms;
    rtt_max = std::max(rtt_max, rtt_ms);
    retrans += c.ti.tcpi_total_retrans;
    lost += c.ti.tcpi_lost;
    rto_max = std::max(rto_max, c.ti.tcpi_rto / 1000.0);
    if (c.ti.tcpi_snd_cwnd > 0) cwnd_min = std::min(cwnd_min, (double)c.ti.tcpi_snd_cwnd);
  }
  Rec agg("tcp", t);
  agg.n("conns_est", n_est);
  agg.n("rtt_ms_mean", n_est > 0 ? rtt_sum / n_est : 0.0);
  agg.n("rtt_ms_max", rtt_max);
  agg.n("retrans_total", retrans);
  agg.n("retrans_s", rate("agg:retrans", retrans, dt));
  agg.n("lost_total", lost);
  agg.n("rto_ms_max", rto_max);
  agg.n("cwnd_min", cwnd_min < 1e18 ? cwnd_min : 0.0);
  out.push_back(std::move(agg));

  // a bounded, deterministically ordered slice of individual connections.
  std::sort(conns.begin(), conns.end(), [](const Conn& a, const Conn& b) {
    if (a.peer != b.peer) return a.peer < b.peer;
    if (a.dport != b.dport) return a.dport < b.dport;
    return a.sport < b.sport;
  });
  int emitted = 0;
  for (const auto& c : conns) {
    if (c.state != TCP_ESTABLISHED || emitted >= 32) continue;
    ++emitted;
    Rec r("conn", t);
    r.s("peer", c.peer + ":" + std::to_string(c.dport));
    r.n("sport", c.sport);
    r.n("rtt_ms", c.ti.tcpi_rtt / 1000.0);
    r.n("rttvar_ms", c.ti.tcpi_rttvar / 1000.0);
    r.n("cwnd", c.ti.tcpi_snd_cwnd);
    r.n("retrans_total", c.ti.tcpi_total_retrans);
    r.n("unacked", c.ti.tcpi_unacked);
    r.n("rto_ms", c.ti.tcpi_rto / 1000.0);
    out.push_back(std::move(r));
  }

  snmp(t, dt, out);
}

}  // namespace kl

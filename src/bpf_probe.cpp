#include "bpf_probe.h"

#include <cstdio>

#include "record.h"

#ifndef KL_HAVE_BPF

namespace kl {
BpfProbe::~BpfProbe() {}
bool BpfProbe::start(const std::string&, uint64_t, uint64_t, std::string& err) {
  err = "built without libbpf";
  return false;
}
int BpfProbe::poll(int, const BpfSink&) { return 0; }
}  // namespace kl

#else

#include <bpf/bpf.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <errno.h>

#include <cstdlib>
#include <cstring>
#include <map>

namespace kl {
namespace {

struct Field {
  const char* name;
  int offset;
};

struct ProgSpec {
  const char* fn;              // bpf function name
  const char* tracepoint;      // subsystem/event
  std::vector<Field> fields;   // layout this program compiles against
};

const std::vector<ProgSpec>& specs() {
  static const std::vector<ProgSpec> s = {
      {"on_sched_switch",
       "sched/sched_switch",
       {{"prev_pid", 24}, {"prev_state", 32}, {"next_comm", 40}, {"next_pid", 56}}},
      {"on_block_rq_issue",
       "block/block_rq_issue",
       {{"dev", 8}, {"sector", 16}, {"comm", 40}}},
      {"on_block_rq_complete",
       "block/block_rq_complete",
       {{"dev", 8}, {"sector", 16}, {"error", 28}}},
  };
  return s;
}

std::string tracing_dir() {
  for (const char* d : {"/sys/kernel/tracing", "/sys/kernel/debug/tracing"})
    if (!slurp(std::string(d) + "/events/sched/sched_switch/format").empty()) return d;
  return {};
}

// parses "field:pid_t prev_pid;\toffset:24;\tsize:4;\tsigned:1;" lines.
std::map<std::string, int> read_format(const std::string& path) {
  std::map<std::string, int> m;
  for (const auto& ln : split_lines(slurp(path))) {
    size_t fp = ln.find("field:");
    size_t op = ln.find("offset:");
    if (fp == std::string::npos || op == std::string::npos) continue;
    size_t semi = ln.find(';', fp);
    if (semi == std::string::npos) continue;
    std::string decl = ln.substr(fp + 6, semi - fp - 6);
    size_t br = decl.find('[');
    if (br != std::string::npos) decl = decl.substr(0, br);
    size_t sp = decl.find_last_of(" \t*");
    if (sp == std::string::npos) continue;
    m[decl.substr(sp + 1)] = atoi(ln.c_str() + op + 7);
  }
  return m;
}

// the tracepoint layouts we hardcode are stable but not guaranteed
bool layout_matches(const std::string& tdir, const ProgSpec& sp, std::string& why) {
  if (tdir.empty()) return true;  // tracefs not mounted so attach and hope
  auto have = read_format(tdir + "/events/" + sp.tracepoint + "/format");
  if (have.empty()) {
    why = "tracepoint not present";
    return false;
  }
  for (const auto& f : sp.fields) {
    auto it = have.find(f.name);
    if (it == have.end()) {
      why = std::string("missing field ") + f.name;
      return false;
    }
    if (it->second != f.offset) {
      why = std::string("field ") + f.name + " at offset " + std::to_string(it->second) +
            ", expected " + std::to_string(f.offset);
      return false;
    }
  }
  return true;
}

int quiet(enum libbpf_print_level lvl, const char* fmt, va_list ap) {
  if (lvl == LIBBPF_DEBUG) return 0;
  return vfprintf(stderr, fmt, ap);
}

int on_sample(void* ctx, void* data, size_t size) {
  auto* self = (BpfProbe*)ctx;
  if (size >= sizeof(BpfEvt) && self->sink_) (*self->sink_)(*(const BpfEvt*)data);
  return 0;
}

}  // namespace

BpfProbe::~BpfProbe() {
  if (rb_) ring_buffer__free((struct ring_buffer*)rb_);
  for (void* l : links_) bpf_link__destroy((struct bpf_link*)l);
  if (obj_) bpf_object__close((struct bpf_object*)obj_);
}

bool BpfProbe::start(const std::string& obj_path, uint64_t offcpu_ns, uint64_t io_ns,
                     std::string& err) {
  libbpf_set_print(quiet);

  struct bpf_object* obj = bpf_object__open_file(obj_path.c_str(), nullptr);
  if (!obj || libbpf_get_error(obj)) {
    err = "cannot open " + obj_path;
    return false;
  }
  obj_ = obj;
  if (bpf_object__load(obj) != 0) {
    err = "bpf_object__load failed (need CAP_BPF/CAP_PERFMON and kernel >= 5.8)";
    return false;
  }

  struct bpf_map* cfg = bpf_object__find_map_by_name(obj, "cfg");
  if (cfg) {
    int fd = bpf_map__fd(cfg);
    uint32_t k;
    uint64_t v;
    k = 0; v = offcpu_ns; bpf_map_update_elem(fd, &k, &v, BPF_ANY);
    k = 1; v = io_ns;     bpf_map_update_elem(fd, &k, &v, BPF_ANY);
  }

  std::string tdir = tracing_dir();
  int attached = 0;
  struct bpf_program* prog;
  bpf_object__for_each_program(prog, obj) {
    const char* fn = bpf_program__name(prog);
    const ProgSpec* sp = nullptr;
    for (const auto& s : specs())
      if (strcmp(s.fn, fn) == 0) sp = &s;
    std::string why;
    if (sp && !layout_matches(tdir, *sp, why)) {
      fprintf(stderr, "kernellens: skipping %s (%s)\n", sp->tracepoint, why.c_str());
      continue;
    }
    struct bpf_link* link = bpf_program__attach(prog);
    if (!link || libbpf_get_error(link)) {
      fprintf(stderr, "kernellens: attach %s failed (%s)\n", fn, strerror(errno));
      continue;
    }
    links_.push_back(link);
    ++attached;
  }
  if (attached == 0) {
    err = "no probes could be attached";
    return false;
  }

  struct bpf_map* events = bpf_object__find_map_by_name(obj, "events");
  if (!events) {
    err = "ring buffer map missing";
    return false;
  }
  rb_ = ring_buffer__new(bpf_map__fd(events), on_sample, this, nullptr);
  if (!rb_) {
    err = "ring_buffer__new failed";
    return false;
  }
  return true;
}

int BpfProbe::poll(int timeout_ms, const BpfSink& sink) {
  if (!rb_) return 0;
  sink_ = &sink;
  int n = ring_buffer__poll((struct ring_buffer*)rb_, timeout_ms);
  sink_ = nullptr;
  return n;
}

}  // namespace kl

#endif  // KL_HAVE_BPF

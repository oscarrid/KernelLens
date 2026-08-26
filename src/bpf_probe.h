#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace kl {

// mirror of struct evt in bpf/kernellens.bpf.c.
struct BpfEvt {
  uint64_t ts;        // CLOCK_MONOTONIC, as returned by bpf_ktime_get_ns()
  uint64_t delta_ns;
  uint32_t pid;
  uint32_t kind;  // 1 = off-cpu wait, 2 = block i/o
  uint32_t aux;   // cpu id, or dev_t
  uint32_t err;
  char comm[16];
};

using BpfSink = std::function<void(const BpfEvt&)>;

class BpfProbe {
 public:
  ~BpfProbe();
  // loads obj_path, verifies tracepoint layouts, attaches what it can.
  // returns false with err set if nothing could be attached.
  bool start(const std::string& obj_path, uint64_t offcpu_ns, uint64_t io_ns, std::string& err);
  bool active() const { return rb_ != nullptr; }
  // waits up to timeout_ms for events. returns records consumed, or <0 on error.
  int poll(int timeout_ms, const BpfSink& sink);

  const BpfSink* sink_ = nullptr;  // valid only inside poll()

 private:
  void* obj_ = nullptr;
  void* rb_ = nullptr;
  std::vector<void*> links_;
};

}  // namespace kl

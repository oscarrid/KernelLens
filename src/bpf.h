#pragma once
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <sys/types.h>

// Background thread that runs one bpftrace one-liner (syscalls per second,
// grouped by process) as a child process and streams its stdout. Needs
// bpftrace installed and root (or CAP_BPF + CAP_PERFMON).
class Bpf {
public:
    Bpf();
    ~Bpf();

    std::vector<std::string> lines();  // thread-safe copy, oldest first

private:
    pid_t pid_ = -1;
    std::mutex mtx_;
    std::vector<std::string> lines_;
    std::jthread thread_;
};

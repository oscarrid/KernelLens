#pragma once
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct ProcInfo {
    int pid = 0;
    std::string name;
    long rss_kb = 0;
};

struct ProcSnapshot {
    long mem_total_kb = 0;
    long mem_available_kb = 0;
    double cpu_percent = 0.0;  // whole-machine busy %, over the last interval
    std::vector<ProcInfo> procs;  // sorted by rss_kb, descending
};

// Background thread that re-reads /proc on a fixed interval.
class Proc {
public:
    explicit Proc(std::chrono::milliseconds interval = std::chrono::milliseconds(500));
    ~Proc();

    ProcSnapshot snapshot();  // thread-safe copy of the latest poll

private:
    std::chrono::milliseconds interval_;
    std::mutex mtx_;
    ProcSnapshot latest_;
    std::jthread thread_;
};

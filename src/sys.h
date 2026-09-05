#pragma once
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct CpuFreq {
    int core = 0;
    long mhz = 0;
};

struct ThermalZone {
    std::string type;
    double celsius = 0.0;
};

struct SysSnapshot {
    std::vector<CpuFreq> freqs;      // sorted by core
    std::vector<ThermalZone> zones;  // sorted by type
};

// Background thread that re-reads a few sysfs knobs on a fixed interval:
// per-core CPU frequency and thermal zone temperatures.
class Sys {
public:
    explicit Sys(std::chrono::milliseconds interval = std::chrono::milliseconds(1000));
    ~Sys();

    SysSnapshot snapshot();  // thread-safe copy of the latest poll

private:
    std::chrono::milliseconds interval_;
    std::mutex mtx_;
    SysSnapshot latest_;
    std::jthread thread_;
};

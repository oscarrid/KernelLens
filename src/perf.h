#pragma once
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct PerfCounter {
    std::string event;  // empty for a raw (unparsed) status/error line
    std::string value;  // e.g. "1,234,567", or the raw line when event is empty
};

// Background thread that repeatedly shells out to `perf stat` over a fixed
// sleep window and parses its machine-readable (-x,) CSV output. Needs
// perf installed, and either root or a permissive perf_event_paranoid.
class Perf {
public:
    Perf();
    ~Perf();

    std::vector<PerfCounter> snapshot();  // thread-safe copy of the latest run

private:
    std::mutex mtx_;
    std::vector<PerfCounter> latest_;
    std::jthread thread_;
};

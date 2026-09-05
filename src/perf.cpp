#include "perf.h"

#include <array>
#include <cstdio>
#include <sstream>

namespace {

// `-- sleep 1` both picks the sample window and paces this thread's loop;
// 2>&1 folds in perf's stderr, where it prints permission/setup errors.
constexpr const char* kCmd =
    "perf stat -x, -e cycles,instructions,cache-misses,context-switches,page-faults "
    "-- sleep 1 2>&1";

// perf's -x, CSV is "value,unit,event,...". Keep just those first three
// fields; a line that doesn't have them (a status/error message) is kept
// verbatim so it's still visible in the UI.
std::vector<PerfCounter> parse(FILE* f) {
    std::vector<PerfCounter> out;
    std::array<char, 512> buf{};
    while (fgets(buf.data(), buf.size(), f)) {
        std::string line(buf.data());
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();

        std::stringstream ss(line);
        std::string value, unit, event;
        if (std::getline(ss, value, ',') && std::getline(ss, unit, ',') &&
            std::getline(ss, event, ',')) {
            out.push_back({event, value});
        } else if (!line.empty()) {
            out.push_back({"", line});
        }
    }
    return out;
}

}  // namespace

Perf::Perf() {
    thread_ = std::jthread([this](std::stop_token st) {
        while (!st.stop_requested()) {
            if (FILE* f = popen(kCmd, "r")) {
                std::vector<PerfCounter> s = parse(f);
                pclose(f);
                std::lock_guard lock(mtx_);
                latest_ = std::move(s);
            }
        }
    });
}

Perf::~Perf() = default;  // jthread requests stop + joins in its destructor

std::vector<PerfCounter> Perf::snapshot() {
    std::lock_guard lock(mtx_);
    return latest_;
}

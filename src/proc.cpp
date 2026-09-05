#include "proc.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>

#include <dirent.h>
#include <unistd.h>

namespace {

long page_kb() {
    static const long v = sysconf(_SC_PAGESIZE) / 1024;
    return v;
}

void read_mem(ProcSnapshot& s) {
    std::ifstream f("/proc/meminfo");
    std::string key, unit;
    long val = 0;
    while (f >> key >> val) {
        std::getline(f, unit);  // discard the trailing " kB"
        if (key == "MemTotal:") s.mem_total_kb = val;
        else if (key == "MemAvailable:") s.mem_available_kb = val;
    }
}

void read_cpu(ProcSnapshot& s) {
    // First line of /proc/stat: "cpu" then jiffie counters, fields 3+4 are idle+iowait.
    std::ifstream f("/proc/stat");
    std::string cpu;
    f >> cpu;
    long long total = 0, idle = 0, v = 0;
    for (int i = 0; f >> v; ++i) {
        total += v;
        if (i == 3 || i == 4) idle += v;
    }
    static long long prev_total = 0, prev_idle = 0;
    long long dt = total - prev_total, di = idle - prev_idle;
    prev_total = total;
    prev_idle = idle;
    if (dt > 0) s.cpu_percent = 100.0 * (dt - di) / dt;
}

void read_procs(ProcSnapshot& s) {
    DIR* d = opendir("/proc");
    if (!d) return;
    while (dirent* e = readdir(d)) {
        if (!std::isdigit(static_cast<unsigned char>(e->d_name[0]))) continue;
        std::string pid = e->d_name;

        // Field 2 of /proc/<pid>/statm is the resident set size in pages.
        std::ifstream sm("/proc/" + pid + "/statm");
        long total_pages = 0, rss_pages = 0;
        if (!(sm >> total_pages >> rss_pages)) continue;  // process already gone

        std::ifstream cm("/proc/" + pid + "/comm");
        std::string name;
        std::getline(cm, name);

        s.procs.push_back({std::atoi(pid.c_str()), name, rss_pages * page_kb()});
    }
    closedir(d);
    std::sort(s.procs.begin(), s.procs.end(),
              [](const ProcInfo& a, const ProcInfo& b) { return a.rss_kb > b.rss_kb; });
}

}  // namespace

Proc::Proc(std::chrono::milliseconds interval) : interval_(interval) {
    thread_ = std::jthread([this](std::stop_token st) {
        while (!st.stop_requested()) {
            ProcSnapshot s;
            read_mem(s);
            read_cpu(s);
            read_procs(s);
            {
                std::lock_guard lock(mtx_);
                latest_ = std::move(s);
            }
            std::this_thread::sleep_for(interval_);
        }
    });
}

Proc::~Proc() = default;  // jthread requests stop + joins in its destructor

ProcSnapshot Proc::snapshot() {
    std::lock_guard lock(mtx_);
    return latest_;
}

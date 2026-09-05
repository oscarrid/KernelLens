#include "sys.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>

#include <dirent.h>

namespace {

void read_freqs(SysSnapshot& s) {
    DIR* d = opendir("/sys/devices/system/cpu");
    if (!d) return;
    while (dirent* e = readdir(d)) {
        std::string name = e->d_name;
        if (name.size() < 4 || name.compare(0, 3, "cpu") != 0 ||
            !std::isdigit(static_cast<unsigned char>(name[3])))
            continue;

        std::ifstream f("/sys/devices/system/cpu/" + name + "/cpufreq/scaling_cur_freq");
        long khz = 0;
        if (f >> khz) s.freqs.push_back({std::atoi(name.c_str() + 3), khz / 1000});
    }
    closedir(d);
    std::sort(s.freqs.begin(), s.freqs.end(),
              [](const CpuFreq& a, const CpuFreq& b) { return a.core < b.core; });
}

void read_thermal(SysSnapshot& s) {
    DIR* d = opendir("/sys/class/thermal");
    if (!d) return;
    while (dirent* e = readdir(d)) {
        std::string name = e->d_name;
        if (name.size() < 12 || name.compare(0, 12, "thermal_zone") != 0) continue;

        std::string base = "/sys/class/thermal/" + name + "/";
        std::ifstream tf(base + "temp");
        long millideg = 0;
        if (!(tf >> millideg)) continue;

        std::ifstream typef(base + "type");
        std::string type;
        std::getline(typef, type);

        s.zones.push_back({type, millideg / 1000.0});
    }
    closedir(d);
    std::sort(s.zones.begin(), s.zones.end(),
              [](const ThermalZone& a, const ThermalZone& b) { return a.type < b.type; });
}

}  // namespace

Sys::Sys(std::chrono::milliseconds interval) : interval_(interval) {
    thread_ = std::jthread([this](std::stop_token st) {
        while (!st.stop_requested()) {
            SysSnapshot s;
            read_freqs(s);
            read_thermal(s);
            {
                std::lock_guard lock(mtx_);
                latest_ = std::move(s);
            }
            std::this_thread::sleep_for(interval_);
        }
    });
}

Sys::~Sys() = default;  // jthread requests stop + joins in its destructor

SysSnapshot Sys::snapshot() {
    std::lock_guard lock(mtx_);
    return latest_;
}

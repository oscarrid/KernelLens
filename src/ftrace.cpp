#include "ftrace.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

// The event this tab traces: one process exec per line, always present,
// never noisy. Point it at any other "group/event" under
// <tracing_dir>/events to watch something else.
constexpr const char* kEvent = "sched/sched_process_exec";

bool dir_exists(const std::string& path) {
    struct stat st {};
    return stat(path.c_str(), &st) == 0;
}

void write_file(const std::string& path, const std::string& value) {
    std::ofstream f(path);
    f << value;  // best-effort: silently does nothing without permission
}

}  // namespace

Ftrace::Ftrace() {
    tracing_dir_ = dir_exists("/sys/kernel/tracing") ? "/sys/kernel/tracing"
                                                      : "/sys/kernel/debug/tracing";
    write_file(tracing_dir_ + "/events/" + kEvent + "/enable", "1");
    write_file(tracing_dir_ + "/tracing_on", "1");

    thread_ = std::jthread([this](std::stop_token st) {
        int fd = open((tracing_dir_ + "/trace_pipe").c_str(), O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            std::lock_guard lock(mtx_);
            lines_.push_back(std::string("cannot open trace_pipe: ") + std::strerror(errno));
            return;
        }

        std::string carry;  // partial line held over between reads
        std::array<char, 4096> buf{};
        while (!st.stop_requested()) {
            ssize_t n = read(fd, buf.data(), buf.size());
            if (n > 0) {
                carry.append(buf.data(), static_cast<std::size_t>(n));
                std::size_t nl;
                while ((nl = carry.find('\n')) != std::string::npos) {
                    std::lock_guard lock(mtx_);
                    lines_.push_back(carry.substr(0, nl));
                    carry.erase(0, nl + 1);
                }
            } else {
                // EAGAIN: caught up with the buffer.
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }
        close(fd);
    });
}

Ftrace::~Ftrace() {
    write_file(tracing_dir_ + "/events/" + kEvent + "/enable", "0");
    write_file(tracing_dir_ + "/tracing_on", "0");
    // thread_'s own destructor requests stop + joins right after this body runs.
}

std::vector<std::string> Ftrace::lines() {
    std::lock_guard lock(mtx_);
    return lines_;
}

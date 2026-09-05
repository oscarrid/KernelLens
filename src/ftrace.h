#pragma once
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Background thread that enables one ftrace tracepoint and streams matching
// events from tracefs's trace_pipe, the same file `cat trace_pipe` reads.
// Needs root (or CAP_SYS_ADMIN / tracefs group access) to write the control
// files; failing to open them is silently ignored, same spirit as the rest
// of this codebase's direct kernel-interface reads.
class Ftrace {
public:
    Ftrace();
    ~Ftrace();

    std::vector<std::string> lines();  // thread-safe copy, oldest first

private:
    std::string tracing_dir_;
    std::mutex mtx_;
    std::vector<std::string> lines_;
    std::jthread thread_;
};

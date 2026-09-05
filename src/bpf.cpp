#include "bpf.h"

#include <array>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

// Per-second syscall counts by process name: a minimal, always-relevant
// probe. Swap the script to trace anything else.
constexpr const char* kScript =
    "tracepoint:raw_syscalls:sys_enter { @[comm] = count(); } "
    "interval:s:1 { print(@); clear(@); }";

}  // namespace

Bpf::Bpf() {
    int fds[2];
    if (pipe(fds) != 0) return;

    pid_ = fork();
    if (pid_ == 0) {
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        close(fds[1]);
        execlp("bpftrace", "bpftrace", "-e", kScript, nullptr);
        _exit(127);  // exec failed
    }
    close(fds[1]);
    int read_fd = fds[0];

    // No stop_token: this loop is driven by the child's lifetime, not
    // cooperative cancellation — see the EOF comment below.
    thread_ = std::jthread([this, read_fd] {
        std::string carry;  // partial line held over between reads
        std::array<char, 4096> buf{};
        ssize_t n;
        while ((n = read(read_fd, buf.data(), buf.size())) > 0) {
            carry.append(buf.data(), static_cast<std::size_t>(n));
            std::size_t nl;
            while ((nl = carry.find('\n')) != std::string::npos) {
                std::lock_guard lock(mtx_);
                lines_.push_back(carry.substr(0, nl));
                carry.erase(0, nl + 1);
            }
        }
        close(read_fd);  // n == 0: child exited, its stdout pipe end closed
    });
}

Bpf::~Bpf() {
    if (pid_ > 0) {
        kill(pid_, SIGTERM);  // unblocks the reader thread's read() with EOF
        waitpid(pid_, nullptr, 0);
    }
    // thread_'s own destructor joins it right after this body runs.
}

std::vector<std::string> Bpf::lines() {
    std::lock_guard lock(mtx_);
    return lines_;
}

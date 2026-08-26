#pragma once
#include <vector>

#include "record.h"

namespace kl {

void sample_proc(uint64_t t, std::vector<Rec>& out);  // processes, memory, fs, disk, psi
void sample_net(uint64_t t, std::vector<Rec>& out);   // TCP_INFO via sock_diag, snmp counters
void sample_hw(uint64_t t, std::vector<Rec>& out);    // thermal, cpufreq, throttling, edac, nic

}  // namespace kl

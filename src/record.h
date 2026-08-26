// kernellens sample record: one flat json object per line, one line per sample
#pragma once
#include <cstdint>
#include <cstdio>
#include <string>
#include <variant>
#include <vector>

namespace kl {

using Val = std::variant<double, std::string>;

struct Rec {
  std::string kind;   // "cpu", "mem", "psi", "disk", "fs", "proc", "tcp", ...
  std::string node;
  uint64_t t_ns = 0;  // CLOCK_REALTIME, so records from several nodes line up
  std::vector<std::pair<std::string, Val>> f;

  explicit Rec(std::string k = {}, uint64_t t = 0) : kind(std::move(k)), t_ns(t) {}
  Rec& n(const char* k, double v) { f.emplace_back(k, Val(v)); return *this; }
  Rec& s(const char* k, std::string v) { f.emplace_back(k, Val(std::move(v))); return *this; }
};

uint64_t now_ns();
void emit(FILE* out, const Rec& r);
bool parse(const std::string& line, Rec& out);

// small /proc- and /sys-flavoured helpers, shared by every sampler.
std::string slurp(const std::string& path);
std::vector<std::string> split_lines(const std::string& s);
std::vector<std::string> fields(const std::string& s);
std::vector<std::string> list_dir(const std::string& dir, const std::string& prefix);
double num(const std::string& s);

}  // namespace kl

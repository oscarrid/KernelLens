#include "record.h"

#include <dirent.h>
#include <time.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstring>

namespace kl {

uint64_t now_ns() {
  struct timespec ts{};
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static std::string esc(const std::string& s) {
  std::string o;
  for (char c : s) {
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if ((unsigned char)c < 0x20) o += ' ';
    else o += c;
  }
  return o;
}

void emit(FILE* out, const Rec& r) {
  fprintf(out, "{\"t\":%llu,\"node\":\"%s\",\"kind\":\"%s\"",
          (unsigned long long)r.t_ns, esc(r.node).c_str(), esc(r.kind).c_str());
  for (const auto& kv : r.f) {
    if (const double* d = std::get_if<double>(&kv.second)) {
      double v = std::isfinite(*d) ? *d : 0.0;
      fprintf(out, ",\"%s\":%.6f", esc(kv.first).c_str(), v);
    } else {
      fprintf(out, ",\"%s\":\"%s\"", esc(kv.first).c_str(),
              esc(std::get<std::string>(kv.second)).c_str());
    }
  }
  fputs("}\n", out);
}

// flat-object reader. the agent is the only writer, so nesting never occurs.
static bool pstr(const std::string& s, size_t& i, std::string& out) {
  if (i >= s.size() || s[i] != '"') return false;
  ++i;
  out.clear();
  while (i < s.size() && s[i] != '"') {
    if (s[i] == '\\' && i + 1 < s.size()) { ++i; out += (s[i] == 'n' ? '\n' : s[i]); }
    else out += s[i];
    ++i;
  }
  if (i >= s.size()) return false;
  ++i;
  return true;
}

bool parse(const std::string& line, Rec& r) {
  size_t i = line.find('{');
  if (i == std::string::npos) return false;
  ++i;
  r = Rec();
  while (i < line.size()) {
    while (i < line.size() && (line[i] == ' ' || line[i] == ',')) ++i;
    if (i >= line.size() || line[i] == '}') break;
    std::string k;
    if (!pstr(line, i, k)) return false;
    while (i < line.size() && (line[i] == ' ' || line[i] == ':')) ++i;
    if (i < line.size() && line[i] == '"') {
      std::string v;
      if (!pstr(line, i, v)) return false;
      if (k == "kind") r.kind = v;
      else if (k == "node") r.node = v;
      else r.s(k.c_str(), v);
    } else {
      size_t j = i;
      while (j < line.size() && line[j] != ',' && line[j] != '}') ++j;
      std::string v = line.substr(i, j - i);
      // nanosecond timestamps exceed the exact range of double, so keep t integral.
      if (k == "t") r.t_ns = strtoull(v.c_str(), nullptr, 10);
      else r.n(k.c_str(), strtod(v.c_str(), nullptr));
      i = j;
    }
  }
  return !r.kind.empty();
}

std::string slurp(const std::string& path) {
  FILE* f = fopen(path.c_str(), "rb");
  if (!f) return {};
  std::string s;
  char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) s.append(buf, n);
  fclose(f);
  return s;
}

std::vector<std::string> split_lines(const std::string& s) {
  std::vector<std::string> v;
  size_t i = 0;
  while (i < s.size()) {
    size_t j = s.find('\n', i);
    if (j == std::string::npos) j = s.size();
    v.push_back(s.substr(i, j - i));
    i = j + 1;
  }
  return v;
}

std::vector<std::string> fields(const std::string& s) {
  std::vector<std::string> v;
  size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && isspace((unsigned char)s[i])) ++i;
    size_t j = i;
    while (j < s.size() && !isspace((unsigned char)s[j])) ++j;
    if (j > i) v.push_back(s.substr(i, j - i));
    i = j;
  }
  return v;
}

std::vector<std::string> list_dir(const std::string& dir, const std::string& prefix) {
  std::vector<std::string> v;
  DIR* d = opendir(dir.c_str());
  if (!d) return v;
  while (struct dirent* e = readdir(d)) {
    std::string name = e->d_name;
    if (name == "." || name == "..") continue;
    if (!prefix.empty() && name.compare(0, prefix.size(), prefix) != 0) continue;
    v.push_back(name);
  }
  closedir(d);
  std::sort(v.begin(), v.end());  // stable iteration order keeps reports reproducible
  return v;
}

double num(const std::string& s) { return strtod(s.c_str(), nullptr); }

}  // namespace kl

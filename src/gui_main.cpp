// kernellens-gui: dashboard for a kernellens jsonl stream w/ four tabs
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <implot.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "record.h"

using kl::Rec;

namespace {

constexpr double kStaleS = 5.0;  // a row not refreshed this long is dropped, not just greyed out

// fixed-capacity point buffer for one chart line. xs/ys are kept as two separate flat arrays
struct ScrollingBuffer {
  size_t max_size = 4096;
  std::vector<float> xs, ys;
  void add(float x, float y) {
    // guards against a corrupt-looking zigzag
    if (!xs.empty() && x < xs.back()) return;
    if (xs.size() >= max_size) { xs.erase(xs.begin()); ys.erase(ys.begin()); }
    xs.push_back(x);
    ys.push_back(y);
  }
};

uint64_t g_t0 = 0;
long g_records = 0, g_lines = 0;
double g_now = -1e18;  // latest sample time seen (relative seconds), for staleness checks
std::vector<std::pair<double, std::string>> g_marks;  // (t_rel, phase), from the injector

struct MemSnap {
  double t = -1e18, total_mb = 0, avail_mb = 0, used_pct = 0, dirty_mb = 0, writeback_mb = 0, swap_mb = 0;
  bool have_swap = false;
};
std::map<std::string, MemSnap> g_mem;             // key: node
std::map<std::string, ScrollingBuffer> g_mem_hist;  // key: node
struct PsiMem { double v = 0, t = -1e18; };
std::map<std::string, PsiMem> g_psi_mem;  // key: node

struct TcpAgg {
  double t = -1e18, conns_est = 0, rtt_mean = 0, rtt_max = 0, retrans_s = 0, lost_total = 0;
} g_tcp;

struct ConnRow {
  double t = -1e18, sport = 0, rtt_ms = 0, rttvar_ms = 0, cwnd = 0, retrans = 0, unacked = 0, rto_ms = 0;
  std::string node, peer;
};
std::map<std::string, ConnRow> g_conns;  // key: node|peer

struct FsRow {
  double t = -1e18, used_pct = 0, avail_mb = 0, inode_pct = 0;
  std::string node, mount, fstype;
};
std::map<std::string, FsRow> g_fs;  // key: node|mount

struct DiskRow {
  double t = -1e18, rd_iops = 0, wr_iops = 0, rd_mbps = 0, wr_mbps = 0, await_ms = 0, util_pct = 0;
  std::string node, dev;
};
std::map<std::string, DiskRow> g_disks;  // key: node|dev

struct ProcRow {
  double t = -1e18, cpu_pct = 0, rss_mb = 0, majflt = 0, threads = 0;
  long pid = 0;
  std::string node, comm;
};
std::map<std::string, ProcRow> g_procs;  // key: node|pid
double g_proctotal = 0, g_proctotal_t = -1e18;

double rel_secs(uint64_t t_ns) { return g_t0 ? (double)((int64_t)t_ns - (int64_t)g_t0) / 1e9 : 0.0; }
bool fresh(double t) { return (g_now - t) < kStaleS; }

void ingest(const Rec& rec) {
  if (!g_t0) g_t0 = rec.t_ns;
  ++g_records;
  double t = rel_secs(rec.t_ns);
  g_now = std::max(g_now, t);

  std::map<std::string, double> n;
  std::map<std::string, std::string> s;
  for (const auto& kv : rec.f) {
    if (const double* d = std::get_if<double>(&kv.second)) n[kv.first] = *d;
    else s[kv.first] = std::get<std::string>(kv.second);
  }

  if (rec.kind == "mark") {
    g_marks.emplace_back(t, s.count("phase") ? s["phase"] : "");
  } else if (rec.kind == "mem") {
    g_mem[rec.node] = {t, n["mem_total_mb"], n["mem_avail_mb"], n["mem_used_pct"], n["dirty_mb"],
                        n["writeback_mb"], n.count("swap_used_mb") ? n["swap_used_mb"] : 0.0,
                        n.count("swap_used_mb") > 0};
    g_mem_hist[rec.node].add((float)t, (float)n["mem_used_pct"]);
  } else if (rec.kind == "psi" && s.count("resource") && s["resource"] == "memory" && n.count("some_avg10")) {
    g_psi_mem[rec.node] = {n["some_avg10"], t};
  } else if (rec.kind == "tcp") {
    g_tcp = {t, n["conns_est"], n["rtt_ms_mean"], n["rtt_ms_max"], n["retrans_s"], n["lost_total"]};
  } else if (rec.kind == "conn") {
    ConnRow& c = g_conns[rec.node + "|" + s["peer"]];
    c = {t, n["sport"], n["rtt_ms"], n["rttvar_ms"], n["cwnd"], n["retrans_total"], n["unacked"], n["rto_ms"],
         rec.node, s["peer"]};
  } else if (rec.kind == "fs") {
    FsRow& r = g_fs[rec.node + "|" + s["mount"]];
    r = {t, n["used_pct"], n["avail_mb"], n["inode_used_pct"], rec.node, s["mount"], s["fstype"]};
  } else if (rec.kind == "disk") {
    DiskRow& r = g_disks[rec.node + "|" + s["dev"]];
    r = {t, n["rd_iops"], n["wr_iops"], n["rd_mbps"], n["wr_mbps"], n["await_ms"], n["util_pct"], rec.node, s["dev"]};
  } else if (rec.kind == "proc") {
    long pid = (long)n["pid"];
    ProcRow& r = g_procs[rec.node + "|" + std::to_string(pid)];
    r = {t, n["cpu_pct"], n["rss_mb"], n["majflt"], n["threads"], pid, rec.node, s["comm"]};
  } else if (rec.kind == "proctotal") {
    g_proctotal = n["processes"];
    g_proctotal_t = t;
  }
}

// tails path from the byte offset it stopped at
void poll_file(const std::string& path, long& pos) {
  FILE* f = fopen(path.c_str(), "rb");
  if (!f) return;
  fseek(f, 0, SEEK_END);
  long end = ftell(f);
  if (end < pos) pos = 0;  // truncated or rotated: start over
  if (end <= pos) { fclose(f); return; }

  fseek(f, pos, SEEK_SET);
  std::string buf(end - pos, '\0');
  size_t n = fread(buf.data(), 1, buf.size(), f);
  fclose(f);
  buf.resize(n);

  size_t last_nl = buf.find_last_of('\n');
  if (last_nl == std::string::npos) return;  // no complete line yet
  pos += (long)last_nl + 1;

  for (const auto& ln : kl::split_lines(buf.substr(0, last_nl + 1))) {
    if (ln.empty()) continue;
    ++g_lines;
    Rec rec;
    if (kl::parse(ln, rec) && rec.t_ns) ingest(rec);
  }
}

void glfw_error(int code, const char* desc) { fprintf(stderr, "glfw error %d: %s\n", code, desc); }

// one labelled number e.g."Available" / "1234 MB"
void stat(const char* label, const char* fmt, double v) {
  ImGui::BeginGroup();
  ImGui::TextDisabled("%s", label);
  ImGui::Text(fmt, v);
  ImGui::EndGroup();
}

ImVec4 pct_color(double pct) {
  if (pct >= 90) return ImVec4(0.95f, 0.35f, 0.35f, 1.0f);
  if (pct >= 75) return ImVec4(0.95f, 0.75f, 0.30f, 1.0f);
  return ImVec4(0.55f, 0.85f, 0.55f, 1.0f);
}

void draw_marks() {
  if (g_marks.empty()) return;
  std::vector<double> xs;
  xs.reserve(g_marks.size());
  for (const auto& m : g_marks) xs.push_back(m.first);
  ImPlot::PlotInfLines("phase marks", xs.data(), (int)xs.size());
}

void tab_memory() {
  bool any = false;
  for (const auto& kv : g_mem)
    if (fresh(kv.second.t)) { any = true; break; }
  if (!any) { ImGui::TextDisabled("waiting for memory samples..."); return; }

  // one stat block per node
  for (const auto& kv : g_mem) {
    const std::string& node = kv.first;
    const MemSnap& m = kv.second;
    if (!fresh(m.t)) continue;

    ImGui::TextColored(ImVec4(0.45f, 0.75f, 1.0f, 1.0f), "%s", node.c_str());
    char overlay[32];
    snprintf(overlay, sizeof(overlay), "%.1f%%", m.used_pct);
    ImGui::ProgressBar((float)(m.used_pct / 100.0), ImVec2(-1, 0), overlay);

    stat("Total", "%.0f MB", m.total_mb);
    ImGui::SameLine(0, 32);
    stat("Available", "%.0f MB", m.avail_mb);
    ImGui::SameLine(0, 32);
    if (m.have_swap) {
      stat("Swap used", "%.0f MB", m.swap_mb);
      ImGui::SameLine(0, 32);
    }
    stat("Dirty + writeback", "%.0f MB", m.dirty_mb + m.writeback_mb);
    auto psi = g_psi_mem.find(node);
    if (psi != g_psi_mem.end() && fresh(psi->second.t)) {
      ImGui::SameLine(0, 32);
      stat("Pressure (PSI some_avg10)", "%.1f%%", psi->second.v);
    }
    ImGui::Spacing();
  }

  ImGui::Separator();
  if (ImPlot::BeginPlot("##memhist", ImVec2(-1, -1))) {
    ImPlot::SetupAxes("seconds since first sample", "% used", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
    draw_marks();
    for (const auto& kv : g_mem_hist) {
      const ScrollingBuffer& b = kv.second;
      if (b.xs.empty()) continue;
      ImPlot::PlotLine(kv.first.c_str(), b.xs.data(), b.ys.data(), (int)b.xs.size());
    }
    ImPlot::EndPlot();
  }
}

void tab_tcp() {
  if (fresh(g_tcp.t)) {
    stat("Established", "%.0f", g_tcp.conns_est);
    ImGui::SameLine(0, 32);
    stat("Mean RTT", "%.2f ms", g_tcp.rtt_mean);
    ImGui::SameLine(0, 32);
    stat("Max RTT", "%.2f ms", g_tcp.rtt_max);
    ImGui::SameLine(0, 32);
    stat("Retrans/s", "%.2f", g_tcp.retrans_s);
    ImGui::SameLine(0, 32);
    stat("Lost (total)", "%.0f", g_tcp.lost_total);
  } else {
    ImGui::TextDisabled("waiting for TCP samples...");
  }
  ImGui::Spacing();
  ImGui::Separator();

  static ImGuiTableFlags flags =
      ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY;
  if (ImGui::BeginTable("##conns", 8, flags, ImVec2(-1, -1))) {
    ImGui::TableSetupColumn("Node");
    ImGui::TableSetupColumn("Peer");
    ImGui::TableSetupColumn("Sport");
    ImGui::TableSetupColumn("RTT ms");
    ImGui::TableSetupColumn("RTTVar ms");
    ImGui::TableSetupColumn("CWnd");
    ImGui::TableSetupColumn("Retrans");
    ImGui::TableSetupColumn("Unacked");
    ImGui::TableHeadersRow();
    for (const auto& kv : g_conns) {
      const ConnRow& c = kv.second;
      if (!fresh(c.t)) continue;
      ImGui::TableNextRow();
      ImGui::TableNextColumn(); ImGui::TextUnformatted(c.node.c_str());
      ImGui::TableNextColumn(); ImGui::TextUnformatted(c.peer.c_str());
      ImGui::TableNextColumn(); ImGui::Text("%.0f", c.sport);
      ImGui::TableNextColumn(); ImGui::Text("%.2f", c.rtt_ms);
      ImGui::TableNextColumn(); ImGui::Text("%.2f", c.rttvar_ms);
      ImGui::TableNextColumn(); ImGui::Text("%.0f", c.cwnd);
      ImGui::TableNextColumn(); ImGui::Text("%.0f", c.retrans);
      ImGui::TableNextColumn(); ImGui::Text("%.0f", c.unacked);
    }
    ImGui::EndTable();
  }
}

void tab_filesystems() {
  ImGui::TextDisabled("Mounts");
  static ImGuiTableFlags flags =
      ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY;
  if (ImGui::BeginTable("##fs", 6, flags, ImVec2(-1, 180))) {
    ImGui::TableSetupColumn("Node");
    ImGui::TableSetupColumn("Mount");
    ImGui::TableSetupColumn("Type");
    ImGui::TableSetupColumn("Used %");
    ImGui::TableSetupColumn("Avail MB");
    ImGui::TableSetupColumn("Inode %");
    ImGui::TableHeadersRow();
    for (const auto& kv : g_fs) {
      const FsRow& r = kv.second;
      if (!fresh(r.t)) continue;
      ImGui::TableNextRow();
      ImGui::TableNextColumn(); ImGui::TextUnformatted(r.node.c_str());
      ImGui::TableNextColumn(); ImGui::TextUnformatted(r.mount.c_str());
      ImGui::TableNextColumn(); ImGui::TextUnformatted(r.fstype.c_str());
      ImGui::TableNextColumn(); ImGui::TextColored(pct_color(r.used_pct), "%.1f", r.used_pct);
      ImGui::TableNextColumn(); ImGui::Text("%.0f", r.avail_mb);
      ImGui::TableNextColumn(); ImGui::Text("%.1f", r.inode_pct);
    }
    ImGui::EndTable();
  }

  ImGui::Spacing();
  ImGui::TextDisabled("Disks");
  if (ImGui::BeginTable("##disks", 7, flags, ImVec2(-1, -1))) {
    ImGui::TableSetupColumn("Node");
    ImGui::TableSetupColumn("Device");
    ImGui::TableSetupColumn("Read IOPS");
    ImGui::TableSetupColumn("Write IOPS");
    ImGui::TableSetupColumn("Read MB/s");
    ImGui::TableSetupColumn("Write MB/s");
    ImGui::TableSetupColumn("Util %");
    ImGui::TableHeadersRow();
    for (const auto& kv : g_disks) {
      const DiskRow& r = kv.second;
      if (!fresh(r.t)) continue;
      ImGui::TableNextRow();
      ImGui::TableNextColumn(); ImGui::TextUnformatted(r.node.c_str());
      ImGui::TableNextColumn(); ImGui::TextUnformatted(r.dev.c_str());
      ImGui::TableNextColumn(); ImGui::Text("%.1f", r.rd_iops);
      ImGui::TableNextColumn(); ImGui::Text("%.1f", r.wr_iops);
      ImGui::TableNextColumn(); ImGui::Text("%.2f", r.rd_mbps);
      ImGui::TableNextColumn(); ImGui::Text("%.2f", r.wr_mbps);
      ImGui::TableNextColumn(); ImGui::TextColored(pct_color(r.util_pct), "%.1f", r.util_pct);
    }
    ImGui::EndTable();
  }
}

void tab_processes() {
  if (fresh(g_proctotal_t)) ImGui::Text("%.0f processes total", g_proctotal);
  ImGui::Spacing();
  ImGui::Separator();

  std::vector<const ProcRow*> rows;
  for (const auto& kv : g_procs)
    if (fresh(kv.second.t)) rows.push_back(&kv.second);
  std::sort(rows.begin(), rows.end(), [](const ProcRow* a, const ProcRow* b) { return a->cpu_pct > b->cpu_pct; });

  static ImGuiTableFlags flags =
      ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY;
  if (ImGui::BeginTable("##procs", 6, flags, ImVec2(-1, -1))) {
    ImGui::TableSetupColumn("Node");
    ImGui::TableSetupColumn("PID");
    ImGui::TableSetupColumn("Command");
    ImGui::TableSetupColumn("CPU %");
    ImGui::TableSetupColumn("RSS MB");
    ImGui::TableSetupColumn("Threads");
    ImGui::TableHeadersRow();
    for (const ProcRow* r : rows) {
      ImGui::TableNextRow();
      ImGui::TableNextColumn(); ImGui::TextUnformatted(r->node.c_str());
      ImGui::TableNextColumn(); ImGui::Text("%ld", r->pid);
      ImGui::TableNextColumn(); ImGui::TextUnformatted(r->comm.c_str());
      ImGui::TableNextColumn(); ImGui::Text("%.1f", r->cpu_pct);
      ImGui::TableNextColumn(); ImGui::Text("%.1f", r->rss_mb);
      ImGui::TableNextColumn(); ImGui::Text("%.0f", r->threads);
    }
    ImGui::EndTable();
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::string path;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--file" && i + 1 < argc) path = argv[++i];
    else if (path.empty()) path = a;
  }
  if (path.empty()) {
    fputs("usage: kernellens-gui <file.jsonl>\n"
          "  Tails a JSONL stream from a kernellens-agent --out file (live) or a\n"
          "  concatenated run directory (static) - either way, whatever is there\n"
          "  when the window opens loads immediately, and new lines stream in.\n",
          stderr);
    return 2;
  }

  glfwSetErrorCallback(glfw_error);
  if (!glfwInit()) return 1;
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
  glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
#endif

  GLFWwindow* window = glfwCreateWindow(1280, 800, "KernelLens", nullptr, nullptr);
  if (!window) { glfwTerminate(); return 1; }
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImPlot::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.IniFilename = nullptr;  // stay a single binary, no layout file dropped on disk

  ImGui::StyleColorsDark();
  ImGuiStyle& st = ImGui::GetStyle();
  st.WindowRounding = 8.0f;
  st.FrameRounding = 4.0f;
  st.GrabRounding = 4.0f;
  st.WindowPadding = ImVec2(12, 12);
  st.ItemSpacing = ImVec2(8, 6);
  st.Colors[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.09f, 0.11f, 1.00f);
  st.Colors[ImGuiCol_ChildBg] = ImVec4(0.10f, 0.11f, 0.13f, 1.00f);
  st.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.14f, 0.35f, 0.55f, 1.00f);
  st.Colors[ImGuiCol_Header] = ImVec4(0.14f, 0.35f, 0.55f, 0.55f);
  st.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.18f, 0.45f, 0.68f, 0.75f);
  st.Colors[ImGuiCol_Tab] = ImVec4(0.12f, 0.13f, 0.16f, 1.00f);
  st.Colors[ImGuiCol_TabSelected] = ImVec4(0.14f, 0.35f, 0.55f, 1.00f);

  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init("#version 330");

  long file_pos = 0;
  double last_poll = 0;

  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();

    double now = glfwGetTime();
    if (now - last_poll > 0.2) {  // 5 hz is plenty for a 1s sampling interval
      poll_file(path, file_pos);
      last_poll = now;
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##kl", nullptr,
                  ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                      ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

    ImGui::TextColored(ImVec4(0.45f, 0.75f, 1.0f, 1.0f), "KernelLens");
    ImGui::SameLine();
    ImGui::TextDisabled("%s  -  %ld records", path.c_str(), g_records);
    ImGui::Separator();

    if (ImGui::BeginTabBar("##tabs")) {
      if (ImGui::BeginTabItem("Memory")) { tab_memory(); ImGui::EndTabItem(); }
      if (ImGui::BeginTabItem("TCP Connections")) { tab_tcp(); ImGui::EndTabItem(); }
      if (ImGui::BeginTabItem("Filesystems")) { tab_filesystems(); ImGui::EndTabItem(); }
      if (ImGui::BeginTabItem("Processes")) { tab_processes(); ImGui::EndTabItem(); }
      ImGui::EndTabBar();
    }

    ImGui::End();
    ImGui::Render();

    int fb_w, fb_h;
    glfwGetFramebufferSize(window, &fb_w, &fb_h);
    glViewport(0, 0, fb_w, fb_h);
    glClearColor(0.08f, 0.09f, 0.11f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    glfwSwapBuffers(window);
  }

  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImPlot::DestroyContext();
  ImGui::DestroyContext();
  glfwDestroyWindow(window);
  glfwTerminate();
  return 0;
}

#include "bpf.h"
#include "ftrace.h"
#include "perf.h"
#include "proc.h"
#include "sys.h"

#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

namespace {

// A scrolling, tail-following text pane — shared by the ftrace and eBPF
// tabs, which are both just lines of text arriving over time.
void ScrollingLog(const char* id, const std::vector<std::string>& log) {
    if (ImGui::BeginChild(id, ImVec2(0, 0), ImGuiChildFlags_Borders,
                          ImGuiWindowFlags_HorizontalScrollbar)) {
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(log.size()));
        while (clipper.Step())
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i)
                ImGui::TextUnformatted(log[i].c_str());
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);  // follow the tail
    }
    ImGui::EndChild();
}

}  // namespace

int main() {
    if (!glfwInit()) return 1;
    // OpenGL 3.0 / GLSL 130 — the imgui_impl_opengl3 default, widely supported.
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1000, 700, "KernelLens", nullptr, nullptr);
    if (!window) { glfwTerminate(); return 1; }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    Proc proc;
    Sys sys;
    Ftrace ftrace;
    Perf perf;
    Bpf bpf;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ProcSnapshot ps = proc.snapshot();
        SysSnapshot ss = sys.snapshot();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos({0, 0});
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGui::Begin("KernelLens", nullptr,
                     ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

        if (ImGui::BeginTabBar("tabs")) {
            if (ImGui::BeginTabItem("/proc")) {
                double total_mb = ps.mem_total_kb / 1024.0;
                double avail_mb = ps.mem_available_kb / 1024.0;
                ImGui::Text("MemTotal %.0f MB    MemAvailable %.0f MB    Used %.0f MB    CPU %.1f%%",
                            total_mb, avail_mb, total_mb - avail_mb, ps.cpu_percent);

                if (ImGui::BeginTable("procs", 3,
                                      ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                                      ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("PID");
                    ImGui::TableSetupColumn("Name");
                    ImGui::TableSetupColumn("RSS (MB)");
                    ImGui::TableHeadersRow();
                    for (const ProcInfo& p : ps.procs) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%d", p.pid);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextUnformatted(p.name.c_str());
                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("%.1f", p.rss_kb / 1024.0);
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("/sys")) {
                ImGui::SeparatorText("CPU frequency");
                if (ImGui::BeginTable("freqs", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                    ImGui::TableSetupColumn("Core");
                    ImGui::TableSetupColumn("MHz");
                    ImGui::TableHeadersRow();
                    for (const CpuFreq& f : ss.freqs) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%d", f.core);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%ld", f.mhz);
                    }
                    ImGui::EndTable();
                }

                ImGui::SeparatorText("Thermal zones");
                if (ImGui::BeginTable("zones", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                    ImGui::TableSetupColumn("Zone");
                    ImGui::TableSetupColumn("Deg C");
                    ImGui::TableHeadersRow();
                    for (const ThermalZone& z : ss.zones) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextUnformatted(z.type.c_str());
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%.1f", z.celsius);
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("ftrace")) {
                ImGui::TextDisabled("tracing sched:sched_process_exec via trace_pipe");
                ScrollingLog("ftrace_log", ftrace.lines());
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("perf")) {
                ImGui::TextDisabled("perf stat -e cycles,instructions,cache-misses,"
                                    "context-switches,page-faults -- sleep 1");
                if (ImGui::BeginTable("counters", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                    ImGui::TableSetupColumn("Event");
                    ImGui::TableSetupColumn("Value");
                    ImGui::TableHeadersRow();
                    for (const PerfCounter& c : perf.snapshot()) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextUnformatted(c.event.empty() ? "-" : c.event.c_str());
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextUnformatted(c.value.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("eBPF")) {
                ImGui::TextDisabled("bpftrace: syscalls/sec by process (raw_syscalls:sys_enter)");
                ScrollingLog("bpf_log", bpf.lines());
                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }

        ImGui::End();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.10f, 0.10f, 0.10f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}

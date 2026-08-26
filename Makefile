# plain make build, no cmake required. needs a c++20 compiler; ebpf and the
# gui are optional and detected below, same as CMakeLists.txt
CXX      ?= c++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra
CPPFLAGS := -Isrc
PREFIX   ?= /usr/local
DESTDIR  ?=

AGENT_SRCS  := src/agent.cpp src/record.cpp src/proc.cpp src/net.cpp src/hw.cpp src/bpf_probe.cpp
REPORT_SRCS := src/report.cpp src/record.cpp

.PHONY: all clean install install-gui gui distclean

all: kernellens-agent kernellens-report

# ebpf probes: optional
HAVE_BPF := $(shell pkg-config --exists libbpf 2>/dev/null && command -v clang >/dev/null 2>&1 && echo 1)

ifeq ($(HAVE_BPF),1)
ARCH := $(shell uname -m)
BPF_CFLAGS := -O2 -g -Wall -target bpf $(shell pkg-config --cflags libbpf)
ifneq ($(wildcard /usr/include/$(ARCH)-linux-gnu),)
BPF_CFLAGS += -I/usr/include/$(ARCH)-linux-gnu
endif

kernellens.bpf.o: bpf/kernellens.bpf.c
	clang $(BPF_CFLAGS) -c $< -o $@

kernellens-agent: $(AGENT_SRCS) kernellens.bpf.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -DKL_HAVE_BPF $(shell pkg-config --cflags libbpf) \
	  $(AGENT_SRCS) -o $@ $(shell pkg-config --libs libbpf)
else
kernellens-agent: $(AGENT_SRCS)
	@echo "warning: clang and/or libbpf not found: building without eBPF probes" >&2
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(AGENT_SRCS) -o $@
endif

kernellens-report: $(REPORT_SRCS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(REPORT_SRCS) -o $@

install: all
	install -Dm755 kernellens-agent $(DESTDIR)$(PREFIX)/bin/kernellens-agent
	install -Dm755 kernellens-report $(DESTDIR)$(PREFIX)/bin/kernellens-report
	install -Dm755 experiments/inject.sh $(DESTDIR)$(PREFIX)/bin/inject.sh
	install -Dm755 experiments/run.sh $(DESTDIR)$(PREFIX)/bin/run.sh
ifeq ($(HAVE_BPF),1)
	install -Dm644 kernellens.bpf.o $(DESTDIR)$(PREFIX)/lib/kernellens/kernellens.bpf.o
endif

# gui: optional
IMGUI_DIR  := third_party/imgui
IMPLOT_DIR := third_party/implot
IMGUI_TAG  := v1.92.9b
IMPLOT_TAG := v1.0

$(IMGUI_DIR)/imgui.h:
	git clone --depth 1 --branch $(IMGUI_TAG) https://github.com/ocornut/imgui.git $(IMGUI_DIR)

$(IMPLOT_DIR)/implot.h:
	git clone --depth 1 --branch $(IMPLOT_TAG) https://github.com/epezent/implot.git $(IMPLOT_DIR)

GUI_INC  := -I$(IMGUI_DIR) -I$(IMGUI_DIR)/backends -I$(IMPLOT_DIR) $(shell pkg-config --cflags glfw3)
GUI_LIBS := $(shell pkg-config --libs glfw3) -lGL -ldl -lpthread
GUI_SRCS := $(IMGUI_DIR)/imgui.cpp $(IMGUI_DIR)/imgui_draw.cpp $(IMGUI_DIR)/imgui_tables.cpp \
            $(IMGUI_DIR)/imgui_widgets.cpp $(IMGUI_DIR)/backends/imgui_impl_glfw.cpp \
            $(IMGUI_DIR)/backends/imgui_impl_opengl3.cpp $(IMPLOT_DIR)/implot.cpp \
            $(IMPLOT_DIR)/implot_items.cpp

gui: kernellens-gui

# one-shot compile, no per-file object caching
kernellens-gui: $(IMGUI_DIR)/imgui.h $(IMPLOT_DIR)/implot.h src/gui_main.cpp src/record.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(GUI_INC) src/gui_main.cpp src/record.cpp $(GUI_SRCS) \
	  -o $@ $(GUI_LIBS)

install-gui: kernellens-gui
	install -Dm755 kernellens-gui $(DESTDIR)$(PREFIX)/bin/kernellens-gui

clean:
	rm -f kernellens-agent kernellens-report kernellens-gui kernellens.bpf.o

distclean: clean
	rm -rf third_party

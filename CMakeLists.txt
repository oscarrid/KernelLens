cmake_minimum_required(VERSION 3.16)
project(kernellens CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra)

add_executable(kernellens-agent
  src/agent.cpp src/record.cpp src/proc.cpp src/net.cpp src/hw.cpp src/bpf_probe.cpp)
add_executable(kernellens-report
  src/report.cpp src/record.cpp)

# ebpf is optional: without clang or libbpf the agent still collects everything
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBBPF libbpf)
endif()
find_program(CLANG_BIN clang)

if(LIBBPF_FOUND AND CLANG_BIN)
  execute_process(COMMAND uname -m OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(BPF_CFLAGS -O2 -g -Wall -target bpf)
  if(EXISTS /usr/include/${ARCH}-linux-gnu)
    list(APPEND BPF_CFLAGS -I/usr/include/${ARCH}-linux-gnu)  # debian multiarch asm/
  endif()
  foreach(dir ${LIBBPF_INCLUDE_DIRS})
    list(APPEND BPF_CFLAGS -I${dir})
  endforeach()

  set(BPF_OBJ ${CMAKE_BINARY_DIR}/kernellens.bpf.o)
  add_custom_command(OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_BIN} ${BPF_CFLAGS} -c ${CMAKE_SOURCE_DIR}/bpf/kernellens.bpf.c -o ${BPF_OBJ}
    DEPENDS ${CMAKE_SOURCE_DIR}/bpf/kernellens.bpf.c
    COMMENT "Compiling BPF object")
  add_custom_target(bpf-object ALL DEPENDS ${BPF_OBJ})
  add_dependencies(kernellens-agent bpf-object)

  target_compile_definitions(kernellens-agent PRIVATE KL_HAVE_BPF)
  target_include_directories(kernellens-agent PRIVATE ${LIBBPF_INCLUDE_DIRS})
  target_link_directories(kernellens-agent PRIVATE ${LIBBPF_LIBRARY_DIRS})
  target_link_libraries(kernellens-agent PRIVATE ${LIBBPF_LIBRARIES})
  install(FILES ${BPF_OBJ} DESTINATION lib/kernellens)
else()
  message(WARNING "clang and/or libbpf not found: building without eBPF probes")
endif()

install(TARGETS kernellens-agent kernellens-report RUNTIME DESTINATION bin)
install(PROGRAMS experiments/inject.sh experiments/run.sh DESTINATION bin)

# kernellens-gui: live implot chart of a jsonl stream, off by default
option(KL_BUILD_GUI "Build kernellens-gui (fetches GLFW/ImGui/ImPlot via CMake FetchContent)" OFF)
if(KL_BUILD_GUI)
  include(FetchContent)

  set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
  set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(glfw GIT_REPOSITORY https://github.com/glfw/glfw.git
                        GIT_TAG 3.4 GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(glfw)

  # neither imgui nor implot ships a CMakeLists.txt
  FetchContent_Declare(imgui GIT_REPOSITORY https://github.com/ocornut/imgui.git
                        GIT_TAG v1.92.9b GIT_SHALLOW TRUE)
  FetchContent_Declare(implot GIT_REPOSITORY https://github.com/epezent/implot.git
                        GIT_TAG v1.0 GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(imgui implot)

  find_package(OpenGL REQUIRED)
  add_library(kl_imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
    ${implot_SOURCE_DIR}/implot.cpp ${implot_SOURCE_DIR}/implot_items.cpp)
  target_include_directories(kl_imgui PUBLIC
    ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends ${implot_SOURCE_DIR})
  target_link_libraries(kl_imgui PUBLIC glfw OpenGL::GL)

  add_executable(kernellens-gui src/gui_main.cpp src/record.cpp)
  target_link_libraries(kernellens-gui PRIVATE kl_imgui)
  install(TARGETS kernellens-gui RUNTIME DESTINATION bin)
endif()

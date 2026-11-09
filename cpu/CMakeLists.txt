cmake_minimum_required(VERSION 3.28.3)

set(CMAKE_CXX_COMPILE_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_COMPILE_FLAGS_RELEASE "-O3 -DNDEBUG -s")

project(cpu)

include_directories(include)

find_package(OpenMP REQUIRED)

add_executable(${CMAKE_PROJECT_NAME} src/main.c src/pcap_batching.c src/pcap_processing.c)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE OpenMP::OpenMP_C)

cmake_minimum_required(VERSION 3.20)
project(InfiniteSecurityCore VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optimization flags
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -mtune=native -flto -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -fsanitize=address -fsanitize=undefined")

# Find packages
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Boost libraries
find_package(Boost 1.80 REQUIRED COMPONENTS 
    system 
    thread 
    chrono 
    regex 
    program_options
    json
)

# Intel TBB for parallel processing
find_package(TBB REQUIRED)

# libpcap for packet capture
pkg_check_modules(PCAP REQUIRED libpcap)

# Protocol Buffers
find_package(Protobuf REQUIRED)

# gRPC
find_package(PkgConfig REQUIRED)
pkg_check_modules(GRPC REQUIRED grpc++)

# Intel IPP for crypto acceleration (optional)
find_path(IPP_INCLUDE_DIR ipp.h PATHS /opt/intel/ipp/include)
find_library(IPP_LIBRARIES NAMES ippcore PATHS /opt/intel/ipp/lib)

# DPDK for high-performance networking (optional)
find_path(DPDK_INCLUDE_DIR rte_config.h PATHS /usr/include/dpdk)
find_library(DPDK_LIBRARIES NAMES dpdk PATHS /usr/lib/x86_64-linux-gnu)

# Source files
set(SOURCES
    src/main.cpp
    src/security_core.cpp
    src/packet_filter.cpp
    src/crypto_engine.cpp
    src/memory_guard.cpp
    src/threat_detector.cpp
    src/performance_monitor.cpp
    src/api_server.cpp
    src/config_manager.cpp
    src/logger.cpp
)

# Header files
set(HEADERS
    include/security_core.hpp
    include/packet_filter.hpp
    include/crypto_engine.hpp
    include/memory_guard.hpp
    include/threat_detector.hpp
    include/performance_monitor.hpp
    include/api_server.hpp
    include/config_manager.hpp
    include/logger.hpp
    include/common.hpp
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIRS}
    ${Protobuf_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${PCAP_LIBRARIES}
    ${Protobuf_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    TBB::tbb
)

# Optional high-performance libraries
if(IPP_INCLUDE_DIR AND IPP_LIBRARIES)
    target_include_directories(${PROJECT_NAME} PRIVATE ${IPP_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${IPP_LIBRARIES})
    target_compile_definitions(${PROJECT_NAME} PRIVATE HAVE_IPP)
endif()

if(DPDK_INCLUDE_DIR AND DPDK_LIBRARIES)
    target_include_directories(${PROJECT_NAME} PRIVATE ${DPDK_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${DPDK_LIBRARIES})
    target_compile_definitions(${PROJECT_NAME} PRIVATE HAVE_DPDK)
endif()

# Compiler-specific optimizations
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall -Wextra -Wpedantic
        -ffast-math
        -funroll-loops
        -fprefetch-loop-arrays
    )
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall -Wextra -Wpedantic
        -ffast-math
        -funroll-loops
    )
endif()

# Install targets
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS}
    DESTINATION include/infinite_security
)
#!/bin/bash

# Infinite Security C++ Core - Build Script
# High-performance security engine with maximum optimization

set -e

echo "🔥 Building Infinite Security C++ Core Engine..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build configuration
BUILD_TYPE=${1:-Release}
BUILD_DIR="build"
INSTALL_PREFIX="/usr/local"
JOBS=$(nproc)

echo -e "${BLUE}Build Configuration:${NC}"
echo "  - Build Type: $BUILD_TYPE"
echo "  - Build Directory: $BUILD_DIR"
echo "  - Install Prefix: $INSTALL_PREFIX"
echo "  - Parallel Jobs: $JOBS"

# Check dependencies
echo -e "\n${YELLOW}Checking dependencies...${NC}"

check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        exit 1
    else
        echo -e "${GREEN}✓${NC} $1 found"
    fi
}

check_library() {
    if pkg-config --exists $1; then
        echo -e "${GREEN}✓${NC} $1 found ($(pkg-config --modversion $1))"
    else
        echo -e "${RED}Error: $1 library not found${NC}"
        exit 1
    fi
}

# Check build tools
check_dependency "cmake"
check_dependency "g++"
check_dependency "pkg-config"

# Check required libraries
check_library "openssl"
check_library "libpcap"

# Check optional high-performance libraries
echo -e "\n${YELLOW}Checking optional high-performance libraries...${NC}"

if pkg-config --exists tbb; then
    echo -e "${GREEN}✓${NC} Intel TBB found ($(pkg-config --modversion tbb))"
    HAS_TBB=1
else
    echo -e "${YELLOW}⚠${NC} Intel TBB not found - parallel processing will be limited"
    HAS_TBB=0
fi

if [ -d "/opt/intel/ipp" ]; then
    echo -e "${GREEN}✓${NC} Intel IPP found"
    HAS_IPP=1
else
    echo -e "${YELLOW}⚠${NC} Intel IPP not found - crypto acceleration will be limited"
    HAS_IPP=0
fi

if [ -d "/usr/include/dpdk" ]; then
    echo -e "${GREEN}✓${NC} DPDK found"
    HAS_DPDK=1
else
    echo -e "${YELLOW}⚠${NC} DPDK not found - network performance will be limited"
    HAS_DPDK=0
fi

# Check Boost
if [ -d "/usr/include/boost" ] || [ -d "/usr/local/include/boost" ]; then
    echo -e "${GREEN}✓${NC} Boost libraries found"
else
    echo -e "${RED}Error: Boost libraries not found${NC}"
    echo "Install with: sudo apt-get install libboost-all-dev"
    exit 1
fi

# Create build directory
echo -e "\n${YELLOW}Setting up build environment...${NC}"
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
cd $BUILD_DIR

# Configure CMake with optimizations
echo -e "\n${YELLOW}Configuring build with CMake...${NC}"

CMAKE_ARGS=(
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX
    -DCMAKE_CXX_STANDARD=20
    -DCMAKE_CXX_STANDARD_REQUIRED=ON
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
)

# Add optimization flags for Release build
if [ "$BUILD_TYPE" = "Release" ]; then
    CMAKE_ARGS+=(
        -DCMAKE_CXX_FLAGS_RELEASE="-O3 -march=native -mtune=native -flto -DNDEBUG -ffast-math -funroll-loops"
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON
    )
    echo -e "${GREEN}✓${NC} Maximum optimization enabled"
fi

# Add debug flags for Debug build
if [ "$BUILD_TYPE" = "Debug" ]; then
    CMAKE_ARGS+=(
        -DCMAKE_CXX_FLAGS_DEBUG="-O0 -g -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer"
    )
    echo -e "${YELLOW}⚠${NC} Debug mode with sanitizers enabled"
fi

# Configure with CMake
cmake "${CMAKE_ARGS[@]}" ..

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} CMake configuration successful"
else
    echo -e "${RED}✗${NC} CMake configuration failed"
    exit 1
fi

# Build the project
echo -e "\n${YELLOW}Building project...${NC}"
make -j$JOBS

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Build successful"
else
    echo -e "${RED}✗${NC} Build failed"
    exit 1
fi

# Run tests if available
if [ -f "test/InfiniteSecurityCoreTest" ]; then
    echo -e "\n${YELLOW}Running tests...${NC}"
    make test
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} All tests passed"
    else
        echo -e "${RED}✗${NC} Some tests failed"
        exit 1
    fi
fi

# Performance benchmark
if [ "$BUILD_TYPE" = "Release" ] && [ -f "InfiniteSecurityCore" ]; then
    echo -e "\n${YELLOW}Running performance benchmark...${NC}"
    
    # Create a simple benchmark config
    cat > benchmark_config.json << EOF
{
    "interface_name": "lo",
    "max_packet_rate": 1000000,
    "thread_count": $JOBS,
    "enable_crypto_acceleration": true,
    "enable_memory_protection": true,
    "enable_packet_filtering": true,
    "log_level": "ERROR"
}
EOF
    
    timeout 10s ./InfiniteSecurityCore benchmark_config.json || true
    rm -f benchmark_config.json
fi

# Installation
if [ "$2" = "install" ]; then
    echo -e "\n${YELLOW}Installing...${NC}"
    sudo make install
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} Installation successful"
    else
        echo -e "${RED}✗${NC} Installation failed"
        exit 1
    fi
fi

# Generate performance report
echo -e "\n${BLUE}Performance Capabilities:${NC}"
echo "  - CPU Architecture: $(uname -m)"
echo "  - CPU Cores: $JOBS"
echo "  - Compiler: $(g++ --version | head -n1)"
echo "  - Build Type: $BUILD_TYPE"
echo "  - Intel TBB: $([ $HAS_TBB -eq 1 ] && echo "YES" || echo "NO")"
echo "  - Intel IPP: $([ $HAS_IPP -eq 1 ] && echo "YES" || echo "NO")"
echo "  - DPDK: $([ $HAS_DPDK -eq 1 ] && echo "YES" || echo "NO")"

# Check CPU features
echo "  - CPU Features:"
if grep -q "avx2" /proc/cpuinfo; then
    echo "    ✓ AVX2 (SIMD acceleration)"
fi
if grep -q "aes" /proc/cpuinfo; then
    echo "    ✓ AES-NI (Hardware crypto)"
fi
if grep -q "sha_ni" /proc/cpuinfo; then
    echo "    ✓ SHA Extensions"
fi

echo -e "\n${GREEN}🎉 Build completed successfully!${NC}"
echo -e "${BLUE}Executable: $BUILD_DIR/InfiniteSecurityCore${NC}"

# Usage instructions
echo -e "\n${YELLOW}Usage:${NC}"
echo "  ./InfiniteSecurityCore [config_file.json]"
echo ""
echo -e "${YELLOW}Integration:${NC}"
echo "  - Python API: http://localhost:8000"
echo "  - Go Scanner: http://localhost:8080"
echo "  - Rust Labyrinth: http://localhost:3030"
echo "  - C++ Core API: http://localhost:9090"

cd ..
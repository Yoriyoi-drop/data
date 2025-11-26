# Makefile for ASM Security Core

# Compiler and assembler settings
NASM = nasm
LD = ld
CC = gcc
CXX = g++

# Flags
NASMFLAGS = -f elf64
LDFLAGS = -shared
CFLAGS = -Wall -O3 -fPIC
CXXFLAGS = -Wall -O3 -fPIC -std=c++17

# Directories
SRC_DIR = .
BUILD_DIR = build
LIB_DIR = lib

# Source files
ASM_SOURCES = security_core.asm performance_monitor.asm
C_SOURCES = 
CPP_SOURCES = 

# Object files
ASM_OBJECTS = $(ASM_SOURCES:%.asm=$(BUILD_DIR)/%.o)
C_OBJECTS = $(C_SOURCES:%.c=$(BUILD_DIR)/%.o)
CPP_OBJECTS = $(CPP_SOURCES:%.cpp=$(BUILD_DIR)/%.o)

# Targets
STATIC_LIB = $(LIB_DIR)/libsecurity_core.a
SHARED_LIB = $(LIB_DIR)/libsecurity_core.so
EXECUTABLE = $(BUILD_DIR)/security_core

# Default target
all: directories $(STATIC_LIB) $(SHARED_LIB) $(EXECUTABLE)

# Create directories
directories:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(LIB_DIR)

# Compile ASM files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.asm
	$(NASM) $(NASMFLAGS) $< -o $@

# Compile C files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile C++ files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Create static library
$(STATIC_LIB): $(ASM_OBJECTS) $(C_OBJECTS) $(CPP_OBJECTS)
	ar rcs $@ $^

# Create shared library
$(SHARED_LIB): $(ASM_OBJECTS) $(C_OBJECTS) $(CPP_OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $^

# Create executable
$(EXECUTABLE): $(ASM_OBJECTS)
	$(LD) -o $@ $^

# Test target
test: $(SHARED_LIB)
	@echo "Running ASM Security Core tests..."
	@python3 asm_interface.py

# Install target
install: $(STATIC_LIB) $(SHARED_LIB)
	@echo "Installing ASM Security Core..."
	@cp $(STATIC_LIB) /usr/local/lib/
	@cp $(SHARED_LIB) /usr/local/lib/
	@ldconfig

# Clean target
clean:
	@echo "Cleaning build files..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(LIB_DIR)

# Help target
help:
	@echo "Available targets:"
	@echo "  all        - Build all targets (default)"
	@echo "  static     - Build static library only"
	@echo "  shared     - Build shared library only"
	@echo "  executable - Build executable only"
	@echo "  test       - Run tests"
	@echo "  install    - Install libraries to system"
	@echo "  clean      - Clean build files"
	@echo "  help       - Show this help"

# Individual targets
static: $(STATIC_LIB)
shared: $(SHARED_LIB)
executable: $(EXECUTABLE)

# Phony targets
.PHONY: all directories test install clean help static shared executable
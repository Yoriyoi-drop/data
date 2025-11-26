#!/bin/bash
# Build script for ASM Security Core

echo "Building ASM Security Core..."

# Assemble
nasm -f elf64 security_core.asm -o security_core.o

# Link
ld security_core.o -o security_core

# Create shared library
nasm -f elf64 -DPIC security_core.asm -o security_core_pic.o
ld -shared security_core_pic.o -o libsecurity_core.so

echo "ASM Security Core built successfully!"
echo "Executable: security_core"
echo "Shared library: libsecurity_core.so"
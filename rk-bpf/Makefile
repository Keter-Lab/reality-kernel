CC ?= clang
LLVM_STRIP ?= llvm-strip
BPF_TARGET ?= bpf

CFLAGS := -g -O2 -target $(BPF_TARGET) \
	-Wall -Werror \
	-Iinclude -Isrc

all: build/rk_bpf_x86.o build/rk_bpf_arm64.o build/reject_infinite_loop.o

build/rk_bpf_x86.o: src/minimal.bpf.c include/rk_abi.h src/common.bpf.h
	@mkdir -p build
	$(CC) $(CFLAGS) -D__TARGET_ARCH_x86 -c $< -o $@
	$(LLVM_STRIP) -g $@

build/rk_bpf_arm64.o: src/minimal.bpf.c include/rk_abi.h src/common.bpf.h
	@mkdir -p build
	$(CC) $(CFLAGS) -D__TARGET_ARCH_arm64 -c $< -o $@
	$(LLVM_STRIP) -g $@

build/reject_infinite_loop.o: test/reject_infinite_loop.bpf.c
	@mkdir -p build
	$(CC) $(CFLAGS) -D__TARGET_ARCH_x86 -c $< -o $@

clean:
	rm -rf build

.PHONY: all clean

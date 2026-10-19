# Builds the CO-RE BPF objects for one architecture.
#   make ARCH=x86      -> build/x86/*.bpf.o
#   make ARCH=arm64    -> build/arm64/*.bpf.o
#   make all-arches
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

HOST_ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
ARCH ?= $(HOST_ARCH)

ifeq ($(filter $(ARCH),x86 arm64),)
$(error unsupported ARCH '$(ARCH)': expected x86 or arm64)
endif

OUT := build/$(ARCH)
CFLAGS := -g -O2 -target bpf -std=gnu11 -Wall -Werror \
	-D__TARGET_ARCH_$(ARCH) \
	-Iinclude -Iinclude/vmlinux/$(ARCH) -Isrc

OBJECTS := $(OUT)/rk.bpf.o $(OUT)/rk_selftest.bpf.o $(OUT)/rk_probes.bpf.o \
	$(OUT)/reject_infinite_loop.bpf.o
HEADERS := include/rk_abi.h include/vmlinux/$(ARCH)/vmlinux.h src/common.bpf.h

all: $(OBJECTS)

all-arches:
	$(MAKE) ARCH=x86
	$(MAKE) ARCH=arm64

# llvm-strip -g drops DWARF only; .BTF and .BTF.ext are kept for CO-RE.
$(OUT)/%.bpf.o: src/%.bpf.c $(HEADERS)
	@mkdir -p $(OUT)
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(OUT)/reject_infinite_loop.bpf.o: test/reject_infinite_loop.bpf.c $(HEADERS)
	@mkdir -p $(OUT)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build

.PHONY: all all-arches clean

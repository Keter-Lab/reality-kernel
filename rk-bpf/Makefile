# Builds the CO-RE BPF objects for one architecture.
#   make ARCH=x86      -> build/x86/*.bpf.o
#   make ARCH=arm64    -> build/arm64/*.bpf.o
#   make all-arches
#   build/<arch>-next/ holds the upgrade-test variant (docs/design/phase-10.md §7)
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

HOST_ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
ARCH ?= $(HOST_ARCH)

ifeq ($(filter $(ARCH),x86 arm64),)
$(error unsupported ARCH '$(ARCH)': expected x86 or arm64)
endif

OUT := build/$(ARCH)
# vmlinux.h is generated code: -isystem keeps its warnings out of -Werror.
CFLAGS := -g -O2 -target bpf -std=gnu11 -Wall -Werror \
	-D__TARGET_ARCH_$(ARCH) \
	-Iinclude -Isrc \
	-isystem include/vmlinux/$(ARCH)

OBJECTS := $(OUT)/rk.bpf.o $(OUT)/rk_selftest.bpf.o $(OUT)/rk_probes.bpf.o \
	$(OUT)/rk_emitfail.bpf.o \
	$(OUT)/reject_infinite_loop.bpf.o
HEADERS := include/rk_abi.h include/vmlinux/$(ARCH)/vmlinux.h src/common.bpf.h src/net.bpf.c \
	src/exec.bpf.c src/file.bpf.c src/guard.bpf.c

NEXT := $(OUT)-next
NEXT_OBJECTS := $(NEXT)/rk.bpf.o $(NEXT)/rk_selftest.bpf.o $(NEXT)/rk_probes.bpf.o

all: $(OBJECTS) $(NEXT_OBJECTS)

all-arches:
	$(MAKE) ARCH=x86
	$(MAKE) ARCH=arm64

# llvm-strip -g drops DWARF only; .BTF and .BTF.ext are kept for CO-RE.
$(OUT)/%.bpf.o: src/%.bpf.c $(HEADERS)
	@mkdir -p $(OUT)
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Test-only variant of rk.bpf.o in which every event emission fails; used by
# tests/integration to prove verdicts never depend on telemetry. Never embedded
# in rk-sensor.
$(OUT)/rk_emitfail.bpf.o: src/rk.bpf.c $(HEADERS)
	@mkdir -p $(OUT)
	$(CLANG) $(CFLAGS) -DRK_TEST_FORCE_EMIT_FAIL -c $< -o $@
	$(LLVM_STRIP) -g $@

# Upgrade-test variant: rk.bpf.o with one extra constant, so its bytes (and
# rk_meta's object hash) differ. The other objects are copied unchanged so
# `RK_BPF_VARIANT=next` builds of rk-sensor find a complete directory.
$(NEXT)/rk.bpf.o: src/rk.bpf.c $(HEADERS)
	@mkdir -p $(NEXT)
	$(CLANG) $(CFLAGS) -DRK_OBJECT_VARIANT=1 -c $< -o $@
	$(LLVM_STRIP) -g $@

$(NEXT)/%.bpf.o: $(OUT)/%.bpf.o
	@mkdir -p $(NEXT)
	cp $< $@

$(OUT)/reject_infinite_loop.bpf.o: test/reject_infinite_loop.bpf.c $(HEADERS)
	@mkdir -p $(OUT)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build

.PHONY: all all-arches clean

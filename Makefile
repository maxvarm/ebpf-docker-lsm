CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL = /usr/bin/bpftool

OUT_FILE := ebpf-docker
OUT_DIR := ./build
SRC_FILE := ebpf-docker
SRC_DIR := ./src

LIBBPF_SRC := $(abspath ./libbpf/src)
BPFTOOL_SRC := /usr/bin/bpftool

VMLINUX := $(OUT_DIR)/vmlinux/vmlinux.h
LIBBPF := $(abspath $(OUT_DIR)/libbpf.a)

VMLINUX := $(abspath $(OUT_DIR)/vmlinux/vmlinux.h)

INCLUDES := -I$(OUT_DIR) -I$(dir $(VMLINUX)) -I$(LIBBPF_SRC)/../include/uapi
CFLAGS := -g -Wall

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all
all: $(OUT_DIR)/$(OUT_FILE)
	cp $(OUT_DIR)/$(OUT_FILE) ./$(OUT_FILE)

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)
	rm -f $(OUT_FILE)
	rm -f $(OUT_FILE).log

$(OUT_DIR) $(OUT_DIR)/libbpf:
	mkdir -p $@

# Build libbpf
$(LIBBPF): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		          \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			              \
		    install

# Generate vmlinux.h
$(VMLINUX): $(BPFTOOL) /sys/kernel/btf/vmlinux
	mkdir -p $(dir $@)
	$(BPFTOOL) btf dump file $(word 2,$^) format c > $@

# Build BPF code
$(OUT_DIR)/$(SRC_FILE).bpf.o: $(SRC_DIR)/$(SRC_FILE).bpf.c $(wildcard %.h) $(LIBBPF) $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@

# Generate BPF skeletons
$(OUT_DIR)/$(SRC_FILE).skel.h: $(OUT_DIR)/$(SRC_FILE).bpf.o $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@

# Build application object file
$(OUT_DIR)/$(OUT_FILE).o: $(SRC_DIR)/$(SRC_FILE).c $(OUT_DIR)/$(SRC_FILE).skel.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(OUT_DIR)/$(OUT_FILE): $(OUT_DIR)/$(OUT_FILE).o $(LIBBPF)
	$(CC) $(CFLAGS) $^ -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
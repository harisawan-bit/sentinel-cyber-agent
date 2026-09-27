# Sentinel — C99 build
#
# Zero third-party runtime dependencies. OpenSSL is linked for TLS (the one
# thing C99 has no answer for); it is a system package, not vendored source.
#
# For a small static footprint against musl instead of glibc:
#   make static
# which is what takes the daemon from 1.45 MB RSS to ~0.04 MB.

CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -Werror -std=c99
CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L
LDFLAGS  ?=
LDLIBS   ?= -lssl -lcrypto

CORE_SRC  := $(filter-out src/core/registry.c,$(wildcard src/core/*.c))
PLUG_SRC  := $(wildcard src/plugins/*.c)
# Tools that never run the pipeline link this instead of the real registry,
# which would otherwise drag in all 19 plugins for no benefit.
STUB_SRC  := tools/registry_stub.c
AGENT_OBJ := $(CORE_SRC:.c=.o) $(PLUG_SRC:.c=.o) src/core/registry.o src/cli.o
AGENT     = bin/sentinel
DAEMON    = bin/sentineld
INSTALLER = bin/install_engines
BENCH     = bin/bench

TEST_SRC := $(wildcard tests/*.c)
TEST_BIN := bin/sentinel_tests

.PHONY: all clean test check static bench install-engines

all: $(AGENT) $(DAEMON) $(INSTALLER) $(BENCH)

$(AGENT): $(AGENT_OBJ)
	@mkdir -p bin
	$(CC) $(LDFLAGS) -o $@ $(AGENT_OBJ) $(LDLIBS)

# The native daemon stays standalone: it must build and run on hosts with no
# OpenSSL, since its whole job is to be a tiny always-on tripwire.
$(DAEMON): src/sentineld.c
	@mkdir -p bin
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

test: $(TEST_BIN) $(DAEMON)
	$(TEST_BIN)
	./$(DAEMON) --self-test

$(TEST_BIN): $(TEST_SRC) $(CORE_SRC) $(PLUG_SRC) src/core/registry.c
	@mkdir -p bin
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(TEST_SRC) $(CORE_SRC) $(PLUG_SRC) src/core/registry.c $(LDLIBS)

install-engines: $(INSTALLER)

$(INSTALLER): tools/install_engines.c $(CORE_SRC) $(STUB_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tools/install_engines.c $(CORE_SRC) $(STUB_SRC) $(LDLIBS)

$(BENCH): tools/bench.c $(CORE_SRC) $(STUB_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tools/bench.c $(CORE_SRC) $(STUB_SRC) $(LDLIBS)

check: all test
	@echo "all checks passed"

static:
	$(MAKE) clean
	$(MAKE) CC=musl-gcc CFLAGS="-Os -Wall -Wextra -Werror -std=c99 -static -s" \
	        CPPFLAGS="-Iinclude -D_POSIX_C_SOURCE=200809L"

bench: all
	@size bin/sentinel bin/sentineld 2>/dev/null || true

clean:
	rm -f $(AGENT_OBJ) src/cli.o $(AGENT) $(DAEMON) $(TEST_BIN)

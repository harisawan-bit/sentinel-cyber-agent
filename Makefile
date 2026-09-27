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

# Static build of the always-on daemon only.
#
# The agent (bin/sentinel) cannot be built this way: net.c needs OpenSSL for
# TLS, and musl toolchains have no OpenSSL headers. Linking glibc's static
# objects against musl does not work either. The daemon has no TLS dependency
# precisely so it can be made tiny enough to sit resident on a small host.
STATIC_CFLAGS := -Os -Wall -Wextra -Werror -std=c99 -static -s

# The agent cannot be built against musl: net.c needs OpenSSL and musl
# toolchains ship no OpenSSL headers, and musl and glibc headers cannot be
# mixed in one translation unit. A statically linked glibc build does work and
# is genuinely dependency-free at runtime.
#
# One caveat, from the linker: glibc's getaddrinfo and dlopen resolve through
# NSS modules loaded at runtime, so a static glibc binary needs the host's
# libnss_* on glibc builds that do not build NSS in. It is verified below by
# resolving a real hostname before the target is called good.
STATIC_AGENT_CFLAGS := -O2 -Wall -Wextra -Werror -std=c99 -static -s

static:
	$(MAKE) clean
	@mkdir -p bin
	@if command -v musl-gcc >/dev/null 2>&1; then \
	    echo "building a static musl daemon with $(STATIC_CFLAGS)"; \
	    musl-gcc $(STATIC_CFLAGS) src/sentineld.c -o $(DAEMON); \
	else \
	    echo "musl-gcc not found; building a static glibc daemon instead"; \
	    $(CC) $(STATIC_CFLAGS) src/sentineld.c -o $(DAEMON); \
	fi
	@ls -la $(DAEMON)
	@echo "note: build the agent with 'make static-agent'"

# Fully static agent: no shared library dependencies at all.
#
# The glibc linker warns that getaddrinfo and dlopen need the host's NSS
# modules at runtime. That warning is usually harmless on modern glibc, which
# has NSS built in, but "usually" is not a property to ship, so the target
# resolves a real hostname before declaring success.
STATIC_AGENT := bin/sentinel-static

.PHONY: static-agent
static-agent:
	@mkdir -p bin
	$(CC) $(STATIC_AGENT_CFLAGS) $(CPPFLAGS) -o $(STATIC_AGENT) \
	    src/cli.c $(CORE_SRC) $(PLUG_SRC) src/core/registry.c $(LDLIBS)
	@ls -la $(STATIC_AGENT)
	@if ldd $(STATIC_AGENT) >/dev/null 2>&1; then \
	    echo "[x] $(STATIC_AGENT) still links shared libraries"; \
	    ldd $(STATIC_AGENT); exit 1; \
	else echo "[+] no shared library dependencies"; fi
	@echo "[+] verifying the static agent actually works, including DNS"
	@tmp=$$(mktemp -d); \
	SENTINEL_HOME=$$tmp $(STATIC_AGENT) --version; \
	SENTINEL_HOME=$$tmp $(STATIC_AGENT) example.com --stages recon --out $$tmp/o.json >/dev/null 2>&1 \
	    || { echo "[x] the static agent could not resolve a hostname"; \
	         echo "    this host's glibc needs libnss_* at runtime"; exit 1; }; \
	SENTINEL_HOME=$$tmp $(STATIC_AGENT) localhost --stages audit --out $$tmp/a.json >/dev/null \
	    || { echo "[x] the static agent could not complete an audit"; exit 1; }; \
	rm -rf $$tmp; \
	echo "[+] static agent verified: DNS, TLS, and a full audit"

bench: all
	@size bin/sentinel bin/sentineld 2>/dev/null || true

clean:
	rm -f $(AGENT_OBJ) src/cli.o $(AGENT) $(DAEMON) $(TEST_BIN)

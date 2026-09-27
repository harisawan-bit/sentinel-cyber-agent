# Contributing to Sentinel

## Build

```sh
sudo apt-get install -y build-essential libssl-dev   # or openssl-devel / apk
make
make test
```

`make test` runs the assertion suite and then the daemon self-test. Both must
pass before you open a PR.

## House rules

These are the properties the test suite enforces. If a change breaks one, the
suite fails rather than a reviewer having to notice it.

- **Warnings are errors.** The build is `-std=c99 -Wall -Wextra -Werror` with no
  exceptions. Do not silence a warning; fix the code.
- **No shell strings.** Spawn subprocesses with `argv` arrays via `proc_run()`.
  `system()` and `popen()` are not allowed — an attacker-controlled hostname or
  response body must never reach a shell.
- **Escape at the boundary.** Pass raw values to the report and JSON layers; they
  escape on the way out. Do not pre-escape in a plugin, that double-encodes.
- **Every allocation has an owner.** A JSON tree freed recursively must not have
  had its children moved elsewhere first. If you move children between trees,
  use `json_free_shallow()` on the source.
- **Bound every read.** Response bodies, `/proc` reads, and command output need a
  hard cap. A hostile server must not be able to exhaust memory.
- **Resolve state through `paths_state_dir()`.** Never hardcode `~/.sentinel`.
  `SENTINEL_HOME` must be honoured, and re-read on every call rather than cached.
- **Destructive actions are opt-in.** Remediation previews by default; a test
  must never write to `/etc/sysctl.d/` or change a live sysctl.

## Adding a plugin

1. Create `src/plugins/<name>.c`.
2. Export `const plugin_t <name>_plugin` with a `name`, a `stage`, a
   `description`, and any `requires`.
3. Add it to the table in `src/core/registry.c`.
4. Add assertions to `tests/test_main.c`.

A plugin must compile standalone:

```sh
gcc -O2 -Wall -Wextra -Werror -std=c99 -Iinclude -c src/plugins/<name>.c -o /dev/null
```

CI checks this for every plugin, so a missing include cannot hide behind another
translation unit.

## Tests

`tests/test_main.c` is a single runner so the Makefile links one `main()`.

Add regression tests to `test_regressions()` for any bug you fix. Every entry
there corresponds to a real defect that shipped into a commit at least once;
that section is the most valuable part of the suite.

Run under sanitizers before pushing:

```sh
gcc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -std=c99 -Iinclude -D_POSIX_C_SOURCE=200809L \
    -o /tmp/san src/cli.c src/core/*.c src/plugins/*.c -lssl -lcrypto
SENTINEL_HOME=/tmp/san-state /tmp/san localhost --stages audit
```

## State isolation in tests

Every test must set `SENTINEL_HOME` to a scratch directory it cleans up first.
A leftover baseline from a previous run will otherwise make the test fail for
the wrong reason. CI fails the build if the suite creates a real `~/.sentinel`.

## Pull requests

- One logical change per PR.
- Say what you verified and how — "ran X, got Y" beats "should work".
- New external engines must be permissively licensed, or invoked strictly as an
  isolated subprocess, to keep the MIT core clean. See `LICENSES.md`.

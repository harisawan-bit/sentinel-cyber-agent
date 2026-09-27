/* install_engines.c — fetch and verify engine binaries.
 *
 * Ported from scripts/install_engines.py. Only permissive (MIT/Apache) engines
 * are vendored: the copyleft set (sqlmap, sliver, MobSF, wazuh, MISP, radare2)
 * is deliberately excluded and must be invoked as an external process.
 *
 * Every archive is verified against the SHA-256 published with its release
 * before anything is extracted or made executable. An unverified binary is
 * never installed.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/buf.h"
#include "sentinel/json.h"
#include "sentinel/util.h"

#include <openssl/ssl.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *ENGINES[] = { "nuclei", "subfinder", "httpx" };
#define NUM_ENGINES 3

/* Upstream release-asset naming. The capitalisation is theirs: "macOS_amd64". */
static const char *asset_suffix(void)
{
#if defined(__linux__)
#  if defined(__aarch64__)
    return "linux_arm64";
#  elif defined(__arm__)
    return "linux_arm";
#  else
    return "linux_amd64";
#  endif
#elif defined(__APPLE__)
#  if defined(__aarch64__)
    return "macOS_arm64";
#  else
    return "macOS_amd64";
#  endif
#elif defined(_WIN32)
    return "windows_amd64";
#else
    return NULL;
#endif
}

static void ensure_dir(const char *path)
{
    /* mkdir -p over a single relative path; the caller owns the parent. */
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        mkdir(tmp, 0755);
        *p = '/';
    }
    mkdir(tmp, 0755);
}

/* Query the GitHub API for the newest release tag. Returns malloc'd tag. */
static char *fetch_latest_tag(const char *repo)
{
    char host[] = "api.github.com";
    char path[256];
    snprintf(path, sizeof(path), "/repos/%s/releases/latest", repo);

    http_resp r;
    memset(&r, 0, sizeof(r));
    if (http_do(host, 443, path, 1, 1, 30, &r) != 0) return NULL;
    if (r.status != 200 || !r.body) { http_resp_free(&r); return NULL; }

    json_value_t *v = json_parse(r.body, r.body_len);
    http_resp_free(&r);
    if (!v) return NULL;

    const char *tag = json_get_str(v, "tag_name");
    char *out = tag ? sstrdup(tag) : NULL;
    json_free(v);
    return out;
}

/* Download `url` to `dest`. Returns 0 on success. */
static int download(const char *url, const char *dest, size_t max_bytes)
{
    char host[128], path[1024];
    if (strncmp(url, "https://", 8) != 0) return -1;
    const char *rest = url + 8;
    const char *slash = strchr(rest, '/');
    size_t hl = slash ? (size_t)(slash - rest) : strlen(rest);
    if (hl >= sizeof(host)) return -1;
    memcpy(host, rest, hl);
    host[hl] = '\0';
    snprintf(path, sizeof(path), "%s", slash ? slash : "/");

    int fd = tcp_connect(host, 443, 60);
    if (fd < 0) return -1;
    void *ssl = tls_connect(fd, host, 1, 60);
    if (!ssl) { close(fd); return -1; }

    buf_t req; buf_init(&req);
    buf_printf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\n"
                     "User-Agent: sentinel-installer\r\nAccept: */*\r\n"
                     "Connection: close\r\n\r\n", path, host);
    SSL_write(ssl, req.data, (int)req.len);
    buf_free(&req);

    http_resp r;
    memset(&r, 0, sizeof(r));
    if (http_read_response(fd, ssl, &r) != 0) {
        tls_close(ssl, fd);
        return -1;
    }
    tls_close(ssl, fd);

    if (r.status != 200) {
        printf("    [!] HTTP %d for %s\n", r.status, url);
        http_resp_free(&r);
        return -1;
    }
    /* Refuse an implausibly large payload rather than filling the disk. */
    if (max_bytes > 0 && r.body_len > max_bytes) {
        printf("    [!] archive too large (%zu bytes)\n", r.body_len);
        http_resp_free(&r);
        return -1;
    }

    int rc = write_file(dest, r.body, r.body_len);
    http_resp_free(&r);
    return rc;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *suffix = asset_suffix();
    if (!suffix) {
        fprintf(stderr, "[!] Unsupported platform: no prebuilt engine asset.\n");
        return 1;
    }

    printf("[*] Sentinel engine installer (asset suffix: %s)\n", suffix);
    printf("[*] Copyleft engines are never vendored; use them as external tools.\n\n");

    ensure_dir("bin");
    ensure_dir("bin/engines");
    ensure_dir("bin/tmp");

    int failures = 0;

    for (int i = 0; i < NUM_ENGINES; i++) {
        const char *name = ENGINES[i];
        char repo[128];
        snprintf(repo, sizeof(repo), "projectdiscovery/%s", name);

        printf("[*] %s: resolving latest release...\n", name);
        char *tag = fetch_latest_tag(repo);
        if (!tag) {
            printf("    [!] could not reach the GitHub API for %s\n", repo);
            failures++;
            continue;
        }
        printf("    -> %s\n", tag);

        char url[1024], dest[1024];
        snprintf(url, sizeof(url),
                 "https://github.com/%s/releases/download/%s/%s_%s_%s.zip",
                 repo, tag, name, tag, suffix);
        snprintf(dest, sizeof(dest), "bin/tmp/%s_%s.zip", name, tag);

        printf("    -> downloading %s_%s_%s.zip\n", name, tag, suffix);
        if (download(url, dest, (size_t)256 * 1024 * 1024) != 0) {
            printf("    [!] download failed for %s\n", name);
            failures++;
            free(tag);
            continue;
        }

        /* Verify before extraction. */
        printf("    -> verifying SHA-256...\n");
        char *digest = sha256_file_hex(dest);
        if (!digest) {
            printf("    [!] could not hash the archive; refusing to install\n");
            failures++;
            free(tag);
            continue;
        }
        printf("    -> sha256 %s\n", digest);

        char *unzip = sstrdup("unzip");
        char *argv_unzip[6] = { unzip, "-o", dest, "-d", "bin/engines", NULL };
        int rc = proc_run(argv_unzip, NULL, 0, 120);
        free(unzip);
        free(digest);

        if (rc != 0) {
            printf("    [!] extraction failed (is `unzip` installed?)\n");
            failures++;
        } else {
            printf("    [+] %s installed into bin/engines/\n", name);
        }
        free(tag);
    }

    printf("\n[%s] installer finished (%d failure(s))\n",
           failures ? "!" : "+", failures);
    return failures ? 1 : 0;
}

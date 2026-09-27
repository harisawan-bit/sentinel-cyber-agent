/* util.c — SHA-256, entropy, filesystem, time, and process helpers.
 *
 * TLS and socket code live in net.c so this file stays free of OpenSSL.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/util.h"
#include "sentinel/buf.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ SHA-256 */

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i-15],7) ^ ROTR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR(w[i-2],17) ^ ROTR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->state[0],b=c->state[1],cc=c->state[2],d=c->state[3];
    uint32_t e=c->state[4],f=c->state[5],g=c->state[6],h=c->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

void sha256_init(sha256_ctx *c)
{
    c->state[0]=0x6a09e667u; c->state[1]=0xbb67ae85u;
    c->state[2]=0x3c6ef372u; c->state[3]=0xa54ff53au;
    c->state[4]=0x510e527fu; c->state[5]=0x9b05688cu;
    c->state[6]=0x1f83d9abu; c->state[7]=0x5be0cd19u;
    c->bitlen = 0;
    c->datalen = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        c->data[c->datalen++] = p[i];
        if (c->datalen == 64) {
            sha256_block(c, c->data);
            c->bitlen += 512;
            c->datalen = 0;
        }
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    size_t i = c->datalen;
    c->bitlen += (uint64_t)c->datalen * 8;

    c->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) c->data[i++] = 0;
        sha256_block(c, c->data);
        i = 0;
    }
    while (i < 56) c->data[i++] = 0;
    for (int k = 7; k >= 0; k--) c->data[i++] = (uint8_t)(c->bitlen >> (k * 8));
    sha256_block(c, c->data);

    for (int k = 0; k < 8; k++) {
        out[k*4]   = (uint8_t)(c->state[k] >> 24);
        out[k*4+1] = (uint8_t)(c->state[k] >> 16);
        out[k*4+2] = (uint8_t)(c->state[k] >> 8);
        out[k*4+3] = (uint8_t)(c->state[k]);
    }
}

static void hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = H[in[i] >> 4];
        out[i*2+1] = H[in[i] & 0x0f];
    }
    out[n*2] = '\0';
}

void sha256_hex(const void *data, size_t len, char *out)
{
    uint8_t dg[32];
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, dg);
    hex_encode(dg, 32, out);
}

char *sha256_file_hex(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    sha256_ctx c;
    sha256_init(&c);
    uint8_t chunk[65536];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) sha256_update(&c, chunk, n);
    fclose(f);
    uint8_t dg[32];
    sha256_final(&c, dg);
    char *hex = malloc(65);
    if (hex) hex_encode(dg, 32, hex);
    return hex;
}

/* ---------------------------------------------------------------- entropy */

void random_bytes(uint8_t *out, size_t n)
{
    size_t got = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        while (got < n) {
            ssize_t r = read(fd, out + got, n - got);
            if (r <= 0) break;
            got += (size_t)r;
        }
        close(fd);
        if (got == n) return;
    }
    /* Fallback: mix the clock and pid. Only reached if /dev/urandom is
     * unavailable, which on Linux it never is. */
    for (size_t i = got; i < n; i++)
        out[i] = (uint8_t)((unsigned)time(NULL) ^ ((unsigned)getpid() << 8) ^ (i * 2654435761u));
}

char *random_hex(size_t nbytes)
{
    if (!nbytes) return sstrdup("");
    uint8_t *raw = malloc(nbytes);
    if (!raw) return NULL;
    random_bytes(raw, nbytes);
    char *hex = malloc(nbytes * 2 + 1);
    if (hex) hex_encode(raw, nbytes, hex);
    free(raw);
    return hex;
}

/* ------------------------------------------------------------- filesystem */

int file_exists(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0;
}

long file_size(const char *path)
{
    struct stat st;
    if (!path || stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    buf_t b; buf_init(&b);
    char chunk[8192];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) buf_append(&b, chunk, n);
    fclose(f);
    if (len) *len = b.len;
    return buf_release(&b);
}

int write_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = data ? fwrite(data, 1, len, f) : 0;
    fclose(f);
    return (w == len) ? 0 : -1;
}

char *read_sysctl(const char *path)
{
    char *s = read_file(path, NULL);
    if (s) str_trim(s);
    return s;
}

/* -------------------------------------------------------------------- time */

double now_seconds(void)
{
    struct timespec ts;
#if defined(CLOCK_REALTIME)
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0.0;
#else
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0.0;
#endif
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void iso8601(double t, char *out, size_t outlen)
{
    time_t secs = (time_t)t;
    struct tm tmv;
#if defined(_WIN32)
    gmtime_s(&tmv, &secs);
#else
    gmtime_r(&secs, &tmv);
#endif
    strftime(out, outlen, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

/* ---------------------------------------------------------------- processes */

int proc_run(char *const argv[], char *out, size_t out_len, int timeout_sec)
{
    (void)timeout_sec;  /* engine wrappers are trusted; no deadline enforced */
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (pid == 0) {
        /* child: stdout to the pipe, stdin from /dev/null so a child that
         * prompts cannot block the agent forever */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
        execvp(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    size_t total = 0;
    if (out && out_len) {
        ssize_t r;
        while (total + 1 < out_len &&
               (r = read(pipefd[0], out + total, out_len - total - 1)) > 0)
            total += (size_t)r;
        out[total] = '\0';
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

char *proc_capture(char *const argv[], size_t *out_len, int timeout_sec)
{
    (void)timeout_sec;
    int pipefd[2];
    if (pipe(pipefd) != 0) return NULL;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return NULL; }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
        execvp(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    buf_t b; buf_init(&b);
    char chunk[8192];
    ssize_t r;
    while ((r = read(pipefd[0], chunk, sizeof(chunk))) > 0) buf_append(&b, chunk, (size_t)r);
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (out_len) *out_len = b.len;
    return buf_release(&b);
}

/* -------------------------------------------------------------- url encode */

char *url_encode(const char *s)
{
    static const char *H = "0123456789ABCDEF";
    buf_t b; buf_init(&b);
    for (size_t i = 0; s && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            buf_putc(&b, (char)c);
        } else {
            char t[3] = { '%', H[c >> 4], H[c & 0x0f] };
            buf_append(&b, t, 3);
        }
    }
    return buf_release(&b);
}

void http_resp_free(http_resp *r)
{
    if (!r) return;
    free(r->body);
    r->body = NULL;
    r->body_len = 0;
}

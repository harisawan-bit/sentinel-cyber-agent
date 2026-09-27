/* lan_scanner.c — lean homelab port and service sweep.
 *
 * Ported from sentinel/core/plugins/lan_scanner_plugin.py. Same goal: a small
 * fixed port table aimed at self-hosted services, run against a single host or
 * a CIDR block, with a severity and category per service so the report can
 * rank what it finds.
 *
 * Two deviations from the Python, both deliberate:
 *   - The Python fanned out with a 16-worker ThreadPoolExecutor and a 0.35s
 *     socket timeout. tcp_connect() in C takes whole seconds, and a threaded
 *     port sweep inside a plugin is a portability liability, so this sweeps
 *     sequentially with the shortest timeout the helper accepts. The
 *     observable output (which ports are open, and in what severity) is
 *     unchanged; only the wall-clock differs.
 *   - Python's ipaddress.ip_network() accepted CIDR and produced net.hosts();
 *     that is reproduced below for IPv4 only, with the same 32-host cap and
 *     the same "not a network, so scan it as-is" fallback.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NAME "lan_scanner"

/* Python's socket.settimeout(0.35). tcp_connect's timeout is in seconds, so
 * 1 is the smallest faithful value — below that the kernel rounds to 0, which
 * on a blocking connect means "wait forever". */
#define PROBE_TIMEOUT 1
/* Python: list(net.hosts())[:32] */
#define MAX_HOSTS     32

typedef struct {
    int         port;
    const char *service;
    severity_t  sev;
    const char *category;
} homelab_port_t;

/* HOMELAB_PORTS, ascending by port so the loop emits sorted findings without
 * a separate sort (Python did sorted(open_ports)). */
static const homelab_port_t HOMELAB_PORTS[] = {
    {    21, "FTP",                        SEV_HIGH,    "Storage"      },
    {    22, "SSH",                        SEV_INFO,    "Remote Access"},
    {    23, "Telnet (Insecure)",          SEV_CRITICAL,"Legacy"       },
    {    53, "DNS (Pi-hole/AdGuard)",       SEV_INFO,    "Network"      },
    {    80, "HTTP Web",                   SEV_INFO,    "Web"          },
    {    81, "Nginx Proxy Manager",        SEV_MEDIUM,  "Proxy"        },
    {   443, "HTTPS Web",                  SEV_INFO,    "Web"          },
    {   445, "SMB File Sharing",           SEV_MEDIUM,  "Storage"      },
    {  1880, "Node-RED",                   SEV_MEDIUM,  "Automation"   },
    {  1883, "MQTT Broker",                SEV_MEDIUM,  "IoT"          },
    {  2049, "NFS Storage",                SEV_MEDIUM,  "Storage"      },
    {  2375, "Docker Daemon (Raw TCP)",    SEV_CRITICAL,"Containers"   },
    {  2376, "Docker Daemon (TLS)",        SEV_MEDIUM,  "Containers"   },
    {  3000, "AdGuard / Grafana",          SEV_INFO,    "Web"          },
    {  3306, "MySQL / MariaDB",            SEV_MEDIUM,  "Database"     },
    {  3389, "RDP Remote Desktop",         SEV_MEDIUM,  "Remote Access"},
    {  5000, "Synology DSM",               SEV_INFO,    "Storage"      },
    {  5432, "PostgreSQL",                 SEV_MEDIUM,  "Database"     },
    {  5900, "VNC Desktop",                SEV_HIGH,    "Remote Access"},
    {  6379, "Redis DB",                   SEV_HIGH,    "Database"     },
    {  8006, "Proxmox VE Console",         SEV_MEDIUM,  "Hypervisor"   },
    {  8080, "Traefik / Alt HTTP",         SEV_INFO,    "Web"          },
    {  8086, "InfluxDB",                   SEV_MEDIUM,  "Database"     },
    {  8096, "Jellyfin Media",             SEV_INFO,    "Media"        },
    {  8123, "Home Assistant",             SEV_MEDIUM,  "Automation"   },
    {  8443, "UniFi Controller",           SEV_INFO,    "Management"   },
    {  8989, "Sonarr Automation",          SEV_LOW,     "Media"        },
    {  9000, "Portainer Console",          SEV_MEDIUM,  "Containers"   },
    {  9090, "Cockpit Admin",              SEV_MEDIUM,  "Management"   },
    {  9443, "Portainer HTTPS",            SEV_MEDIUM,  "Containers"   },
    { 27017, "MongoDB",                    SEV_HIGH,    "Database"     },
    { 32400, "Plex Media Server",          SEV_INFO,    "Media"        },
};
#define NPORTS (sizeof(HOMELAB_PORTS) / sizeof(HOMELAB_PORTS[0]))

/* LanScannerPlugin._probe_port */
static int probe_port(const char *host, int port)
{
    int fd = tcp_connect(host, port, PROBE_TIMEOUT);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

/* Expand "a.b.c.d/len" into up to max usable host addresses.
 * Returns the number written. 0 means the target was not IPv4/CIDR at all. */
static size_t expand_cidr(const char *target, char hosts[][16], size_t max)
{
    unsigned a, b, c, d;
    int prefix = 32;
    int consumed = 0;

    /* %n tells us exactly how much sscanf ate, so "1.2.3.4.5" and "1.2.3.4x"
     * are rejected here rather than silently becoming 1.2.3.4. Python's
     * ip_network() raised ValueError on those and the plugin fell back to
     * scanning the literal string, which would then never resolve. */
    if (sscanf(target, "%u.%u.%u.%u%n", &a, &b, &c, &d, &consumed) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    if (target[consumed] != '\0' && target[consumed] != '/') return 0;

    const char *slash = strchr(target, '/');
    if (slash) {
        char *endp = NULL;
        long p = strtol(slash + 1, &endp, 10);
        if (!endp || *endp != '\0' || p < 0 || p > 32) return 0;
        prefix = (int)p;
    }
    /* else: a bare address is a /32, which is what Python's ip_network()
     * defaulted to and what net.hosts() then yielded. */

    unsigned long long n = (unsigned long long)a << 24 |
                           (unsigned long long)b << 16 |
                           (unsigned long long)c << 8 | d;
    unsigned long long first, last;
    if (prefix >= 31) {
        /* /31 and /32 have no network or broadcast address, so every address
         * in the block is usable — matching net.hosts(). */
        first = n;
        last  = n + (prefix == 31 ? 1ULL : 0ULL);
    } else {
        unsigned long long span = 1ULL << (32 - prefix);
        unsigned long long net  = (n / span) * span;
        first = net + 1;
        last  = net + span - 2;
    }

    size_t n_out = 0;
    for (unsigned long long ip = first; ip <= last && n_out < max; ip++) {
        snprintf(hosts[n_out], 16, "%u.%u.%u.%u",
                 (unsigned)((ip >> 24) & 0xFF), (unsigned)((ip >> 16) & 0xFF),
                 (unsigned)((ip >> 8) & 0xFF), (unsigned)(ip & 0xFF));
        n_out++;
    }
    return n_out;
}

static void scan_host(orchestrator_t *ctx, const char *host)
{
    for (size_t i = 0; i < NPORTS; i++) {
        if (!probe_port(host, HOMELAB_PORTS[i].port)) continue;

        char value[16];
        snprintf(value, sizeof(value), "%d/tcp", HOMELAB_PORTS[i].port);

        char detail[160];
        snprintf(detail, sizeof(detail), "%s (%s)",
                 HOMELAB_PORTS[i].service, HOMELAB_PORTS[i].category);

        json_value_t *meta = json_object();
        json_object_set_num(meta, "port", (double)HOMELAB_PORTS[i].port);
        json_object_set_str(meta, "service", HOMELAB_PORTS[i].service);
        json_object_set_str(meta, "category", HOMELAB_PORTS[i].category);
        json_object_set_str(meta, "host", host);

        finding_t *f = finding_new(NAME, FT_PORT, value, host, HOMELAB_PORTS[i].sev);
        if (f) {
            finding_set_detail(f, detail);
            finding_set_meta(f, meta);
            orch_add(ctx, f);
        } else {
            json_free(meta);
        }
    }
}

static int run(orchestrator_t *ctx, const char *target)
{
    char hosts[MAX_HOSTS][16];
    size_t n = expand_cidr(target, hosts, MAX_HOSTS);

    if (n == 0) {
        /* Not CIDR: Python fell through to hosts = [target] and scanned the
         * literal string. tcp_connect() resolves names, so a hostname target
         * still works. */
        char one[256];
        size_t len = strlen(target);
        if (len >= sizeof(one)) len = sizeof(one) - 1;
        memcpy(one, target, len);
        one[len] = '\0';
        scan_host(ctx, one);
        return 0;
    }

    for (size_t i = 0; i < n; i++) scan_host(ctx, hosts[i]);
    return 0;
}

const plugin_t lan_scanner_plugin = {
    "lan_scanner",
    "Ultra-lean multi-threaded homelab port and service discovery",
    STAGE_RECON,
    { NULL },
    run
};

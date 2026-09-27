/* honeyport.c — active deception honeyport trip audit.
 *
 * Ported from sentinel/core/plugins/honeyport_plugin.py (HoneyportPlugin.run).
 * That module also defined HoneyportServer, a threaded decoy listener. A
 * plugin_t has a single run() entry point and no lifecycle, so only the audit
 * half is ported here; the listening half is the daemon's job and already
 * exists as the trap sockets in src/sentineld.c. What this file reproduces is
 * the Python's read of honeyport_trips.json and the two finding shapes.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"

#include <stdlib.h>
#include <string.h>

#define NAME "honeyport"
#define TRIPWIRE_LOG_NAME "honeyport_trips.json"

/* DEFAULT_HONEY_PORTS */
static const int HONEY_PORTS[] = { 23, 445, 2375, 8888 };
#define NPORTS (sizeof(HONEY_PORTS) / sizeof(HONEY_PORTS[0]))

/* Python gated on the target string before touching any host state, so a
 * remote scan never reports on this machine's decoys. */
static int is_local_target(const char *t)
{
    return strcmp(t, "localhost") == 0 || strcmp(t, "127.0.0.1") == 0 ||
           strcmp(t, "::1") == 0         || strcmp(t, "local") == 0 ||
           strcmp(t, "server") == 0     || strncmp(t, "127.", 4) == 0;
}

/* A finding's detail is rendered into the HTML report, and a trip payload is
 * raw bytes an attacker chose, so escape here. Control bytes become numeric
 * references so a payload cannot break out of a table cell or smuggle markup.
 * The metadata dict does not need this: json_dump() escapes on serialize. */
static char *html_escape_n(const char *in, size_t max_src)
{
    buf_t b;
    buf_init(&b);
    if (!in) return buf_release(&b);

    size_t used = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && used < max_src; p++, used++) {
        switch (*p) {
            case '&':  buf_puts(&b, "&amp;");  break;
            case '<':  buf_puts(&b, "&lt;");   break;
            case '>':  buf_puts(&b, "&gt;");   break;
            case '"':  buf_puts(&b, "&quot;"); break;
            case '\'': buf_puts(&b, "&#x27;"); break;
            default:
                if (*p < 0x20 || *p == 0x7f) {
                    char ref[8];
                    snprintf(ref, sizeof(ref), "&#x%02X;", *p);
                    buf_puts(&b, ref);
                } else {
                    buf_putc(&b, (char)*p);
                }
        }
    }
    /* Never end mid-UTF-8-sequence: the report would render a replacement
     * glyph. Escaped entities always end in ';' so only raw runes can be
     * split here. */
    if (b.len > 0 && ((unsigned char)b.data[b.len - 1] & 0xC0) == 0x80) {
        size_t k = b.len;
        while (k > 0 && ((unsigned char)b.data[k - 1] & 0xC0) == 0x80) k--;
        if (k > 0) k--;
        b.len = k;
        b.data[k] = '\0';
    }
    return buf_release(&b);
}

static void emit_trip(orchestrator_t *ctx, const char *target,
                      const json_value_t *trip)
{
    /* Python's trip.get("attacker_ip", "unknown") interpolated whatever JSON
     * type it found. A non-string here means the trip log was tampered with,
     * so fall back to the literal rather than inventing a value. */
    const char *ip = json_get_str(trip, "attacker_ip");
    if (!ip) ip = "unknown";
    int port = (int)json_get_num(trip, "port", 0.0);
    const char *payload = json_get_str(trip, "payload");

    char *e_ip = html_escape_n(ip, 512);
    /* Python: payload[:80] if payload else 'SYN Scan' */
    char *e_pay = html_escape_n(payload, 80);
    int have_pay = payload && *payload;

    char value[640];
    snprintf(value, sizeof(value), "Active Honeyport Breach: %s -> port %d", e_ip, port);

    char detail[1024];
    snprintf(detail, sizeof(detail),
             "CRITICAL ACTIVE DECEPTION TRIGGER: Hostile IP %s connected to decoy "
             "honeyport %d/tcp. Probe payload: %s. Immediate firewall ban recommended.",
             e_ip, port, have_pay ? e_pay : "SYN Scan");

    /* The ban rules are rendered into the report as copy-paste remediation, so
     * they carry the same escaped IP. */
    char iptables_ban[768];
    char nftables_ban[768];
    snprintf(iptables_ban, sizeof(iptables_ban), "iptables -I INPUT -s %s -j DROP", e_ip);
    snprintf(nftables_ban, sizeof(nftables_ban),
             "nft add rule inet filter input ip saddr %s drop", e_ip);

    json_value_t *meta = json_object();
    json_object_set_str(meta, "attacker_ip", ip);
    json_object_set_num(meta, "decoy_port", (double)port);
    json_object_set_str(meta, "threat_category", "deception_honeyport_tripped");
    json_object_set_str(meta, "iptables_ban", iptables_ban);
    json_object_set_str(meta, "nftables_ban", nftables_ban);

    finding_t *f = finding_new(NAME, FT_VULNERABILITY, value, target, SEV_CRITICAL);
    if (f) {
        finding_set_detail(f, detail);
        finding_set_meta(f, meta);
        orch_add(ctx, f);
    } else {
        json_free(meta);
    }
    free(e_ip);
    free(e_pay);
}

static void emit_readiness(orchestrator_t *ctx, const char *target)
{
    char ports[64];
    size_t off = 0;
    ports[0] = '\0';
    for (size_t i = 0; i < NPORTS; i++)
        off += (size_t)snprintf(ports + off, sizeof(ports) - off, "%s%d",
                                i ? ", " : "", HONEY_PORTS[i]);

    char value[96];
    snprintf(value, sizeof(value), "Honeyport Deception Decoys (%u ports)", (unsigned)NPORTS);
    char detail[256];
    snprintf(detail, sizeof(detail),
             "Honeyport deception traps monitored on ports: %s.", ports);

    json_value_t *meta = json_object();
    json_value_t *list = json_array();
    for (size_t i = 0; i < NPORTS; i++)
        json_array_push(list, json_number((double)HONEY_PORTS[i]));
    json_object_set(meta, "monitored_ports", list);
    json_object_set_str(meta, "status", "active");

    finding_t *f = finding_new(NAME, FT_HARDENING, value, target, SEV_INFO);
    if (f) {
        finding_set_detail(f, detail);
        finding_set_meta(f, meta);
        orch_add(ctx, f);
    } else {
        json_free(meta);
    }
}

static int run(orchestrator_t *ctx, const char *target)
{
    if (!is_local_target(target) && !ctx->server_audit) return 0;

    /* paths_state_path() is only valid until the next call, and SENTINEL_HOME
     * can relocate the state dir, so resolve it fresh and never assume
     * ~/.sentinel. */
    char *log_path = sstrdup(paths_state_path(TRIPWIRE_LOG_NAME));

    size_t len = 0;
    char *raw = read_file(log_path, &len);
    if (raw) {
        json_value_t *trips = json_parse(raw, len);
        free(raw);

        if (trips && trips->type == JSON_ARRAY) {
            for (size_t i = 0; i < json_len(trips); i++) {
                const json_value_t *trip = json_at(trips, i);
                if (trip && trip->type == JSON_OBJECT) emit_trip(ctx, target, trip);
            }
        } else {
            /* Python swallowed a parse failure and reported zero trips, which
             * reads identical to "nothing tripped". Say so, so a corrupt log
             * is not mistaken for a quiet decoy grid. */
            char d[512];
            snprintf(d, sizeof(d),
                     "Honeyport tripwire log '%s' is not a readable JSON array; "
                     "recorded decoy trips were skipped.", log_path);
            orch_note(ctx, NAME, "honeyport trip log unreadable", target, d);
        }
        json_free(trips);
    }

    /* Python emits the readiness finding unconditionally, including when the
     * log does not exist yet. */
    emit_readiness(ctx, target);
    free(log_path);
    return 0;
}

const plugin_t honeyport_plugin = {
    "honeyport",
    "Active deception honeyport listener and reconnaissance trap",
    STAGE_AUDIT,
    { NULL },
    run
};

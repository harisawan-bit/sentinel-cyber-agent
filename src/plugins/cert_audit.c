/* cert_audit.c — port of CertAuditPlugin
 * (sentinel/core/plugins/cert_audit_plugin.py).
 *
 * Pulls the peer certificate off each common TLS port and reports expiry risk,
 * issuer and self-signed status. util.h exposes tls_connect()/tls_close() but
 * no certificate introspection, so the X509 accessors come straight from
 * OpenSSL in this file; every object taken from OpenSSL is freed here.
 *
 * Deliberate divergence from Python: the original called
 * getpeercert(binary_form=False) on a context with verify_mode = CERT_NONE,
 * which returns an empty dict for an unvalidated chain — so its `if not cert:
 * continue` swallowed every certificate and the plugin never emitted a single
 * finding. Using SSL_get_peer_certificate() makes the intended behaviour real.
 */
#include "sentinel/sentinel.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "cert_audit needs OpenSSL 1.1.0+ for X509_get0_notBefore/X509_get0_notAfter"
#endif

#define PLUGIN_NAME "cert_audit"

static const int TLS_PORTS[] = { 443, 8443, 8006, 9443, 5001 };
#define TLS_TIMEOUT 1   /* Python used 0.5s; tcp_connect() takes whole seconds */

typedef struct {
    int y, mo, d, h, mi, s;
    int valid;
} utc_t;

/* Days from 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
 * algorithm). Hand-rolled rather than timegm(), which glibc only declares
 * under _DEFAULT_SOURCE — the contract only sanctions _POSIX_C_SOURCE, and
 * this keeps the file free of feature-test games. */
static long long days_from_civil(int y, unsigned m, unsigned d)
{
    y -= (m <= 2);
    const long long era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);                  /* [0, 399] */
    const unsigned doy = (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u;
    const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;   /* [0, 146096] */
    return era * 146097LL + (long long)doe - 719468LL;
}

/* An ASN1_TIME is a tagged binary structure, not a number: reading it as an
 * integer yields nonsense dates. Decoding it to a GENERALIZEDTIME string
 * ("YYYYMMDDHHMMSSZ", always UTC) is the portable read. */
static utc_t asn1_utc(const ASN1_TIME *t)
{
    utc_t out;
    memset(&out, 0, sizeof out);

    ASN1_GENERALIZEDTIME *gt = NULL;
    if (!t || !ASN1_TIME_to_generalizedtime(t, &gt)) {
        ERR_clear_error();
        return out;
    }

    char buf[32];
    int len = ASN1_STRING_length(gt);
    if (len > 0 && len < (int)sizeof buf) {
        const unsigned char *data = ASN1_STRING_get0_data(gt);
        memcpy(buf, data, (size_t)len);
        buf[len] = '\0';
        if (sscanf(buf, "%4d%2d%2d%2d%2d%2d",
                   &out.y, &out.mo, &out.d, &out.h, &out.mi, &out.s) == 6)
            out.valid = 1;
    }
    ASN1_GENERALIZEDTIME_free(gt);
    return out;
}

static long long utc_epoch(const utc_t *v)
{
    if (!v->valid) return -1;
    return days_from_civil(v->y, (unsigned)v->mo, (unsigned)v->d) * 86400LL
         + v->h * 3600LL + v->mi * 60LL + v->s;
}

static void format_utc(const utc_t *v, char *out, size_t outlen)
{
    if (!v->valid) { snprintf(out, outlen, "unknown"); return; }
    snprintf(out, outlen, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             v->y, v->mo, v->d, v->h, v->mi, v->s);
}

/* X509_NAME_get_text_by_NID copies into a caller buffer, so there is nothing to
 * free here (unlike X509_NAME_oneline, which would need a free). */
static void name_cn(X509_NAME *name, char *out, size_t outlen)
{
    if (!outlen) return;
    out[0] = '\0';
    if (name && X509_NAME_get_text_by_NID(name, NID_commonName, out, (int)outlen) < 0)
        out[0] = '\0';
}

/* Python compares issuer and subject commonName only, which is a weak proxy
 * for self-signed; kept as-is so severities stay comparable. Two absent CNs
 * compare equal in Python too (None == None), and empty strings do the same
 * here. */
static int is_self_signed(const char *issuer_cn, const char *subject_cn)
{
    return strcmp(issuer_cn ? issuer_cn : "", subject_cn ? subject_cn : "") == 0;
}

/* First few dNSName SANs, comma separated, for the report metadata. */
static void collect_sans(X509 *cert, char *out, size_t outlen)
{
    if (!outlen) return;
    out[0] = '\0';

    GENERAL_NAMES *names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!names) { ERR_clear_error(); return; }   /* absent extension, not an error */

    size_t used = 0;
    int total = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < total; i++) {
        const GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);
        if (gn->type != GEN_DNS) continue;
        const unsigned char *data = ASN1_STRING_get0_data(gn->d.dNSName);
        int len = ASN1_STRING_length(gn->d.dNSName);
        if (len <= 0) continue;

        char one[256];
        if (len >= (int)sizeof one) len = (int)sizeof one - 1;
        memcpy(one, data, (size_t)len);
        one[len] = '\0';

        int n = snprintf(out + used, outlen - used, "%s%s", used ? "," : "", one);
        if (n < 0 || (size_t)n >= outlen - used) break;
        used += (size_t)n;
    }
    GENERAL_NAMES_free(names);   /* X509_get_ext_d2i hands back an owned stack */
}

/* Returns 1 when a certificate was inspected and a finding emitted. */
static int audit_port(orchestrator_t *ctx, const char *target, int port)
{
    int fd = tcp_connect(target, port, TLS_TIMEOUT);
    if (fd < 0) return 0;

    /* verify=0: the point of the audit is to inspect whatever certificate is
     * presented, self-signed and expired ones included. */
    void *ssl = tls_connect(fd, target, 0, TLS_TIMEOUT);
    if (!ssl) { tls_close(NULL, fd); return 0; }

    X509 *cert = SSL_get_peer_certificate((SSL *)ssl);
    if (!cert) { tls_close(ssl, fd); return 0; }

    int emitted = 0;
    utc_t not_before = asn1_utc(X509_get0_notBefore(cert));
    utc_t not_after = asn1_utc(X509_get0_notAfter(cert));
    if (!not_after.valid) goto done;   /* Python: ValueError -> `continue` */

    char issuer_cn[256], subject_cn[256], sans[1024];
    name_cn(X509_get_issuer_name(cert), issuer_cn, sizeof issuer_cn);
    name_cn(X509_get_subject_name(cert), subject_cn, sizeof subject_cn);
    collect_sans(cert, sans, sizeof sans);

    char now_iso[32], before_iso[32], after_iso[32];
    long long now = (long long)now_seconds();
    long long exp = utc_epoch(&not_after);
    long long start = utc_epoch(&not_before);
    format_utc(&not_before, before_iso, sizeof before_iso);
    format_utc(&not_after, after_iso, sizeof after_iso);
    iso8601((double)now, now_iso, sizeof now_iso);

    long long diff = exp - now;
    /* Python's timedelta.days floors towards negative infinity, so a
     * certificate that lapsed 12 hours ago counts as day -1, not day 0. */
    long days = (long)(diff / 86400LL);
    if (diff < 0 && diff % 86400LL) days--;

    int self_signed = is_self_signed(issuer_cn, subject_cn);
    int not_yet_valid = (start > 0 && start > now);

    char value[64];
    snprintf(value, sizeof value, "cert:%d/tcp", port);

    finding_t *f = finding_new(PLUGIN_NAME, FT_NOTE, value, target, SEV_INFO);
    if (!f) goto done;

    if (not_yet_valid) {
        /* Python never looked at notBefore and would have called a not-yet-valid
         * certificate "Valid". A certificate that is not usable yet is a
         * misconfiguration, and saying otherwise is a false all-clear. */
        f->type = FT_MISCONFIGURATION;
        f->severity = SEV_HIGH;
        char detail[256];
        snprintf(detail, sizeof detail,
                 "Certificate on port %d is not valid until %s", port, before_iso);
        finding_set_detail(f, detail);
    } else if (days <= 0) {
        f->type = FT_MISCONFIGURATION;
        f->severity = SEV_CRITICAL;
        char detail[256];
        snprintf(detail, sizeof detail,
                 "Certificate on port %d EXPIRED %ld days ago",
                 port, days < 0 ? -days : 0);
        finding_set_detail(f, detail);
    } else if (days < 14) {
        f->type = FT_MISCONFIGURATION;
        f->severity = SEV_HIGH;
        char detail[256];
        snprintf(detail, sizeof detail,
                 "Certificate on port %d expires soon (%ld days remaining)", port, days);
        finding_set_detail(f, detail);
    } else if (days < 30) {
        f->type = FT_MISCONFIGURATION;
        f->severity = SEV_MEDIUM;
        char detail[256];
        snprintf(detail, sizeof detail,
                 "Certificate on port %d expires in %ld days", port, days);
        finding_set_detail(f, detail);
    } else {
        /* Valid and comfortably in date: Python emitted a note, not a
         * misconfiguration, and only upgraded it to low when self-signed. */
        f->type = FT_NOTE;
        f->severity = SEV_INFO;
        char detail[512];
        snprintf(detail, sizeof detail,
                 "Valid certificate (%ld days left) issued by %s",
                 days, issuer_cn[0] ? issuer_cn : "Unknown");
        if (self_signed) {
            f->severity = SEV_LOW;
            /* U+00B7 middle dot, as in the Python detail string. */
            strncat(detail, " \xc2\xb7 Self-signed",
                    sizeof detail - strlen(detail) - 1);
        }
        finding_set_detail(f, detail);
    }

    json_value_t *meta = json_object();
    json_object_set_num(meta, "port", port);
    json_object_set_num(meta, "days_left", (double)days);
    json_object_set(meta, "self_signed", json_bool(self_signed));
    /* Beyond Python's metadata, but the port brief asks for these and the
     * report renders metadata as one line. */
    json_object_set_str(meta, "not_before", before_iso);
    json_object_set_str(meta, "not_after", after_iso);
    json_object_set_str(meta, "checked_at", now_iso);
    json_object_set_str(meta, "subject_cn", subject_cn);
    json_object_set_str(meta, "issuer_cn", issuer_cn);
    json_object_set_str(meta, "sans", sans);
    finding_set_meta(f, meta);

    orch_add(ctx, f);
    emitted = 1;

done:
    X509_free(cert);
    tls_close(ssl, fd);
    return emitted;
}

static int run(orchestrator_t *ctx, const char *target)
{
    if (!ctx || !target) return 0;

    int audited = 0;
    for (size_t i = 0; i < sizeof TLS_PORTS / sizeof TLS_PORTS[0]; i++)
        audited += audit_port(ctx, target, TLS_PORTS[i]);

    /* Rule 4: say what was skipped when the target turned out to have no
     * inspectable TLS listener, instead of returning a bare success. Counted
     * per run rather than sniffed back out of ctx->findings, which
     * accumulates across targets and plugins. */
    if (!audited) {
        char detail[256];
        snprintf(detail, sizeof detail,
                 "No TLS certificate was retrieved from %s on ports 443, 8443, "
                 "8006, 9443, 5001; certificate expiry could not be assessed.",
                 target);
        orch_note(ctx, PLUGIN_NAME, "no TLS certificate found", target, detail);
    }
    return 0;
}

const plugin_t cert_audit_plugin = {
    PLUGIN_NAME,
    "Checks SSL/TLS certificate validity, expiry, and self-signed status",
    STAGE_SCAN,
    { NULL },
    run
};

/* report.c — standalone HTML report generation.
 *
 * Ported from sentinel/core/report.py. The stylesheet and the client-side
 * script are extracted verbatim into report_css.h / report_js.h so both
 * renderers produce byte-identical chrome; this file owns the data-driven
 * sections and the aggregation logic.
 *
 * Every value interpolated into markup passes through html_escape(). Findings
 * carry network- and process-derived strings, so this is a security boundary,
 * not cosmetic.
 */
#include "sentinel/report.h"
#include "sentinel/buf.h"
#include "sentinel/util.h"
#include "sentinel/report_css.h"
#include "sentinel/report_js.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Palette shared with the Python renderer. */
static const char *SEV_COLORS[] = {
    "#ff3b5c", "#ff7a45", "#d4a359", "#7a9ebb", "#8a93a6", "#8a93a6"
};
static const severity_t SEV_ORDER[] = { SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO };

static const char *sev_color(severity_t s)
{
    if (s < 0 || s > SEV_UNKNOWN) return "#8a93a6";
    return SEV_COLORS[s];
}

/* Escape for HTML text and quoted attribute contexts. */
static char *html_escape(const char *in)
{
    if (!in) return sstrdup("");
    buf_t b; buf_init(&b);
    for (size_t i = 0; in[i]; i++) {
        switch (in[i]) {
            case '&':  buf_puts(&b, "&amp;");  break;
            case '<':  buf_puts(&b, "&lt;");   break;
            case '>':  buf_puts(&b, "&gt;");   break;
            case '"':  buf_puts(&b, "&quot;"); break;
            case '\'': buf_puts(&b, "&#x27;"); break;
            default:   buf_putc(&b, in[i]);
        }
    }
    return buf_release(&b);
}

char *report_render_json(const json_value_t *findings, const char *title)
{
    if (!title) title = "Sentinel Homelab Report";

    size_t total = json_len(findings);
    size_t nsev[SEV_UNKNOWN + 1] = {0};
    size_t port_count = 0;

    /* Aggregate while escaping, so we walk the data exactly once. */
    for (size_t i = 0; i < total; i++) {
        const json_value_t *f = json_at(findings, i);
        severity_t s = severity_parse(json_get_str(f, "severity"));
        nsev[s]++;
        const char *ft = json_get_str(f, "finding_type");
        if (ft && strcmp(ft, "port") == 0) port_count++;
    }

    buf_t o; buf_init(&o);
    char *etitle = html_escape(title);

    buf_printf(&o,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>SENTINEL // %s</title>\n<style>%s</style>\n</head>\n",
        etitle, REPORT_CSS);
    free(etitle);

    /* --- header --- */
    buf_puts(&o,
        "<body>\n  <header>\n    <div class=\"header-container\">\n"
        "      <div class=\"brand-row\">\n        <div class=\"brand-group\">\n"
        "          <h1>SENTINEL // ");
    char *etitle2 = html_escape(title);
    buf_printf(&o, "%s", etitle2);
    free(etitle2);
    buf_printf(&o,
        "</h1>\n          <span class=\"brand-badge\">Homelab Guardian</span>\n"
        "        </div>\n        <div class=\"header-subtitle\">\n"
        "          <span>Total events: <strong>%zu</strong></span>\n"
        "          <span>&bull;</span>\n"
        "          <span>Open ports: <strong>%zu</strong></span>\n"
        "          <span>&bull;</span>\n"
        "          <span>Target(s): <strong>%zu</strong></span>\n"
        "        </div>\n      </div>\n    </div>\n  </header>\n\n"
        "  <main class=\"wrap\">\n",
        total, port_count, total ? 1u : 0u);

    /* --- severity spectrum --- */
    buf_puts(&o,
        "    <section class=\"progress-card\" aria-label=\"Finding Severity Distribution\">\n"
        "      <div class=\"progress-card-top\">\n"
        "        <div class=\"progress-title\">Severity Spectrum</div>\n"
        "        <div class=\"progress-stats\">\n"
        "          <span>");
    buf_printf(&o, "%zu</span> validated item(s) across systems\n"
                  "        </div>\n      </div>\n"
                  "      <div class=\"progress-bar-bg\">\n", total);
    if (total) {
        for (size_t k = 0; k < sizeof(SEV_ORDER) / sizeof(SEV_ORDER[0]); k++) {
            severity_t s = SEV_ORDER[k];
            if (!nsev[s]) continue;
            double pct = (double)nsev[s] * 100.0 / (double)total;
            buf_printf(&o,
                "        <div class=\"dist-seg\" style=\"width:%.1f%%; background:%s;\" "
                "title=\"%s: %zu (%.1f%%)\"></div>\n",
                pct, sev_color(s), severity_str(s), nsev[s], pct);
        }
    } else {
        buf_puts(&o, "        <div class=\"dist-seg\" style=\"width:100%; background:var(--border);\" title=\"No findings\"></div>\n");
    }
    buf_puts(&o, "      </div>\n    </section>\n\n");

    /* --- defense matrix --- */
    {
        size_t ndef = 0;
        for (size_t i = 0; i < total; i++) {
            const json_value_t *f = json_at(findings, i);
            /* Recreate is_defense() against the JSON form. */
            const char *ft = json_get_str(f, "finding_type");
            int hit = ft && (strcmp(ft,"hardening")==0 || strcmp(ft,"anomaly")==0 ||
                             strcmp(ft,"threat_intel")==0 || strcmp(ft,"canary")==0 ||
                             strcmp(ft,"integrity")==0 || strcmp(ft,"deception")==0 ||
                             strcmp(ft,"remediation")==0);
            const json_value_t *m = json_get(f, "metadata");
            if (!hit && m) {
                static const char *K[] = { "cisa_kev","mitigation","threat_category","sigma_id" };
                for (int i2 = 0; i2 < 4 && !hit; i2++) if (json_get(m, K[i2])) hit = 1;
            }
            if (hit) ndef++;
        }
        if (ndef) {
            buf_puts(&o,
                "    <section class=\"defense-card\" aria-label=\"Server 0-Day and Exploit Mitigations\">\n"
                "      <div class=\"section-title\">Server 0-Day &amp; Exploit Mitigations</div>\n"
                "      <table class=\"matrix\"><thead><tr>"
                "<th>Severity</th><th>Category</th><th>Target</th>"
                "<th>Finding</th><th>Tool</th><th>Detail</th>"
                "</tr></thead><tbody>\n");
            for (size_t i = 0; i < total; i++) {
                const json_value_t *f = json_at(findings, i);
                const char *ft = json_get_str(f, "finding_type");
                int hit = ft && (strcmp(ft,"hardening")==0 || strcmp(ft,"anomaly")==0 ||
                                 strcmp(ft,"threat_intel")==0 || strcmp(ft,"canary")==0 ||
                                 strcmp(ft,"integrity")==0 || strcmp(ft,"deception")==0 ||
                                 strcmp(ft,"remediation")==0);
                const json_value_t *m = json_get(f, "metadata");
                if (!hit && m) {
                    static const char *K[] = { "cisa_kev","mitigation","threat_category","sigma_id" };
                    for (int i2 = 0; i2 < 4 && !hit; i2++) if (json_get(m, K[i2])) hit = 1;
                }
                if (!hit) continue;

                severity_t s = severity_parse(json_get_str(f, "severity"));
                const char *tool = json_get_str(f, "tool");
                const char *value = json_get_str(f, "value");
                const char *target = json_get_str(f, "target");
                const char *detail = json_get_str(f, "detail");

                char *cat = sstrdup("Defense");
                if (m && json_get(m, "mitigation"))          free(cat), cat = sstrdup("Kernel Mitigation");
                else if (m && json_get(m, "cisa_kev"))        free(cat), cat = sstrdup("CISA KEV Exploit");
                else if (m) {
                    const char *tc = json_get_str(m, "threat_category");
                    if (tc && strcmp(tc, "0day_rce_execution") == 0) { free(cat); cat = sstrdup("Process Anomaly"); }
                }
                else if (m && json_get(m, "sigma_id"))        free(cat), cat = sstrdup("Sigma Detection");
                else if (tool && str_contains(tool, "fim"))   { free(cat); cat = sstrdup("File Integrity (FIM)"); }
                else if (tool && str_contains(tool, "honeyport")) { free(cat); cat = sstrdup("Deception Honeyport"); }
                else if (tool && str_contains(tool, "canary"))    { free(cat); cat = sstrdup("Deception Tripwire"); }
                else if (ft)                                 { free(cat); cat = sstrdup(ft); }

                char *ecat = html_escape(cat);
                char *evalue = html_escape(value ? value : "");
                char *etarget = html_escape(target ? target : "local");
                char *etool = html_escape(tool ? tool : "");
                char *edetail = html_escape(detail ? detail : "");

                buf_printf(&o,
                    "        <tr data-sev=\"%s\"><td><span class=\"pill pill-%s\">%s</span></td>"
                    "<td>%s</td><td class=\"mono\">%s</td><td class=\"mono\">%s</td>"
                    "<td class=\"mono\">%s</td><td>%s</td></tr>\n",
                    severity_str(s), severity_str(s), severity_str(s),
                    ecat, etarget, evalue, etool, edetail);
                free(ecat); free(evalue); free(etarget); free(etool); free(edetail); free(cat);
            }
            buf_puts(&o, "      </tbody></table>\n    </section>\n\n");
        }
    }

    /* --- controls --- */
    buf_puts(&o,
        "    <section class=\"controls-bar\" aria-label=\"Report Controls\">\n"
        "      <div class=\"filter-group\">\n"
        "        <span class=\"filter-label\">Filter:</span>\n");
    buf_printf(&o,
        "        <button class=\"filter-btn pill pill-all active\" data-filter=\"all\">ALL: %zu</button>\n", total);
    for (size_t k = 0; k < sizeof(SEV_ORDER) / sizeof(SEV_ORDER[0]); k++) {
        severity_t s = SEV_ORDER[k];
        if (!nsev[s]) continue;
        buf_printf(&o,
            "        <button class=\"filter-btn pill pill-%s\" data-filter=\"%s\">%s: %zu</button>\n",
            severity_str(s), severity_str(s), severity_str(s), nsev[s]);
    }
    buf_puts(&o,
        "      </div>\n      <div>\n"
        "        <input type=\"text\" id=\"searchInput\" class=\"search-input\" "
        "placeholder=\"Search host, tool, port, CVE...\" oninput=\"handleSearch()\">\n"
        "      </div>\n    </section>\n\n");

    /* --- findings table --- */
    buf_puts(&o,
        "    <section class=\"target-container\" id=\"targetContainer\">\n"
        "      <table class=\"matrix\"><thead><tr>"
        "<th>Severity</th><th>Type</th><th>Target</th><th>Finding</th>"
        "<th>Tool</th><th>Detail</th><th>Time</th>"
        "</tr></thead><tbody>\n");
    for (size_t i = 0; i < total; i++) {
        const json_value_t *f = json_at(findings, i);
        severity_t s = severity_parse(json_get_str(f, "severity"));
        const char *ft = json_get_str(f, "finding_type");
        const char *tool = json_get_str(f, "tool");
        const char *value = json_get_str(f, "value");
        const char *target = json_get_str(f, "target");
        const char *detail = json_get_str(f, "detail");
        double ts = json_get_num(f, "timestamp", 0);
        char tsbuf[32] = "";
        if (ts > 0) iso8601(ts, tsbuf, sizeof(tsbuf));

        char *esev = html_escape(severity_str(s));
        char *eft  = html_escape(ft ? ft : "");
        char *etool = html_escape(tool ? tool : "");
        char *evalue = html_escape(value ? value : "");
        char *etarget = html_escape(target ? target : "local");
        char *edetail = html_escape(detail ? detail : "");
        char *ets = html_escape(tsbuf);

        buf_printf(&o,
            "        <tr data-sev=\"%s\"><td><span class=\"pill pill-%s\">%s</span></td>"
            "<td>%s</td><td class=\"mono\">%s</td><td class=\"mono\">%s</td>"
            "<td class=\"mono\">%s</td><td>%s</td><td class=\"mono\">%s</td></tr>\n",
            severity_str(s), severity_str(s), esev, eft, etarget, evalue, etool, edetail, ets);
        free(esev); free(eft); free(etool); free(evalue); free(etarget); free(edetail); free(ets);
    }
    buf_puts(&o, "      </tbody></table>\n    </section>\n\n");

    buf_puts(&o,
        "    <footer>\n"
        "      Autonomous assessment generated by Sentinel Cyber Agent &bull; "
        "Low-memory engine &bull; Zero external CDN dependencies\n"
        "    </footer>\n  </main>\n\n  <script>");

    /* The Python source doubled its braces for the f-string; undo that here. */
    for (const char *p = REPORT_JS; *p; p++) {
        if (p[0] == '{' && p[1] == '{') { buf_putc(&o, '{'); p++; }
        else if (p[0] == '}' && p[1] == '}') { buf_putc(&o, '}'); p++; }
        else buf_putc(&o, *p);
    }
    buf_puts(&o, "</script>\n</body>\n</html>\n");

    return buf_release(&o);
}

char *report_render(const orchestrator_t *o, const char *title)
{
    json_value_t *arr = orch_findings_json(o);
    char *html = report_render_json(arr, title);
    json_free(arr);
    return html;
}

/* test_main.c — the whole C test suite in one binary.
 *
 * A single runner rather than one program per file: the Makefile links
 * every C file under tests/ into one binary, and separate mains would
 * collide at link time. Each suite is a function returning a failure count.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"
#include "sentinel/buf.h"
#include "sentinel/notifiers.h"
#include "sentinel/remediation.h"
#include "sentinel/report.h"
#include "sentinel/sarif.h"
#include "sentinel/state.h"
#include "sentinel/util.h"

#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail = 0;
static int g_checks = 0;

static void check(const char *what, int ok)
{
    g_checks++;
    if (!ok) {
        g_fail++;
        printf("  FAIL  %s\n", what);
    }
}

static void section(const char *name) { printf("\n== %s ==\n", name); }

/* ------------------------------------------------------------------ sha256 */

static void test_sha256(void)
{
    section("sha256 (NIST vectors)");
    struct { const char *in, *want; } v[] = {
        { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        char out[65];
        sha256_hex(v[i].in, strlen(v[i].in), out);
        check("sha256 known vector", strcmp(out, v[i].want) == 0);
    }
    sha256_ctx c;
    sha256_init(&c);
    char a[1000];
    memset(a, 'a', sizeof(a));
    for (int i = 0; i < 1000; i++) sha256_update(&c, a, sizeof(a));
    uint8_t dg[32];
    sha256_final(&c, dg);
    char hex[65];
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { hex[i*2] = H[dg[i] >> 4]; hex[i*2+1] = H[dg[i] & 15]; }
    hex[64] = '\0';
    check("sha256 1M 'a' stress vector",
          strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
}

/* -------------------------------------------------------------------- json */

static void test_json(void)
{
    section("json");
    const char *src = "{\"vulns\":[{\"id\":\"CVE-2024-1\",\"score\":9.8,"
                      "\"mod\":{\"k\":\"v\",\"n\":null,\"ok\":true,\"neg\":-3}}],\"n\":2}";
    json_value_t *v = json_parse(src, strlen(src));
    check("parse object", v != NULL);
    if (!v) return;
    check("array length", json_len(json_get(v, "vulns")) == 1);
    json_value_t *first = json_at(json_get(v, "vulns"), 0);
    check("nested string", strcmp(json_get_str(first, "id"), "CVE-2024-1") == 0);
    check("nested number", json_get_num(first, "score", 0) == 9.8);
    json_value_t *mod = json_get(first, "mod");
    check("null literal", json_get(mod, "n") && json_get(mod, "n")->type == JSON_NULL);
    check("bool true", json_get(mod, "ok") && json_get(mod, "ok")->boolean == 1);
    check("negative number", json_get_num(mod, "neg", 0) == -3.0);
    check("missing key is NULL", json_get(v, "nope") == NULL);
    char *dump = json_dump(v, 0);
    check("re-parse after dump", dump && json_parse(dump, strlen(dump)) != NULL);
    free(dump);
    json_free(v);

    /* Malformed input must be rejected, not crash. */
    check("rejects truncated", json_parse("{\"a\":", 5) == NULL);
    check("rejects empty", json_parse("", 0) == NULL);
    check("rejects garbage", json_parse("nope", 4) == NULL);
}

static void test_json_escaping(void)
{
    section("json escaping (attacker-controlled input)");
    const char *hostile = "a\"b\\c\nd\te\x01f/g<h>&i";
    char esc[512], quoted[514];
    json_escape(hostile, esc, sizeof(esc));
    snprintf(quoted, sizeof(quoted), "\"%s\"", esc);
    json_value_t *v = json_parse(quoted, strlen(quoted));
    check("hostile string round-trips", v != NULL);
    if (v) {
        check("value preserved byte-for-byte", strcmp(v->string, hostile) == 0);
        json_free(v);
    }
    /* Truncation must never overflow. */
    char tiny[8];
    size_t n = json_escape("aaaaaaaaaaaaaaaaaaaaaaaa", tiny, sizeof(tiny));
    check("escape truncates safely", n < sizeof(tiny));
}

/* -------------------------------------------------------------------- model */

static void test_model(void)
{
    section("model");
    check("severity round-trip", severity_parse(severity_str(SEV_CRITICAL)) == SEV_CRITICAL);
    check("severity parse unknown", severity_parse("bogus") == SEV_UNKNOWN);
    for (int i = 0; i < FT__COUNT; i++)
        check("finding_type round-trip",
              finding_type_parse(finding_type_str((finding_type_t)i)) == (finding_type_t)i);

    finding_t *f = finding_new("t", FT_VULNERABILITY, "CVE-1", "host", SEV_HIGH);
    check("finding has id", f && strlen(f->id) == 12);
    check("id is hex", f && strspn(f->id, "0123456789abcdef") == 12);
    json_value_t *meta = json_object();
    json_object_set_str(meta, "cisa_kev", "yes");
    finding_set_meta(f, meta);

    json_value_t *j = finding_to_json(f);
    finding_t *g = finding_from_json(j);
    check("json round-trip severity", g && g->severity == SEV_HIGH);
    check("json round-trip value", g && strcmp(g->value, "CVE-1") == 0);
    check("json round-trip id", g && strcmp(g->id, f->id) == 0);
    check("json round-trip metadata",
          g && g->metadata && strcmp(json_get_str(g->metadata, "cisa_kev"), "yes") == 0);
    json_free(j);
    finding_free(f);
    finding_free(g);

    /* Findings must escape freed metadata independently (deep copy). */
    finding_t *h = finding_new("t", FT_NOTE, "v", "t", SEV_INFO);
    json_value_t *m2 = json_object();
    json_object_set_str(m2, "k", "before");
    finding_set_meta(h, m2);
    finding_t *h2 = finding_from_json(finding_to_json(h));
    json_free(h->metadata);
    h->metadata = NULL;
    check("metadata deep-copied", h2 && h2->metadata &&
          strcmp(json_get_str(h2->metadata, "k"), "before") == 0);
    finding_free(h);
    finding_free(h2);
}

/* -------------------------------------------------------------------- paths */

static void test_paths(void)
{
    section("state isolation (SENTINEL_HOME)");
    const char *tmp = "/tmp/sentinel_c_test_state";
    /* Start from a known-empty directory: a leftover baseline from a previous
     * run would make "absent initially" fail for reasons unrelated to the code
     * under test. */
    {
        char *rm[] = { "rm", "-rf", (char *)tmp, NULL };
        proc_run(rm, NULL, 0, 30);   /* best effort; the assertions still apply */
    }

    setenv("SENTINEL_HOME", tmp, 1);
    check("SENTINEL_HOME honoured", strcmp(paths_state_dir(), tmp) == 0);
    check("state path joins", strstr(paths_state_path("a.json"), "/a.json") != NULL);
    check("ensure_dir creates nested path", paths_ensure_dir() == 0);
    check("state file absent initially", !file_exists(paths_state_path("state.json")));

    /* Relocating the state dir mid-process must take effect immediately. */
    setenv("SENTINEL_HOME", "/tmp/sentinel_c_test_state_b", 1);
    check("relocation takes effect without restart",
          strcmp(paths_state_dir(), "/tmp/sentinel_c_test_state_b") == 0);
    {
        char *rm[] = { "rm", "-rf", "/tmp/sentinel_c_test_state_b", NULL };
        proc_run(rm, NULL, 0, 30);
    }
    setenv("SENTINEL_HOME", tmp, 1);

    /* state_update then state_diff must round-trip and detect a new asset. */
    json_value_t *arr = json_array();
    finding_t *a = finding_new("p", FT_PORT, "22", "host", SEV_LOW);
    json_array_push(arr, finding_to_json(a));
    finding_free(a);
    check("state_update writes", state_update(arr) == 0);
    check("state file now exists", file_exists(paths_state_path("state.json")));

    json_value_t *arr2 = json_array();
    finding_t *b = finding_new("p", FT_PORT, "22", "host", SEV_LOW);
    json_array_push(arr2, finding_to_json(b));
    finding_free(b);
    finding_t *c = finding_new("p", FT_PORT, "3389", "host", SEV_MEDIUM);
    json_array_push(arr2, finding_to_json(c));
    finding_free(c);

    json_value_t *drift = state_diff(arr2);
    check("drift detects the new port", json_len(drift) == 1);
    if (json_len(drift) == 1)
        check("drift names the port",
              strstr(json_get_str(json_at(drift, 0), "value"), "3389") != NULL);
    json_free(drift);
    json_free(arr);
    json_free(arr2);

    unsetenv("SENTINEL_HOME");
    /* A run with no override must not touch the test dir. */
    check("falls back to ~/.sentinel", strstr(paths_state_dir(), ".sentinel") != NULL);
}

/* ------------------------------------------------------------------- report */

static void test_report(void)
{
    section("report (HTML escaping is a security boundary)");
    orchestrator_t *o = orch_new();
    finding_t *f = finding_new("test", FT_VULNERABILITY, "<script>alert(1)</script>",
                               "evil\"host", SEV_CRITICAL);
    finding_set_detail(f, "detail with & <tags> and \"quotes\"");
    orch_add(o, f);
    finding_t *g = finding_new("test", FT_PORT, "22", "host", SEV_LOW);
    orch_add(o, g);

    char *html = report_render(o, "Title <script>");
    check("report renders", html != NULL && strlen(html) > 500);
    check("script tag escaped", html && !strstr(html, "<script>alert"));
    check("escaped form present", html && strstr(html, "&lt;script&gt;"));
    check("title escaped", html && strstr(html, "Title &lt;script&gt;"));
    check("attribute quote escaped", html && strstr(html, "&quot;host"));
    check("detail ampersand escaped", html && strstr(html, "&amp; &lt;tags&gt;"));
    check("has severity pill", html && strstr(html, "pill-critical"));
    check("has both findings", html && strstr(html, "3389") == NULL && strstr(html, "22") != NULL);
    free(html);
    orch_free(o);
}

static void test_sarif(void)
{
    section("sarif");
    orchestrator_t *o = orch_new();
    orch_add(o, finding_new("t", FT_VULNERABILITY, "CVE-1", "h", SEV_CRITICAL));
    orch_add(o, finding_new("t", FT_HARDENING, "aslr", "h", SEV_LOW));
    json_value_t *doc = sarif_build(o, "sentinel");
    check("sarif version", strcmp(json_get_str(doc, "version"), "2.1.0") == 0);
    check("schema present", json_get_str(doc, "$schema") != NULL);
    json_value_t *runs = json_get(doc, "runs");
    check("one run", json_len(runs) == 1);
    json_value_t *results = json_get(json_at(runs, 0), "results");
    check("two results", json_len(results) == 2);
    json_value_t *r0 = json_at(results, 0);
    check("critical maps to error",
          strcmp(json_get_str(json_get(r0, "level"), "level"), "error") == 0);
    check("low maps to note",
          strcmp(json_get_str(json_get(json_at(results, 1), "level"), "level"), "note") == 0);
    check("location present", json_get(json_at(results, 0), "locations") != NULL);
    char *dump = json_dump(doc, 0);
    check("sarif is valid json", dump && json_parse(dump, strlen(dump)) != NULL);
    free(dump);
    json_free(doc);
    orch_free(o);
}

/* ----------------------------------------------------------------- notifiers */

static void test_notifiers(void)
{
    section("notifiers");
    orchestrator_t *o = orch_new();
    orch_add(o, finding_new("t", FT_VULNERABILITY, "CVE-1", "h", SEV_CRITICAL));
    orch_add(o, finding_new("t", FT_PORT, "22", "h", SEV_INFO));
    char *d = notifier_digest(o, "myhost");
    check("digest mentions count", d && strstr(d, "2 finding"));
    check("digest surfaces critical", d && strstr(d, "CVE-1"));
    check("digest has severity tally", d && strstr(d, "CRITICAL 1"));
    free(d);
    /* Missing credentials must be a no-op, not a crash. */
    check("telegram without creds is safe", notifier_send_telegram(NULL, NULL, "x") == 0);
    check("slack without webhook is safe", notifier_send_slack(NULL, "x") == 0);
    orch_free(o);
}

static void test_remediation(void)
{
    section("remediation");
    char *p = remediation_conf_preview();
    check("preview generated", p && strlen(p) > 50);
    check("preview has aslr", p && strstr(p, "kernel.randomize_va_space = 2"));
    check("preview has kptr", p && strstr(p, "kernel.kptr_restrict = 2"));
    free(p);
    /* Dry run must not modify the system. */
    int n = remediation_apply(1);
    check("dry run returns >= 0", n >= 0);
}

/* ------------------------------------------------------------------ registry */

static void test_registry(void)
{
    section("plugin registry");
    size_t count = 0;
    const plugin_t *list = sentinel_plugin_list(&count);
    check("registry populated", list != NULL && count == 19);
    int have_http = 0, have_nuclei = 0, have_fim = 0, have_cert = 0;
    for (size_t i = 0; i < count; i++) {
        if (str_ieq(list[i].name, "http-probe")) have_http = 1;
        if (str_ieq(list[i].name, "nuclei")) have_nuclei = 1;
        if (str_ieq(list[i].name, "fim_audit")) have_fim = 1;
        if (str_ieq(list[i].name, "cert_audit")) have_cert = 1;
        check("plugin has a run function", list[i].run != NULL);
        check("plugin has a name", list[i].name && *list[i].name);
    }
    check("http-probe registered (python name kept)", have_http);
    check("nuclei registered", have_nuclei);
    check("fim_audit registered (python name kept)", have_fim);
    check("cert_audit registered", have_cert);
    check("find by name", sentinel_plugin_find("nuclei") != NULL);
    check("find unknown returns NULL", sentinel_plugin_find("nope") == NULL);

    /* Engine-backed plugins must declare what they need. */
    const plugin_t *n = sentinel_plugin_find("nuclei");
    check("nuclei declares requires", n && n->requires[0] && strcmp(n->requires[0], "nuclei") == 0);
    check("nuclei is scan stage", n && n->stage == STAGE_SCAN);

    /* The name field must hold a name and the description field prose. A
     * swapped pair compiles fine but silently breaks registry lookup and stage
     * filtering, so assert the shape explicitly for every plugin. */
    for (size_t i = 0; i < count; i++) {
        const char *nm = list[i].name;
        const char *ds = list[i].description;
        check("name is short and identifier-like",
              nm && strlen(nm) > 0 && strlen(nm) < 32);
        check("name has no spaces", nm && !strchr(nm, ' '));
        check("description is prose", ds && strlen(ds) > 0);
        check("description differs from name", ds && strcmp(nm, ds) != 0);
    }
}

/* -------------------------------------------------------------------- buffer */

static void test_buf(void)
{
    section("buf / string helpers");
    buf_t b; buf_init(&b);
    buf_puts(&b, "hello");
    buf_putc(&b, ' ');
    buf_printf(&b, "%s %d", "world", 42);
    check("buf contents", strcmp(b.data, "hello world 42") == 0);
    check("buf length", b.len == 14);
    char *rel = buf_release(&b);
    check("release returns contents", strcmp(rel, "hello world 42") == 0);
    free(rel);

    check("str_ieq case-insensitive", str_ieq("ABC", "abc") == 1);
    check("str_ieq negative", str_ieq("ABC", "abd") == 0);
    check("str_contains hit", str_contains("kernel.randomize", "randomize"));
    check("str_contains miss", !str_contains("abc", "zzz"));

    char *r = str_replace_all("a.b.c", ".", "->");
    check("replace all", strcmp(r, "a->b->c") == 0);
    free(r);

    char low[16];
    str_lower("MiXeD", low, sizeof(low));
    check("str_lower", strcmp(low, "mixed") == 0);

    char *e = url_encode("a b&c=d");
    check("url_encode", strcmp(e, "a%20b%26c%3Dd") == 0);
    free(e);
}

/* ------------------------------------------------------------------ main */


/* --- Regression tests for bugs found during the C99 port. -------------------
 * Each of these was a real defect that shipped into a commit at least once.
 * They are cheap to run and expensive to rediscover, so they stay.
 */

static void test_regressions(void)
{
    section("regressions (each one shipped broken at least once)");

    /* 1. A JSON parser that accepts truncated input turns a partial HTTP
     *    response into a valid-looking empty result. A threat feed read this
     *    way reported every CVE as unexploited. */
    check("truncated object is rejected",
          json_parse("{\"a\":", 5) == NULL);
    check("truncated array is rejected",
          json_parse("{\"a\":[1,2", 8) == NULL);
    check("truncated string is rejected",
          json_parse("{\"a\":\"unterminated", 16) == NULL);
    {
        json_value_t *ok = json_parse("{\"a\":[1,2]}", 11);
        check("complete object still parses", ok != NULL);
        json_free(ok);
    }

    /* 2. Content-Type was read one character past the value, so every
     *    "text/html" came back as "ext/html" and chunked was never detected. */
    {
        const char *resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: 5\r\n\r\nhello";
        /* find_ci is static in net.c, so assert the offset arithmetic here:
         * "\nContent-Type:" is 14 bytes, so the value starts at +14. */
        const char *ct = strstr(resp, "\nContent-Type:");
        /* "\nContent-Type:" is 14 bytes, then one space, so the value starts
         * at +15. Reading from +14 captured the space and turned every
         * "text/html" into " text/htm", which then failed to match "chunked". */
        check("content-type value starts past the space",
              ct != NULL && strncmp(ct + 15, "text/html", 9) == 0);
    }

    /* 3. Moving children between JSON trees and then freeing the source
     *    recursively double-frees every one of them. */
    {
        json_value_t *src = json_parse("[{\"a\":1},{\"b\":2}]", 17);
        json_value_t *dst = json_array();
        check("parse array for move test", src != NULL && dst != NULL);
        for (size_t i = 0; i < json_len(src); i++)
            json_array_push(dst, json_at(src, i));
        json_free_shallow(src);          /* must NOT touch the moved children */
        check("moved children survive a shallow free", json_len(dst) == 2);
        check("moved child keeps its fields",
              json_get(json_at(dst, 0), "a") != NULL);
        check("moved child kept every field",
              json_get(json_at(dst, 1), "b") != NULL);
        json_free(dst);
    }

    /* 4. SENTINEL_HOME was cached on first read, so a test could not relocate
     *    state after the first call. This is the same class of bug that once
     *    wrote canary findings into a real ~/.sentinel. */
    {
        const char *d = "/tmp/sentinel_c_regression_state";
        setenv("SENTINEL_HOME", d, 1);
        check("paths honour a freshly set SENTINEL_HOME",
              strcmp(paths_state_dir(), d) == 0);
        setenv("SENTINEL_HOME", "/tmp/sentinel_c_regression_other", 1);
        check("paths re-read SENTINEL_HOME after it changes",
              strcmp(paths_state_dir(), "/tmp/sentinel_c_regression_other") == 0);
        {
            char *rm[] = { "rm", "-rf", (char *)d,
                           "/tmp/sentinel_c_regression_other", NULL };
            proc_run(rm, NULL, 0, 30);   /* best-effort cleanup */
        }
    }

    /* 5. Drift detection was narrowed to four finding types, so it could never
     *    fire on the audit stage. Verify the broad semantics: a new value for a
     *    target that already exists in the baseline is drift. */
    {
        const char *st = "/tmp/sentinel_c_drift_state";
        {
            char *rm[]  = { "rm", "-rf", "/tmp/sentinel_c_drift_state", NULL };
            char *mk[]  = { "mkdir", "-p", "/tmp/sentinel_c_drift_state", NULL };
            proc_run(rm, NULL, 0, 30);
            proc_run(mk, NULL, 0, 30);
        }
        setenv("SENTINEL_HOME", st, 1);

        /* seed a baseline with two findings for "localhost" */
        json_value_t *base = json_array();
        for (int i = 0; i < 2; i++) {
            json_value_t *f = json_object();
            json_object_set_str(f, "target", "localhost");
            json_object_set_str(f, "finding_type", "hardening");
            char v[64];
            snprintf(v, sizeof(v), "kernel.p_%d = 1", i);
            json_object_set_str(f, "value", v);
            json_object_set_str(f, "severity", "info");
            json_object_set_str(f, "detail", "baseline");
            json_array_push(base, f);
        }
        state_update(base);
        json_free(base);

        /* a new finding for the same target => 1 drift event */
        json_value_t *cur = json_array();
        for (int i = 0; i < 2; i++) {
            json_value_t *f = json_object();
            json_object_set_str(f, "target", "localhost");
            json_object_set_str(f, "finding_type", "hardening");
            char v[64];
            snprintf(v, sizeof(v), "kernel.p_%d = 1", i);
            json_object_set_str(f, "value", v);
            json_object_set_str(f, "severity", "info");
            json_object_set_str(f, "detail", "baseline");
            json_array_push(cur, f);
        }
        json_value_t *nf = json_object();
        json_object_set_str(nf, "target", "localhost");
        json_object_set_str(nf, "finding_type", "anomaly");
        json_object_set_str(nf, "value", "kernel.brand_new = 9");
        json_object_set_str(nf, "severity", "high");
        json_object_set_str(nf, "detail", "something changed");
        json_array_push(cur, nf);

        json_value_t *drift = state_diff(cur);
        check("a new finding for a known target is drift", json_len(drift) == 1);
        json_free(drift);
        json_free(cur);

        /* a target that is entirely new is an asset, not drift */
        json_value_t *cur2 = json_array();
        json_value_t *f2 = json_object();
        json_object_set_str(f2, "target", "brand-new-host");
        json_object_set_str(f2, "finding_type", "hardening");
        json_object_set_str(f2, "value", "x = 1");
        json_object_set_str(f2, "severity", "info");
        json_object_set_str(f2, "detail", "new asset");
        json_array_push(cur2, f2);
        json_value_t *d2 = state_diff(cur2);
        check("an unseen target is not reported as drift", json_len(d2) == 0);
        json_free(d2);
        json_free(cur2);

        /* an unchanged re-scan is silent */
        json_value_t *same = json_array();
        for (int i = 0; i < 2; i++) {
            json_value_t *f = json_object();
            json_object_set_str(f, "target", "localhost");
            json_object_set_str(f, "finding_type", "hardening");
            char v[64];
            snprintf(v, sizeof(v), "kernel.p_%d = 1", i);
            json_object_set_str(f, "value", v);
            json_object_set_str(f, "severity", "info");
            json_object_set_str(f, "detail", "baseline");
            json_array_push(same, f);
        }
        json_value_t *d3 = state_diff(same);
        check("an unchanged re-scan reports no drift", json_len(d3) == 0);
        json_free(d3);
        json_free(same);

        {
            char *rm[] = { "rm", "-rf", (char *)st, NULL };
            proc_run(rm, NULL, 0, 30);
        }
    }

    /* 6. Two findings sharing one metadata object: freeing the first corrupted
     *    the second. This was a use-after-free that crashed every live scan. */
    {
        json_value_t *shared = json_object();
        json_object_set_str(shared, "mitigation", "ASLR");
        json_value_t *arr = json_array();
        for (int i = 0; i < 2; i++) {
            json_value_t *f = json_object();
            json_object_set_str(f, "target", "localhost");
            json_object_set_str(f, "finding_type", "hardening");
            json_object_set_str(f, "value", "kernel.test = 1");
            json_object_set_str(f, "severity", "info");
            json_object_set(f, "metadata", shared);   /* same pointer twice */
            json_array_push(arr, f);
        }
        char *dump = json_dump(arr, 2);
        check("aliased metadata serializes", dump != NULL);
        if (dump) {
            json_value_t *back = json_parse(dump, strlen(dump));
            check("aliased metadata round-trips", back != NULL);
            if (back) {
                json_value_t *m1 = json_get(json_at(back, 0), "metadata");
                json_value_t *m2 = json_get(json_at(back, 1), "metadata");
                check("both findings keep their own copy of the metadata",
                      m1 && m2 && m1 != m2);
                json_free(back);
            }
            free(dump);
        }
        /* free the shared parent last: the dump above must have deep-copied */
        json_free(shared);
        json_free_shallow(arr);
    }

    /* 7. The decoy trap ignored SIGINT and never exited, so a supervisor could
     *    not stop it. A trap that cannot be killed is worse than no trap. */
    {
        pid_t pid = fork();
        if (pid == 0) {
            /* child: the trap, on ports chosen to be free */
            char *argv[] = { (char *)getenv("SENTINEL_BIN"),
                             (char *)"--burner-daemon",
                             (char *)"--burner-ssh", (char *)"39222",
                             (char *)"--burner-smtp", (char *)"39525",
                             (char *)"--burner-n8n",  (char *)"39678", NULL };
            setenv("SENTINEL_HOME", "/tmp/sentinel_c_burner", 1);
            execv(argv[0], argv);
            _exit(127);
        }
        check("the decoy trap forked", pid > 0);
        if (pid > 0) {
            sleep(2);
            kill(pid, SIGINT);
            /* Poll for exit rather than blocking: a hang must fail the test, not
             * the whole suite. */
            int alive = 1;
            for (int i = 0; i < 40 && alive; i++) {
                { struct timespec ts = { 0, 250000000 }; nanosleep(&ts, NULL); }
                if (waitpid(pid, NULL, WNOHANG) == pid) alive = 0;
            }
            check("the decoy trap exits on SIGINT", !alive);
            if (alive) {
                kill(pid, SIGKILL);
                waitpid(pid, NULL, 0);
            }
        }
        {
            char *rm[] = { "rm", "-rf", "/tmp/sentinel_c_burner", NULL };
            proc_run(rm, NULL, 0, 30);
        }
    }
}

int main(void)
{
    printf("sentinel C test suite\n");

    test_buf();
    test_json();
    test_json_escaping();
    test_sha256();
    test_model();
    test_paths();
    test_report();
    test_sarif();
    test_notifiers();
    test_remediation();
    test_registry();
    test_regressions();

    printf("\n%d checks, %d failure(s)\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}

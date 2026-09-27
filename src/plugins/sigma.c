/* sigma.c — Detection-as-Code: Sigma rule evaluator.
 *
 * Ported from sentinel/core/plugins/sigma_plugin.py.
 *
 * The Python engine compiled five regexes per rule. C99 has no regex in the
 * standard library and POSIX <regex.h> is outside the dependency budget for
 * this port, so a rule is instead an OR-list of AND-lists of literal keywords
 * matched case-insensitively, with each keyword required to appear *after* the
 * previous one in the sample text. That is exactly what the original
 * `a.*b` alternatives expressed, minus the quantifier metacharacters
 * (see SIGMA-002 below for the one place that mattered).
 *
 * Rule sources, in precedence-free union:
 *   1. the built-in table below (always active; this is the Python behaviour);
 *   2. *.rules / *.sigma files under $SENTINEL_SIGMA_RULES, else
 *      $SENTINEL_HOME/sigma.
 * A missing/unreadable rules directory is reported as an informational note
 * and the built-in rules still run, so a default install behaves exactly like
 * the Python engine.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define SIGMA_TOOL        "sigma_rules"
#define SIGMA_MAX_ALTS    6      /* OR-branches per rule                  */
#define SIGMA_MAX_TOKENS  6      /* AND-keywords per branch               */
#define SIGMA_RULE_MAX    (256 * 1024)  /* refuse absurd rule files       */
#define SIGMA_MAX_PERFILE 256    /* rules harvested from one file         */

typedef struct {
    const char *id;
    const char *title;
    const char *mitre;
    const char *description;
    severity_t  severity;
    size_t      nalt;
    /* Each row is a NULL-terminated keyword list: one OR-branch. */
    const char *alt[SIGMA_MAX_ALTS][SIGMA_MAX_TOKENS + 1];
} sigma_rule_t;

/* ------------------------------------------------------------------------ */
/* Built-in rules — ids, titles, MITRE tags, severities and finding values
 * are byte-identical to BUILTIN_SIGMA_RULES in the Python module. Only the
 * `pattern` field changed representation.                          */

static const sigma_rule_t BUILTIN_RULES[] = {
    {
        "SIGMA-001", "Suspicious Interactive Reverse Shell Spawn", "T1059.004",
        "Detects interactive shell command line indicative of standard reverse shell payload.",
        SEV_CRITICAL, 5,
        {
            { "/bin/bash -i", NULL },
            { "/bin/sh -i", NULL },
            { "nc -e /bin/sh", NULL },
            { "& /dev/tcp/", NULL },
            { "bash -c", ">& /dev/tcp", NULL }
        }
    },
    {
        "SIGMA-002", "Encoded PowerShell Download Cradle", "T1059.001",
        "Detects encoded PowerShell or IEX download cradle used in payload delivery.",
        SEV_HIGH, 3,
        {
            /* Python required `powershell.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}`.
             * The 20-char base64 length check is dropped (it is the only
             * quantifier in the table); "-e" still covers -enc and
             * -encodedcommand because both contain it. */
            { "powershell", "-e", NULL },
            { "invoke-webrequest", "iex", NULL },
            { "downloadstring", NULL }
        }
    },
    {
        "SIGMA-003", "Shadow File Access or Credential Exfiltration", "T1003.008",
        "Detects command attempting to read or dump Linux shadow credential file.",
        SEV_CRITICAL, 4,
        {
            { "cat /etc/shadow", NULL },
            { "getent shadow", NULL },
            { "unshadow", NULL },
            { "grep", "/etc/shadow", NULL }
        }
    },
    {
        "SIGMA-004", "Dynamic Linker Preload Persistence (LD_PRELOAD)", "T1574.006",
        "Detects userland rootkit injection via ld.so.preload modification.",
        SEV_HIGH, 2,
        {
            { "echo", ">>", "/etc/ld.so.preload", NULL },
            { "ld_preload=", ".so", NULL }
        }
    },
    {
        "SIGMA-005", "Suspicious Download Tool Invocation via Web Service", "T1105",
        "Detects silent download and execute commands used by threat actors.",
        SEV_HIGH, 3,
        {
            { "curl -fssl", NULL },
            { "wget -qo-", NULL },
            { "certutil -urlcache -split -f", NULL }
        }
    }
};

#define SIGMA_BUILTIN_COUNT (sizeof(BUILTIN_RULES) / sizeof(BUILTIN_RULES[0]))

/* ------------------------------------------------------------------------ */

typedef struct {
    sigma_rule_t *v;
    size_t        n, cap;
} rule_set_t;

static int rules_push(rule_set_t *rs, const sigma_rule_t *r)
{
    if (rs->n == rs->cap) {
        size_t cap = rs->cap ? rs->cap * 2 : 16;
        sigma_rule_t *p = realloc(rs->v, cap * sizeof(*p));
        if (!p) return -1;
        rs->v = p;
        rs->cap = cap;
    }
    rs->v[rs->n++] = *r;
    return 0;
}

static void rules_free(rule_set_t *rs)
{
    free(rs->v);
    rs->v = NULL;
    rs->n = rs->cap = 0;
}

/* Offsets into the arena, not pointers: buf_t reallocates, so any pointer
 * captured mid-parse would dangle by the time the arena is released.
 *
 * The "is this field set" flags are explicit rather than encoded as a
 * zero offset: the first string in an arena legitimately sits at offset 0,
 * and treating that as "unset" silently drops the first rule in every file. */
typedef struct {
    size_t     id, title, mitre, description;
    size_t     alt[SIGMA_MAX_ALTS][SIGMA_MAX_TOKENS];
    size_t     nalttok[SIGMA_MAX_ALTS];
    size_t     nalt;
    severity_t severity;
    int        has_id, has_title, has_mitre, has_description;
    int        overflow;
} rule_offsets_t;

typedef struct {
    rule_offsets_t *v;
    size_t          n, cap;
} pending_set_t;

static int pending_push(pending_set_t *ps, const rule_offsets_t *r)
{
    if (ps->n == ps->cap) {
        size_t cap = ps->cap ? ps->cap * 2 : 16;
        rule_offsets_t *p = realloc(ps->v, cap * sizeof(*p));
        if (!p) return -1;
        ps->v = p;
        ps->cap = cap;
    }
    ps->v[ps->n++] = *r;
    return 0;
}

static void pending_free(pending_set_t *ps)
{
    free(ps->v);
    ps->v = NULL;
    ps->n = ps->cap = 0;
}

static size_t arena_put(buf_t *b, const char *s, size_t n)
{
    size_t off = b->len;
    buf_append(b, s, n);
    buf_putc(b, '\0');
    return off;
}

/* ------------------------------------------------------------------------ */

typedef struct {
    char  **v;
    size_t  n, cap;
} strlist_t;

static int strlist_push_owned(strlist_t *l, char *s)
{
    if (!s) return -1;
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 16;
        char **p = realloc(l->v, cap * sizeof(*p));
        if (!p) { free(s); return -1; }
        l->v = p;
        l->cap = cap;
    }
    l->v[l->n++] = s;
    return 0;
}

static void strlist_free(strlist_t *l)
{
    for (size_t i = 0; i < l->n; i++) free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

/* HTML-escape for anything that lands in a finding's `detail`/`value`.
 * The Python pipeline escaped at report time (report.py::_esc); this port
 * escapes at the point of ingestion per the porting contract's hard rule 5,
 * so the report renderer must not escape a second time. */
static char *esc_html(const char *s)
{
    buf_t b;
    buf_init(&b);
    for (const char *p = s ? s : ""; *p; p++) {
        switch (*p) {
            case '&': buf_puts(&b, "&amp;");  break;
            case '<': buf_puts(&b, "&lt;");   break;
            case '>': buf_puts(&b, "&gt;");   break;
            case '"': buf_puts(&b, "&quot;"); break;
            case '\'': buf_puts(&b, "&#39;"); break;
            default:  buf_putc(&b, *p);       break;
        }
    }
    return buf_release(&b);
}

/* One OR-branch: every keyword present, in order, case-insensitively.
 * `text` must already be lowercased; so must the keywords. */
static int alt_matches(const char *text, const char *const *kw)
{
    const char *p = text;
    for (size_t i = 0; kw[i]; i++) {
        const char *hit = strstr(p, kw[i]);
        if (!hit) return 0;
        p = hit + strlen(kw[i]);
    }
    return 1;
}

static int rule_matches(const sigma_rule_t *r, const char *lower_text)
{
    for (size_t a = 0; a < r->nalt; a++)
        if (alt_matches(lower_text, r->alt[a])) return 1;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Rule file parsing.
 *
 * Expected format (one rule per block, keys may repeat for `match`):
 *
 *   id: SIGMA-100
 *   title: Example
 *   mitre: T1059
 *   severity: high
 *   description: Free text.
 *   match: /dev/tcp | nc -e
 *   match: curl -fssl
 *
 * `match` values are OR-separated branches; whitespace inside a branch is an
 * AND-list matched in order, matching the built-in table's semantics.
 */

static void commit_rule(pending_set_t *ps, rule_offsets_t *cur, int have_id)
{
    if (!have_id || !cur->has_id || !cur->has_title || cur->nalt == 0 || cur->overflow)
        return;
    (void)pending_push(ps, cur);
    memset(cur, 0, sizeof(*cur));
}

/* A strtok_r work-alike without the global tokenizer state or the POSIX
 * feature-test macro: static cursor advanced across calls. Only ever used
 * inside parse_match_value(), which is single-threaded by construction. */
static char *strtok_space(char *s)
{
    static char *cur = NULL;
    if (s) cur = s;
    if (!cur) return NULL;
    while (*cur && isspace((unsigned char)*cur)) cur++;
    if (!*cur) { cur = NULL; return NULL; }
    char *tok = cur;
    while (*cur && !isspace((unsigned char)*cur)) cur++;
    if (*cur) *cur++ = '\0';
    return tok;
}

/* Split a match value on '|' into branches, each split on whitespace.
 * Tokenized in place so no global strtok state is involved. */
static void parse_match_value(rule_offsets_t *cur, buf_t *arena, const char *value)
{
    char *work = sstrdup(value);
    if (!work) { cur->overflow = 1; return; }

    char *branch = work;
    while (branch && *branch) {
        char *bar = strchr(branch, '|');
        char *next = NULL;
        if (bar) { *bar = '\0'; next = bar + 1; }

        if (cur->nalt < SIGMA_MAX_ALTS) {
            size_t g = cur->nalt;
            size_t k = 0;
            for (char *tok = strtok_space(branch); tok; tok = strtok_space(NULL)) {
                if (k >= SIGMA_MAX_TOKENS) { cur->overflow = 1; break; }
                char low[256];
                str_lower(tok, low, sizeof(low));
                cur->alt[g][k] = arena_put(arena, low, strlen(low));
                k++;
            }
            if (!cur->overflow) {
                cur->nalttok[g] = k;
                cur->nalt++;
            }
        } else {
            cur->overflow = 1;
        }
        branch = next;
    }
    free(work);
}

static void parse_rule_text(pending_set_t *ps, buf_t *arena, const char *text)
{
    char  *copy = sstrdup(text);
    if (!copy) return;

    rule_offsets_t cur;
    memset(&cur, 0, sizeof(cur));
    int have_id = 0;

    char *line = copy;
    while (*line) {
        char *nl = strchr(line, '\n');
        char *next = NULL;
        if (nl) { *nl = '\0'; next = nl + 1; }

        str_trim(line);
        if (*line && *line != '#') {
            char *colon = strchr(line, ':');
            if (colon) {
                *colon = '\0';
                char *key = str_trim(line);
                char *val = str_trim(colon + 1);
                if (str_ieq(key, "id")) {
                    commit_rule(ps, &cur, have_id);
                    if (val && *val) {
                        cur.id = arena_put(arena, val, strlen(val));
                        cur.has_id = 1;
                        have_id = 1;
                    }
                } else if (str_ieq(key, "title")) {
                    if (val && *val) {
                        cur.title = arena_put(arena, val, strlen(val));
                        cur.has_title = 1;
                    }
                } else if (str_ieq(key, "mitre")) {
                    if (val && *val) {
                        cur.mitre = arena_put(arena, val, strlen(val));
                        cur.has_mitre = 1;
                    }
                } else if (str_ieq(key, "description")) {
                    if (val && *val) {
                        cur.description = arena_put(arena, val, strlen(val));
                        cur.has_description = 1;
                    }
                } else if (str_ieq(key, "severity")) {
                    severity_t s = severity_parse(val);
                    /* An unrecognised word is a rule-authoring mistake, not an
                     * emergency: fall back to medium rather than dropping the
                     * rule or reporting it as unknown severity. */
                    cur.severity = (s == SEV_UNKNOWN) ? SEV_MEDIUM : s;
                } else if (str_ieq(key, "match")) {
                    if (val && *val) parse_match_value(&cur, arena, val);
                }
            }
        }

        if (!next) break;
        line = next;
    }
    free(copy);
    commit_rule(ps, &cur, have_id);
}

static int has_rule_suffix(const char *name)
{
    size_t n = strlen(name);
    return (n > 6 && strcmp(name + n - 6, ".rules") == 0) ||
           (n > 6 && strcmp(name + n - 6, ".sigma") == 0);
}

static int is_regular_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Harvest every rule file in `dir` into `rs`. All files share one arena that
 * is frozen exactly once at the end, so rule strings stay valid for the whole
 * plugin run and the caller frees a single block via *arena_out. */
static void load_rules_dir(rule_set_t *rs, const char *dir, buf_t *arena,
                           char **arena_out, size_t *n_loaded)
{
    DIR *d = opendir(dir);
    if (!d) return;

    pending_set_t ps;
    memset(&ps, 0, sizeof(ps));

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (!has_rule_suffix(de->d_name)) continue;

        char path[4096];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        if (!is_regular_file(path)) continue;

        long sz = file_size(path);
        if (sz < 0 || sz > SIGMA_RULE_MAX) continue;

        size_t len = 0;
        char *text = read_file(path, &len);
        if (!text) continue;

        parse_rule_text(&ps, arena, text);
        free(text);
    }
    closedir(d);

    if (ps.n == 0) { pending_free(&ps); return; }

    /* Freeze the arena: offsets recorded during parsing become stable
     * pointers, and the base must outlive every rule built from it. */
    char *base = buf_release(arena);
    for (size_t i = 0; i < ps.n; i++) {
        const rule_offsets_t *o = &ps.v[i];
        sigma_rule_t r;
        memset(&r, 0, sizeof(r));
        r.id = base + o->id;
        r.title = base + o->title;
        r.mitre = o->has_mitre ? base + o->mitre : "";
        r.description = o->has_description ? base + o->description : base + o->title;
        r.severity = o->severity;
        r.nalt = o->nalt;
        for (size_t a = 0; a < o->nalt; a++) {
            r.alt[a][o->nalttok[a]] = NULL;   /* terminator */
            for (size_t k = 0; k < o->nalttok[a]; k++)
                r.alt[a][k] = base + o->alt[a][k];
        }
        if (rules_push(rs, &r) == 0) (*n_loaded)++;
    }
    pending_free(&ps);
    *arena_out = base;
}

/* ------------------------------------------------------------------------ */

static void emit_match(orchestrator_t *ctx, const char *target,
                       const sigma_rule_t *r)
{
    char *esc_id = esc_html(r->id);
    char *esc_title = esc_html(r->title);
    char *esc_mitre = esc_html(r->mitre);
    char *esc_desc = esc_html(r->description);

    buf_t v;
    buf_init(&v);
    buf_printf(&v, "Sigma Match [%s]: %s", esc_id, esc_title);

    finding_t *f = finding_new(SIGMA_TOOL, FT_VULNERABILITY, v.data, target, r->severity);
    buf_free(&v);

    if (f) {
        buf_t d;
        buf_init(&d);
        buf_printf(&d, "%s (MITRE ATT&CK: %s)", esc_desc, esc_mitre);
        finding_set_detail(f, d.data);
        buf_free(&d);

        /* Metadata is serialized as JSON, so the JSON writer does the
         * escaping here — no manual HTML escaping. */
        json_value_t *meta = json_object();
        json_object_set_str(meta, "sigma_id", r->id);
        json_object_set_str(meta, "mitre_technique", r->mitre);
        json_object_set_str(meta, "title", r->title);
        finding_set_meta(f, meta);
        orch_add(ctx, f);
    }

    free(esc_id);
    free(esc_title);
    free(esc_mitre);
    free(esc_desc);
}

static void emit_engine_status(orchestrator_t *ctx, const char *target, size_t n_rules)
{
    buf_t v;
    buf_init(&v);
    buf_printf(&v, "Sigma Detection Engine (%zu community rules)", n_rules);

    finding_t *f = finding_new(SIGMA_TOOL, FT_HARDENING, v.data, target, SEV_INFO);
    buf_free(&v);
    if (!f) return;

    buf_t d;
    buf_init(&d);
    buf_printf(&d, "Sigma Detection-as-Code engine active with %zu MITRE ATT&CK mapped rules.",
               n_rules);
    finding_set_detail(f, d.data);
    buf_free(&d);

    json_value_t *meta = json_object();
    json_object_set_num(meta, "rule_count", (double)n_rules);
    json_object_set_str(meta, "status", "active");
    finding_set_meta(f, meta);
    orch_add(ctx, f);
}

static int run(orchestrator_t *ctx, const char *target)
{
    rule_set_t rs;
    memset(&rs, 0, sizeof(rs));

    for (size_t i = 0; i < SIGMA_BUILTIN_COUNT; i++) {
        if (rules_push(&rs, &BUILTIN_RULES[i]) != 0) {
            orch_note(ctx, SIGMA_TOOL, "sigma: out of memory loading built-in rules",
                      target, "Rule set allocation failed; detection engine inactive.");
            rules_free(&rs);
            return 0;
        }
    }

    const char *env_dir = getenv("SENTINEL_SIGMA_RULES");
    const char *dir = (env_dir && *env_dir) ? env_dir : paths_state_path("sigma");

    buf_t arena;
    buf_init(&arena);
    char *arena_base = NULL;
    size_t n_loaded = 0;
    load_rules_dir(&rs, dir, &arena, &arena_base, &n_loaded);
    buf_free(&arena);

    if (n_loaded == 0) {
        char *esc_dir = esc_html(dir ? dir : "");
        buf_t v;
        buf_init(&v);
        buf_printf(&v, "sigma: no external rule directory at %s", esc_dir);
        orch_note(ctx, SIGMA_TOOL, v.data, target,
                  "Built-in Sigma rules are still active; drop *.rules files there to extend coverage.");
        buf_free(&v);
        free(esc_dir);
    }

    /* Snapshot the sample texts before emitting: orch_add() appends to the
     * very list we are walking, so matching while emitting would iterate a
     * list that grows underneath it. */
    strlist_t samples;
    memset(&samples, 0, sizeof(samples));
    for (const finding_t *f = ctx->findings; f; f = f->next) {
        buf_t b;
        buf_init(&b);
        buf_puts(&b, f->value);
        buf_putc(&b, ' ');
        buf_puts(&b, f->detail);
        buf_putc(&b, ' ');
        const char *cmdline = json_get_str(f->metadata, "cmdline");
        if (cmdline) buf_puts(&b, cmdline);
        char *raw = buf_release(&b);

        char *lower = malloc(strlen(raw) + 1);
        if (lower) {
            str_lower(raw, lower, strlen(raw) + 1);
            if (strlist_push_owned(&samples, lower) != 0) free(lower);
        }
        free(raw);
    }

    unsigned char *seen = rs.n ? calloc(rs.n, 1) : NULL;
    for (size_t s = 0; s < samples.n; s++) {
        for (size_t i = 0; i < rs.n; i++) {
            if (seen && seen[i]) continue;   /* Python's matched_rules set */
            if (!rule_matches(&rs.v[i], samples.v[s])) continue;
            if (seen) seen[i] = 1;
            emit_match(ctx, target, &rs.v[i]);
        }
    }

    emit_engine_status(ctx, target, rs.n);

    free(seen);
    strlist_free(&samples);
    free(arena_base);
    rules_free(&rs);
    return 0;
}

const plugin_t sigma_plugin = {
    SIGMA_TOOL,
    "Detection-as-Code engine evaluating Sigma rules mapped to MITRE ATT&CK",
    STAGE_AUDIT,
    { NULL },
    run
};

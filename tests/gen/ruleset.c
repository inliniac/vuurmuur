/* Tier 1: generate a ruleset from a fixture tree and compare it against the
 * golden file. Nothing runs as root and no iptables is needed. */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vuurmuur.h"
#include "main.h"

#include "sandbox.h"
#include "tap.h"
#include "vrmr_test.h"

static char actual[768 * 1024];

static struct vrmr_ctx vctx;

/* one assertion, with a formatted description */
static void t_ok(int cond, const char *fmt, ...) ATTR_FMT_PRINTF(2, 3);

static void t_ok(int cond, const char *fmt, ...)
{
    char msg[512] = "";
    va_list ap;

    va_start(ap, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    tap_ok(cond, msg);
}

static char *read_file(const char *path, size_t *len)
{
    struct stat st;
    char *buf;
    FILE *fp = fopen(path, "r");

    *len = 0;

    if (fp == NULL)
        return NULL;

    if (fstat(fileno(fp), &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_size > 64 * 1024 * 1024) {
        fclose(fp);
        return NULL;
    }

    if ((buf = malloc((size_t)st.st_size + 1)) == NULL) {
        fclose(fp);
        return NULL;
    }

    *len = fread(buf, 1, (size_t)st.st_size, fp);
    buf[*len] = '\0';
    fclose(fp);

    return buf;
}

/* First line that differs, with one line of context from both sides. */
static void report_diff(const char *want, const char *got)
{
    char wl[256] = "", gl[256] = "";
    size_t line = 1, n = 0;
    const char *a = want, *b = got;

    while (*a != '\0' && *b != '\0' && *a == *b) {
        if (*a == '\n')
            line++;
        a++;
        b++;
    }

    for (n = 0; n < sizeof(wl) - 2 && a[n] != '\0' && a[n] != '\n'; n++)
        wl[n] = a[n];
    for (n = 0; n < sizeof(gl) - 2 && b[n] != '\0' && b[n] != '\n'; n++)
        gl[n] = b[n];

    tap_note("first difference at line %zu", line);
    tap_note("golden: %s", wl);
    tap_note("actual: %s", gl);
}

static int write_file(const char *path, const char *buf, size_t len)
{
    FILE *fp = fopen(path, "w");

    if (fp == NULL) {
        fprintf(stderr, "cannot write %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (fwrite(buf, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/* One full pass over the fixture: context, config, objects, analyze, apply, then render
 * into `actual`. Returns the rendered length or -1 after reporting. It tears its own
 * context down, so a case can be generated twice from one sandbox - which is how the
 * driver shows generation is a function of the fixture rather than of the run. */
static int generate_once(const char *name)
{
    int len, result;

    if (vrmr_test_setup_ctx(&vctx, "vuurmuur") != 0) {
        t_ok(0, "%s: vrmr_test_setup_ctx failed", name);
        return -1;
    }

    result = vrmr_init_config(&vctx.conf);
    if (result < VRMR_CNF_OK) {
        t_ok(0, "%s: config result %d", name, result);
        return -1;
    }

    /* normally set in main() of the daemon */
    (void)strlcpy(version_string, VUURMUUR_VERSION, sizeof(version_string));

    /* the capability probe cannot answer meaningfully here: assume a kernel
     * with everything the engine uses, which is what production targets */
    vctx.conf.vrmr_check_iptcaps = FALSE;

    if (vrmr_backends_load(&vctx.conf, &vctx) < 0) {
        t_ok(0, "%s: vrmr_backends_load failed", name);
        return -1;
    }
    if (vrmr_services_load(&vctx, &vctx.services, &vctx.reg) < 0) {
        t_ok(0, "%s: vrmr_services_load failed", name);
        return -1;
    }
    if (vrmr_interfaces_load(&vctx, &vctx.interfaces) < 0) {
        t_ok(0, "%s: vrmr_interfaces_load failed", name);
        return -1;
    }
    if (vrmr_zones_load(&vctx, &vctx.zones, &vctx.interfaces, &vctx.reg) < 0) {
        t_ok(0, "%s: vrmr_zones_load failed", name);
        return -1;
    }

    (void)vrmr_blocklist_init_list(&vctx, &vctx.conf, &vctx.zones,
            &vctx.blocklist, /*load_ips*/ FALSE, /*no_refcnt*/ FALSE);

    if (vrmr_rules_init_list(&vctx, &vctx.conf, &vctx.rules, &vctx.reg) < 0) {
        t_ok(0, "%s: vrmr_rules_init_list failed", name);
        return -1;
    }

    /* only the apply phase is interesting: loading created no ruleset */
    vrmr_test_effects_reset();

    if (analyze_all_rules(&vctx, &vctx.rules) < 0) {
        t_ok(0, "%s: analyze_all_rules failed", name);
        return -1;
    }
    if (load_ruleset(&vctx) < 0) {
        t_ok(0, "%s: load_ruleset failed", name);
        return -1;
    }

    len = vrmr_test_render(actual, sizeof(actual));
    if (len < 0) {
        t_ok(0, "%s: render overflow", name);
        return -1;
    }

    (void)vrmr_backends_unload(&vctx.conf, &vctx);
    vrmr_rules_cleanup_list(&vctx.rules);
    vrmr_destroy_zonedatalist(&vctx.zones);
    vrmr_destroy_interfaceslist(&vctx.interfaces);
    vrmr_destroy_serviceslist(&vctx.services);
    vrmr_test_teardown_ctx(&vctx);

    if (len < 0) {
        t_ok(0, "%s: render overflow", name);
        return -1;
    }

    return len;
}

/* Count and echo the fixture complaints the capture layer recorded. */
static int fixture_problems(const char *artifact)
{
    const char *p = artifact;
    static const char *const marks[] = {"# no fixture:", "# bad fixture:",
        "# unreadable:", "# too large:", NULL};
    int n = 0, i;

    while ((p = strstr(p, "\n#")) != NULL) {
        p++;
        for (i = 0; marks[i] != NULL; i++) {
            if (strncmp(p, marks[i], strlen(marks[i])) == 0) {
                const char *e = strchr(p, '\n');

                tap_note("%.*s", (int)(e != NULL ? (size_t)(e - p) : strlen(p)),
                        p);
                n++;
                break;
            }
        }
    }

    return n;
}

static int run_case(const char *cases_dir, const char *golden_dir,
        const char *name, int update)
{
    char golden_path[PATH_MAX], path[PATH_MAX];
    char *golden = NULL, *first = NULL;
    size_t golden_len = 0;
    int len = 0, len2 = 0, n_bad = 0;

    snprintf(golden_path, sizeof(golden_path), "%s/%s.txt", golden_dir, name);

    if (vrmr_test_sandbox_setup(cases_dir, name) != 0) {
        t_ok(0, "%s: sandbox setup failed", name);
        goto out;
    }

    tap_note("== %s", name);

    len = generate_once(name);
    if (len < 0)
        goto out;

    /* A read with no fixture answers as an empty listing, which is what a
     * kernel without the table answers too, so the commands alone cannot tell
     * the two apart. The names are in the artifact's # fixtures block, and such
     * a generation must not become truth - least of all under --update. */
    n_bad = fixture_problems(actual);
    if (n_bad > 0) {
        t_ok(0, "%s: %d fixture problem(s), golden untouched", name, n_bad);
        goto out;
    }

    /* A golden is only an oracle if generation is a function of the fixture. Snapshot one
     * pass, run it again from the same sandbox, and require the two to be byte-identical: a
     * difference is a dependence the corpus would freeze in place, and a golden that moves
     * between runs is worth less than no golden. */
    first = malloc((size_t)len + 1);
    if (first == NULL) {
        t_ok(0, "%s: out of memory", name);
        goto out;
    }
    memcpy(first, actual, (size_t)len);

    len2 = generate_once(name);
    if (len2 < 0)
        goto out;

    t_ok(len2 == len && memcmp(first, actual, (size_t)len) == 0,
        "%s: two generations of one fixture are byte-identical (%d vs %d bytes)",
        name, len, len2);


    if (update) {
        if (write_file(golden_path, actual, (size_t)len) != 0) {
            t_ok(0, "%s: cannot write golden", name);
            goto out;
        }
        t_ok(1, "%s (golden written)", name);
        goto out;
    }

    if ((golden = read_file(golden_path, &golden_len)) == NULL) {
        t_ok(0, "%s: no golden in %s", name, golden_path);
        goto out;
    }

    if (golden_len == (size_t)len && memcmp(golden, actual, (size_t)len) == 0) {
        t_ok(1, "%s: matches golden", name);
    } else {
        /* into the build dir, not beside the goldens: a diff dump that reads
         * like a golden invites the wrong fix */
        (void)mkdir("failures", 0755);
        snprintf(path, sizeof(path), "failures/%s.txt", name);
        (void)write_file(path, actual, strlen(actual));
        t_ok(0, "%s: ruleset differs (see %s)", name, path);
        report_diff(golden, actual);
    }

out:
    free(golden);
    free(first);
    vrmr_test_sandbox_teardown();

    return 0;
}

int main(int argc, char **argv)
{
    const char *cases_dir = NULL, *golden_dir = NULL;
    int i, update = 0, failed = 0;

    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <cases-dir> <golden-dir> [--update] [case...]\n",
                argv[0]);
        return 2;
    }

    cases_dir = argv[1];
    golden_dir = argv[2];

    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--update") == 0)
            update = 1;
    }

    for (i = 3; i < argc; i++) {
        int r;

        if (strcmp(argv[i], "--update") == 0)
            continue;

        r = run_case(cases_dir, golden_dir, argv[i], update);
        if (r < 0)
            failed = 1;
    }

    return (tap_finish() != 0 || failed) ? 1 : 0;
}

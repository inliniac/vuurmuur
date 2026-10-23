/* Sandbox for the generation tests: fixture copy, path rooting and capture of
 * everything the tools would have run. */

#include "config.h"

#include <ctype.h>
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "vuurmuur.h"
#include "vrmr_exec_priv.h"

#include "sandbox.h"

#define MAX_EFFECTS 2048

/* what a proc file holds before the engine has said anything to it */
#define PROC_STUB "9\n"
#define MAX_REF 4
#define RENDER_SIZE (4u * 1024u * 1024u)

struct ref {
    char token[48];
    char *content;
};

struct effect {
    char *line;
    struct ref ref[MAX_REF];
    int n_ref;
};

static struct effect effects[MAX_EFFECTS];
static int n_effects;

static char sb[PATH_MAX] = "";
static char sb_tmp[PATH_MAX + 64] = "";
static char sb_proc[PATH_MAX + 64] = "";
static char canned[PATH_MAX + 64] = "";
static char canned_common[PATH_MAX + 64] = "";

/* Reads whose canned answer is missing or unusable, first-seen order, deduped.
 * The engine cannot tell an absent fixture from a kernel without the table -
 * both give it an empty listing - so the fact has to reach the artifact. */
static char *fix_problems[64];
static int n_fix_problems;

static char *render_buf;

static int cap_pipe(
        struct vrmr_config *cnf, const char *command, char ignore_error);
static int cap_exec(struct vrmr_config *cnf, const char *path,
        const char *argv[], char *output[]);
static int cap_read(
        struct vrmr_config *cnf, const char *command, char *buf, size_t size);
static void fixture_problem(const char *fmt, ...);

static const struct vrmr_exec_ops cap_ops = {
        .pipe = cap_pipe,
        .exec = cap_exec,
        .read = cap_read,
};

static void mkdir_p(const char *path);

static void mkdir_mode(const char *path)
{
    if (mkdir(path, 0700) == 0) {
        /* the umask may have eaten bits the tools insist on */
        (void)chmod(path, 0700);
    } else if (errno != EEXIST) {
        fprintf(stderr, "sandbox: mkdir %s: %s\n", path, strerror(errno));
    }
}

static void mkdir_p_for_file(const char *path)
{
    char dir[PATH_MAX + 128];
    const char *slash = strrchr(path, '/');

    if (slash == NULL)
        return;

    (void)strlcpy(dir, path, sizeof(dir));
    dir[slash - path] = '\0';
    mkdir_p(dir);
}

static void mkdir_p(const char *path)
{
    char dir[PATH_MAX];
    char *p;

    (void)strlcpy(dir, path, sizeof(dir));

    for (p = dir + 1; *p != '\0'; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        mkdir_mode(dir);
        *p = '/';
    }

    mkdir_mode(dir);
}

static char *slurp(const char *path, size_t *len)
{
    struct stat st;
    char *buf;
    size_t n = 0;
    FILE *fp = fopen(path, "r");

    *len = 0;

    if (fp == NULL)
        return NULL;

    if (fstat(fileno(fp), &st) == 0 && S_ISREG(st.st_mode))
        n = (size_t)st.st_size;

    /* headroom: normalizing a buffer in place can make it longer */
    if ((buf = malloc(n + 256)) == NULL) {
        fclose(fp);
        return NULL;
    }

    n = fread(buf, 1, n, fp);
    buf[n] = '\0';
    fclose(fp);
    *len = n;

    return buf;
}

/* Fixtures name the sandbox root as @SB@ because it is only known at run
 * time. */
static char *expand_sb(char *buf)
{
    char *out, *p, *o;
    size_t n = 0;

    if (strstr(buf, "@SB@") == NULL)
        return buf;

    for (p = buf, n = 0; *p != '\0'; p++)
        n += strncmp(p, "@SB@", 4) == 0 ? strlen(sb) + 1 : 1;

    if ((out = o = malloc(n + 1)) == NULL) {
        free(buf);
        return NULL;
    }

    for (p = buf; *p != '\0'; p++) {
        if (strncmp(p, "@SB@", 4) == 0) {
            memcpy(o, sb, strlen(sb));
            o += strlen(sb);
            p += 3;
            continue;
        }
        *o++ = *p;
    }
    *o = '\0';

    free(buf);

    return out;
}

static int copy_tree(const char *from, const char *to)
{
    DIR *d;
    struct dirent *de;
    struct stat st;
    char src[PATH_MAX], dst[PATH_MAX];

    if (stat(from, &st) != 0)
        return 0; /* nothing to copy */

    mkdir_p(to);

    if ((d = opendir(from)) == NULL) {
        fprintf(stderr, "sandbox: opendir %s: %s\n", from, strerror(errno));
        return -1;
    }

    while ((de = readdir(d)) != NULL) {
        char *content;
        size_t len = 0;
        FILE *out;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        snprintf(src, sizeof(src), "%s/%s", from, de->d_name);
        snprintf(dst, sizeof(dst), "%s/%s", to, de->d_name);

        if (stat(src, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            if (copy_tree(src, dst) != 0)
                goto err;
            continue;
        }
        if (!S_ISREG(st.st_mode))
            continue;

        if ((content = slurp(src, &len)) == NULL)
            goto err;

        if ((content = expand_sb(content)) == NULL)
            goto err;
        len = strlen(content);

        if ((out = fopen(dst, "w")) == NULL) {
            fprintf(stderr, "sandbox: %s: %s\n", dst, strerror(errno));
            free(content);
            goto err;
        }

        if (fwrite(content, 1, len, out) != len) {
            fprintf(stderr, "sandbox: %s: %s\n", dst, strerror(errno));
            fclose(out);
            free(content);
            goto err;
        }

        /* git only stores the exec bit, so set the modes the tools want */
        (void)fchmod(fileno(out), 0600);
        fclose(out);
        free(content);
    }

    closedir(d);
    return 0;

err:
    closedir(d);
    return -1;
}

/* Splice out n bytes at p and put tok there. */
static void splice_str(char *p, size_t n, const char *tok)
{
    size_t rest = strlen(p + n);
    size_t t = strlen(tok);

    memmove(p + t, p + n, rest + 1);
    memcpy(p, tok, t);
}

/* Collapse the sandbox prefix and the mkstemp names. The sandbox goes first:
 * its mkdtemp suffix looks exactly like a ruleset tempfile. */
static void squash(char *s)
{
    char *p;

    if (sb_tmp[0] != '\0') {
        p = s;
        while ((p = strstr(p, sb_tmp)) != NULL) {
            splice_str(p, strlen(sb_tmp), "<TMP>");
            p += 5;
        }
    }

    if (sb[0] != '\0') {
        p = s;
        while ((p = strstr(p, sb)) != NULL) {
            splice_str(p, strlen(sb), "<SB>");
            p += 4;
        }
    }

    p = s;
    while ((p = strstr(p, "/vuurmuur")) != NULL) {
        const char *tok = NULL;
        size_t n = 0;

        if (strncmp(p, "/vuurmuur-load-result-", 22) == 0) {
            tok = "/<RESULT>";
            n = 22;
        } else if (strncmp(p, "/vuurmuur-shape-", 16) == 0) {
            tok = "/<SHAPE>";
            n = 16;
        } else if (strncmp(p, "/vuurmuur-", 10) == 0) {
            tok = "/<RULESET>";
            n = 10;
        }

        if (tok == NULL) {
            p += 9;
            continue;
        }

        while (isalnum((unsigned char)p[n]))
            n++;

        splice_str(p, n, tok);
        p += strlen(tok);
    }
}

/* RULESET, SHAPE or RESULT for the basename of a tempfile */
static const char *tmpfile_token(const char *path)
{
    const char *base = strrchr(path, '/');

    if (base == NULL)
        base = path;
    else
        base++;

    if (strncmp(base, "vuurmuur-load-result-", 21) == 0)
        return "RESULT";
    if (strncmp(base, "vuurmuur-shape-", 15) == 0)
        return "SHAPE";
    if (strncmp(base, "vuurmuur-", 9) == 0)
        return "RULESET";

    return base;
}

void vrmr_test_normalize(char *dst, size_t size, const char *src)
{
    char *banner;
    char *version;

    (void)strlcpy(dst, src, size);
    squash(dst);

    /* the banner carries the build version */
    if ((banner = strstr(dst, "Generated by Vuurmuur ")) != NULL &&
            (version = strstr(banner, " (c)")) != NULL) {
        banner += strlen("Generated by Vuurmuur ");
        splice_str(banner, (size_t)(version - banner), "<version>");
    }
}

static void effect_free(struct effect *e)
{
    int i;

    free(e->line);
    for (i = 0; i < e->n_ref; i++)
        free(e->ref[i].content);

    e->line = NULL;
    e->n_ref = 0;
}

void vrmr_test_effects_reset(void)
{
    int i;

    for (i = 0; i < n_fix_problems; i++) {
        free(fix_problems[i]);
        fix_problems[i] = NULL;
    }
    n_fix_problems = 0;

    for (i = 0; i < n_effects; i++) {
        effect_free(&effects[i]);
    }
    n_effects = 0;
}

/* Whitespace-delimited token at *pp; *pp lands on the byte after it. */
static size_t take_token(const char **pp, char *out, size_t size)
{
    size_t n = 0;

    while (**pp != '\0' && isspace((unsigned char)**pp))
        (*pp)++;

    while (**pp != '\0' && !isspace((unsigned char)**pp) && n < size - 1)
        out[n++] = *(*pp)++;

    out[n] = '\0';

    return n;
}

/* RULESET and SHAPE are inputs the golden has to carry. RESULT is a sink for
 * stderr, and anything else is not a sandbox tempfile. */
static int is_pinned_tempfile(const char *path)
{
    const char *token = tmpfile_token(path);

    return strcmp(token, "RULESET") == 0 || strcmp(token, "SHAPE") == 0;
}

static int dump_ref(struct effect *e, const char *path)
{
    char token[48] = "";
    char *content;
    size_t len = 0;
    int i, seen = 1;

    if ((content = slurp(path, &len)) == NULL) {
        /* a section that is simply absent is the same silent failure this whole
         * mechanism exists to close, so it is a complaint, not a warning */
        fixture_problem("# unreadable: %s (%s)", tmpfile_token(path),
                strerror(errno));
        return -1;
    }

    (void)strlcpy(token, tmpfile_token(path), sizeof(token));
    for (i = 0; i < n_effects; i++) {
        int r;
        for (r = 0; r < effects[i].n_ref; r++) {
            if (strcmp(effects[i].ref[r].token, token) == 0)
                seen++;
        }
    }
    if (seen > 1) {
        char numbered[96] = "";

        snprintf(numbered, sizeof(numbered), "%s-%d", token, seen);
        (void)strlcpy(token, numbered, sizeof(token));
    }

    vrmr_test_normalize(content, len + 256, content);
    (void)strlcpy(e->ref[e->n_ref].token, token, sizeof(e->ref[0].token));
    e->ref[e->n_ref].content = content;
    e->n_ref++;

    return 0;
}

/* Record one command and snapshot the files it consumes: by the time the test
 * looks, the ruleset and shaping tempfiles are gone. Repeats of the same token
 * are numbered so a v4 and a v6 ruleset cannot be confused. */
static void record(const char *command)
{
    struct effect *e;
    const char *p;

    if (n_effects >= MAX_EFFECTS) {
        fprintf(stderr, "sandbox: too many effects\n");
        return;
    }

    e = &effects[n_effects];
    memset(e, 0, sizeof(*e));

    if ((e->line = strdup(command)) == NULL)
        return;

    for (p = strstr(command, " < "); p != NULL && e->n_ref < MAX_REF;
            p = strstr(p + 1, " < ")) {
        char path[PATH_MAX + 64] = "";

        p += 3;
        (void)take_token(&p, path, sizeof(path));
        (void)dump_ref(e, path);
    }

    /* A tempfile passed as an argument carries no delimiter: the engine runs
     * the shaping script as `bash <SHAPE>`, so the argv sweep is the only thing
     * that pins the second file it writes. Redirect targets were collected
     * above. */
    for (p = command; *p != '\0' && e->n_ref < MAX_REF; ) {
        char path[PATH_MAX + 64] = "";
        char probe[PATH_MAX + 80] = "";
        const char *start = p;

        if (take_token(&p, path, sizeof(path)) == 0) {
            if (p == start)
                p++;            /* no whitespace and no token: stall guard */
            continue;
        }
        if (path[0] != '/' || !is_pinned_tempfile(path))
            continue;
        if (snprintf(probe, sizeof(probe), " < %s", path) > 0 &&
                strstr(command, probe) != NULL)
            continue;
        (void)dump_ref(e, path);
    }

    squash(e->line);
    n_effects++;
}

static int cap_pipe(
        struct vrmr_config *cnf, const char *command, char ignore_error)
{
    char line[3 * VRMR_MAX_PIPE_COMMAND + 16] = "";

    (void)cnf;
    (void)ignore_error;

    snprintf(line, sizeof(line), "pipe: %s", command);
    record(line);

    return 0;
}

static int cap_exec(struct vrmr_config *cnf, const char *path,
        const char *argv[], char *output[])
{
    char line[8 * 1024] = "";
    size_t n = 0;
    int i;

    (void)cnf;
    (void)output;

    n += (size_t)snprintf(line, sizeof(line), "exec: %s", path);
    for (i = 1; argv != NULL && argv[i] != NULL && n < sizeof(line) - 64; i++)
        n += (size_t)snprintf(line + n, sizeof(line) - n, " %s", argv[i]);

    record(line);

    return 0;
}

/* iptables -t <table> -nL and friends: answer from the case fixtures so the
 * generated ruleset does not depend on the host. No fixture means an empty
 * table, which is a freshly booted system. */
/* Which canned answer a read wants. The counter reads carry no -t, so keying
 * only on the table left them unreachable; listings are per table and family. */
static const char *read_fixture(const char *command, char *key, size_t size)
{
    const char *p;
    char name[64] = "", ip6[4] = "";
    size_t n = 0;

    for (p = command; *p != '\0' && *p != ' '; p++) {
        if (strncmp(p, "ip6tables", 9) == 0)
            (void)strlcpy(ip6, "ip6", sizeof(ip6));
    }

    if ((p = strstr(command, " -vnL ")) != NULL) {
        p += 6;
        while (*p != '\0' && !isspace((unsigned char)*p) && n < sizeof(name) - 1)
            name[n++] = *p++;
        name[n] = '\0';

        return snprintf(key, size, "%s%s-counters.txt", ip6, name) < (int)size
            ? "counters" : NULL;
    }

    n = 0;
    if ((p = strstr(command, " -t ")) != NULL) {
        p += 4;
        while (*p != '\0' && !isspace((unsigned char)*p) && n < sizeof(name) - 1)
            name[n++] = *p++;
    }
    if (n == 0)
        (void)strlcpy(name, "filter", sizeof(name));
    name[n] = '\0';

    return snprintf(key, size, "%s%s-nL.txt", ip6, name) < (int)size
        ? "listing" : NULL;
}

/* iptables prints a column header before any rule line, and the parsers anchor
 * on it: a fixture without one cannot be answered truthfully */
static int listing_has_header(const char *content)
{
    const char *p = content;

    while ((p = strstr(p, "target")) != NULL) {
        if (strstr(p, "prot") != NULL)
            return 1;
        p += 6;
    }

    return 0;
}

static int cap_read(
        struct vrmr_config *cnf, const char *command, char *buf, size_t size)
{
    char key[128] = "";
    char file[PATH_MAX + 160] = ""; /* root + key, so the join cannot truncate */
    const char *kind;
    char *content;
    size_t len = 0;
    int r = 0;

    (void)cnf;

    kind = read_fixture(command, key, sizeof(key));
    if (kind == NULL) {
        fixture_problem("# no fixture: (unclassified read) %s", command);
        buf[0] = '\0';
        return 0;
    }

    /* the case overrides the canned state every case builds on */
    (void)snprintf(file, sizeof(file), "%s/%s", canned, key);
    if (access(file, R_OK) != 0) {
        (void)snprintf(file, sizeof(file), "%s/%s", canned_common, key);
        if (access(file, R_OK) != 0) {
            fixture_problem("# no fixture: iptables/%s", key);
            buf[0] = '\0';
            return 0;
        }
    }

    if ((content = slurp(file, &len)) == NULL) {
        fixture_problem("# unreadable: iptables/%s (%s)", key, strerror(errno));
        buf[0] = '\0';
        return 0;
    }

    if (strcmp(kind, "counters") == 0 && !listing_has_header(content)) {
        fixture_problem("# bad fixture: iptables/%s: no column header", key);
        free(content);
        buf[0] = '\0';
        return 0;
    }

    if (len >= size) {
        fixture_problem("# too large: iptables/%s", key);
        r = -1;
    } else {
        memcpy(buf, content, len);
        buf[len] = '\0';
        r = (int)len;
    }
    free(content);

    return r;
}

static void fixture_problem(const char *fmt, ...)
{
    va_list ap;
    char line[PATH_MAX + 128] = "";
    int i;

    if (n_fix_problems >= (int)(sizeof(fix_problems) / sizeof(fix_problems[0])))
        return;

    va_start(ap, fmt);
    (void)vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    for (i = 0; i < n_fix_problems; i++) {
        if (strcmp(fix_problems[i], line) == 0)
            return;
    }

    if ((fix_problems[n_fix_problems] = strdup(line)) != NULL)
        n_fix_problems++;
}

/* The protect rules write per-device proc entries, so the sandbox needs those
 * files. The devices come from the interface objects. */
static void dyn_fixtures(const char *cases_dir, const char *name);

static void dyn_fixtures(const char *cases_dir, const char *name)
{
    char dir[2 * PATH_MAX];
    char file[2 * PATH_MAX];
    DIR *d;
    struct dirent *de;

    (void)snprintf(dir, sizeof(dir), "%s/%s/etc/state/interfaces",
            cases_dir, name);

    if ((d = opendir(dir)) == NULL)
        return;

    while ((de = readdir(d)) != NULL) {
        char path[2 * PATH_MAX];
        char line[512];
        char device[64] = "";
        size_t len = 0;
        char *content;
        FILE *fp;
        int dynamic = 0;

        if (de->d_name[0] == '.')
            continue;

        (void)snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);

        if ((fp = fopen(path, "r")) == NULL)
            continue;

        while (fgets(line, sizeof(line), fp) != NULL) {
            if (strncmp(line, "DEVICE=\"", 8) == 0) {
                /* quoted, and a device name never contains a quote */
                char *v = line + 8;
                char *end = strchr(v, '"');
                size_t n = end != NULL ? (size_t)(end - v) : 0;

                if (n >= sizeof(device))
                    n = sizeof(device) - 1;

                memcpy(device, v, n);
                device[n] = '\0';
            } else if (strncmp(line, "IPADDRESS=\"dynamic\"",
                        strlen("IPADDRESS=\"dynamic\"")) == 0)
                dynamic = 1;
        }
        (void)fclose(fp);

        if (!dynamic || device[0] == '\0')
            continue;

        /* the case answers for itself first, then the common set, exactly like
         * the iptables fixtures */
        (void)snprintf(file, sizeof(file), "%s/%s/net/%s.txt",
                cases_dir, name, device);
        if (access(file, R_OK) != 0)
            (void)snprintf(file, sizeof(file), "%s/common/net/%s.txt",
                    cases_dir, device);

        if (access(file, R_OK) == 0 &&
                (content = slurp(file, &len)) != NULL) {
            char *nl = strchr(content, '\n');

            if (nl != NULL)
                *nl = '\0';
            vrmr_set_dynamic_address(device, content);
            free(content);
        } else {
            /* present and unreadable is the same answer as absent: the device
             * did not learn an address */
            vrmr_set_dynamic_address(device, NULL);
        }
    }

    closedir(d);
}

static void proc_add_device(const char *device)
{
    static const char *const entry[] = {"accept_source_route",
            "accept_redirects", "send_redirects", "rp_filter", "log_martians",
            NULL};
    int i;

    for (i = 0; entry[i] != NULL; i++) {
        char path[PATH_MAX + 128];
        FILE *fp;

        snprintf(path, sizeof(path), "%s/sys/net/ipv4/conf/%s/%s", sb_proc,
                device, entry[i]);
        mkdir_p_for_file(path);
        if ((fp = fopen(path, "w")) != NULL) {
            (void)fputs(PROC_STUB, fp);
            fclose(fp);
        }
    }
}

static void proc_from_state(void)
{
    char dir[PATH_MAX + 64];
    DIR *d;
    struct dirent *de;

    snprintf(dir, sizeof(dir), "%s/state/interfaces", sb);
    if ((d = opendir(dir)) == NULL)
        return;

    while ((de = readdir(d)) != NULL) {
        char path[PATH_MAX + 512];
        char *p, *end;
        FILE *fp;

        if (strstr(de->d_name, ".conf") == NULL)
            continue;

        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        if ((fp = fopen(path, "r")) == NULL)
            continue;

        /* DEVICE="eth0" */
        while (fgets(p = path, (int)sizeof(path), fp) != NULL) {
            if (strncmp(p, "DEVICE=\"", 8) != 0)
                continue;

            p += 8;
            if ((end = strchr(p, '\"')) != NULL)
                *end = '\0';
            if (p[0] != '\0' && strcmp(p, "any") != 0)
                proc_add_device(p);
            break;
        }

        fclose(fp);
    }

    closedir(d);
}

int vrmr_test_sandbox_setup(const char *cases_dir, const char *name)
{
    char path[PATH_MAX + 128];
    FILE *fp;

    snprintf(path, sizeof(path), "%s/vuurmuur-test-XXXXXX",
            getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp");

    if (mkdtemp(path) == NULL) {
        fprintf(stderr, "sandbox: mkdtemp: %s\n", strerror(errno));
        return -1;
    }
    (void)strlcpy(sb, path, sizeof(sb));
    snprintf(sb_tmp, sizeof(sb_tmp), "%s/tmp", sb);
    snprintf(sb_proc, sizeof(sb_proc), "%s/proc", sb);

    mkdir_p(sb_tmp);

    /* the two system wide protect entries the engine always writes.
     * The stub value is 9 because protect writes a 0 or a 1: with any of those
     * as the starting point, "the engine stopped writing" and "the engine wrote
     * the default" are the same artifact, which is the failure this section is
     * here to make visible. */
    snprintf(path, sizeof(path), "%s/sys/net/ipv4", sb_proc);
    mkdir_p(path);
    snprintf(path, sizeof(path), "%s/sys/net/ipv4/tcp_syncookies", sb_proc);
    if ((fp = fopen(path, "w")) != NULL) {
        (void)fputs(PROC_STUB, fp);
        fclose(fp);
    }
    snprintf(path, sizeof(path), "%s/sys/net/ipv4/icmp_echo_ignore_broadcasts",
            sb_proc);
    if ((fp = fopen(path, "w")) != NULL) {
        (void)fputs(PROC_STUB, fp);
        fclose(fp);
    }
    proc_add_device("all");
    proc_add_device("default");
    proc_add_device("lo");

    dyn_fixtures(cases_dir, name);

    snprintf(canned, sizeof(canned), "%s/%s/iptables", cases_dir, name);
    snprintf(canned_common, sizeof(canned_common), "%s/common/iptables",
            cases_dir);

    snprintf(path, sizeof(path), "%s/common/etc", cases_dir);
    if (copy_tree(path, sb) != 0)
        return -1;

    snprintf(path, sizeof(path), "%s/%s/etc", cases_dir, name);
    if (copy_tree(path, sb) != 0)
        return -1;

    proc_from_state();

    /* keep the tools out of the real tree */
    setenv("VUURMUUR_SYSCONFDIR", sb, 1);
    vrmr_set_tmpdir(sb_tmp);
    vrmr_set_proc_prefix(sb_proc);
    vrmr_set_trusted_owner(geteuid(), getegid());
    vrmr_set_iface_probe_config(1);
    vrmr_set_exec_ops(&cap_ops);

    vrmr_test_effects_reset();

    if ((render_buf = malloc(RENDER_SIZE)) == NULL)
        return -1;

    return 0;
}

void vrmr_test_sandbox_teardown(void)
{
    char cmd[PATH_MAX + 16];

    if (getenv("VRMR_TEST_KEEP") != NULL) {
        fprintf(stderr, "sandbox: kept %s\n", sb);
        sb[0] = '\0';
        return;
    }

    vrmr_set_exec_ops(NULL);
    vrmr_set_tmpdir(NULL);
    vrmr_set_proc_prefix(NULL);
    vrmr_set_trusted_owner(0, 0);
    vrmr_set_iface_probe_config(0);
    unsetenv("VUURMUUR_SYSCONFDIR");

    vrmr_test_effects_reset();
    free(render_buf);
    render_buf = NULL;

    if (sb[0] != '\0') {
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", sb);
        if (system(cmd) != 0)
            fprintf(stderr, "sandbox: cleanup of %s failed\n", sb);
        sb[0] = '\0';
    }
}

/* Kernel state the engine writes directly, with fopen() and no exec op to
 * intercept: vrmr_set_proc_entry() truncates the file and puts a single digit in
 * it, which is the whole of what 'protect' means for a sysctl. The prefix set in
 * vrmr_test_sandbox_setup() keeps those writes below the sandbox, so the host is
 * untouched - but nothing in the artifact ever showed them, so every one of them
 * was unpinned. Reading the tree back after the run is the only way to see them
 * without inventing a second seam in lib/proc.c.
 *
 * The list is sorted: readdir() order is not stable across filesystems and a
 * golden has to be. */
#define MAX_PROC_FILES 512

static int proc_name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *) a, *(const char *const *) b);
}

static void proc_collect(const char *dir, char **list, int *n, int max)
{
    DIR *d;
    struct dirent *de;
    struct stat st;
    char path[2 * PATH_MAX];

    if ((d = opendir(dir)) == NULL)
        return;

    while ((de = readdir(d)) != NULL && *n < max) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        (void)snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);

        if (lstat(path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            proc_collect(path, list, n, max);
        } else if (S_ISREG(st.st_mode)) {
            char *name = strdup(path + strlen(sb_proc));

            if (name == NULL)
                break;
            list[(*n)++] = name;
        }
    }

    closedir(d);
}

int vrmr_test_render(char *buf, size_t size)
{
    size_t n = 0;
    int i, j;

    if (render_buf == NULL)
        return -1;

    n += (size_t)snprintf(render_buf, RENDER_SIZE, "# side effects\n");
    for (i = 0; i < n_effects && n < RENDER_SIZE - 64; i++)
        n += (size_t)snprintf(
                render_buf + n, RENDER_SIZE - n, "%s\n", effects[i].line);

    {
        char *list[MAX_PROC_FILES];
        int count = 0;

        proc_collect(sb_proc, list, &count, MAX_PROC_FILES);
        qsort(list, (size_t) count, sizeof(list[0]), proc_name_cmp);

        if (count > 0)
            n += (size_t) snprintf(
                    render_buf + n, RENDER_SIZE - n, "# proc\n");

        for (i = 0; i < count && n < RENDER_SIZE - 256; i++) {
            char path[2 * PATH_MAX];
            char *content;
            size_t len = 0;
            char *nl;

            (void)snprintf(path, sizeof(path), "%s%s", sb_proc, list[i]);
            content = slurp(path, &len);

            if (content == NULL) {
                /* a file that vanished between the walk and the read is a
                 * complaint, not a blank in the golden */
                if ((content = strdup("# unreadable")) == NULL)
                    continue;
            } else {
                if (len > 0 && content[len - 1] == '\n')
                    content[len - 1] = '\0';
                if (content[0] == '\0')
                    (void)strlcpy(content, "(empty)", len + 1);
                else if ((nl = strchr(content, '\n')) != NULL)
                    *nl = '\0';
            }

            n += (size_t) snprintf(render_buf + n, RENDER_SIZE - n,
                    "write: /proc%s = %s\n", list[i], content);
            free(content);
            free(list[i]);
        }
    }

    if (n_fix_problems > 0) {
        n += (size_t)snprintf(render_buf + n, RENDER_SIZE - n, "# fixtures\n");
        for (i = 0; i < n_fix_problems && n < RENDER_SIZE - 64; i++)
            n += (size_t)snprintf(render_buf + n, RENDER_SIZE - n, "%s\n",
                    fix_problems[i]);
    }

    /* the content of the referenced files is dropped as it is rendered: a
     * second render pass is not meaningful */
    for (i = 0; i < n_effects && n < RENDER_SIZE - 64; i++) {
        for (j = 0; j < effects[i].n_ref && n < RENDER_SIZE - 64; j++) {
            if (effects[i].ref[j].content == NULL)
                continue;

            n += (size_t)snprintf(render_buf + n, RENDER_SIZE - n, "# %s\n",
                    effects[i].ref[j].token);
            n += (size_t)snprintf(render_buf + n, RENDER_SIZE - n, "%s",
                    effects[i].ref[j].content);
        }
    }

    if (n >= size)
        return -1;

    memcpy(buf, render_buf, n + 1);

    return (int)n;
}

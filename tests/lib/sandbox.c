/* Sandbox for the generation tests: fixture copy, path rooting and capture of
 * everything the tools would have run. */

#include "config.h"

#include <ctype.h>
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

static char *render_buf;

static int cap_pipe(
        struct vrmr_config *cnf, const char *command, char ignore_error);
static int cap_exec(struct vrmr_config *cnf, const char *path,
        const char *argv[], char *output[]);
static int cap_read(
        struct vrmr_config *cnf, const char *command, char *buf, size_t size);

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

    for (i = 0; i < n_effects; i++) {
        effect_free(&effects[i]);
    }
    n_effects = 0;
}

/* Record one command and snapshot the files it consumes: by the time the test
 * looks, the ruleset tempfile is gone. Repeats of the same token are numbered
 * so a v4 and a v6 ruleset cannot be confused. */
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
        char token[48] = "";
        char *content;
        size_t n = 0, len = 0;
        int i, seen = 1;

        p += 3;
        while (*p != '\0' && !isspace((unsigned char)*p) &&
                n < sizeof(path) - 1)
            path[n++] = *p++;
        path[n] = '\0';

        if ((content = slurp(path, &len)) == NULL) {
            fprintf(stderr, "sandbox: ref '%s': %s\n", path, strerror(errno));
            continue;
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
static int cap_read(
        struct vrmr_config *cnf, const char *command, char *buf, size_t size)
{
    const char *b = NULL, *t = NULL;
    char table[32] = "", file[PATH_MAX] = "";
    char ip6 = 0;
    char *content;
    size_t len = 0, n = 0;

    (void)cnf;

    /* the binary name is the first token, up to the first space */
    for (b = command; *b != '\0' && *b != ' '; b++) {
        if (strncmp(b, "ip6tables", 9) == 0)
            ip6 = 1;
    }

    if ((t = strstr(command, " -t ")) != NULL) {
        t += 4;
        while (n < sizeof(table) - 1 && *t != '\0' &&
                !isspace((unsigned char)*t))
            table[n++] = *t++;
        table[n] = '\0';
    }

    (void)strlcpy(file, canned, sizeof(file));
    (void)strlcat(file, "/", sizeof(file));
    (void)strlcat(file, ip6 ? "ip6" : "", sizeof(file));
    (void)strlcat(file, table, sizeof(file));
    (void)strlcat(file, ".txt", sizeof(file));

    if ((content = slurp(file, &len)) == NULL) {
        buf[0] = '\0';
        return 0;
    }

    if (len >= size) {
        free(content);
        return -1;
    }

    memcpy(buf, content, len);
    buf[len] = '\0';
    free(content);

    return (int)len;
}

/* The protect rules write per-device proc entries, so the sandbox needs those
 * files. The devices come from the interface objects. */
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
            (void)fputs("1\n", fp);
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

    /* the two system wide protect entries the engine always writes */
    snprintf(path, sizeof(path), "%s/sys/net/ipv4", sb_proc);
    mkdir_p(path);
    snprintf(path, sizeof(path), "%s/sys/net/ipv4/tcp_syncookies", sb_proc);
    if ((fp = fopen(path, "w")) != NULL) {
        (void)fputs("1\n", fp);
        fclose(fp);
    }
    snprintf(path, sizeof(path), "%s/sys/net/ipv4/icmp_echo_ignore_broadcasts",
            sb_proc);
    if ((fp = fopen(path, "w")) != NULL) {
        (void)fputs("1\n", fp);
        fclose(fp);
    }
    proc_add_device("all");
    proc_add_device("default");
    proc_add_device("lo");

    snprintf(canned, sizeof(canned), "%s/%s/iptables", cases_dir, name);

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

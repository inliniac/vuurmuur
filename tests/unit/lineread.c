/***************************************************************************
 *   Copyright (C) 2002-2026 by Victor Julien                              *
 *   victor@vuurmuur.org                                                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

/* Tier 1: the tail-safe line reader behind the log viewer. Plain files, no
 * root, no UI. The logview_section reader is just a wrapper over this. */

#include "config.h"
#include "vuurmuur.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"

#define BUFSZ 64

static char tmppath[PATH_MAX];

/* TMPDIR when set, so a harness that redirects temp files is respected */
static void new_template(void)
{
    const char *dir = getenv("TMPDIR");

    if (dir == NULL || dir[0] == '\0') {
        dir = "/tmp";
    }

    (void)snprintf(tmppath, sizeof(tmppath), "%s/vrmr-lineread-XXXXXX", dir);
}

/* the directory the template lives in, for the case that needs a read error */
static void template_dir(char *out, size_t size)
{
    char *slash = NULL;

    strlcpy(out, tmppath, size);
    slash = strrchr(out, '/');
    if (slash != NULL) {
        *slash = '\0';
    } else {
        strlcpy(out, ".", size);
    }
}

/* write an exact byte string to a fresh file and open it for reading */
static FILE *stream_from(const char *data, size_t len)
{
    new_template();
    int fd = mkstemp(tmppath);
    if (fd < 0)
        return NULL;

    if (len > 0 && write(fd, data, len) != (ssize_t)len) {
        close(fd);
        unlink(tmppath);
        return NULL;
    }
    lseek(fd, 0, SEEK_SET);
    return fdopen(fd, "r");
}

static void close_stream(FILE *fp)
{
    if (fp != NULL)
        fclose(fp);
    unlink(tmppath);
}

static void test_short_lines(void)
{
    char buf[BUFSZ];
    FILE *fp = stream_from("hello world\nnext\n", 17);
    tap_non_null("short: stream", fp);
    if (fp == NULL)
        return;

    tap_int_eq("short: first line read", vrmr_lineread(fp, buf, sizeof(buf)), 1);
    tap_str_eq("short: first line kept", buf, "hello world\n");
    tap_int_eq("short: position after first", (long)ftell(fp), 12);

    tap_int_eq("short: second line read", vrmr_lineread(fp, buf, sizeof(buf)), 1);
    tap_str_eq("short: second line kept", buf, "next\n");

    tap_int_eq("short: eof yields nothing", vrmr_lineread(fp, buf, sizeof(buf)), 0);

    /* the flags are cleared, so a tailer that later gets more data does not
       stay blocked on a stale eof */
    tap_int_eq("short: eof flag cleared", feof(fp), 0);
    tap_int_eq("short: error flag clear", ferror(fp), 0);
    long pos = ftell(fp);
    tap_int_eq("short: position determinate", pos != -1L, 1);

    tap_int_eq("short: eof stays put", vrmr_lineread(fp, buf, sizeof(buf)), 0);
    tap_int_eq("short: eof position stable", (long)ftell(fp), (long)pos);

    close_stream(fp);
}

static void test_long_line(void)
{
    char buf[BUFSZ];
    char got[1024];
    size_t gotlen = 0;
    int rounds = 0;

    /* one line, far longer than the buffer */
    char line[301];
    memset(line, 'a', 300);
    line[300] = '\n';
    FILE *fp = stream_from(line, sizeof(line));
    tap_non_null("long: stream", fp);
    if (fp == NULL)
        return;

    /* an overlong line is handed over in full-size chunks, never dropped */
    tap_int_eq("long: first round reads", vrmr_lineread(fp, buf, sizeof(buf)), 1);
    tap_int_eq("long: first chunk is full", (long)strlen(buf), (long)sizeof(buf) - 1);
    tap_int_eq("long: first chunk unterminated", buf[strlen(buf) - 1] != '\n', 1);
    gotlen = strlen(buf);
    memcpy(got, buf, gotlen);

    while (rounds++ < 16) {
        int r = vrmr_lineread(fp, buf, sizeof(buf));
        tap_int_eq("long: chunk read", r, 1);
        if (r != 1)
            break;
        size_t n = strlen(buf);
        if (gotlen + n < sizeof(got)) {
            memcpy(got + gotlen, buf, n);
            gotlen += n;
        }
        if (n > 0 && buf[n - 1] == '\n')
            break;
    }

    tap_int_eq("long: line reassembled", (long)gotlen, 301);
    tap_int_eq("long: last round was the tail", got[gotlen - 1] == '\n', 1);
    tap_int_eq("long: nothing left", vrmr_lineread(fp, buf, sizeof(buf)), 0);

    close_stream(fp);
}

static void test_partial_tail(void)
{
    char buf[BUFSZ];
    FILE *fp = stream_from("aaa\nbbb", 7);
    tap_non_null("partial: stream", fp);
    if (fp == NULL)
        return;

    tap_int_eq("partial: complete line read", vrmr_lineread(fp, buf, sizeof(buf)), 1);
    tap_str_eq("partial: complete line", buf, "aaa\n");

    long before = ftell(fp);
    tap_int_eq("partial: incomplete gives nothing",
            vrmr_lineread(fp, buf, sizeof(buf)), 0);
    tap_int_eq("partial: incomplete not consumed", (long)ftell(fp), (long)before);

    /* a viewer polls this in a loop: repeating must not eat the line */
    tap_int_eq("partial: second attempt", vrmr_lineread(fp, buf, sizeof(buf)), 0);
    tap_int_eq("partial: still parked", (long)ftell(fp), (long)before);

    /* the bytes stay parked until the newline lands */
    int afd = open(tmppath, O_WRONLY | O_APPEND);
    const char *rest = "bb\n";
    ssize_t wrote = afd >= 0 ? write(afd, rest, strlen(rest)) : -1;
    if (afd >= 0)
        close(afd);
    tap_int_eq("partial: append landed", wrote > 0, 1);
    if (wrote > 0) {
        /* parked at the start of the old partial text, so what the reader
           picks up now is the finished line */
        tap_int_eq("partial: reads after append",
                vrmr_lineread(fp, buf, sizeof(buf)), 1);
    }

    close_stream(fp);
}

static void test_error_path(void)
{
    char buf[BUFSZ];

    /* reading a directory fails on the first fetch: the stand-in for a stream
       error, reachable without root or a broken device */
    char dir[PATH_MAX];

    new_template();
    template_dir(dir, sizeof(dir));
    int fd = open(dir, O_RDONLY);
    tap_ok(fd >= 0, "error: directory fd");
    if (fd < 0)
        return;

    FILE *fp = fdopen(fd, "r");
    tap_non_null("error: stream", fp);
    if (fp == NULL) {
        close(fd);
        return;
    }

    tap_int_eq("error: read gives nothing", vrmr_lineread(fp, buf, sizeof(buf)), 0);

    /* the point of the clearerr and the re-anchor: the position is usable */
    tap_int_eq("error: position determinate", ftell(fp) != -1L, 1);
    tap_int_eq("error: seek works afterwards", fseek(fp, 0, SEEK_CUR), 0);
    tap_int_eq("error: flag cleared", ferror(fp), 0);

    tap_int_eq("error: second attempt", vrmr_lineread(fp, buf, sizeof(buf)), 0);

    fclose(fp);
}

static void test_nul_byte(void)
{
    char buf[BUFSZ];
    FILE *fp = stream_from("\0abc\ndef\n", 9);
    tap_non_null("nul: stream", fp);
    if (fp == NULL)
        return;

    tap_int_eq("nul: yields nothing", vrmr_lineread(fp, buf, sizeof(buf)), 0);

    /* fgets ran to the newline, so the whole line went past. Dropping it is
       fine; stalling on it would not be. */
    tap_int_eq("nul: position advanced past it", (long)ftell(fp), 5);
    tap_int_eq("nul: line after it", vrmr_lineread(fp, buf, sizeof(buf)), 1);
    tap_str_eq("nul: line after it kept", buf, "def\n");

    close_stream(fp);
}

static void test_bad_args(void)
{
    char buf[BUFSZ];
    tap_int_eq("args: null buffer", vrmr_lineread(stdout, NULL, BUFSZ), -1);
    tap_int_eq("args: zero size", vrmr_lineread(stdout, buf, 0), -1);
}

/*
    A pipe gives a partial line and refuses the rewind, which is the one branch
    the file-backed cases cannot reach. pclose, never fclose: the handle is the
    stream pclose owns.
*/
static void test_unseekable_stream(void)
{
    char buf[BUFSZ];
    FILE *fp = popen("printf abc", "r");

    tap_non_null("pipe: stream", fp);
    if (fp != NULL) {
        tap_int_eq("pipe: partial line gives nothing",
                vrmr_lineread(fp, buf, sizeof(buf)), 0);
        (void)pclose(fp);
    }
}

int main(void)
{
    if (vrmr_test_setup() < 0) {
        (void)fprintf(stdout, "Bail out! vrmr_test_setup failed\n");
        return EXIT_FAILURE;
    }

    test_short_lines();
    test_long_line();
    test_partial_tail();
    test_error_path();
    test_nul_byte();
    test_bad_args();
    test_unseekable_stream();

    vrmr_test_teardown();

    return tap_finish();
}

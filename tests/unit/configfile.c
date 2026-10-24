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

/* Tier 0: vrmr_ask_configfile() reading a config file off disk. The parser
 * used to bound its own copies by the caller's answer size, so a long name or
 * value in a config file wrote past fixed stack buffers. Plain files, no root,
 * no UI. */

#include "config.h"
#include "vuurmuur.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"
#include "vrmr_exec_priv.h"

static char path[PATH_MAX];

static void write_config(const char *body)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        (void)fprintf(stderr, "Bail out! cannot write %s: %s\n", path,
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    (void)fputs(body, fp);
    (void)fclose(fp);

    /* vuurmuur_fopen() only opens a config file the owner can read */
    if (chmod(path, 0600) < 0)
        (void)fprintf(stderr, "# chmod %s: %s\n", path, strerror(errno));
}

static void test_ask_configfile(void)
{
    char answer[1024] = "";
    char big[600];
    int r = 0;

    if (snprintf(path, sizeof(path), "%s/configfile.conf",
                getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp") >=
            (int)sizeof(path)) {
        (void)fprintf(stderr, "Bail out! temp path too long\n");
        exit(EXIT_FAILURE);
    }

    /* the normal case: quotes are stripped, the answer comes back */
    write_config("# comment\nMAINMENU_STATUS=\"startup\"\nDUMPTY=\"no\"\n");
    answer[0] = '\0';
    r = vrmr_ask_configfile(&vrmr_test_ctx.conf, "MAINMENU_STATUS", answer,
            path, sizeof(answer));
    (void)tap_int_eq("configfile: a set value is found", r, 1);
    (void)tap_str_eq("configfile: the quotes are stripped", answer, "startup");

    /* not on this line */
    answer[0] = '\0';
    (void)tap_int_eq("configfile: an unknown question is not an error",
            vrmr_ask_configfile(&vrmr_test_ctx.conf, "NO SUCH VARIABLE", answer,
                    path, sizeof(answer)),
            0);

    /* a missing file is */
    (void)tap_int_eq("configfile: a missing file is an error",
            vrmr_ask_configfile(&vrmr_test_ctx.conf, "MAINMENU_STATUS", answer,
                    "/nonexistent/vuurmuur-test-configfile", sizeof(answer)),
            -1);

    /* a name longer than the 128 byte variable buffer used to be copied whole
     */
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char line[768] = "";
    (void)snprintf(line, sizeof(line), "%s=x\n", big);
    write_config(line);
    answer[0] = '\0';
    (void)tap_int_eq("configfile: an over-long name is skipped, not copied",
            vrmr_ask_configfile(&vrmr_test_ctx.conf, "NO SUCH VARIABLE", answer,
                    path, sizeof(answer)),
            0);

    /* and so is a value longer than the 256 byte value buffer, but as an
     * error: silently answering with a truncated value is how a config gets
     * quietly broken */
    memset(big, 'B', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    (void)snprintf(line, sizeof(line), "OVERLONG=\"%s\"\n", big);
    write_config(line);
    answer[0] = '\0';
    (void)tap_int_eq("configfile: an over-long value is an error",
            vrmr_ask_configfile(&vrmr_test_ctx.conf, "OVERLONG", answer, path,
                    sizeof(answer)),
            -1);
    (void)tap_str_eq("configfile: the answer is left alone", answer, "");

    /* a line with no assignment at all */
    write_config("just some text\nOK_ONE=\"1\"\n");
    answer[0] = '\0';
    r = vrmr_ask_configfile(
            &vrmr_test_ctx.conf, "OK_ONE", answer, path, sizeof(answer));
    (void)tap_int_eq("configfile: a junk line does not stop the walk", r, 1);
    (void)tap_str_eq(
            "configfile: the value after it is still read", answer, "1");

    /* an answer buffer too small for the value is an error, not a silent
     * truncation */
    char small[4] = "zz";
    write_config("LONGISH=\"abcdefghij\"\n");
    (void)tap_int_eq("configfile: too small an answer buffer is an error",
            vrmr_ask_configfile(
                    &vrmr_test_ctx.conf, "LONGISH", small, path, sizeof(small)),
            -1);

    (void)unlink(path);
}

int main(void)
{
    if (vrmr_test_setup() < 0) {
        (void)fprintf(stdout, "Bail out! vrmr_test_setup failed\n");
        return EXIT_FAILURE;
    }

    /* the files we write are owned by us, not by root */
    vrmr_set_trusted_owner(geteuid(), getegid());

    test_ask_configfile();

    vrmr_test_teardown();

    return tap_finish();
}

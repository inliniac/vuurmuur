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

/* Tier 0: how libvuurmuur_exec_command() maps a child's wait status. Every
 * caller in the tree tests the result against 0, so a command that died from a
 * signal must come back non-zero. No root, no firewall: plain /bin/sh. */

#include "config.h"
#include "vuurmuur.h"

#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"
#include "../lib/vrmr_exec_priv.h"

static int run(const char *script)
{
    const char *path = "/bin/sh";
    const char *argv[] = {path, "-c", script, NULL};

    /* the implementation ignores cnf */
    return libvuurmuur_exec_command(&vrmr_test_ctx.conf, path, argv, NULL);
}

/* the other way this tree runs a command: popen, read to EOF, close. The status
 * of the child only exists at the close, and one caller (the system chain
 * listing that decides what gets flushed) acts on it. */
static int read_status(const char *script)
{
    struct vrmr_cmdout co;
    char line[128] = "";

    if (vrmr_cmdout_open(&co, &vrmr_test_ctx.conf, script) != 0)
        return (-42);

    while (vrmr_cmdout_nextline(&co, line, sizeof(line)) != NULL) {
        ;
    }

    return vrmr_cmdout_close(&co);
}

int main(void)
{
    if (vrmr_test_setup() < 0) {
        (void)fprintf(stdout, "Bail out! vrmr_test_setup failed\n");
        return EXIT_FAILURE;
    }

    (void)tap_int_eq("exit 0 reads as success", run("exit 0"), 0);
    (void)tap_int_eq("exit code is passed through", run("exit 3"), 3);

    (void)tap_int_eq("SIGTERM death is 128+signal", run("kill -TERM $$"),
            128 + SIGTERM);
    (void)tap_int_eq("SIGKILL death is 128+signal", run("kill -KILL $$"),
            128 + SIGKILL);

    (void)tap_int_eq("cmdout: a read that ran closes at 0",
            read_status("echo one"), 0);
    (void)tap_int_eq("cmdout: the exit code of a reader command",
            read_status("exit 4"), 4);
    (void)tap_int_eq("cmdout: a killed reader is not a good answer",
            read_status("kill -TERM $$"), 128 + SIGTERM);

    /* the child execs a binary that cannot start: exit(127) from the child */
    const char *missing = "/nonexistent/vuurmuur-test-binary";
    const char *argv[] = {missing, NULL};
    (void)tap_int_eq("a binary that will not exec is not success",
            libvuurmuur_exec_command(&vrmr_test_ctx.conf, missing, argv, NULL),
            127);

    vrmr_test_teardown();

    return tap_finish();
}

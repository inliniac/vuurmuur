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

/* Injection points for the test harness. Not installed, not public API:
 * production never calls these, so the real behaviour stays in force. */

#ifndef __VRMR_EXEC_PRIV_H__
#define __VRMR_EXEC_PRIV_H__

#include <vuurmuur.h>

struct vrmr_exec_ops {
    /* run a shell command line; 0 ok, -1 failed */
    int (*pipe)(
            struct vrmr_config *cnf, const char *command, char ignore_error);

    /* fork/exec path with a NULL terminated argv; command exit code or -1 */
    int (*exec)(struct vrmr_config *cnf, const char *path, const char *argv[],
            char *output[]);

    /* capture stdout of a shell command line into buf; byte count or -1 */
    int (*read)(struct vrmr_config *cnf, const char *command, char *buf,
            size_t size);
};

void vrmr_set_exec_ops(const struct vrmr_exec_ops *ops);

/* Ruleset tempfiles are created below this directory (default /tmp). */
void vrmr_set_tmpdir(const char *tmpdir);
const char *vrmr_tmpdir(void);

/* A mkstemp-able path below the tmpdir: "<tmpdir>/<name>-XXXXXX". */
void vrmr_tmpfile(char *out, size_t size, const char *name);

/* Prefix that replaces /proc when reading and writing proc entries. */
void vrmr_set_proc_prefix(const char *prefix);

/* Map a /proc/... path into the prefix above. */
void vrmr_proc_resolve(const char *entry, char *out, size_t size);

/* Config and state files have to belong to this owner; root:root by default. */
void vrmr_set_trusted_owner(uid_t uid, gid_t gid);

/* Interface state normally comes from the kernel. Set to non-zero to take the
 * configured address as the actual one, which is what a fixture needs. */
void vrmr_set_iface_probe_config(int use_config);

/* Address a dynamic interface is said to have learned, per device. NULL from the
 * getter means the fixture did not answer, which reads as an interface down. */
void vrmr_set_dynamic_address(const char *device, const char *addr);
/*@observer@*/ const char *vrmr_dynamic_address(const char *device);
int vrmr_iface_probe_use_config(void);

/* Line at a time command output: popen/fgets normally, the captured buffer of
 * the read op when the harness is in charge. Use this instead of popen so the
 * tree has a single, auditable execution path. */
struct vrmr_cmdout {
    FILE *fp;
    char *buf;
    size_t len;
    size_t pos;
};

/* enough for a chain listing, and only allocated in capture mode */
#define VRMR_CMDOUT_SIZE (128u * 1024u)

/* All three hooks are mandatory: a partial set would let real commands
 * through a test run. */
int vrmr_cmdout_open(
        struct vrmr_cmdout *co, struct vrmr_config *cnf, const char *command);
char *vrmr_cmdout_nextline(struct vrmr_cmdout *co, char *line, size_t size);
void vrmr_cmdout_close(struct vrmr_cmdout *co);

#endif

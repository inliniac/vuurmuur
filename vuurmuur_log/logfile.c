/***************************************************************************
 *   Copyright (C) 2003-2019 by Victor Julien                              *
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
#include "vuurmuur_log.h"
#include "logfile.h"

static int close_vuurmuurlog(
        const struct vrmr_config *conf, FILE **vuurmuur_log)
{
    int retval = 0;

    /* close the logfiles */
    if (fclose(*vuurmuur_log) < 0) {
        vrmr_error(-1, "Error", "closing the vuurmuur-log '%s' failed: %s.",
                conf->trafficlog_location, strerror(errno));
        retval = -1;
    }

    *vuurmuur_log = NULL;

    return (retval);
}

FILE *open_logfile(
        const struct vrmr_config *cnf, const char *path, const char *mode)
{
    FILE *fp = NULL;

    assert(path && mode);

    /* open the logfile */
    if (!(fp = vuurmuur_fopen(cnf, path, mode))) {
        vrmr_error(-1, "Error", "the logfile '%s' could not be opened: %s",
                path, strerror(errno));
        return (NULL);
    }

    /* listen at the end of the file */
    if (fseek(fp, (off_t)0, SEEK_END) == -1) {
        vrmr_error(-1, "Error",
                "attaching to the end of the logfile failed: %s",
                strerror(errno));
        fclose(fp);
        return (NULL);
    }

    return (fp);
}

int open_vuurmuurlog(const struct vrmr_config *cnf, FILE **vuurmuur_log)
{
    /* open the vuurmuur logfile */
    if (!(*vuurmuur_log = open_logfile(cnf, cnf->trafficlog_location, "a"))) {
        vrmr_error(-1, "Error", "opening traffic log file '%s' failed: %s",
                cnf->trafficlog_location, strerror(errno));
        return (-1);
    }
    return (0);
}

int reopen_vuurmuurlog(const struct vrmr_config *cnf, FILE **vuurmuur_log)
{
    vrmr_debug(NONE, "Reopening vuurmuur log");

    /* close the logfiles */
    (void)close_vuurmuurlog(cnf, vuurmuur_log);

    /* re-open the vuurmuur logfile */
    if (!(*vuurmuur_log = open_logfile(cnf, cnf->trafficlog_location, "a"))) {
        vrmr_error(-1, "Error", "Re-opening traffic log file '%s' failed: %s.",
                cnf->trafficlog_location, strerror(errno));
        return (-1);
    }

    vrmr_debug(NONE, "Done reopening");
    return (0);
}

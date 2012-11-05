/***************************************************************************
 *   Copyright (C) 2003-2012 by Victor Julien                              *
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

#include "main.h"

void
send_hup_to_vuurmuurlog(const int debuglvl)
{
    int     i = 0;
    pid_t   vuurmuur_pid;
    int     result = 0;

    /* get the pid (the i is bogus) */
    vuurmuur_pid = get_vuurmuur_pid("/var/run/vuurmuur_log.pid", &i);
    if(vuurmuur_pid > 0)
    {
        /* send a signal to vuurmuur_log */
        result = kill(vuurmuur_pid, SIGHUP);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "sending SIGHUP to Vuurmuur_log failed (PID: %ld): %s.",
                                (long)vuurmuur_pid,
                                strerror(errno));
        }
    }
    else
    {
        (void)vrprint.warning("Warning", "sending SIGHUP to Vuurmuur_log failed: could not get pid.");
    }

    return;
}

void cmdline_override_config(const int debuglvl) {
    if (cmdline.check_iptcaps_set == TRUE) {
        conf.check_iptcaps = cmdline.check_iptcaps;
        (void)vrprint.debug(__FUNC__, "overriding check_iptcaps from commandline to %s.",
            conf.check_iptcaps ? "TRUE" : "FALSE");
    }

    if (cmdline.verbose_out_set == TRUE) {
        conf.verbose_out = cmdline.verbose_out;
        (void)vrprint.debug(__FUNC__, "overriding verbose_out from commandline to %s.",
            conf.verbose_out ? "TRUE" : "FALSE");
    }

    if (cmdline.configfile_set == TRUE) {
        strlcpy(conf.configfile, cmdline.configfile, sizeof(conf.configfile));
        (void)vrprint.debug(__FUNC__, "overriding configfile from commandline to %s.",
            conf.configfile);
    }

    if (cmdline.loglevel_set == TRUE) {
        strlcpy(cmdline.loglevel, conf.loglevel, sizeof(cmdline.loglevel));
        conf.loglevel_cmdline = TRUE;
        (void)vrprint.debug(__FUNC__, "overriding verbose_out from loglevel to %s.",
            conf.loglevel);
    }
}

int sysctl_exec(const int debuglvl, struct vuurmuur_config *cnf, char *key, char *value, int bash_out) {
    if (bash_out) {
        fprintf(stdout, "%s -w %s=%s\n", cnf->sysctl_location, key, value);
        return 0;
    }

    char line[1024];
    snprintf(line, sizeof(line), "%s=%s", key, value);

    char *args[] = { cnf->sysctl_location, "-w", line, NULL };
    int result = libvuurmuur_exec_command(debuglvl, cnf, cnf->sysctl_location, args, NULL);
    if (result != 0) {
        //(void)vrprint.error(result, "Error", "sysctl %s=%s failed", key, value);
        return -1;
    }
    return 0;
}


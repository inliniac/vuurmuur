/***************************************************************************
 *   Copyright (C) 2003-2007 by Victor Julien                              *
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

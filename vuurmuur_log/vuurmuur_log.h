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

#ifndef __VUURMUUR_LOG_H__
#define __VUURMUUR_LOG_H__

#include "../config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <vuurmuur.h>
#include <signal.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>

#define PIDFILE "/var/run/vuurmuur_log.pid"
#define SVCNAME "vuurmuur_log"

/* the line starts at position 0 */
#define LINE_START 0

/*  The maximum time to wait for the next line: if the time is reached, we close
   the logfiles, and open them again. This is to prevent the program from
   getting confused because of log rotation.

    NOTE: the time is in 10th's of a second!
*/
#define MAX_WAIT_TIME 600

/* define these here so converting to gettext will be easier */
#define VR_ERR "Error"
#define VR_INTERR "Internal Error"
#define VR_INFO "Info"
#define VR_WARN "Warning"

int reopen_logfiles(FILE **, FILE **);
int open_logfiles(const struct vrmr_config *cnf, FILE **, FILE **);

int process_logrecord(struct vrmr_log_record *log_record);

extern char version_string[128];
extern int sem_id;

#endif /* __VUURMUUR_LOG_H__ */

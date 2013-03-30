/***************************************************************************
 *   Copyright (C) 2003-2008 by Victor Julien                              *
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

#ifndef __LOGFILE_H__
#define __LOGFILE_H__

#include "stats.h"

struct file_mon
{
    struct stat old_file;
    struct stat new_file;

    off_t       windback;
};


int search_in_ipt_line(char *, size_t, char *, size_t *, size_t *);
int check_ipt_line(char *);
int parse_ipt_logline(const int, char *, size_t, char *, struct vrmr_log_record *, struct Counters_ *);
FILE *open_logfile(const int, const struct vrmr_config *, const char *, const char *);

int open_syslog(const int, const struct vrmr_config *, FILE **);
int reopen_syslog(const int, const struct vrmr_config *, FILE **);

int open_vuurmuurlog(const int, const struct vrmr_config *, FILE **);
int reopen_vuurmuurlog(const int, const struct vrmr_config *, FILE **);

int reopen_logfiles(const int, FILE **, FILE **);

#endif

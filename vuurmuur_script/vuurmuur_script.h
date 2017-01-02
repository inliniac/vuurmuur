/***************************************************************************
 *   Copyright (C) 2002-2017 by Victor Julien                              *
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
#ifndef __VUURMUUR_SCRIPT_H__
#define __VUURMUUR_SCRIPT_H__

/*****************************************************************************************************************\
 ********************************* INCLUDES **********************************************************************
\*****************************************************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libgen.h>     /* for basename */
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>     /* for catching signals */
#include <time.h>       /* included for logging */
#include <errno.h>      /* error handling */
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/wait.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>

/* our own vuurmuurlib */
#include <vuurmuur.h>

#include "../vuurmuur/version.h"

/*****************************************************************************************************************\
 ********************************* DEFINES ***********************************************************************
\*****************************************************************************************************************/

#define YES                 1
#define NO                  0

/* define these here so converting to gettext will be easier */
#define VR_ERR              "Error"
#define VR_INTERR           "Internal Error"
#define VR_INFO             "Info"
#define VR_WARN             "Warning"

#define EXIT_SUCCESS            0
#define EXIT_COMMANDLINE_ERROR  1


/*************************************************************************************************************************\
 ******************************************************* DATATYPES *******************************************************
\*************************************************************************************************************************/

/*@null@*/
struct vrmr_shm_table *shm_table;

/* semaphore id */
int sem_id;

/* pointer to the environment */
extern char **environ;

enum
{
    CMD_UNSET = 0,

    CMD_ADD, /* add an object */
    CMD_DEL, /* delete an object */
    CMD_MOD, /* modify an object */
    CMD_REN, /* rename an object */
    CMD_PRT, /* print the content of an object */
    CMD_LST, /* lists objects */
    CMD_BLK, /* block an ip, host or group */
    CMD_UBL, /* unblock an ip, host or group */
    CMD_LBL, /* list blocked objects */
    CMD_RLD, /* apply changes without any other action */

    CMD_ERROR,
};

enum
{
    VRS_SUCCESS = 0,
    VRS_ERR_COMMANDLINE = 1,
    VRS_ERR_COMMAND_FAILED = 2,
    VRS_ERR_NOT_FOUND = 3,
    VRS_ERR_ALREADY_EXISTS = 4,
    VRS_ERR_MALLOC = 5,
    VRS_ERR_DATA_INCONSISTENCY = 6,
    VRS_ERR_INTERNAL = 254,
};

char version_string[128];

typedef struct VuurmuurScript_
{
    int         cmd,
                type;

    char        name[VRMR_VRMR_MAX_HOST_NET_ZONE],

                name_zone[VRMR_MAX_ZONE],
                name_net[VRMR_MAX_NETWORK],
                name_host[VRMR_MAX_HOST];

    char        var[32];
    char        set[1024];

    char        overwrite;

    /* some data used by most function */
    int         zonetype;
    char        bdat[1024];

    /* try to instruct vuurmuur and vuurmuur_log to reload? */
    char        apply;

    /* print rule numbers? */
    char        print_rule_numbers;

    /* library ctx */
    struct vrmr_ctx vctx;
} VuurmuurScript;

/*************************************************************************************************************************\
 ******************************************************* FUNCTIONS *******************************************************
\*************************************************************************************************************************/

void logchange(VuurmuurScript *,char *fmt, ...);

int script_print(const int, VuurmuurScript *);
int script_list(const int, VuurmuurScript *);
int script_add(const int, VuurmuurScript *);
int script_delete(const int, VuurmuurScript *);
int script_modify(const int, VuurmuurScript *);
int script_rename(const int, VuurmuurScript *);
int script_apply(const int debuglvl, VuurmuurScript *vr_script);
int script_unblock(const int debuglvl, VuurmuurScript *vr_script);
int script_list_devices(const int);

int backend_check(const int, int, char *, char *, char, struct vrmr_regex *);

char * remove_leading_part(char *input);

#endif

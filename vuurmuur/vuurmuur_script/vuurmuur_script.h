/***************************************************************************
 *   Copyright (C) 2002-2006 by Victor Julien                              *
 *   victor@nk.nl                                                          *
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

#define _GNU_SOURCE
#include <getopt.h>

/* our own vuurmuurlib */
#include <vuurmuur.h>

#include "../vuurmuur/version.h"

/*****************************************************************************************************************\
 ********************************* DEFINES ***********************************************************************
\*****************************************************************************************************************/

#define YES                 1
#define NO                  0

#define LOCK(x)             LockSHM(1, x)
#define UNLOCK(x)           LockSHM(0, x)

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
struct SHM_TABLE *shm_table;

/* pluginlist */
d_list PluginList;

/* semaphore id */
int sem_id;

/* pointer to the environment */
extern char **environ;

VR_user_t user_data;

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
    CMD_LDV, /* list system devices */
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

char version_string[18];

typedef struct VuurmuurScript_
{
    int         cmd,
                type;

    char        name[MAX_HOST_NET_ZONE],

                name_zone[MAX_ZONE],
                name_net[MAX_NETWORK],
                name_host[MAX_HOST];

    char        var[32];
    char        set[1024];

    char        overwrite;

    /* some data used by most function */
    int         zonetype;
    char        bdat[1024];
    struct rgx_ reg;

    /* try to instruct vuurmuur and vuurmuur_log to reload? */
    char        apply;

    /* print rule numbers? */
    char        print_rule_numbers;

} VuurmuurScript;


/*************************************************************************************************************************\
 ******************************************************* FUNCTIONS *******************************************************
\*************************************************************************************************************************/

void logchange(char *fmt, ...);

int script_print(const int, VuurmuurScript *);
int script_list(const int, VuurmuurScript *);
int script_add(const int, VuurmuurScript *);
int script_delete(const int, VuurmuurScript *);
int script_modify(const int, VuurmuurScript *);
int script_rename(const int, VuurmuurScript *);
int script_apply(const int debuglvl, VuurmuurScript *vr_script);
int script_unblock(const int debuglvl, VuurmuurScript *vr_script);
int script_list_devices(const int);

int backend_check(const int, int, char *, char *, char, struct rgx_ *);

char * remove_leading_part(char *input);

#endif

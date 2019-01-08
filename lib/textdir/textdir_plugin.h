/***************************************************************************
 *   Copyright (C) 2002-2019 by Victor Julien                              *
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

#ifndef __TEXTDIR_PLUGIN_H__
#define __TEXTDIR_PLUGIN_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <config.h>
#include <vuurmuur.h>

#define MAX_LINE_LENGTH 512

#define MAX_RULE_NAME 32

struct textdir_backend {
    /* 0: if backend is closed, 1: open */
    bool backend_open;

    /* not yet used */
    bool writable;

    DIR *zone_p;
    DIR *network_p;
    DIR *host_p;
    DIR *group_p;

    DIR *service_p;

    DIR *interface_p;

    DIR *rule_p;

    FILE *file;

    char cur_zone[VRMR_MAX_ZONE], cur_network[VRMR_MAX_NETWORK],
            cur_host[VRMR_MAX_HOST];

    char interface[VRMR_MAX_INTERFACE];

    char rule[MAX_RULE_NAME];

    char textdirlocation[512];

    void *plugin_handle;

    /* regexes for checking the names */
    regex_t *zonename_reg;
    regex_t *servicename_reg;
    regex_t *interfacename_reg;

    /* Vuurmuur configuration. Some libvuurmuur functions need this to
     * do their work, but we shouldn't be accessing it ourselves. */
    const struct vrmr_config *cfg;
};

char *get_filelocation(
        void *backend, const char *name, const enum vrmr_objecttypes type);
int ask_textdir(void *backend, const char *name, const char *question,
        char *answer, size_t max_answer, enum vrmr_objecttypes type, int multi);
int tell_textdir(void *backend, const char *name, const char *question,
        const char *answer, int overwrite, enum vrmr_objecttypes type);
int open_textdir(void *backend, int mode, enum vrmr_backend_types type);
int close_textdir(void *backend, enum vrmr_backend_types type);
char *list_textdir(
        void *backend, char *name, int *zonetype, enum vrmr_backend_types type);
int init_textdir(void *backend, enum vrmr_backend_types type);
int add_textdir(void *backend, const char *name, enum vrmr_objecttypes type);
int del_textdir(void *backend, const char *name, enum vrmr_objecttypes type,
        int recurs);
int rename_textdir(void *backend, const char *name, const char *newname,
        enum vrmr_objecttypes type);
int conf_textdir(void *backend);
int setup_textdir(const struct vrmr_config *vuurmuur_config, void **backend);

#endif

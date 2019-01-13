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

#include "textdir_plugin.h"

/*  list_textdir

    Listing the items in the backend. A number of checks are done:
        - regex validation
        - stat (file perms) validation
        - .conf suffix check (optional)

    Returns a pointer to the name, or NULL when done.
*/
char *list_textdir(
        void *backend, char *name, int *zonetype, enum vrmr_backend_types type)
{
    char dir_location[PATH_MAX] = "", netdir_location[PATH_MAX] = "",
         hostdir_location[PATH_MAX] = "", groupdir_location[PATH_MAX] = "",
         *file_location = NULL;
    char cur_zonename[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";
    struct dirent *dir_entry_p = NULL;
    int done = 0;

    assert(backend && name && zonetype);

    /* check if the backend is opened */
    struct textdir_backend *tb = (struct textdir_backend *)backend;
    if (!tb->backend_open) {
        vrmr_error(-1, "Internal Error", "backend not opened yet");
        return (NULL);
    }

    /* services */
    if (type == VRMR_BT_SERVICES) {
        /* set the dir location */
        if (snprintf(dir_location, sizeof(dir_location), "%s/services",
                    tb->textdirlocation) >= (int)sizeof(dir_location)) {
            return (NULL);
        }

        /* the loop */
        while (!done) {
            /* check if already open */
            if (!tb->service_p) {
                /* open the dir */
                if (!(tb->service_p =
                                    vuurmuur_opendir(tb->cfg, dir_location))) {
                    vrmr_error(-1, "Error",
                            "unable to open '%s', %s (in: list_textdir, "
                            "opendir).",
                            dir_location, strerror(errno));
                    return (NULL);
                }
            }

            /* now read the contents of the dir */
            if ((dir_entry_p = readdir(tb->service_p)) != NULL) {
                vrmr_debug(HIGH, "name: '%s'.", dir_entry_p->d_name);

                (void)strlcpy(name, dir_entry_p->d_name, VRMR_MAX_SERVICE);

                /* only return names which do not start with a dot (hidden
                 * files) and don't open . and .. */
                if (strncmp(name, ".", 1) != 0 && strcmp(name, "..") != 0) {
                    /* now validate the name */
                    if (vrmr_validate_servicename(name, tb->servicename_reg) ==
                            0) {
                        /* determine the location of the file */
                        if (!(file_location = get_filelocation(
                                      backend, name, VRMR_TYPE_SERVICE)))
                            return (NULL);

                        vrmr_debug(HIGH, "service '%s', file: '%s'.", name,
                                file_location);

                        /* now stat it */
                        if (vrmr_stat_ok(tb->cfg, file_location,
                                    VRMR_STATOK_WANT_FILE, VRMR_STATOK_QUIET,
                                    VRMR_STATOK_MUST_EXIST)) {
                            free(file_location);

                            *zonetype = VRMR_TYPE_SERVICE;
                            return (name);
                        }

                        free(file_location);
                    }
                }
            }
            /* close the dir if we cant read no more */
            else {
                /* close the dir */
                done = 1;
                closedir(tb->service_p);
                tb->service_p = NULL;
            }
        }
    }
    /* interfaces */
    else if (type == VRMR_BT_INTERFACES) {
        // set the dirlocation
        if (snprintf(dir_location, sizeof(dir_location), "%s/interfaces",
                    tb->textdirlocation) >= (int)sizeof(dir_location)) {
            return (NULL);
        }

        while (done == 0) {
            // check if already open, if not: open it
            if (!tb->interface_p) {
                // open the dir
                if (!(tb->interface_p =
                                    vuurmuur_opendir(tb->cfg, dir_location))) {
                    vrmr_error(-1, "Error", "Unable to open '%s', %s.",
                            dir_location, strerror(errno));
                    return (NULL);
                }
            }

            if ((dir_entry_p = readdir(tb->interface_p)) != NULL) {
                vrmr_debug(HIGH, "name: '%s'.", dir_entry_p->d_name);

                if (strncmp(dir_entry_p->d_name, ".", 1) != 0 &&
                        strcmp(dir_entry_p->d_name, "..") != 0 &&
                        strlen(dir_entry_p->d_name) > 5) {
                    /* this way we check if filename ends with '.conf' */
                    if (dir_entry_p->d_name[strlen(dir_entry_p->d_name) - 5] ==
                                    '.' &&
                            dir_entry_p->d_name[strlen(dir_entry_p->d_name) -
                                                4] == 'c' &&
                            dir_entry_p->d_name[strlen(dir_entry_p->d_name) -
                                                3] == 'o' &&
                            dir_entry_p->d_name[strlen(dir_entry_p->d_name) -
                                                2] == 'n' &&
                            dir_entry_p->d_name[strlen(dir_entry_p->d_name) -
                                                1] == 'f') {
                        /* make sure we dont allow too long filenames */
                        if ((strlen(dir_entry_p->d_name) <
                                    VRMR_MAX_INTERFACE + 5)) {
                            (void)strlcpy(tb->interface, dir_entry_p->d_name,
                                    (strlen(dir_entry_p->d_name) - 5) + 1);
                            tb->interface[strlen(dir_entry_p->d_name) - 5] =
                                    '\0';

                            if (vrmr_validate_interfacename(tb->interface,
                                        tb->interfacename_reg) == 0) {
                                *zonetype = VRMR_TYPE_INTERFACE;
                                (void)strlcpy(name, tb->interface,
                                        VRMR_MAX_INTERFACE);

                                // determine the location of the file
                                if (!(file_location = get_filelocation(backend,
                                              name, VRMR_TYPE_INTERFACE)))
                                    return (NULL);

                                vrmr_debug(HIGH, "interface '%s', file: '%s'.",
                                        name, file_location);

                                /* now stat it */
                                if (vrmr_stat_ok(tb->cfg, file_location,
                                            VRMR_STATOK_WANT_FILE,
                                            VRMR_STATOK_QUIET,
                                            VRMR_STATOK_MUST_EXIST)) {
                                    free(file_location);
                                    vrmr_debug(HIGH, "returning name: '%s'.",
                                            name);
                                    return (name);
                                }

                                // free temp mem
                                free(file_location);
                            }
                        } else {
                            vrmr_debug(HIGH, "'%s' is too long.",
                                    dir_entry_p->d_name);
                        }
                    }
                }
            } else {
                done = 1;
                closedir(tb->interface_p);
                tb->interface_p = NULL;
            }
        }
    }
    /* rules */
    else if (type == VRMR_BT_RULES) {
        /* set the dirlocation */
        if (snprintf(dir_location, sizeof(dir_location), "%s/rules",
                    tb->textdirlocation) >= (int)sizeof(dir_location)) {
            return (NULL);
        }

        while (done == 0) {
            /* check if already open, if not: open it */
            if (!tb->rule_p) {
                /* open the dir */
                if (!(tb->rule_p = vuurmuur_opendir(tb->cfg, dir_location))) {
                    vrmr_error(-1, "Error", "unable to open '%s': %s.",
                            dir_location, strerror(errno));
                    return (NULL);
                }
            }

            if ((dir_entry_p = readdir(tb->rule_p)) != NULL) {
                vrmr_debug(HIGH, "name: '%s'.", dir_entry_p->d_name);

                if ((strncmp(dir_entry_p->d_name, ".", 1) != 0) &&
                        (strcmp(dir_entry_p->d_name, "..") != 0) &&
                        (strlen(dir_entry_p->d_name) > 5)) {
                    /* this way we check if filename ends with '.conf' */
                    if (dir_entry_p->d_name[strlen(dir_entry_p->d_name) - 5] ==
                                    '.' &&
                            dir_entry_p->d_name[strlen(dir_entry_p->d_name) -
                                                4] == 'c' &&
                            dir_entry_p->d_name[strlen(dir_entry_p->d_name) -
                                                3] == 'o' &&
                            dir_entry_p->d_name[strlen(dir_entry_p->d_name) -
                                                2] == 'n' &&
                            dir_entry_p->d_name[strlen(dir_entry_p->d_name) -
                                                1] == 'f') {
                        /* make sure we dont allow too long filenames */
                        if ((strlen(dir_entry_p->d_name) < MAX_RULE_NAME + 5)) {
                            (void)strlcpy(tb->rule, dir_entry_p->d_name,
                                    (strlen(dir_entry_p->d_name) - 5) + 1);
                            tb->rule[strlen(dir_entry_p->d_name) - 5] = '\0';

                            *zonetype = VRMR_TYPE_RULE;
                            (void)strlcpy(name, tb->rule, MAX_RULE_NAME);

                            /* determine the location of the file */
                            if (!(file_location = get_filelocation(
                                          backend, name, VRMR_TYPE_RULE)))
                                return (NULL);

                            vrmr_debug(HIGH, "rule '%s', file: '%s'.", name,
                                    file_location);

                            /* now stat it */
                            if (vrmr_stat_ok(tb->cfg, file_location,
                                        VRMR_STATOK_WANT_FILE,
                                        VRMR_STATOK_QUIET,
                                        VRMR_STATOK_MUST_EXIST)) {
                                free(file_location);
                                vrmr_debug(HIGH, "returning name: '%s'.", name);
                                return (name);
                            }

                            /* free temp mem */
                            free(file_location);
                        }
                    }
                }
            } else {
                done = 1;
                closedir(tb->rule_p);
                tb->rule_p = NULL;
            }
        }
    } else if (type == VRMR_BT_ZONES) {
        while (!done) {
            // this is the base dir
            if (snprintf(dir_location, sizeof(dir_location), "%s/zones",
                        tb->textdirlocation) >= (int)sizeof(dir_location)) {
                return (NULL);
            }

            if (tb->host_p != NULL) {
                vrmr_debug(HIGH, "getting a hostname.");

                if ((dir_entry_p = readdir(tb->host_p)) != NULL) {
                    // make sure that we dont use '.' and '..' and files that
                    // are not long enough to be serious
                    if ((strncmp(dir_entry_p->d_name, ".", 1) != 0) &&
                            (strcmp(dir_entry_p->d_name, "..") != 0) &&
                            (strlen(dir_entry_p->d_name) > 5)) {
                        vrmr_debug(HIGH, "host name: %s.", dir_entry_p->d_name);
                        vrmr_debug(HIGH, "item: %s, %d.", dir_entry_p->d_name,
                                (int)strlen(dir_entry_p->d_name));

                        // max sure the name is not too long
                        if (strlen(dir_entry_p->d_name) < VRMR_MAX_HOST + 5) {
                            (void)strlcpy(tb->cur_host, dir_entry_p->d_name,
                                    (strlen(dir_entry_p->d_name) - 5) + 1);
                            tb->cur_host[strlen(dir_entry_p->d_name) - 5] =
                                    '\0';

                            snprintf(cur_zonename, sizeof(cur_zonename),
                                    "%s.%s.%s", tb->cur_host, tb->cur_network,
                                    tb->cur_zone);

                            // lets check against regex
                            if (vrmr_validate_zonename(cur_zonename, 1, NULL,
                                        NULL, NULL, tb->zonename_reg,
                                        VRMR_QUIET) == 0) {
                                // determine the location of the file
                                if (!(file_location = get_filelocation(backend,
                                              cur_zonename, VRMR_TYPE_HOST)))
                                    return (NULL);
                                vrmr_debug(HIGH, "host '%s', file: '%s'.",
                                        cur_zonename, file_location);

                                // now stat it
                                if (vrmr_stat_ok(tb->cfg, file_location,
                                            VRMR_STATOK_WANT_FILE,
                                            VRMR_STATOK_QUIET,
                                            VRMR_STATOK_MUST_EXIST)) {
                                    free(file_location);

                                    *zonetype = VRMR_TYPE_HOST;

                                    (void)strlcpy(name, cur_zonename,
                                            VRMR_VRMR_MAX_HOST_NET_ZONE);
                                    return (name);
                                }

                                free(file_location);
                            }
                        }
                    }
                } else {
                    vrmr_debug(HIGH, "host dir closed.");
                    closedir(tb->host_p);
                    tb->host_p = NULL;
                }
            } else if (tb->group_p != NULL) {
                vrmr_debug(HIGH, "getting a groupname.");

                if ((dir_entry_p = readdir(tb->group_p)) != NULL) {
                    // make sure that we dont use '.' and '..' and files that
                    // are not long enough to be serious
                    if ((strncmp(dir_entry_p->d_name, ".", 1) != 0) &&
                            (strcmp(dir_entry_p->d_name, "..") != 0) &&
                            (strlen(dir_entry_p->d_name) > 5)) {
                        vrmr_debug(
                                HIGH, "group name: %s.", dir_entry_p->d_name);

                        // max sure the name is not too long
                        if (strlen(dir_entry_p->d_name) < VRMR_MAX_HOST + 5) {
                            (void)strlcpy(tb->cur_host, dir_entry_p->d_name,
                                    (strlen(dir_entry_p->d_name) - 6) + 1);
                            tb->cur_host[strlen(dir_entry_p->d_name) - 6] =
                                    '\0';

                            snprintf(cur_zonename, sizeof(cur_zonename),
                                    "%s.%s.%s", tb->cur_host, tb->cur_network,
                                    tb->cur_zone);

                            // lets check against regex
                            if (vrmr_validate_zonename(cur_zonename, 1, NULL,
                                        NULL, NULL, tb->zonename_reg,
                                        VRMR_QUIET) == 0) {
                                // determine the location of the file
                                if (!(file_location = get_filelocation(backend,
                                              cur_zonename, VRMR_TYPE_GROUP)))
                                    return (NULL);
                                vrmr_debug(HIGH, "group '%s', file: '%s'.",
                                        cur_zonename, file_location);

                                // now stat it
                                if (vrmr_stat_ok(tb->cfg, file_location,
                                            VRMR_STATOK_WANT_FILE,
                                            VRMR_STATOK_QUIET,
                                            VRMR_STATOK_MUST_EXIST)) {
                                    free(file_location);

                                    *zonetype = VRMR_TYPE_GROUP;

                                    (void)strlcpy(name, cur_zonename,
                                            VRMR_VRMR_MAX_HOST_NET_ZONE);
                                    return (name);
                                }

                                free(file_location);
                            }
                        }
                    }
                } else {
                    vrmr_debug(HIGH, "group dir closed.");

                    closedir(tb->group_p);
                    tb->group_p = NULL;
                }
            } else if (tb->network_p != NULL) {
                vrmr_debug(HIGH, "getting a networkname.");

                if ((dir_entry_p = readdir(tb->network_p)) != NULL) {
                    snprintf(netdir_location, sizeof(netdir_location),
                            "%s/zones/%s/networks", tb->textdirlocation,
                            tb->cur_zone);

                    vrmr_debug(HIGH, "network entry: %s.", dir_entry_p->d_name);

                    if ((strncmp(dir_entry_p->d_name, ".", 1) != 0) &&
                            (strcmp(dir_entry_p->d_name, "..") != 0)) {
                        (void)strlcpy(tb->cur_network, dir_entry_p->d_name,
                                VRMR_MAX_NETWORK);
                        vrmr_debug(
                                HIGH, "network name: %s.", dir_entry_p->d_name);

                        // open the hostdir
                        if (snprintf(hostdir_location, sizeof(hostdir_location),
                                    "%s/%s/hosts", netdir_location,
                                    dir_entry_p->d_name) >=
                                (int)sizeof(hostdir_location)) {
                            return (NULL);
                        }
                        vrmr_debug(HIGH, "opening host dir: %s.",
                                hostdir_location);

                        /* this is allowed to fail, if it does, is will be NULL,
                         * and will be detected above */
                        tb->host_p =
                                vuurmuur_tryopendir(tb->cfg, hostdir_location);

                        /* open the groupdir */
                        if (snprintf(groupdir_location,
                                    sizeof(groupdir_location), "%s/%s/groups",
                                    netdir_location, dir_entry_p->d_name) >=
                                (int)sizeof(groupdir_location)) {
                            return (NULL);
                        }
                        vrmr_debug(HIGH, "opening group dir: %s.",
                                groupdir_location);

                        /* this is allowed to fail, if it does, is will be NULL,
                         * and will be detected above */
                        tb->group_p =
                                vuurmuur_tryopendir(tb->cfg, groupdir_location);

                        snprintf(cur_zonename, sizeof(cur_zonename), "%s.%s",
                                tb->cur_network, tb->cur_zone);

                        /* lets check against regex */
                        if (vrmr_validate_zonename(cur_zonename, 1, NULL, NULL,
                                    NULL, tb->zonename_reg, VRMR_QUIET) == 0) {
                            // determine the location of the file
                            if (!(file_location = get_filelocation(backend,
                                          cur_zonename, VRMR_TYPE_NETWORK)))
                                return (NULL);
                            vrmr_debug(HIGH,
                                    "list_textdir: network '%s', file: '%s'.",
                                    cur_zonename, file_location);

                            // now stat it
                            if (vrmr_stat_ok(tb->cfg, file_location,
                                        VRMR_STATOK_WANT_FILE,
                                        VRMR_STATOK_QUIET,
                                        VRMR_STATOK_MUST_EXIST)) {
                                free(file_location);

                                vrmr_debug(HIGH,
                                        "list_textdir: '%s' ('%s', '%s').",
                                        cur_zonename, tb->cur_network,
                                        tb->cur_zone);

                                *zonetype = VRMR_TYPE_NETWORK;

                                (void)strlcpy(
                                        name, cur_zonename, VRMR_MAX_NET_ZONE);
                                return (name);
                            }

                            free(file_location);
                        }
                    }
                } else {
                    vrmr_debug(HIGH, "network dir closed.");

                    closedir(tb->network_p);
                    tb->network_p = NULL;
                }
            } else if (tb->zone_p != NULL) {
                vrmr_debug(HIGH, "getting a zonename.");

                if ((dir_entry_p = readdir(tb->zone_p)) != NULL) {
                    vrmr_debug(HIGH, "zone entry: %s.", dir_entry_p->d_name);

                    if ((strncmp(dir_entry_p->d_name, ".", 1) != 0) &&
                            (strcmp(dir_entry_p->d_name, "..") != 0)) {
                        (void)strlcpy(tb->cur_zone, dir_entry_p->d_name,
                                VRMR_MAX_ZONE);

                        vrmr_debug(HIGH, "zone name: %s.", dir_entry_p->d_name);

                        // open the networkdir
                        if (snprintf(netdir_location, sizeof(netdir_location),
                                    "%s/%s/networks", dir_location,
                                    dir_entry_p->d_name) >=
                                (int)sizeof(netdir_location)) {
                            return (NULL);
                        }
                        vrmr_debug(HIGH, "opening: %s.", netdir_location);

                        /* this is allowed to fail, if it does, is will be NULL,
                         * and will be detected above */
                        tb->network_p =
                                vuurmuur_tryopendir(tb->cfg, netdir_location);

                        // lets check against regex
                        if (vrmr_validate_zonename(dir_entry_p->d_name, 1, NULL,
                                    NULL, NULL, tb->zonename_reg,
                                    VRMR_QUIET) == 0) {
                            // determine the location of the file
                            if (!(file_location = get_filelocation(backend,
                                          dir_entry_p->d_name, VRMR_TYPE_ZONE)))
                                return (NULL);
                            vrmr_debug(HIGH, "zone '%s', file: '%s'.",
                                    tb->cur_zone, file_location);

                            // now stat it
                            if (vrmr_stat_ok(tb->cfg, file_location,
                                        VRMR_STATOK_WANT_FILE,
                                        VRMR_STATOK_QUIET,
                                        VRMR_STATOK_MUST_EXIST)) {
                                free(file_location);

                                vrmr_debug(HIGH, "zone '%s'.", tb->cur_zone);

                                *zonetype = VRMR_TYPE_ZONE;

                                (void)strlcpy(name, dir_entry_p->d_name,
                                        VRMR_MAX_ZONE);
                                return (name);
                            }

                            free(file_location);
                        }
                    }
                } else {
                    vrmr_debug(HIGH, "zone dir closing.");
                    closedir(tb->zone_p);
                    tb->zone_p = NULL;

                    done = 1;
                }
            }

            if (!done && !tb->zone_p) {
                vrmr_debug(HIGH, "opening the zonesdir.");

                // open the dir
                if (!(tb->zone_p = vuurmuur_opendir(tb->cfg, dir_location))) {
                    vrmr_error(-1, "Error", "unable to open directory: %s: %s.",
                            dir_location, strerror(errno));
                    return (NULL);
                }
            }
        }
    } else {
        vrmr_error(-1, "Internal Error", "unknown type '%d'.", type);
        return (NULL);
    }

    return (NULL);
}

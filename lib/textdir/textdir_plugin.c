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

#include "textdir.h"
#include "textdir_plugin.h"

/*  get_filelocation

    get the file location of the 'name' with type 'type'.

    Returns NULL on error.

    The caller needs to free the memory.
*/
char *get_filelocation(
        void *backend, const char *name, const enum vrmr_objecttypes type)
{
    char hostname[VRMR_MAX_HOST] = "", networkname[VRMR_MAX_NETWORK] = "",
         zonename[VRMR_MAX_ZONE] = "";
    char file_location[512] = "", *fileloc_ptr = NULL;

    assert(backend && name);
    assert(type >= VRMR_TYPE_HOST && type <= VRMR_TYPE_RULE);

    struct textdir_backend *tb = (struct textdir_backend *)backend;

    /* check if backend is open */
    if (!tb->backend_open) {
        vrmr_error(-1, "Error", "backend not opened yet");
        return (NULL);
    }

    switch (type) {
        case VRMR_TYPE_ZONE:
        case VRMR_TYPE_NETWORK:
        case VRMR_TYPE_GROUP:
        case VRMR_TYPE_HOST:
            /* validate the name */
            if (vrmr_validate_zonename(name, 0, zonename, networkname, hostname,
                        tb->zonename_reg, VRMR_VERBOSE) != 0) {
                vrmr_error(-1, "Error", "zonename '%s' is not valid", name);
                return (NULL);
            }
            break;
        case VRMR_TYPE_SERVICE:
        case VRMR_TYPE_SERVICEGRP:
            /* validate the name */
            if (vrmr_validate_servicename(name, tb->servicename_reg) != 0) {
                vrmr_error(-1, "Error", "servicename '%s' is not valid.", name);
                return (NULL);
            }
            break;
        case VRMR_TYPE_INTERFACE:
            /* validate the name */
            if (vrmr_validate_interfacename(name, tb->interfacename_reg) != 0) {
                vrmr_error(
                        -1, "Error", "interfacename '%s' is not valid.", name);
                return (NULL);
            }
            break;
        default:
            break;
    }

    switch (type) {
        /* host */
        case VRMR_TYPE_HOST:

            vrmr_debug(HIGH, "%s is a host.", name);
            vrmr_debug(HIGH, "arguments: %s, %s and %s", hostname, networkname,
                    zonename);

            /* assemble the filestring, and make sure we dont overflow */
            if (snprintf(file_location, sizeof(file_location),
                        "%s/zones/%s/networks/%s/hosts/%s.host",
                        tb->textdirlocation, zonename, networkname,
                        hostname) >= (int)sizeof(file_location)) {
                vrmr_error(-1, "Error", "buffer overflow");
                return (NULL);
            }
            break;

            /* group */
        case VRMR_TYPE_GROUP:

            vrmr_debug(HIGH, "%s is a group.", name);
            vrmr_debug(HIGH, "arguments: %s, %s and %s", hostname, networkname,
                    zonename);

            /* assemble the filestring, and make sure we dont overflow */
            if (snprintf(file_location, sizeof(file_location),
                        "%s/zones/%s/networks/%s/groups/%s.group",
                        tb->textdirlocation, zonename, networkname,
                        hostname) >= (int)sizeof(file_location)) {
                vrmr_error(-1, "Error", "buffer overflow");
                return (NULL);
            }
            break;

            /* network */
        case VRMR_TYPE_NETWORK:

            vrmr_debug(HIGH, "%s is a network.", name);
            vrmr_debug(HIGH, "arguments: %s and %s.", networkname, zonename);

            /* assemble the filestring, and make sure we dont overflow */
            if (snprintf(file_location, sizeof(file_location),
                        "%s/zones/%s/networks/%s/network.config",
                        tb->textdirlocation, zonename,
                        networkname) >= (int)sizeof(file_location)) {
                vrmr_error(-1, "Error", "buffer overflow");
                return (NULL);
            }
            break;

            /* zone */
        case VRMR_TYPE_ZONE:

            vrmr_debug(HIGH, "%s is a zone.", name);
            vrmr_debug(HIGH, "arguments: %s.", zonename);

            /* assemble the filestring, and make sure we dont overflow */
            if (snprintf(file_location, sizeof(file_location),
                        "%s/zones/%s/zone.config", tb->textdirlocation,
                        zonename) >= (int)sizeof(file_location)) {
                vrmr_error(-1, "Error", "buffer overflow");
                return (NULL);
            }
            break;

        case VRMR_TYPE_SERVICE:
        case VRMR_TYPE_SERVICEGRP:
            vrmr_debug(
                    HIGH, "looking up data from services, service: %s.", name);

            /* assemble the filestring, and make sure we dont overflow */
            if (snprintf(file_location, sizeof(file_location), "%s/services/%s",
                        tb->textdirlocation,
                        name) >= (int)sizeof(file_location)) {
                vrmr_error(-1, "Error", "buffer overflow");
                return (NULL);
            }
            break;

        case VRMR_TYPE_INTERFACE:
            vrmr_debug(HIGH, "looking up data from interfaces, interface: %s.",
                    name);

            /* assemble the filestring, and make sure we dont overflow */
            if (snprintf(file_location, sizeof(file_location),
                        "%s/interfaces/%s.conf", tb->textdirlocation,
                        name) >= (int)sizeof(file_location)) {
                vrmr_error(-1, "Error", "buffer overflow");
                return (NULL);
            }
            break;

        case VRMR_TYPE_RULE:
            /* assemble the filestring, and make sure we dont overflow */
            if (snprintf(file_location, sizeof(file_location),
                        "%s/rules/%s.conf", tb->textdirlocation,
                        name) >= (int)sizeof(file_location)) {
                vrmr_error(-1, "Error", "buffer overflow");
                return (NULL);
            }
            break;

        default:
            break;
    }

    vrmr_debug(HIGH, "file_location: %s.", file_location);
    /* now allocate some memory */
    if (!(fileloc_ptr = strdup(file_location))) {
        vrmr_error(-1, "Error", "strdup failed: %s", strerror(errno));
        return (NULL);
    }
    return (fileloc_ptr);
}

/*
    opening the backend
*/
int open_textdir(
        void *backend, int mode ATTR_UNUSED, enum vrmr_backend_types type)
{
    char dir_location[PATH_MAX] = "";
    DIR *dir_p = NULL;

    assert(backend);

    struct textdir_backend *tb = (struct textdir_backend *)backend;

    /* see if we like the permissions of the textdirroot */
    if (!(vrmr_stat_ok(tb->cfg, tb->textdirlocation, VRMR_STATOK_WANT_DIR,
                VRMR_STATOK_QUIET, VRMR_STATOK_MUST_EXIST)))
        return (-1);

    if (tb->backend_open == 1) {
        vrmr_error(
                -1, "Internal Error", "opening textdir failed: already open");
        return (-1);
    } else {
        vrmr_debug(HIGH, "setting backed_open to 1");

        /* set to open */
        tb->backend_open = 1;
    }

    /* now if were opening for type VRMR_BT_ZONES, setup the regex */
    if (type == VRMR_BT_ZONES) {
        /* regex setup */
        if (!(tb->zonename_reg = malloc(sizeof(regex_t)))) {
            vrmr_error(
                    -1, "Internal Error", "malloc failed: %s", strerror(errno));

            /* set the backend to closed again */
            tb->backend_open = 0;
            return (-1);
        }

        /* this regex is defined in libvuurmuur -> vuurmuur.h */
        if (regcomp(tb->zonename_reg, VRMR_ZONE_REGEX, REG_EXTENDED) != 0) {
            vrmr_error(-1, "Internal Error", "regcomp() failed");
            /* set the backend to closed again */
            tb->backend_open = 0;

            free(tb->zonename_reg);
            tb->zonename_reg = NULL;

            return (-1);
        }

        vrmr_debug(HIGH, "setting up regex for zonename success.");

        /* set the dirlocation */
        snprintf(dir_location, sizeof(dir_location), "%s/zones",
                tb->textdirlocation);
    } else if (type == VRMR_BT_SERVICES) {
        /* regex setup */
        if (!(tb->servicename_reg = malloc(sizeof(regex_t)))) {
            vrmr_error(
                    -1, "Internal Error", "malloc failed: %s", strerror(errno));

            /* set the backend to closed again */
            tb->backend_open = 0;
            return (-1);
        }

        /* this regex is defined in libvuurmuur -> vuurmuur.h */
        if (regcomp(tb->servicename_reg, VRMR_SERV_REGEX, REG_EXTENDED) != 0) {
            vrmr_error(-1, "Internal Error", "regcomp() failed");
            /* set the backend to closed again */
            tb->backend_open = 0;

            free(tb->servicename_reg);
            tb->servicename_reg = NULL;

            return (-1);
        }

        vrmr_debug(HIGH, "setting up regex for servicename success.");

        /* set the dirlocation */
        snprintf(dir_location, sizeof(dir_location), "%s/services",
                tb->textdirlocation);
    } else if (type == VRMR_BT_INTERFACES) {
        /* regex setup */
        if (!(tb->interfacename_reg = malloc(sizeof(regex_t)))) {
            vrmr_error(
                    -1, "Internal Error", "malloc failed: %s", strerror(errno));

            /* set the backend to closed again */
            tb->backend_open = 0;
            return (-1);
        }

        /* this regex is defined in libvuurmuur -> vuurmuur.h */
        if (regcomp(tb->interfacename_reg, VRMR_IFAC_REGEX, REG_EXTENDED) !=
                0) {
            vrmr_error(-1, "Internal Error", "regcomp() failed");
            /* set the backend to closed again */
            tb->backend_open = 0;

            free(tb->interfacename_reg);
            tb->interfacename_reg = NULL;

            return (-1);
        }

        vrmr_debug(HIGH, "setting up regex for interfacename success.");

        /* set the dirlocation */
        snprintf(dir_location, sizeof(dir_location), "%s/interfaces",
                tb->textdirlocation);
    } else if (type == VRMR_BT_RULES) {
        /* set the dirlocation */
        snprintf(dir_location, sizeof(dir_location), "%s/rules",
                tb->textdirlocation);
    } else {
        vrmr_error(-1, "Internal Error", "unknown type %d", type);
        return (-1);
    }

    /* create the dir if it does not exist */
    if (!(dir_p = opendir(dir_location))) {
        if (errno == ENOENT) {
            if (mkdir(dir_location, 0700) < 0) {
                vrmr_error(-1, "Error", "creating directory '%s' failed: %s",
                        dir_location, strerror(errno));
                return (-1);
            }
        } else {
            vrmr_error(-1, "Error", "opening directory '%s' failed: %s",
                    dir_location, strerror(errno));
            return (-1);
        }
    } else {
        closedir(dir_p);
    }

    /* now stat it */
    if (vrmr_stat_ok(tb->cfg, dir_location, VRMR_STATOK_WANT_DIR,
                VRMR_STATOK_VERBOSE, VRMR_STATOK_MUST_EXIST) != 1) {
        vrmr_error(-1, "Error",
                "checking '%s' failed. Please check if the directory exists "
                "and that the permissions are ok.",
                dir_location);
        return (-1);
    }

    return (0);
}

int close_textdir(void *backend, enum vrmr_backend_types type)
{
    assert(backend);

    struct textdir_backend *tb = (struct textdir_backend *)backend;
    if (tb->backend_open) {
        vrmr_debug(HIGH, "closing: setting backend_open to close");
        tb->backend_open = false;
    }

    /* cleanup regex */
    if (type == VRMR_BT_ZONES && tb->zonename_reg != NULL) {
        vrmr_debug(HIGH, "cleaning up regex.");

        regfree(tb->zonename_reg);
        free(tb->zonename_reg);
        tb->zonename_reg = NULL;
    } else if (type == VRMR_BT_SERVICES && tb->servicename_reg != NULL) {
        vrmr_debug(HIGH, "cleaning up regex.");

        regfree(tb->servicename_reg);
        free(tb->servicename_reg);
        tb->servicename_reg = NULL;
    } else if (type == VRMR_BT_INTERFACES && tb->interfacename_reg != NULL) {
        vrmr_debug(HIGH, "cleaning up regex.");

        regfree(tb->interfacename_reg);
        free(tb->interfacename_reg);
        tb->interfacename_reg = NULL;
    } else if (type == VRMR_BT_RULES) {
        /* nothing yet */
    } else {
        vrmr_error(-1, "Internal Error", "unknown type %d", type);
        return (-1);
    }

    return (0);
}

/* setting up the backend for first use */
int init_textdir(
        void *backend ATTR_UNUSED, enum vrmr_backend_types type ATTR_UNUSED)
{
    // TODO
    return (0);
}

static int create_dir_if_missing(const char *dir_location)
{
    errno = 0;
    if (mkdir(dir_location, 0700) < 0) {
        if (errno == EEXIST)
            return 0;

        vrmr_error(-1, "Error", "Creating directory %s failed: %s.",
                dir_location, strerror(errno));
        return -1;
    }
    return 0;
}

/*  add item to the backend

*/
int add_textdir(void *backend, const char *name, enum vrmr_objecttypes type)
{
    FILE *fp = NULL;
    char *file_location = NULL, dir_location[PATH_MAX] = "",
         hostname[VRMR_MAX_HOST] = "", networkname[VRMR_MAX_NETWORK] = "",
         zonename[VRMR_MAX_ZONE] = "";
    int fd = 0;

    assert(backend && name);

    /* check if the backend is open */
    struct textdir_backend *tb = (struct textdir_backend *)backend;
    if (!tb->backend_open) {
        vrmr_error(-1, "Error", "Backend not opened yet");
        return (-1);
    }

    /* determine the location of the file */
    if (!(file_location = get_filelocation(backend, name, type)))
        return (-1);

    /* check if the file already exist */
    if ((fp = fopen(file_location, "r"))) {
        vrmr_error(
                -1, "Error", "creating %s failed: file exists.", file_location);

        fclose(fp);
        free(file_location);
        return (-1);
    }

    /* create the dirs for zones and networks */
    if (type == VRMR_TYPE_ZONE || type == VRMR_TYPE_NETWORK ||
            type == VRMR_TYPE_HOST || type == VRMR_TYPE_GROUP) {
        /* split up the name */
        if (vrmr_validate_zonename(name, 0, zonename, networkname, hostname,
                    tb->zonename_reg, VRMR_VERBOSE) != 0) {
            vrmr_error(-1, "Error", "Zonename '%s' is not valid.", name);

            free(file_location);
            file_location = NULL;
            return (-1);
        }

        switch (type) {
            case VRMR_TYPE_ZONE:
                /* zones dir */
                snprintf(dir_location, sizeof(dir_location), "%s/zones",
                        tb->textdirlocation);
                if (create_dir_if_missing(dir_location) < 0) {
                    free(file_location);
                    file_location = NULL;
                    return (-1);
                }
                /* zone dir */
                snprintf(dir_location, sizeof(dir_location), "%s/zones/%s",
                        tb->textdirlocation, zonename);
                if (create_dir_if_missing(dir_location) < 0) {
                    free(file_location);
                    file_location = NULL;
                    return (-1);
                }

                /* network dir */
                snprintf(dir_location, sizeof(dir_location),
                        "%s/zones/%s/networks", tb->textdirlocation, zonename);
                if (create_dir_if_missing(dir_location) < 0) {
                    free(file_location);
                    file_location = NULL;
                    return (-1);
                }
                break;
            case VRMR_TYPE_NETWORK:
                /* networks dir */
                snprintf(dir_location, sizeof(dir_location),
                        "%s/zones/%s/networks", tb->textdirlocation, zonename);
                if (create_dir_if_missing(dir_location) < 0) {
                    free(file_location);
                    file_location = NULL;
                    return (-1);
                }

                /* network dir */
                snprintf(dir_location, sizeof(dir_location),
                        "%s/zones/%s/networks/%s", tb->textdirlocation,
                        zonename, networkname);
                if (create_dir_if_missing(dir_location) < 0) {
                    free(file_location);
                    file_location = NULL;
                    return (-1);
                }

                /* host dir */
                snprintf(dir_location, sizeof(dir_location),
                        "%s/zones/%s/networks/%s/hosts", tb->textdirlocation,
                        zonename, networkname);
                if (create_dir_if_missing(dir_location) < 0) {
                    free(file_location);
                    file_location = NULL;
                    return (-1);
                }

                /* group dir */
                snprintf(dir_location, sizeof(dir_location),
                        "%s/zones/%s/networks/%s/groups", tb->textdirlocation,
                        zonename, networkname);
                if (create_dir_if_missing(dir_location) < 0) {
                    free(file_location);
                    file_location = NULL;
                    return (-1);
                }
                break;

            case VRMR_TYPE_HOST:
            case VRMR_TYPE_GROUP:
                /* host dir */
                snprintf(dir_location, sizeof(dir_location),
                        "%s/zones/%s/networks/%s/hosts", tb->textdirlocation,
                        zonename, networkname);
                if (create_dir_if_missing(dir_location) < 0) {
                    free(file_location);
                    file_location = NULL;
                    return (-1);
                }

                /* group dir */
                snprintf(dir_location, sizeof(dir_location),
                        "%s/zones/%s/networks/%s/groups", tb->textdirlocation,
                        zonename, networkname);
                if (create_dir_if_missing(dir_location) < 0) {
                    free(file_location);
                    file_location = NULL;
                    return (-1);
                }
                break;
            default:
                break;
        }
    }

    /* now open for writing (file will be created) */
    if ((fd = open(file_location, O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1) {
        vrmr_error(-1, "Error", "Creating %s failed: %s (in: add_textdir).",
                file_location, strerror(errno));

        free(file_location);
        file_location = NULL;
        return (-1);
    }

    free(file_location);
    file_location = NULL;

    /*
        print the content
    */
    if (type != VRMR_TYPE_RULE) {
        if (write(fd, "ACTIVE=\"\"\n", 10) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
    }

    if (type == VRMR_TYPE_HOST) {
        if (write(fd, "IPADDRESS=\"\"\n", 13) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "MAC=\"\"\n", 7) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
    } else if (type == VRMR_TYPE_GROUP) {
        if (write(fd, "MEMBER=\"\"\n", 10) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
    } else if (type == VRMR_TYPE_NETWORK) {
        if (write(fd, "NETWORK=\"\"\n", 11) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "NETMASK=\"\"\n", 11) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "INTERFACE=\"\"\n", 13) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "RULE=\"\"\n", 8) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
    } else if (type == VRMR_TYPE_SERVICE) {
        if (write(fd, "TCP=\"\"\n", 7) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "UDP=\"\"\n", 7) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "ICMP=\"\"\n", 8) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "GRE=\"\"\n", 7) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "AH=\"\"\n", 6) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "ESP=\"\"\n", 7) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "PROTO_41=\"\"\n", 12) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "BROADCAST=\"\"\n", 13) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "HELPER=\"\"\n", 10) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
    } else if (type == VRMR_TYPE_INTERFACE) {
        if (write(fd, "IPADDRESS=\"\"\n", 13) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "DEVICE=\"\"\n", 10) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "VIRTUAL=\"\"\n", 11) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
        if (write(fd, "RULE=\"\"\n", 8) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
    } else if (type == VRMR_TYPE_RULE) {
        if (write(fd, "RULE=\"\"\n", 8) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
    }

    if (type != VRMR_TYPE_RULE) {
        if (write(fd, "COMMENT=\"\"\n", 11) == -1) {
            vrmr_error(-1, "Error", "write: %s", strerror(errno));
            goto error;
        }
    }

    fsync(fd);
    (void)close(fd);
    return (0);
error:
    (void)close(fd);
    return (-1);
}

/*  del_textdir

    Delete from the textdir.

    Returncodes:
        0: ok
        -1: error
*/
int del_textdir(void *backend, const char *name, enum vrmr_objecttypes type,
        int recurs ATTR_UNUSED)
{
    char *file_location = NULL, dir_location[512] = "",
         hostname[VRMR_MAX_HOST] = "", networkname[VRMR_MAX_NETWORK] = "",
         zonename[VRMR_MAX_ZONE] = "";

    assert(backend && name);

    /* check if the backend was properly openend */
    struct textdir_backend *tb = (struct textdir_backend *)backend;
    if (!tb->backend_open) {
        vrmr_error(-1, "Error", "backend not opened yet");
        return (-1);
    }

    /* name splitting only needed for network and zone, as host and group just
       use the file_location this is because network and zone need to remove
       directories as well
    */
    if (type == VRMR_TYPE_ZONE || type == VRMR_TYPE_NETWORK) {
        // split up the name
        if (vrmr_validate_zonename(name, 0, zonename, networkname, hostname,
                    tb->zonename_reg, VRMR_VERBOSE) != 0) {
            vrmr_error(-1, "Error", "Zonename '%s' is not valid", name);
            return (-1);
        }
    }

    /* determine the location of the file */
    if (!(file_location = get_filelocation(backend, name, type)))
        return (-1);

    /* see if we like the file permissions */
    if (!(vrmr_stat_ok(tb->cfg, file_location, VRMR_STATOK_WANT_FILE,
                VRMR_STATOK_VERBOSE, VRMR_STATOK_MUST_EXIST))) {
        free(file_location);
        return (-1);
    }

    /*
        HERE WE DO THE REMOVAL
    */

    if (type == VRMR_TYPE_HOST) {
        if (remove(file_location) < 0) {
            vrmr_error(-1, "Error", "Deleting host file for '%s': %s.", name,
                    strerror(errno));

            free(file_location);
            return (-1);
        }

        vrmr_info("Info", "host '%s' deleted from disk.", name);
    } else if (type == VRMR_TYPE_GROUP) {
        if (remove(file_location) < 0) {
            vrmr_error(-1, "Error", "deleting group file for '%s': %s.", name,
                    strerror(errno));

            free(file_location);
            return (-1);
        }

        vrmr_info("Info", "group '%s' deleted from disk.", name);
    } else if (type == VRMR_TYPE_NETWORK) {
        /* first check the hosts dir */
        if (snprintf(dir_location, sizeof(dir_location),
                    "%s/zones/%s/networks/%s/hosts", tb->textdirlocation,
                    zonename, networkname) >= (int)sizeof(dir_location)) {
            vrmr_error(-1, "Internal Error",
                    "overflow while determining the location to remove");

            free(file_location);
            return (-1);
        }

        /* now remove the dir */
        if (rmdir(dir_location) < 0) {
            vrmr_error(-1, "Error", "deleting host dir failed: %s",
                    strerror(errno));

            free(file_location);
            return (-1);
        }

        /* second check the group dir */
        if (snprintf(dir_location, sizeof(dir_location),
                    "%s/zones/%s/networks/%s/groups", tb->textdirlocation,
                    zonename, networkname) >= (int)sizeof(dir_location)) {
            vrmr_error(-1, "Internal Error",
                    "overflow while determining the location to remove");

            free(file_location);
            return (-1);
        }

        /* now remove the dir */
        if (rmdir(dir_location) < 0) {
            vrmr_error(-1, "Error", "deleting group dir '%s' failed: %s.",
                    dir_location, strerror(errno));

            /* restore the hosts dir */
            if (snprintf(dir_location, sizeof(dir_location),
                        "%s/zones/%s/networks/%s/hosts", tb->textdirlocation,
                        zonename, networkname) >= (int)sizeof(dir_location)) {
                vrmr_error(-1, "Internal Error",
                        "overflow while determining the location to remove");

                free(file_location);
                return (-1);
            }

            if (mkdir(dir_location, 0700) < 0) {
                vrmr_error(-1, "Error", "recreating hostdir failed: %s.",
                        strerror(errno));

                free(file_location);
                return (-1);
            }

            /* now quit */
            free(file_location);
            return (-1);
        }

        /* the network.config file */
        if (remove(file_location) < 0) {
            vrmr_error(-1, "Error", "deleting network.config: %s",
                    strerror(errno));

            free(file_location);
            return (-1);
        }

        /* the network dir */
        if (snprintf(dir_location, sizeof(dir_location),
                    "%s/zones/%s/networks/%s", tb->textdirlocation, zonename,
                    networkname) >= (int)sizeof(dir_location)) {
            vrmr_error(-1, "Internal Error",
                    "overflow while determining the location to remove");

            free(file_location);
            return (-1);
        }
        if (rmdir(dir_location) < 0) {
            vrmr_error(
                    -1, "Error", "deleting network dir: %s", strerror(errno));

            free(file_location);
            return (-1);
        }

        vrmr_info("Info", "Network '%s' deleted from disk.", name);
    } else if (type == VRMR_TYPE_ZONE) {
        /* first check the network */
        if (snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks",
                    tb->textdirlocation, name) >= (int)sizeof(dir_location)) {
            vrmr_error(-1, "Internal Error",
                    "overflow while determining the location to remove");

            free(file_location);
            return (-1);
        }
        if (rmdir(dir_location) < 0) {
            vrmr_error(-1, "Error", "deleting network dir failed: %s",
                    strerror(errno));

            free(file_location);
            return (-1);
        }

        /* the zone.config file */
        if (remove(file_location) < 0) {
            vrmr_error(-1, "Error", "deleting zone.config failed: %s",
                    strerror(errno));

            free(file_location);
            return (-1);
        }

        if (snprintf(dir_location, sizeof(dir_location), "%s/zones/%s",
                    tb->textdirlocation, name) >= (int)sizeof(dir_location)) {
            vrmr_error(-1, "Internal Error",
                    "overflow while determining the location to remove");

            free(file_location);
            return (-1);
        }
        if (rmdir(dir_location) < 0) {
            vrmr_error(-2, "Error", "deleting zone dir failed: %s",
                    strerror(errno));

            free(file_location);
            return (-1);
        }
    } else if (type == VRMR_TYPE_SERVICE) {
        if (remove(file_location) < 0) {
            vrmr_error(-1, "Error", "deleting service %s: %s (%s)", name,
                    strerror(errno), file_location);

            free(file_location);
            return (-1);
        }
    } else if (type == VRMR_TYPE_INTERFACE) {
        if (remove(file_location) < 0) {
            vrmr_error(-1, "Error", "deleting interface %s: %s (%s)", name,
                    strerror(errno), file_location);

            free(file_location);
            return (-1);
        }
    }
    /* handle unknown */
    else {
        vrmr_error(-1, "Internal Error", "unknown type: %d", type);
        free(file_location);
        return (-1);
    }

    /* cleanup */
    free(file_location);
    return (0);
}

/*  rename_textdir

    Renames the item 'name' to 'newname'. The item can be a host, interface,
   service, etc.

    Warning: when renaming a host, group or network, make sure you _only_ rename
    the host/group/network part of the name!

    Returncodes:
        -1: error
         0: ok
*/
int rename_textdir(void *backend, const char *name, const char *newname,
        enum vrmr_objecttypes type)
{
    int result = 0;
    char *oldpath = NULL, *newpath = NULL;
    char vrmr_new_zone_name[VRMR_MAX_ZONE] = "",
         new_net_name[VRMR_MAX_NETWORK] = "", new_host_name[VRMR_MAX_HOST] = "";
    char old_zone_name[VRMR_MAX_ZONE] = "", old_net_name[VRMR_MAX_NETWORK] = "",
         old_host_name[VRMR_MAX_HOST] = "";
    char new_file_location[256] = "", old_file_location[256] = "";

    assert(backend && name && newname);

    struct textdir_backend *tb = (struct textdir_backend *)backend;
    /* check if the backend was properly openend */
    if (!tb->backend_open) {
        vrmr_error(-1, "Error", "backend not opened yet");
        return (-1);
    }

    /* first see if the name and newname are the same */
    if (strcmp(name, newname) == 0)
        return (0);

    /* validate and split the new and the old names for zones and networks */
    if (type == VRMR_TYPE_ZONE || type == VRMR_TYPE_NETWORK) {
        /* validate the name */
        if (vrmr_validate_zonename(name, 0, old_zone_name, old_net_name,
                    old_host_name, tb->zonename_reg, VRMR_VERBOSE) != 0) {
            vrmr_error(-1, "Error", "zonename '%s' is not valid", newname);
            return (-1);
        }

        /* validate the name */
        if (vrmr_validate_zonename(newname, 0, vrmr_new_zone_name, new_net_name,
                    new_host_name, tb->zonename_reg, VRMR_VERBOSE) != 0) {
            vrmr_error(-1, "Error", "zonename '%s' is not valid", newname);
            return (-1);
        }
    }

    if (type == VRMR_TYPE_ZONE) {
        /* get the old path */

        /* assemble the dirstring, and make sure we dont overflow */
        if (snprintf(old_file_location, sizeof(old_file_location),
                    "%s/zones/%s", tb->textdirlocation,
                    old_zone_name) >= (int)sizeof(old_file_location)) {
            vrmr_error(-1, "Error", "buffer overflow");
            return (-1);
        }

        /* get the new path */

        /* assemble the dirstring, and make sure we dont overflow */
        if (snprintf(new_file_location, sizeof(new_file_location),
                    "%s/zones/%s", tb->textdirlocation,
                    vrmr_new_zone_name) >= (int)sizeof(new_file_location)) {
            vrmr_error(-1, "Error", "buffer overflow");
            return (-1);
        }

        result = rename(old_file_location, new_file_location);
        if (result != 0) {
            vrmr_error(-1, "Error", "renaming '%s' to '%s' failed: %s", name,
                    newname, strerror(errno));
            return (-1);
        }
    } else if (type == VRMR_TYPE_NETWORK) {
        /* get the old path */

        /* assemble the filestring, and make sure we dont overflow */
        if (snprintf(old_file_location, sizeof(old_file_location),
                    "%s/zones/%s/networks/%s", tb->textdirlocation,
                    old_zone_name,
                    old_net_name) >= (int)sizeof(old_file_location)) {
            vrmr_error(-1, "Error", "buffer overflow");
            return (-1);
        }

        /* get the new path */

        /* assemble the dirstring, and make sure we dont overflow */
        if (snprintf(new_file_location, sizeof(new_file_location),
                    "%s/zones/%s/networks/%s", tb->textdirlocation,
                    vrmr_new_zone_name,
                    new_net_name) >= (int)sizeof(new_file_location)) {
            vrmr_error(-1, "Error", "buffer overflow");
            return (-1);
        }

        result = rename(old_file_location, new_file_location);
        if (result != 0) {
            vrmr_error(-1, "Error", "renaming '%s' to '%s' failed: %s", name,
                    newname, strerror(errno));
            return (-1);
        }
    } else if (type == VRMR_TYPE_HOST || type == VRMR_TYPE_GROUP) {
        /* determine the location of the file */
        if (!(oldpath = get_filelocation(backend, name, type))) {
            vrmr_error(-1, "Error", "getting path for '%s' failed", name);
            return (-1);
        }
        vrmr_debug(HIGH, "oldpath: '%s'.", oldpath);

        /* determine the location of the new file */
        if (!(newpath = get_filelocation(backend, newname, type))) {
            vrmr_error(-1, "Error", "getting path for '%s' failed", newname);
            free(oldpath);
            return (-1);
        }
        vrmr_debug(HIGH, "newpath: '%s'.", newpath);

        result = rename(oldpath, newpath);
        /* first free the mem */
        free(oldpath);
        free(newpath);
        /* then analyse result */
        if (result != 0) {
            vrmr_error(-1, "Error", "renaming '%s' to '%s' failed: %s", name,
                    newname, strerror(errno));
            return (-1);
        }
    } else if (type == VRMR_TYPE_SERVICE || type == VRMR_TYPE_INTERFACE) {
        /* determine the location of the file */
        if (!(oldpath = get_filelocation(backend, name, type))) {
            vrmr_error(-1, "Error", "getting path for '%s' failed", name);
            return (-1);
        }

        /* determine the location of the new file */
        if (!(newpath = get_filelocation(backend, newname, type))) {
            vrmr_error(-1, "Error", "getting path for '%s' failed", newname);
            free(oldpath);
            return (-1);
        }

        result = rename(oldpath, newpath);
        /* first free the mem */
        free(oldpath);
        free(newpath);
        /* then analyse result */
        if (result != 0) {
            vrmr_error(-1, "Error", "renaming '%s' to '%s' failed: %s", name,
                    newname, strerror(errno));
            return (-1);
        }
    } else {
        vrmr_error(-1, "Internal Error", "unknown type '%d'", type);
        return (-1);
    }

    return (0);
}

/*  conf_textdir

    Loads the config settings from the plugin config file.

    Returncodes:
         0: ok
        -1: error
*/
int conf_textdir(void *backend)
{
    char configfile_location[512] = "";

    assert(backend);

    struct textdir_backend *tb = (struct textdir_backend *)backend;

    /* assemble config location */
    if (snprintf(configfile_location, sizeof(configfile_location),
                "%s/vuurmuur/plugins/textdir.conf",
                tb->cfg->etcdir) >= (int)sizeof(configfile_location)) {
        vrmr_error(-1, "Internal Error",
                "could not determine configfile location: locationstring "
                "overflow");
        return (-1);
    }

    /* now get the backend location from the configfile */
    int result = vrmr_ask_configfile(tb->cfg, "LOCATION", tb->textdirlocation,
            configfile_location, sizeof(tb->textdirlocation));
    if (result < 0) {
        vrmr_error(-1, "Error",
                "failed to get the textdir-root from: %s. Please make sure "
                "LOCATION is set",
                configfile_location);
        return -1;
    } else if (result == 0) {
        vrmr_error(-1, "Error",
                "no information about the location of the backend in '%s'",
                configfile_location);
        return -1;
    } else {
        vrmr_debug(MEDIUM, "textdir location: LOCATION = %s.",
                tb->textdirlocation);
        return 0;
    }
}

int setup_textdir(const struct vrmr_config *cfg, void **backend)
{
    struct textdir_backend *tb = NULL;

    if (!(tb = malloc(sizeof(struct textdir_backend)))) {
        vrmr_error(-1, "Error", "malloc failed: %s", strerror(errno));
        return (-1);
    }

    /* start closed of course */
    tb->backend_open = 0;

    /* not used yet */
    tb->writable = 0; /* TODO */

    tb->zone_p = NULL;
    tb->network_p = NULL;
    tb->host_p = NULL;
    tb->group_p = NULL;
    tb->service_p = NULL;
    tb->interface_p = NULL;
    tb->rule_p = NULL;

    tb->file = NULL;

    tb->zonename_reg = NULL;
    tb->servicename_reg = NULL;
    tb->interfacename_reg = NULL;

    /* register the config */
    tb->cfg = cfg;

    /* return the backend pointer to the caller */
    *backend = (void *)tb;

    return (0);
}

static struct vrmr_plugin_data textdir_plugin = {
        .ask = ask_textdir,

        .tell = tell_textdir,
        .open = open_textdir,
        .close = close_textdir,
        .list = list_textdir,
        .init = init_textdir,
        .add = add_textdir,
        .del = del_textdir,
        .rename = rename_textdir,
        .conf = conf_textdir,
        .setup = setup_textdir,
        .version = VUURMUUR_VERSION,
        .name = "textdir",
};

void //__attribute__ ((constructor))
textdir_init(void)
{
    vrmr_plugin_register(&textdir_plugin);
}
#if 0
void //__attribute__ ((destructor))
textdir_fini(void) {
    /* nothing to do */
}
#endif

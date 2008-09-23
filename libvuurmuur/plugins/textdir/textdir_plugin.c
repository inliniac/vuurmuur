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

#include "textdir_plugin.h"

/*  get_filelocation

    get the file location of the 'name' with type 'type'.
    
    Returns NULL on error.
    
    The caller needs to free the memory.
*/
char
*get_filelocation(const int debuglvl, void *backend, char *name, const int type)
{
    char                    hostname[MAX_HOST] = "",
                            networkname[MAX_NETWORK] = "",
                            zonename[MAX_ZONE] = "";

    char                    file_location[512] = "",
                            *fileloc_ptr = NULL;

    struct TextdirBackend_  *ptr = NULL;

    /* better safe than sorry */
    if(!backend || !name)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(NULL);
    }

    if(!(ptr = (struct TextdirBackend_ *)backend))
    {
        (void)vrprint.error(-1, "Internal Error", "backend parameter problem (in: %s).", __FUNC__);
        return(NULL);
    }

    /* check if backend is open */
    if(!ptr->backend_open)
    {
        (void)vrprint.error(-1, "Error", "backend not opened yet (in: %s).", __FUNC__);
        return(NULL);
    }

    /*
        first zones
    */
    if(type == TYPE_ZONE || type == TYPE_NETWORK || type == TYPE_GROUP || type == TYPE_HOST)
    {
        if (debuglvl>=HIGH)
            (void)vrprint.debug(__FUNC__, "looking up data from zones.");

        /* validate the name */
        if(validate_zonename(debuglvl, name, 0, zonename, networkname, hostname, ptr->zonename_reg, VALNAME_VERBOSE) != 0)
        {
            (void)vrprint.error(-1, "Error", "zonename '%s' is not valid.", name);
            return(NULL);
        }

        /*
            first we determine the zonetype
        */
        switch(type)
        {
            /* host */
            case TYPE_HOST:

                if(debuglvl >= HIGH)
                {
                    (void)vrprint.debug(__FUNC__, "%s is a host.", name);
                    (void)vrprint.debug(__FUNC__, "arguments: %s, %s and %s", hostname, networkname, zonename);
                }

                /* assemble the filestring, and make sure we dont overflow */
                if(snprintf(file_location, sizeof(file_location), "%s/zones/%s/networks/%s/hosts/%s.host", ptr->textdirlocation, zonename, networkname, hostname) >= (int)sizeof(file_location))
                {
                    (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(NULL);
                }

                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "file_location: %s.", file_location);

                break;

            /* group */
            case TYPE_GROUP:

                if(debuglvl >= HIGH)
                {
                    (void)vrprint.debug(__FUNC__, "%s is a group.", name);
                    (void)vrprint.debug(__FUNC__, "arguments: %s, %s and %s", hostname, networkname, zonename);
                }
                
                /* assemble the filestring, and make sure we dont overflow */
                if(snprintf(file_location, sizeof(file_location), "%s/zones/%s/networks/%s/groups/%s.group", ptr->textdirlocation, zonename, networkname, hostname) >= (int)sizeof(file_location))
                {
                    (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(NULL);
                }
                
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "file_location: %s.", file_location);
                
                break;

            /* network */
            case TYPE_NETWORK:

                if (debuglvl >= HIGH)
                {
                    (void)vrprint.debug(__FUNC__, "%s is a network.", name);
                    (void)vrprint.debug(__FUNC__, "arguments: %s and %s.", networkname, zonename);
                }

                /* assemble the filestring, and make sure we dont overflow */
                if(snprintf(file_location, sizeof(file_location), "%s/zones/%s/networks/%s/network.config", ptr->textdirlocation, zonename, networkname) >= (int)sizeof(file_location))
                {
                    (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(NULL);
                }

                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "file_location: %s.", file_location);

                break;

            /* zone */
            case TYPE_ZONE:

                if (debuglvl >= HIGH)
                {
                    (void)vrprint.debug(__FUNC__, "%s is a zone.", name);
                    (void)vrprint.debug(__FUNC__, "arguments: %s.", zonename);
                }

                /* assemble the filestring, and make sure we dont overflow */
                if(snprintf(file_location, sizeof(file_location), "%s/zones/%s/zone.config", ptr->textdirlocation, zonename) >= (int)sizeof(file_location))
                {
                    (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(NULL);
                }
                
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "file_location: %s.", file_location);
                
                break;
        }
    }

    /*
        services are next
    */
    else if(type == TYPE_SERVICE || type == TYPE_SERVICEGRP)
    {
        /* validate the name */
        if(validate_servicename(debuglvl, name, ptr->servicename_reg, VALNAME_VERBOSE) != 0)
        {
            (void)vrprint.error(-1, "Error", "servicename '%s' is not valid.", name);
            return(NULL);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "looking up data from services, service: %s.", name);
        
        /* assemble the filestring, and make sure we dont overflow */
        if(snprintf(file_location, sizeof(file_location), "%s/services/%s", ptr->textdirlocation, name) >= (int)sizeof(file_location))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "file_location: %s.", file_location);
    }

    /*
        interfaces are next
    */
    else if(type == TYPE_INTERFACE)
    {
        /* validate the name */
        if(validate_interfacename(debuglvl, name, ptr->interfacename_reg) != 0)
        {
            (void)vrprint.error(-1, "Error", "interfacename '%s' is not valid.", name);
            return(NULL);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "looking up data from interfaces, interface: %s.", name);
            
        /* assemble the filestring, and make sure we dont overflow */
        if(snprintf(file_location, sizeof(file_location), "%s/interfaces/%s.conf", ptr->textdirlocation, name) >= (int)sizeof(file_location))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "file_location: %s.", file_location);
    }
    else if(type == TYPE_RULE)
    {
        /* assemble the filestring, and make sure we dont overflow */
        if(snprintf(file_location, sizeof(file_location), "%s/rules/%s.conf", ptr->textdirlocation, name) >= (int)sizeof(file_location))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).",
                                    __FUNC__, __LINE__);
            return(NULL);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "file_location: %s.", file_location);
    }

    /* well, this should not happen, right? */
    else
    {
        (void)vrprint.error(-1, "Internal Error", "unknown type of question '%d' (in: %s).", type, __FUNC__);
        return(NULL);
    }

    /* now allocate some memory */
    if(!(fileloc_ptr = malloc(strlen(file_location)+1)))
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s (in: %s).", strerror(errno), __FUNC__);
        return(NULL);
    }

    /* now copy the string to the new mem */
    if(strlcpy(fileloc_ptr, file_location, strlen(file_location)+1) >= strlen(file_location)+1)
    {
        (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
        free(fileloc_ptr);
        return(NULL);
    }

    /* return it! */
    return(fileloc_ptr);
}


/*
    opening the backend
*/
int
open_textdir(int debuglvl, void *backend, int mode, int type)
{
    struct TextdirBackend_  *ptr = NULL;
    char                    dir_location[256] = "";
    DIR                     *dir_p = NULL;


    if(backend == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }

    /* check if the backend is opened */
    if(!(ptr = (struct TextdirBackend_ *)backend))
    {
        (void)vrprint.error(-1, "Internal Error", "backend parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }

    /* see if we like the permissions of the textdirroot */
    if(!(stat_ok(debuglvl, ptr->textdirlocation, STATOK_WANT_DIR, STATOK_QUIET)))
        return(-1);

    if(ptr->backend_open == 1)
    {
        (void)vrprint.error(-1, "Internal Error", "opening textdir failed: already open (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }
    else
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "setting backed_open to 1");

        /* set to open */
        ptr->backend_open = 1;
    }

    /* now if were opening for type CAT_ZONES, setup the regex */
    if(type == CAT_ZONES)
    {
        /* regex setup */
        if(!(ptr->zonename_reg = malloc(sizeof(regex_t))))
        {
            (void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
                                    strerror(errno), __FUNC__, __LINE__);

            /* set the backend to closed again */
            ptr->backend_open = 0;
            return(-1);
        }

        /* this regex is defined in libvuurmuur -> vuurmuur.h */
        if(regcomp(ptr->zonename_reg, ZONE_REGEX, REG_EXTENDED) != 0)
        {
            (void)vrprint.error(-1, "Internal Error", "regcomp() failed (in: %s:%d).",
                                    __FUNC__, __LINE__);
            /* set the backend to closed again */
            ptr->backend_open = 0;

            free(ptr->zonename_reg);
            ptr->zonename_reg = NULL;

            return(-1);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "setting up regex for zonename success.");

        /* set the dirlocation */
        snprintf(dir_location, sizeof(dir_location), "%s/zones", ptr->textdirlocation);
    }
    else if(type == CAT_SERVICES)
    {
        /* regex setup */
        if(!(ptr->servicename_reg = malloc(sizeof(regex_t))))
        {
            (void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
                                    strerror(errno), __FUNC__, __LINE__);

            /* set the backend to closed again */
            ptr->backend_open = 0;
            return(-1);
        }

        /* this regex is defined in libvuurmuur -> vuurmuur.h */
        if(regcomp(ptr->servicename_reg, SERV_REGEX, REG_EXTENDED) != 0)
        {
            (void)vrprint.error(-1, "Internal Error", "regcomp() failed (in: %s:%d).",
                                    __FUNC__, __LINE__);
            /* set the backend to closed again */
            ptr->backend_open = 0;

            free(ptr->servicename_reg);
            ptr->servicename_reg = NULL;

            return(-1);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "setting up regex for servicename success.");

        /* set the dirlocation */
        snprintf(dir_location, sizeof(dir_location), "%s/services", ptr->textdirlocation);
    }
    else if(type == CAT_INTERFACES)
    {
        /* regex setup */
        if(!(ptr->interfacename_reg = malloc(sizeof(regex_t))))
        {
            (void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
                                    strerror(errno), __FUNC__, __LINE__);

            /* set the backend to closed again */
            ptr->backend_open = 0;
            return(-1);
        }

        /* this regex is defined in libvuurmuur -> vuurmuur.h */
        if(regcomp(ptr->interfacename_reg, IFAC_REGEX, REG_EXTENDED) != 0)
        {
            (void)vrprint.error(-1, "Internal Error", "regcomp() failed (in: %s:%d).",
                                    __FUNC__, __LINE__);
            /* set the backend to closed again */
            ptr->backend_open = 0;

            free(ptr->interfacename_reg);
            ptr->interfacename_reg = NULL;

            return(-1);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "setting up regex for interfacename success.");

        /* set the dirlocation */
        snprintf(dir_location, sizeof(dir_location), "%s/interfaces", ptr->textdirlocation);
    }
    else if(type == CAT_RULES)
    {
        /* set the dirlocation */
        snprintf(dir_location, sizeof(dir_location), "%s/rules", ptr->textdirlocation);
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "unknown type %d (in: %s:%d).",
                                    type, __FUNC__, __LINE__);
        return(-1);
    }

    /* create the dir if it does not exist */
    if(!(dir_p = opendir(dir_location)))
    {
        if(errno == ENOENT)
        {
            if(mkdir(dir_location, 0700) < 0)
            {
                (void)vrprint.error(-1, "Error", "creating directory '%s' failed: %s (in %s:%d).",
                                    dir_location, strerror(errno), __FUNC__, __LINE__);
                return(-1);
            }
        }
        else
        {
            (void)vrprint.error(-1, "Error", "opening directory '%s' failed: %s (in %s:%d).",
                                dir_location, strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        closedir(dir_p);
    }

    /* now stat it */
    if(stat_ok(debuglvl, dir_location, STATOK_WANT_DIR, STATOK_VERBOSE) != 1)
    {
        (void)vrprint.error(-1, "Error", "checking '%s' failed. Please check if the directory exists and that the permissions are ok.",
                                dir_location);
        return(-1);
    }

    return(0);
}


int
close_textdir(int debuglvl, void *backend, int type)
{
    struct TextdirBackend_ *ptr = NULL;

    if(backend == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }

    if(!(ptr = (struct TextdirBackend_ *)backend))
    {
        (void)vrprint.error(-1, "Internal Error", "backend parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }

    if(ptr->backend_open == 1)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "closing: setting backend_open to 0");

        ptr->backend_open = 0;
    }

    /* cleanup regex */
    if(type == CAT_ZONES && ptr->zonename_reg != NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "cleaning up regex.");

        regfree(ptr->zonename_reg);
        free(ptr->zonename_reg);
        ptr->zonename_reg = NULL;
    }
    else if(type == CAT_SERVICES && ptr->servicename_reg != NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "cleaning up regex.");

        regfree(ptr->servicename_reg);
        free(ptr->servicename_reg);
        ptr->servicename_reg = NULL;
    }
    else if(type == CAT_INTERFACES && ptr->interfacename_reg != NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "cleaning up regex.");

        regfree(ptr->interfacename_reg);
        free(ptr->interfacename_reg);
        ptr->interfacename_reg = NULL;
    }
    else if(type == CAT_RULES)
    {
        /* nothing yet */
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "unknown type %d (in: %s:%d).",
                                    type, __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


/* setting up the backend for first use */
int
init_textdir(int debuglvl, void *backend, int type)
{
//TODO
    return(0);
}


/*  add item to the backend

*/
int
add_textdir(const int debuglvl, void *backend, char *name, int type)
{
    FILE                    *fp = NULL;
    struct TextdirBackend_  *ptr = NULL;
    char                    *file_location = NULL,
                            dir_location[512] = "",
                            hostname[MAX_HOST] = "",
                            networkname[MAX_NETWORK] = "",
                            zonename[MAX_ZONE] = "";
    int                     fd = 0;


    /* safety */
    if(!backend || !name)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* check if the backend is open */
    if(!(ptr = (struct TextdirBackend_ *)backend))
    {
        (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!ptr->backend_open)
    {
        (void)vrprint.error(-1, "Error", "Backend not opened yet (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* determine the location of the file */
    if(!(file_location = get_filelocation(debuglvl, backend, name, type)))
        return(-1);

    /* check if the file already exist */
    if((fp = fopen(file_location, "r")))
    {
        (void)vrprint.error(-1, "Error", "creating %s failed: file exists.", file_location);

        fclose(fp);
        free(file_location);
        return(-1);
    }

    /* create the dirs for zones and networks */
    if(type == TYPE_ZONE || type == TYPE_NETWORK)
    {
        /* split up the name */
        if(validate_zonename(debuglvl, name, 0, zonename, networkname, hostname, ptr->zonename_reg, VALNAME_VERBOSE) != 0)
        {
            (void)vrprint.error(-1, "Error", "Zonename '%s' is not valid.", name);

            free(file_location);
            file_location = NULL;
            return(-1);
        }

        if(type == TYPE_ZONE)
        {
            /* zone dir */
            snprintf(dir_location, sizeof(dir_location), "%s/zones/%s", ptr->textdirlocation, zonename);
            if(mkdir(dir_location, 0700) < 0)
            {
                (void)vrprint.error(-1, "Error", "Creating directory %s failed: %s.", dir_location, strerror(errno));

                free(file_location);
                file_location = NULL;
                return(-1);
            }

            /* network dir */
            snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks", ptr->textdirlocation, zonename);
            if(mkdir(dir_location, 0700) < 0)
            {
                (void)vrprint.error(-1, "Error", "Creating directory %s failed: %s.", dir_location, strerror(errno));

                free(file_location);
                file_location = NULL;
                return(-1);
            }
        }
        else if(type == TYPE_NETWORK)
        {
            /* network dir */
            snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks/%s", ptr->textdirlocation, zonename, networkname);
            if(mkdir(dir_location, 0700) < 0)
            {
                (void)vrprint.error(-1, "Error", "Creating directory %s failed: %s.", dir_location, strerror(errno));

                free(file_location);
                file_location = NULL;
                return(-1);
            }

            /* host dir */
            snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks/%s/hosts", ptr->textdirlocation, zonename, networkname);
            if(mkdir(dir_location, 0700) < 0)
            {
                (void)vrprint.error(-1, "Error", "Creating directory %s failed: %s.", dir_location, strerror(errno));

                free(file_location);
                file_location = NULL;
                return(-1);
            }

            /* group dir */
            snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks/%s/groups", ptr->textdirlocation, zonename, networkname);
            if(mkdir(dir_location, 0700) < 0)
            {
                (void)vrprint.error(-1, "Error", "Creating directory %s failed: %s.", dir_location, strerror(errno));

                free(file_location);
                file_location = NULL;
                return(-1);
            }
        }
    }

    /* now open for writing (file will be created) */
    if((fd = open(file_location, O_WRONLY|O_CREAT|O_EXCL, 0600)) == -1)
    {
        (void)vrprint.error(-1, "Error", "Creating %s failed: %s (in: add_textdir).", file_location, strerror(errno));

        free(file_location);
        file_location = NULL;
        return(-1);
    }

    free(file_location);
    file_location = NULL;

    /*
        print the content
    */
    if(type != TYPE_RULE)
    {
        if(write(fd, "ACTIVE=\"\"\n", 10) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
    }

    if(type == TYPE_HOST)
    {
        if(write(fd, "IPADDRESS=\"\"\n", 13) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "MAC=\"\"\n", 7) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
    }
    else if(type == TYPE_GROUP)
    {
        if(write(fd, "MEMBER=\"\"\n", 10) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
    }
    else if(type == TYPE_NETWORK)
    {
        if(write(fd, "NETWORK=\"\"\n", 11) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "NETMASK=\"\"\n", 11) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "INTERFACE=\"\"\n", 13) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "RULE=\"\"\n", 8) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
    }
    else if(type == TYPE_SERVICE)
    {
        if(write(fd, "TCP=\"\"\n", 7) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "UDP=\"\"\n", 7) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "ICMP=\"\"\n", 8) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "GRE=\"\"\n", 7) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "AH=\"\"\n", 6) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "ESP=\"\"\n", 7) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "PROTO_41=\"\"\n", 12) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "BROADCAST=\"\"\n", 13) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "HELPER=\"\"\n", 10) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
    }
    else if(type == TYPE_INTERFACE)
    {
        if(write(fd, "IPADDRESS=\"\"\n", 13) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "INTERFACE=\"\"\n", 13) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "VIRTUAL=\"\"\n", 11) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
        if(write(fd, "RULE=\"\"\n", 8) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
    }
    else if(type == TYPE_RULE)
    {
        if(write(fd, "RULE=\"\"\n", 8) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
    }

    if(type != TYPE_RULE)
    {
        if(write(fd, "COMMENT=\"\"\n", 11) == -1)
        {
            (void)vrprint.error(-1, "Error", "write: %s", strerror(errno));
            return(-1);
        }
    }

    fsync(fd);

    if(close(fd) == -1)
    {
        (void)vrprint.error(-1, "Error", "closing file descriptor failed.");
        return(-1);
    }

    return(0);
}


/*  del_textdir

    Delete from the textdir.
    
    Returncodes:
        0: ok
        -1: error
*/
int
del_textdir(const int debuglvl, void *backend, char *name, int type, int recurs)
{
    char                    *file_location = NULL,
                            dir_location[512] = "",
                            hostname[MAX_HOST] = "",
                            networkname[MAX_NETWORK] = "",
                            zonename[MAX_ZONE] = "";
    struct TextdirBackend_  *ptr = NULL;

    /* safety */
    if(!backend || !name)
    {
        (void)vrprint.error(-1, "Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* check if the backend was properly openend */
    if(!(ptr = (struct TextdirBackend_ *)backend))
    {
        (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!ptr->backend_open)
    {
        (void)vrprint.error(-1, "Error", "backend not opened yet (in: %s).", __FUNC__);
        return(-1);
    }

    /* determine the location of the file */
    if(!(file_location = get_filelocation(debuglvl, backend, name, type)))
        return(-1);

    /* see if we like the file permissions */
    if(!(stat_ok(debuglvl, file_location, STATOK_WANT_FILE, STATOK_VERBOSE)))
        return(-1);

    /* name splitting only needed for network and zone, as host and group just use the file_location
       this is because network and zone need to remove directories as well
    */
    if(type == TYPE_ZONE || type == TYPE_NETWORK)
    {
        // split up the name
        if(validate_zonename(debuglvl, name, 0, zonename, networkname, hostname, ptr->zonename_reg, VALNAME_VERBOSE) != 0)
        {
            (void)vrprint.error(-1, "Error", "Zonename '%s' is not valid.", name);
            return(-1);
        }
    }

    /*
        HERE WE DO THE REMOVAL
    */

    if(type == TYPE_HOST)
    {
        if(remove(file_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "Deleting host file for '%s': %s.", name, strerror(errno));

            free(file_location);
            return(-1);
        }

        (void)vrprint.info("Info", "host '%s' deleted from disk.", name);
    }
    else if(type == TYPE_GROUP)
    {
        if(remove(file_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "deleting group file for '%s': %s.", name, strerror(errno));

            free(file_location);
            return(-1);
        }

        (void)vrprint.info("Info", "group '%s' deleted from disk.", name);
    }
    else if(type == TYPE_NETWORK)
    {
        /* first check the hosts dir */
        if(snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks/%s/hosts", ptr->textdirlocation, zonename, networkname) >= (int)sizeof(dir_location))
        {
            (void)vrprint.error(-1, "Internal Error", "overflow while determining the location to remove (in: %s:%d).", __FUNC__, __LINE__);

            free(file_location);
            return(-1);
        }

        /* now remove the dir */
        if(rmdir(dir_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "deleting host dir failed: %s", strerror(errno));

            free(file_location);
            return(-1);
        }

        /* second check the group dir */
        if(snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks/%s/groups", ptr->textdirlocation, zonename, networkname) >= (int)sizeof(dir_location))
        {
            (void)vrprint.error(-1, "Internal Error", "overflow while determining the location to remove (in: %s:%d).", __FUNC__, __LINE__);

            free(file_location);
            return(-1);
        }

        /* now remove the dir */
        if(rmdir(dir_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "deleting group dir '%s' failed: %s.", dir_location, strerror(errno));

            /* restore the hosts dir */
            if(snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks/%s/hosts", ptr->textdirlocation, zonename, networkname) >= (int)sizeof(dir_location))
            {
                (void)vrprint.error(-1, "Internal Error", "overflow while determining the location to remove (in: %s:%d).", __FUNC__, __LINE__);

                free(file_location);
                return(-1);
            }

            if(mkdir(dir_location, 0700) < 0)
            {
                (void)vrprint.error(-1, "Error", "recreating hostdir failed: %s.", strerror(errno));

                free(file_location);
                return(-1);
            }

            /* now quit */
            free(file_location);
            return(-1);
        }

        /* the network.config file */
        if(remove(file_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "deleting network.config: %s.", strerror(errno));

            free(file_location);
            return(-1);
        }

        /* the network dir */
        if(snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks/%s", ptr->textdirlocation, zonename, networkname) >= (int)sizeof(dir_location))
        {
            (void)vrprint.error(-1, "Internal Error", "overflow while determining the location to remove (in: %s:%d).", __FUNC__, __LINE__);

            free(file_location);
            return(-1);
        }
        if(rmdir(dir_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "deleting network dir: %s.", strerror(errno));

            free(file_location);
            return(-1);
        }

        (void)vrprint.info("Info", "Network '%s' deleted from disk.", name);
    }
    else if(type == TYPE_ZONE)
    {
        /* first check the network */
        if(snprintf(dir_location, sizeof(dir_location), "%s/zones/%s/networks", ptr->textdirlocation, name) >= (int)sizeof(dir_location))
        {
            (void)vrprint.error(-1, "Internal Error", "overflow while determining the location to remove (in: %s:%d).", __FUNC__, __LINE__);

            free(file_location);
            return(-1);
        }
        if(rmdir(dir_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "deleting network dir failed: %s", strerror(errno));

            free(file_location);
            return(-1);
        }

        /* the zone.config file */
        if(remove(file_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "deleting zone.config failed: %s.", strerror(errno));

            free(file_location);
            return(-1);
        }

        if(snprintf(dir_location, sizeof(dir_location), "%s/zones/%s", ptr->textdirlocation, name) >= (int)sizeof(dir_location))
        {
            (void)vrprint.error(-1, "Internal Error", "overflow while determining the location to remove (in: %s:%d).", __FUNC__, __LINE__);

            free(file_location);
            return(-1);
        }
        if(rmdir(dir_location) < 0)
        {
            (void)vrprint.error(-2, "Error", "deleting zone dir failed: %s", strerror(errno));

            free(file_location);
            return(-1);
        }
    }
    else if(type == TYPE_SERVICE)
    {
        if(remove(file_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "deleting service %s: %s (%s).", name, strerror(errno), file_location);

            free(file_location);
            return(-1);
        }
    }
    else if(type == TYPE_INTERFACE)
    {
        if(remove(file_location) < 0)
        {
            (void)vrprint.error(-1, "Error", "deleting interface %s: %s (%s).", name, strerror(errno), file_location);

            free(file_location);
            return(-1);
        }
    }
    /* handle unknown */
    else
    {
        (void)vrprint.error(-1, "Internal Error", "unknown type: %d (in: del_textdir).", type);
        free(file_location);
        return(-1);
    }

    /* cleanup */
    free(file_location);
    return(0);
}


/*  rename_textdir

    Renames the item 'name' to 'newname'. The item can be a host, interface, service, etc.

    Warning: when renaming a host, group or network, make sure you _only_ rename
    the host/group/network part of the name!
    
    Returncodes:
        -1: error
         0: ok
*/
int
rename_textdir(const int debuglvl, void *backend, char *name, char *newname, int type)
{
    int                     result = 0;
    char                    *oldpath = NULL,
                            *newpath = NULL;
    char                    new_zone_name[MAX_ZONE] = "",
                            new_net_name[MAX_NETWORK] = "",
                            new_host_name[MAX_HOST] = "";
    char                    old_zone_name[MAX_ZONE] = "",
                            old_net_name[MAX_NETWORK] = "",
                            old_host_name[MAX_HOST] = "";
    struct TextdirBackend_  *ptr = NULL;
    char                    new_file_location[256] = "",
                            old_file_location[256] = "";

    /* safety */
    if(!backend || !name || !newname)
    {
        (void)vrprint.error(-1, "Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* check if the backend was properly openend */
    if(!(ptr = (struct TextdirBackend_ *)backend))
    {
        (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!ptr->backend_open)
    {
        (void)vrprint.error(-1, "Error", "backend not opened yet (in: %s).", __FUNC__);
        return(-1);
    }

    /* first see if the name and newname are the same */
    if(strcmp(name, newname) == 0)
        return(0);


    /* validate and split the new and the old names for zones and networks */
    if(type == TYPE_ZONE || type == TYPE_NETWORK)
    {
        /* validate the name */
        if(validate_zonename(debuglvl, name, 0, old_zone_name, old_net_name, old_host_name, ptr->zonename_reg, VALNAME_VERBOSE) != 0)
        {
            (void)vrprint.error(-1, "Error", "zonename '%s' is not valid.", newname);
            return(-1);
        }

        /* validate the name */
        if(validate_zonename(debuglvl, newname, 0, new_zone_name, new_net_name, new_host_name, ptr->zonename_reg, VALNAME_VERBOSE) != 0)
        {
            (void)vrprint.error(-1, "Error", "zonename '%s' is not valid.", newname);
            return(-1);
        }
    }

    if(type == TYPE_ZONE)
    {
        /* get the old path */

        /* assemble the dirstring, and make sure we dont overflow */
        if(snprintf(old_file_location, sizeof(old_file_location), "%s/zones/%s", ptr->textdirlocation, old_zone_name) >= (int)sizeof(old_file_location))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* get the new path */

        /* assemble the dirstring, and make sure we dont overflow */
        if(snprintf(new_file_location, sizeof(new_file_location), "%s/zones/%s", ptr->textdirlocation, new_zone_name) >= (int)sizeof(new_file_location))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        result = rename(old_file_location, new_file_location);
        if(result != 0)
        {
            (void)vrprint.error(-1, "Error", "renaming '%s' to '%s' failed: %s (in: %s:%d).", name, newname, strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }
    }
    else if(type == TYPE_NETWORK)
    {
        /* get the old path */

        /* assemble the filestring, and make sure we dont overflow */
        if(snprintf(old_file_location, sizeof(old_file_location), "%s/zones/%s/networks/%s", ptr->textdirlocation, old_zone_name, old_net_name) >= (int)sizeof(old_file_location))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* get the new path */

        /* assemble the dirstring, and make sure we dont overflow */
        if(snprintf(new_file_location, sizeof(new_file_location), "%s/zones/%s/networks/%s", ptr->textdirlocation, new_zone_name, new_net_name) >= (int)sizeof(new_file_location))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        result = rename(old_file_location, new_file_location);
        if(result != 0)
        {
            (void)vrprint.error(-1, "Error", "renaming '%s' to '%s' failed: %s (in: %s:%d).", name, newname, strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }
    }
    else if(type == TYPE_HOST || type == TYPE_GROUP)
    {
        /* determine the location of the file */
        if(!(oldpath = get_filelocation(debuglvl, backend, name, type)))
        {
            (void)vrprint.error(-1, "Error", "getting path for '%s' failed (in: %s:%d).", name, __FUNC__, __LINE__);
            return(-1);
        }
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "oldpath: '%s'.", oldpath);

        /* determine the location of the new file */
        if(!(newpath = get_filelocation(debuglvl, backend, newname, type)))
        {
            (void)vrprint.error(-1, "Error", "getting path for '%s' failed (in: %s:%d).", newname, __FUNC__, __LINE__);
            free(oldpath);
            return(-1);
        }
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "newpath: '%s'.", newpath);

        result = rename(oldpath, newpath);
        /* first free the mem */
        free(oldpath);
        free(newpath);
        /* then analyse result */
        if(result != 0)
        {
            (void)vrprint.error(-1, "Error", "renaming '%s' to '%s' failed: %s (in: %s:%d).", name, newname, strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }
    }
    else if(type == TYPE_SERVICE || type == TYPE_INTERFACE)
    {
        /* determine the location of the file */
        if(!(oldpath = get_filelocation(debuglvl, backend, name, type)))
        {
            (void)vrprint.error(-1, "Error", "getting path for '%s' failed (in: %s:%d).", name, __FUNC__, __LINE__);
            return(-1);
        }

        /* determine the location of the new file */
        if(!(newpath = get_filelocation(debuglvl, backend, newname, type)))
        {
            (void)vrprint.error(-1, "Error", "getting path for '%s' failed (in: %s:%d).", newname, __FUNC__, __LINE__);
            free(oldpath);
            return(-1);
        }

        result = rename(oldpath, newpath);
        /* first free the mem */
        free(oldpath);
        free(newpath);
        /* then analyse result */
        if(result != 0)
        {
            (void)vrprint.error(-1, "Error", "renaming '%s' to '%s' failed: %s (in: %s:%d).", name, newname, strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "unknown type '%d' (in: %s:%d).", type, __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


/*  conf_textdir

    Loads the config settings from the plugin config file.

    Returncodes:
         0: ok
        -1: error
*/
int
conf_textdir(const int debuglvl, void *backend)
{
    int                     retval = 0,
                            result = 0;
    char                    configfile_location[512] = "";
    struct TextdirBackend_  *ptr = NULL;


    /* safety first */
    if(!backend)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    if(!(ptr = (struct TextdirBackend_ *)backend))
    {
        (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* assemble config location */
    if(snprintf(configfile_location, sizeof(configfile_location), "%s/vuurmuur/plugins/textdir.conf", conf.etcdir) >= (int)sizeof(configfile_location))
    {
        (void)vrprint.error(-1, "Internal Error", "could not determine configfile location: locationstring overflow (in: %s).", __FUNC__);
        return(-1);
    }

    /* now get the backend location from the configfile */
    result = ask_configfile(debuglvl, "LOCATION", ptr->textdirlocation, configfile_location, sizeof(ptr->textdirlocation));
    if(result < 0)
    {
        (void)vrprint.error(-1, "Error", "failed to get the textdir-root from: %s. Please make sure LOCATION is set (in: %s).", configfile_location, __FUNC__);
        retval = -1;
    }
    else if(result == 0)
    {
        (void)vrprint.error(-1, "Error", "no information about the location of the backend in '%s' (in: %s).", configfile_location, __FUNC__);
        retval = -1;
    }
    else
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "textdir location: LOCATION = %s.",
                                    ptr->textdirlocation);
    }

    return(retval);
}


int
setup_textdir(int debuglvl, void **backend)
{
    struct TextdirBackend_ *ptr = NULL;

    if(!(ptr = malloc(sizeof(struct TextdirBackend_))))
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s (in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* start closed of course */
    ptr->backend_open = 0;

    /* not used yet */
    ptr->writable = 0; /* TODO */

    ptr->zone_p = NULL;
    ptr->network_p = NULL;
    ptr->host_p = NULL;
    ptr->group_p = NULL;
    ptr->service_p = NULL;
    ptr->interface_p = NULL;
    ptr->rule_p = NULL;

    ptr->file = NULL;

    ptr->zonename_reg = NULL;
    ptr->servicename_reg = NULL;
    ptr->interfacename_reg = NULL;

    /* return the backend pointer to the caller */
    *backend = (void *)ptr;

    return(0);
}


void __attribute__ ((constructor)) 
textdir_init(void)
{
    BackendFunctions.ask = ask_textdir;
    BackendFunctions.tell = tell_textdir;
    BackendFunctions.open = open_textdir;
    BackendFunctions.close = close_textdir;
    BackendFunctions.list = list_textdir;
    BackendFunctions.init = init_textdir;
    BackendFunctions.add = add_textdir;
    BackendFunctions.del = del_textdir;
    BackendFunctions.rename = rename_textdir;
    BackendFunctions.conf = conf_textdir;
    BackendFunctions.setup = setup_textdir;

    /* set the version */
    BackendFunctions.version = LIBVUURMUUR_VERSION;
}


void __attribute__ ((destructor)) 
textdir_fini(void)
{
    //fprintf(stdout, "textdir fini done\n");
}

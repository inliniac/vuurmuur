/***************************************************************************
 *   Copyright (C) 2002-2008 by Victor Julien                              *
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
char
*list_textdir(const int debuglvl, void *backend, char *name, int *zonetype, int type)
{
    struct TextdirBackend_  *ptr = NULL;
    char                    dir_location[512] = "",
                            netdir_location[512] = "",
                            hostdir_location[512] = "",
                            groupdir_location[512] = "",
                            *file_location = NULL;
    char                    cur_zonename[MAX_HOST_NET_ZONE] = "";
    struct dirent           *dir_entry_p = NULL;
    int                     done = 0;


    /* safety */
    if(!backend || !name || !zonetype)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(NULL);
    }


    /* check if the backend is opened */
    if(!(ptr = (struct TextdirBackend_ *)backend))
    {
        (void)vrprint.error(-1, "Internal Error", "backend parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }
    if(!ptr->backend_open)
    {
        (void)vrprint.error(-1, "Internal Error", "backend not opened yet (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }


    /* services */
    if(type == CAT_SERVICES)
    {
        /* set the dir location */
        snprintf(dir_location, sizeof(dir_location), "%s/services", ptr->textdirlocation);

        /* the loop */
        while(!done)
        {
            /* check if already open */
            if(!ptr->service_p)
            {
                /* open the dir */
                if(!(ptr->service_p = vuurmuur_opendir(debuglvl, dir_location)))
                {
                    (void)vrprint.error(-1, "Error", "unable to open '%s', %s (in: list_textdir, opendir).", dir_location, strerror(errno));
                    return(NULL);
                }
            }

            /* now read the contents of the dir */
            if((dir_entry_p = readdir(ptr->service_p)) != NULL)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "name: '%s'.", dir_entry_p->d_name);

                (void)strlcpy(name, dir_entry_p->d_name, MAX_SERVICE);

                /* only return names which do not start with a dot (hidden files) and don't open . and .. */
                if( strncmp(name, ".", 1) != 0 &&
                    strcmp(name, "..") != 0)
                {
                    /* now validate the name */
                    if(validate_servicename(debuglvl, name, ptr->servicename_reg, VALNAME_QUIET) == 0)
                    {
                        /* determine the location of the file */
                        if(!(file_location = get_filelocation(debuglvl, backend, name, TYPE_SERVICE)))
                            return(NULL);
                        
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "service '%s', file: '%s'.", name, file_location);

                        /* now stat it */
                        if(stat_ok(debuglvl, file_location, STATOK_WANT_FILE, STATOK_QUIET, STATOK_MUST_EXIST))
                        {
                            free(file_location);

                            *zonetype = TYPE_SERVICE;
                            return(name);
                        }

                        free(file_location);
                    }
                }
            }
            /* close the dir if we cant read no more */
            else
            {
                /* close the dir */
                done = 1;
                closedir(ptr->service_p);
                ptr->service_p = NULL;
            }
        }
    }
    /* interfaces */
    else if(type == CAT_INTERFACES)
    {
        // set the dirlocation
        snprintf(dir_location, sizeof(dir_location), "%s/interfaces", ptr->textdirlocation);

        while(done == 0)
        {
            // check if already open, if not: open it
            if(!ptr->interface_p)
            {
                // open the dir
                if(!(ptr->interface_p = vuurmuur_opendir(debuglvl, dir_location)))
                {
                    (void)vrprint.error(-1, "Error", "Unable to open '%s', %s.", dir_location, strerror(errno));
                    return(NULL);
                }
            }

            if((dir_entry_p = readdir(ptr->interface_p)) != NULL)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "name: '%s'.", dir_entry_p->d_name);

                if( strncmp(dir_entry_p->d_name, ".", 1) != 0 &&
                    strcmp(dir_entry_p->d_name, "..") != 0 &&
                    strlen(dir_entry_p->d_name) > 5)
                {
                    /* this way we check if filename ends with '.conf' */
                    if( dir_entry_p->d_name[strlen(dir_entry_p->d_name)-5] == '.' &&
                        dir_entry_p->d_name[strlen(dir_entry_p->d_name)-4] == 'c' &&
                        dir_entry_p->d_name[strlen(dir_entry_p->d_name)-3] == 'o' &&
                        dir_entry_p->d_name[strlen(dir_entry_p->d_name)-2] == 'n' &&
                        dir_entry_p->d_name[strlen(dir_entry_p->d_name)-1] == 'f'
                    )
                    {
                        /* make sure we dont allow too long filenames */
                        if((strlen(dir_entry_p->d_name) < MAX_INTERFACE+5))
                        {
                            (void)strlcpy(ptr->interface, dir_entry_p->d_name, (strlen(dir_entry_p->d_name)-5)+1);
                            ptr->interface[strlen(dir_entry_p->d_name)-5]='\0';

                            if(validate_interfacename(debuglvl, ptr->interface, ptr->interfacename_reg) == 0)
                            {
                                *zonetype = TYPE_INTERFACE;
                                (void)strlcpy(name, ptr->interface, MAX_INTERFACE);

                                // determine the location of the file
                                if(!(file_location = get_filelocation(debuglvl, backend, name, TYPE_INTERFACE)))
                                    return(NULL);
                                
                                if(debuglvl >= HIGH)
                                    (void)vrprint.debug(__FUNC__, "interface '%s', file: '%s'.", name, file_location);

                                /* now stat it */
                                if(stat_ok(debuglvl, file_location, STATOK_WANT_FILE, STATOK_QUIET, STATOK_MUST_EXIST))
                                {
                                    free(file_location);

                                    if(debuglvl >= HIGH)
                                        (void)vrprint.debug(__FUNC__, "returning name: '%s'.", name);
                                    
                                    return(name);
                                }

                                // free temp mem
                                free(file_location);
                            }
                        }
                        else
                        {
                            if(debuglvl >= HIGH)
                                (void)vrprint.debug(__FUNC__, "'%s' is too long.", dir_entry_p->d_name);
                        }
                    }
                }
            }
            else
            {
                done=1;
                closedir(ptr->interface_p);
                ptr->interface_p = NULL;
            }
        }
    }
    /* rules */
    else if(type == CAT_RULES)
    {
        /* set the dirlocation */
        snprintf(dir_location, sizeof(dir_location), "%s/rules", ptr->textdirlocation);

        while(done == 0)
        {
            /* check if already open, if not: open it */
            if(!ptr->rule_p)
            {
                /* open the dir */
                if(!(ptr->rule_p = vuurmuur_opendir(debuglvl, dir_location)))
                {
                    (void)vrprint.error(-1, "Error", "unable to open '%s': %s.",
                                        dir_location, strerror(errno));
                    return(NULL);
                }
            }

            if((dir_entry_p = readdir(ptr->rule_p)) != NULL)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "name: '%s'.", dir_entry_p->d_name);

                if( (strncmp(dir_entry_p->d_name, ".", 1) != 0) &&
                    (strcmp(dir_entry_p->d_name, "..") != 0) &&
                    (strlen(dir_entry_p->d_name) > 5))
                {
                    /* this way we check if filename ends with '.conf' */
                    if( dir_entry_p->d_name[strlen(dir_entry_p->d_name)-5] == '.' &&
                        dir_entry_p->d_name[strlen(dir_entry_p->d_name)-4] == 'c' &&
                        dir_entry_p->d_name[strlen(dir_entry_p->d_name)-3] == 'o' &&
                        dir_entry_p->d_name[strlen(dir_entry_p->d_name)-2] == 'n' &&
                        dir_entry_p->d_name[strlen(dir_entry_p->d_name)-1] == 'f'
                    )
                    {
                        /* make sure we dont allow too long filenames */
                        if((strlen(dir_entry_p->d_name) < MAX_RULE_NAME + 5))
                        {
                            (void)strlcpy(ptr->rule, dir_entry_p->d_name, (strlen(dir_entry_p->d_name)-5)+1);
                            ptr->rule[strlen(dir_entry_p->d_name)-5]='\0';

                            *zonetype = TYPE_RULE;
                            (void)strlcpy(name, ptr->rule, MAX_RULE_NAME);

                            /* determine the location of the file */
                            if(!(file_location = get_filelocation(debuglvl, backend, name, TYPE_RULE)))
                                return(NULL);

                            if(debuglvl >= HIGH)
                                (void)vrprint.debug(__FUNC__, "rule '%s', file: '%s'.", name, file_location);

                            /* now stat it */
                            if(stat_ok(debuglvl, file_location, STATOK_WANT_FILE, STATOK_QUIET, STATOK_MUST_EXIST))
                            {
                                free(file_location);

                                if(debuglvl >= HIGH)
                                    (void)vrprint.debug(__FUNC__, "returning name: '%s'.", name);
                                    
                                return(name);
                            }

                            /* free temp mem */
                            free(file_location);
                        }
                    }
                }
            }
            else
            {
                done = 1;
                closedir(ptr->rule_p);
                ptr->rule_p = NULL;
            }
        }
    }
    else if(type == CAT_ZONES)
    {
        while(!done)
        {
            // this is the base dir
            snprintf(dir_location, sizeof(dir_location), "%s/zones", ptr->textdirlocation);

            if(ptr->host_p != NULL)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "getting a hostname.");


                if((dir_entry_p = readdir(ptr->host_p)) != NULL)
                {
                    // make sure that we dont use '.' and '..' and files that are not long enough to be serious
                    if((strncmp(dir_entry_p->d_name, ".", 1) != 0) && (strcmp(dir_entry_p->d_name, "..") != 0) && (strlen(dir_entry_p->d_name) > 5))
                    {
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "host name: %s.", dir_entry_p->d_name);

                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "item: %s, %d.", dir_entry_p->d_name, strlen(dir_entry_p->d_name));

                        // max sure the name is not too long
                        if(strlen(dir_entry_p->d_name) < MAX_HOST + 5)
                        {
                            (void)strlcpy(ptr->cur_host, dir_entry_p->d_name, (strlen(dir_entry_p->d_name)-5)+1);
                            ptr->cur_host[strlen(dir_entry_p->d_name)-5]='\0';

                            snprintf(cur_zonename, sizeof(cur_zonename), "%s.%s.%s", ptr->cur_host, ptr->cur_network, ptr->cur_zone);

                            // lets check against regex
                            if(validate_zonename(debuglvl, cur_zonename, 1, NULL, NULL, NULL, ptr->zonename_reg, VALNAME_QUIET) == 0)
                            {
                                // determine the location of the file
                                if(!(file_location = get_filelocation(debuglvl, backend, cur_zonename, TYPE_HOST)))
                                    return(NULL);
                                
                                if(debuglvl >= HIGH)
                                    (void)vrprint.debug(__FUNC__, "host '%s', file: '%s'.", cur_zonename, file_location);

                                // now stat it
                                if(stat_ok(debuglvl, file_location, STATOK_WANT_FILE, STATOK_QUIET, STATOK_MUST_EXIST))
                                {
                                    free(file_location);

                                    *zonetype = TYPE_HOST;

                                    (void)strlcpy(name, cur_zonename, MAX_HOST_NET_ZONE);
                                    return(name);
                                }

                                free(file_location);
                            }
                        }
                    }
                }
                else
                {
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "host dir closed.");
                    
                    closedir(ptr->host_p);
                    ptr->host_p = NULL;
                }
            }
            else if(ptr->group_p != NULL)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "getting a groupname.");

                if((dir_entry_p = readdir(ptr->group_p)) != NULL)
                {
                    // make sure that we dont use '.' and '..' and files that are not long enough to be serious
                    if((strncmp(dir_entry_p->d_name, ".", 1) != 0) && (strcmp(dir_entry_p->d_name, "..") != 0) && (strlen(dir_entry_p->d_name) > 5))
                    {
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "group name: %s.", dir_entry_p->d_name);

                        // max sure the name is not too long
                        if(strlen(dir_entry_p->d_name) < MAX_HOST + 5)
                        {
                            (void)strlcpy(ptr->cur_host, dir_entry_p->d_name, (strlen(dir_entry_p->d_name)-6)+1);
                            ptr->cur_host[strlen(dir_entry_p->d_name)-6]='\0';

                            snprintf(cur_zonename, sizeof(cur_zonename), "%s.%s.%s", ptr->cur_host, ptr->cur_network, ptr->cur_zone);

                            // lets check against regex
                            if(validate_zonename(debuglvl, cur_zonename, 1, NULL, NULL, NULL, ptr->zonename_reg, VALNAME_QUIET) == 0)
                            {
                                // determine the location of the file
                                if(!(file_location = get_filelocation(debuglvl, backend, cur_zonename, TYPE_GROUP)))
                                    return(NULL);
                                
                                if(debuglvl >= HIGH)
                                    (void)vrprint.debug(__FUNC__, "group '%s', file: '%s'.", cur_zonename, file_location);

                                // now stat it
                                if(stat_ok(debuglvl, file_location, STATOK_WANT_FILE, STATOK_QUIET, STATOK_MUST_EXIST))
                                {
                                    free(file_location);

                                    *zonetype = TYPE_GROUP;

                                    (void)strlcpy(name, cur_zonename, MAX_HOST_NET_ZONE);
                                    return(name);
                                }

                                free(file_location);
                            }
                        }
                    }
                }
                else
                {
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "group dir closed.");

                    closedir(ptr->group_p);
                    ptr->group_p = NULL;
                }
            }
            else if(ptr->network_p != NULL)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "getting a networkname.");

                if((dir_entry_p = readdir(ptr->network_p)) != NULL)
                {
                    snprintf(netdir_location, sizeof(netdir_location), "%s/zones/%s/networks", ptr->textdirlocation, ptr->cur_zone);

                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "network entry: %s.", dir_entry_p->d_name);

                    if((strncmp(dir_entry_p->d_name, ".", 1) != 0) && (strcmp(dir_entry_p->d_name, "..") != 0))
                    {
                        (void)strlcpy(ptr->cur_network, dir_entry_p->d_name, MAX_NETWORK);
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "network name: %s.", dir_entry_p->d_name);

                        // open the hostdir
                        snprintf(hostdir_location, sizeof(hostdir_location), "%s/%s/hosts", netdir_location, dir_entry_p->d_name);
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "opening host dir: %s.", hostdir_location);

                        /* this is allowed to fail, if it does, is will be NULL, and will be detected above */
                        ptr->host_p = vuurmuur_opendir(debuglvl, hostdir_location);

                        /* open the groupdir */
                        snprintf(groupdir_location, sizeof(groupdir_location), "%s/%s/groups", netdir_location, dir_entry_p->d_name);
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "opening group dir: %s.", groupdir_location);

                        /* this is allowed to fail, if it does, is will be NULL, and will be detected above */
                        ptr->group_p = vuurmuur_opendir(debuglvl, groupdir_location);

                        snprintf(cur_zonename, sizeof(cur_zonename), "%s.%s", ptr->cur_network, ptr->cur_zone);

                        /* lets check against regex */
                        if(validate_zonename(debuglvl, cur_zonename, 1, NULL, NULL, NULL, ptr->zonename_reg, VALNAME_QUIET) == 0)
                        {
                            // determine the location of the file
                            if(!(file_location = get_filelocation(debuglvl, backend, cur_zonename, TYPE_NETWORK)))
                                return(NULL);
                            
                            if(debuglvl >= HIGH)
                                (void)vrprint.debug(__FUNC__, "list_textdir: network '%s', file: '%s'.", cur_zonename, file_location);

                            // now stat it
                            if(stat_ok(debuglvl, file_location, STATOK_WANT_FILE, STATOK_QUIET, STATOK_MUST_EXIST))
                            {
                                free(file_location);

                                if(debuglvl >= HIGH)
                                    (void)vrprint.debug(__FUNC__, "list_textdir: '%s' ('%s', '%s').", cur_zonename, ptr->cur_network, ptr->cur_zone);

                                *zonetype = TYPE_NETWORK;

                                (void)strlcpy(name, cur_zonename, MAX_NET_ZONE);
                                return(name);
                            }

                            free(file_location);
                        }
                    }
                }
                else
                {
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "network dir closed.");

                    closedir(ptr->network_p);
                    ptr->network_p = NULL;
                }
            }
            else if(ptr->zone_p != NULL)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "getting a zonename.");

                if((dir_entry_p = readdir(ptr->zone_p)) != NULL)
                {
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "zone entry: %s.", dir_entry_p->d_name);

                    if((strncmp(dir_entry_p->d_name, ".", 1) != 0) && (strcmp(dir_entry_p->d_name, "..") != 0))
                    {
                        (void)strlcpy(ptr->cur_zone, dir_entry_p->d_name, MAX_ZONE);

                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "zone name: %s.", dir_entry_p->d_name);

                        // open the networkdir
                        snprintf(netdir_location, sizeof(netdir_location), "%s/%s/networks", dir_location, dir_entry_p->d_name);
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "opening: %s.", netdir_location);

                        /* this is allowed to fail, if it does, is will be NULL, and will be detected above */
                        ptr->network_p = vuurmuur_opendir(debuglvl, netdir_location);

                        // lets check against regex
                        if(validate_zonename(debuglvl, dir_entry_p->d_name, 1, NULL, NULL, NULL, ptr->zonename_reg, VALNAME_QUIET) == 0)
                        {
                            // determine the location of the file
                            if(!(file_location = get_filelocation(debuglvl, backend, dir_entry_p->d_name, TYPE_ZONE)))
                                return(NULL);
                            
                            if(debuglvl >= HIGH)
                                (void)vrprint.debug(__FUNC__, "zone '%s', file: '%s'.", ptr->cur_zone, file_location);

                            // now stat it
                            if(stat_ok(debuglvl, file_location, STATOK_WANT_FILE, STATOK_QUIET, STATOK_MUST_EXIST))
                            {
                                free(file_location);

                                if(debuglvl >= HIGH)
                                    (void)vrprint.debug(__FUNC__, "zone '%s'.", ptr->cur_zone);

                                *zonetype = TYPE_ZONE;

                                (void)strlcpy(name, dir_entry_p->d_name, MAX_ZONE);
                                return(name);
                            }

                            free(file_location);
                        }
                    }
                }
                else
                {
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "zone dir closing.");

                    closedir(ptr->zone_p);
                    ptr->zone_p = NULL;

                    done = 1;
                }
            }

            if(!done && !ptr->zone_p)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "opening the zonesdir.");

                // open the dir
                if(!(ptr->zone_p = vuurmuur_opendir(debuglvl, dir_location)))
                {
                    (void)vrprint.error(-1, "Error", "unable to open directory: %s: %s.", dir_location, strerror(errno));
                    return(NULL);
                }
            }
        }
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "unknown type '%d'.", type);
        return(NULL);
    }

    return(NULL);
}

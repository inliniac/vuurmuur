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

#include "config.h"
#include "vuurmuur.h"

/*  vrmr_rule_malloc

    Allocates memory for a rule, and inits all variables.

    Returns the address of the memory on succes and NULL on failure.
*/
void *
vrmr_rule_malloc(void)
{
    struct vrmr_rule *rule_ptr = NULL;

    rule_ptr = malloc(sizeof(struct vrmr_rule));
    if(rule_ptr == NULL)
    {
        return(NULL);
    }
    /* clear */
    memset(rule_ptr, 0, sizeof(struct vrmr_rule));

    rule_ptr->type = VRMR_TYPE_RULE;

    return(rule_ptr);
}


void *
vrmr_rule_option_malloc(const int debuglvl)
{
    struct vrmr_rule_options  *opt_ptr = NULL;

    /* alloc the memory */
    opt_ptr = malloc(sizeof(struct vrmr_rule_options));
    if(opt_ptr == NULL)
    {
        return(NULL);
    }
    /* initialize the mem */
    memset(opt_ptr, 0, sizeof(struct vrmr_rule_options));

    /* setup the lists */
    (void)vrmr_list_setup(debuglvl, &opt_ptr->RemoteportList, NULL);
    (void)vrmr_list_setup(debuglvl, &opt_ptr->ListenportList, NULL);

    return(opt_ptr);
}


void *
vrmr_zone_malloc(const int debuglvl)
{
    struct vrmr_zone *zone_ptr = NULL;

    /* alloc memory */
    zone_ptr = malloc(sizeof(struct vrmr_zone));
    if(zone_ptr == NULL)
    {
        return(NULL);
    }
    /* initialize */
    memset(zone_ptr, 0, sizeof(struct vrmr_zone));

    zone_ptr->ipv6.cidr6 = -1;

    zone_ptr->GroupList.len = 0;
    if(vrmr_list_setup(debuglvl, &zone_ptr->GroupList, NULL) < 0)
        return(NULL);

    zone_ptr->InterfaceList.len = 0;
    if(vrmr_list_setup(debuglvl, &zone_ptr->InterfaceList, NULL) < 0)
        return(NULL);

    zone_ptr->ProtectList.len = 0;
    if(vrmr_list_setup(debuglvl, &zone_ptr->ProtectList, free) < 0)
        return(NULL);

    zone_ptr->type = VRMR_TYPE_UNSET;

    /* done, return the zone */
    return(zone_ptr);
}


void
vrmr_zone_free(const int debuglvl, struct vrmr_zone *zone_ptr)
{
    if(!zone_ptr)
        return;

    if(zone_ptr->type == VRMR_TYPE_GROUP)
        (void)vrmr_list_cleanup(debuglvl, &zone_ptr->GroupList);

    if(zone_ptr->type == VRMR_TYPE_NETWORK)
    {
        (void)vrmr_list_cleanup(debuglvl, &zone_ptr->InterfaceList);
        (void)vrmr_list_cleanup(debuglvl, &zone_ptr->ProtectList);
    }

    free(zone_ptr);
}


void *
vrmr_service_malloc(void)
{
    struct vrmr_service *ser_ptr = NULL;

    /* alloc some mem */
    ser_ptr = malloc(sizeof(struct vrmr_service));
    if(ser_ptr == NULL)
    {
        return(NULL);
    }

    /* init */
    memset(ser_ptr, 0, sizeof(struct vrmr_service));

    ser_ptr->type = VRMR_TYPE_SERVICE;

    return(ser_ptr);
}


/* returns a initialized interface memory area */
void *
vrmr_interface_malloc(const int debuglvl)
{
    struct vrmr_interface *iface_ptr = NULL;

    iface_ptr = malloc(sizeof(struct vrmr_interface));
    if(iface_ptr == NULL)
    {
        return(NULL);
    }

    memset(iface_ptr, 0, sizeof(struct vrmr_interface));
    iface_ptr->ipv6.cidr6 = -1;
    iface_ptr->type = VRMR_TYPE_INTERFACE;

    iface_ptr->active = TRUE;

    if(vrmr_list_setup(debuglvl, &iface_ptr->ProtectList, free) < 0)
        return(NULL);

    iface_ptr->cnt = NULL;

    return(iface_ptr);
}


/*

*/
int
vrmr_shm_lock(int lock, int sem_id)
{
    int                     z;
    static struct sembuf    sops = { 0, -1, 0 };

    sops.sem_num = 0;
    sops.sem_op  = (short int)(lock ? -1 : 1);

    do
    {
        z = semop(sem_id, &sops, 1);
    }
    while (z == -1 && errno == EINTR);

    if(z == -1)
    {
        return(0);
    }

    return(1);
}

/* return a ptr to the lib version string */
char *libvuurmuur_get_version(void) {
    return LIBVUURMUUR_VERSION;
}

/*  range_strcpy

    src must be NULL-terminated.

    Returncodes:
        0: ok
        -1: error

*/
int
range_strcpy(char *dest, const char *src, const size_t start,
        const size_t end, size_t size)
{
    size_t  s = 0,
            d = 0,
            src_len = 0;

    if(!dest || !src)
        return(-1);

    src_len = strlen(src);

    if(start >= src_len || end > src_len)
        return(-1);

    for(s = start, d = 0; s < end && d < size && s < src_len; s++, d++)
    {
        dest[d] = src[s];
    }
    dest[d]='\0';

    return(0);
}



/* textfield regex

    General regular expression for filtering out problematic
    chars like '"' and %...
*/
//#define TEXTFIELD_REGEX   "^([a-zA-Z0-9_-][.] )$"


/*
    Actions:     1: setup
                 0: setdown

    Returncodes:
            0: ok
            -1: error

*/
int
vrmr_regex_setup(int action, struct vrmr_regex *reg)
{
    if(!reg)
        return(-1);

    if(action < 0 || action > 1 || reg == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(action == 1)
    {
        /* regex setup */
        if(!(reg->zonename = malloc(sizeof(regex_t))))
        {
            vrmr_error(-1, "Internal Error", "malloc "
                    "failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(regcomp(reg->zonename, VRMR_ZONE_REGEX, REG_EXTENDED) != 0)
        {
            vrmr_error(-1, "Internal Error", "regcomp() "
                    "failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /* regex setup */
        if(!(reg->zone_part = malloc(sizeof(regex_t))))
        {
            vrmr_error(-1, "Internal Error", "malloc "
                    "failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(regcomp(reg->zone_part, VRMR_VRMR_ZONE_REGEX_ZONEPART, REG_EXTENDED) != 0)
        {
            vrmr_error(-1, "Internal Error", "regcomp() "
                    "failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /* regex setup */
        if(!(reg->network_part = malloc(sizeof(regex_t))))
        {
            vrmr_error(-1, "Internal Error", "malloc "
                    "failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(regcomp(reg->network_part, VRMR_VRMR_ZONE_REGEX_NETWORKPART, REG_EXTENDED) != 0)
        {
            vrmr_error(-1, "Internal Error", "regcomp() "
                    "failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /* regex setup */
        if(!(reg->host_part = malloc(sizeof(regex_t))))
        {
            vrmr_error(-1, "Internal Error", "malloc "
                    "failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(regcomp(reg->host_part, VRMR_VRMR_ZONE_REGEX_HOSTPART, REG_EXTENDED) != 0)
        {
            vrmr_error(-1, "Internal Error", "regcomp() "
                    "failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /* regex setup */
        if(!(reg->servicename = malloc(sizeof(regex_t))))
        {
            vrmr_error(-1, "Internal Error", "malloc "
                    "failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(regcomp(reg->servicename, VRMR_SERV_REGEX, REG_EXTENDED) != 0)
        {
            vrmr_error(-1, "Internal Error", "regcomp() "
                    "failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /* regex setup */
        if(!(reg->interfacename = malloc(sizeof(regex_t))))
        {
            vrmr_error(-1, "Internal Error", "malloc "
                    "failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(regcomp(reg->interfacename, VRMR_IFAC_REGEX, REG_EXTENDED) != 0)
        {
            vrmr_error(-1, "Internal Error", "regcomp() "
                    "failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /* regex setup */
        if(!(reg->macaddr = malloc(sizeof(regex_t))))
        {
            vrmr_error(-1, "Internal Error", "malloc "
                    "failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(regcomp(reg->macaddr, VRMR_MAC_REGEX, REG_EXTENDED) != 0)
        {
            vrmr_error(-1, "Internal Error", "regcomp() "
                    "failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /* regex setup */
        if(!(reg->configline = malloc(sizeof(regex_t))))
        {
            vrmr_error(-1, "Internal Error", "malloc "
                    "failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(regcomp(reg->configline, VRMR_CONFIG_REGEX, REG_EXTENDED) != 0)
        {
            vrmr_error(-1, "Internal Error", "regcomp() "
                    "failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /* regex setup */
/*        if(!(reg->comment = malloc(sizeof(regex_t))))
        {
            vrmr_error(-1, "Internal Error", "malloc "
                    "failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(regcomp(reg->comment, TEXTFIELD_REGEX, REG_EXTENDED) != 0)
        {
            vrmr_error(-1, "Internal Error", "regcomp() "
                    "failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
*/
    }
    else
    {
        /* zone */
        regfree(reg->zonename);
        free(reg->zonename);
        regfree(reg->zone_part);
        free(reg->zone_part);
        regfree(reg->network_part);
        free(reg->network_part);
        regfree(reg->host_part);
        free(reg->host_part);

        /* service */
        regfree(reg->servicename);
        free(reg->servicename);

        /* interface */
        regfree(reg->interfacename);
        free(reg->interfacename);

        /* mac */
        regfree(reg->macaddr);
        free(reg->macaddr);

        /* config */
        regfree(reg->configline);
        free(reg->configline);

        /* comment */
//        regfree(reg->comment);
//        free(reg->comment);
    }

    return(0);
}

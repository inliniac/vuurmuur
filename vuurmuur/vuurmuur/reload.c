/***************************************************************************
 *   Copyright (C) 2002-2013 by Victor Julien                              *
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
#include "main.h"


/* prototypes */
int reload_blocklist(const int, struct vuurmuur_config *, struct vrmr_zones *, struct vrmr_blocklist *);
int reload_rules(const int, VuurmuurCtx *, struct vrmr_regex *);
int check_for_changed_networks(const int, struct vrmr_zones *);


/*  apply changes

    This function checks all data in memory for changes and applies the changes to the
    rules in memory.

    Returncodes:
         0: succes, changes applied
         1: succes, no changes seen //defuct
        -1: error
*/
static int
apply_changes_ruleset(const int debuglvl, VuurmuurCtx *vctx, struct vrmr_regex *reg)
{
    int     retval=0,   // start at no changes
            result=0;

    (void)vrprint.info("Info", "Reloading config...");

    /* close the current backends */
    result = vrmr_backends_unload(debuglvl, vctx->conf);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Error", "unloading backends failed.");
        return(-1);
    }
    shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 5);


    /* reload the config

       if it fails it's no big deal, we just keep using the old config.
    */
    if(reload_config(debuglvl, vctx->conf) < VRMR_CNF_OK)
    {
        (void)vrprint.warning("Warning", "reloading config failed, using old config.");
    }
    else
    {
        (void)vrprint.info("Info", "Reloading config completed successfully.");

        /* reapply the cmdline overrides. Fixes #67. */
        cmdline_override_config(debuglvl);
    }
    /* loglevel */
    create_loglevel_string(debuglvl, vctx->conf, loglevel, sizeof(loglevel));
    /* tcp options */
    create_logtcpoptions_string(debuglvl, vctx->conf, log_tcp_options, sizeof(log_tcp_options));

    shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 10);


    /* reopen the backends */
    result = vrmr_backends_load(debuglvl, vctx->conf);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Error", "re-opening backends failed.");
        return(-1);
    }
    shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 15);


    /* reload the services, interfaces, zones and rules. */
    (void)vrprint.info("Info", "Reloading services...");
    result = reload_services(debuglvl, vctx->services, reg->servicename);
    if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "Services didn't change.");
    }
    else if(result == 1)
    {
        (void)vrprint.info("Info", "Services changed.");
        retval=0;
    }
    else
    {
        (void)vrprint.error(-1, "Error", "Reloading services failed.");
        return(-1);
    }
    shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 20);

    (void)vrprint.info("Info", "Reloading interfaces...");
    result = reload_interfaces(debuglvl, vctx->interfaces);
    if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "Interfaces didn't change.");
    }
    else if(result == 1)
    {
        (void)vrprint.info("Info", "Interfaces changed.");
        retval = 0;
    }
    else
    {
        (void)vrprint.error(-1, "Error", "Reloading interfaces failed.");
        return(-1);
    }
    shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 25);

    (void)vrprint.info("Info", "Reloading zones...");
    result = reload_zonedata(debuglvl, vctx->zones, vctx->interfaces, reg);
    if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "Zones didn't change.");
    }
    else if(result == 1)
    {
        (void)vrprint.info("Info", "Zones changed.");
        retval=0;
    }
    else
    {
        (void)vrprint.error(-1, "Error", "Reloading zones failed.");
        return(-1);
    }
    shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 30);

    /* changed networks (for antispoofing) */
    result = check_for_changed_networks(debuglvl, vctx->zones);
    if(result == -1)
    {
        (void)vrprint.error(-1, "Error", "checking for changed networks failed.");
        return(-1);
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "No changed networks.");
    }
    else
    {
        (void)vrprint.info("Info", "Networks changed.");
    }


    /* reload the blocklist */
    result = reload_blocklist(debuglvl, vctx->conf, vctx->zones, vctx->blocklist);
    if(result == -1)
    {
        (void)vrprint.error(-1, "Error", "Reloading blocklist failed.");
        return(-1);
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "Blocklist didn't change.");
    }
    else
    {
        (void)vrprint.info("Info", "Blocklist changed.");
    }


    /* reload the rules */
    result = reload_rules(debuglvl, vctx, reg);
    if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "No changed rules.");
    }
    else if(result == 1)
    {
    }
    else
    {
        (void)vrprint.error(-1, "Error", "reloading rules failed.");
        retval=-1;
    }
    shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 40);


    /* analyzing the rules */
    if(analyze_all_rules(debuglvl, vctx, vctx->rules) != 0)
    {
        (void)vrprint.error(-1, "Error", "analizing the rules failed.");
        retval=-1;
    }
    shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 80);


    /* create the new ruleset */
    if(load_ruleset(debuglvl, vctx) < 0)
    {
        (void)vrprint.error(-1, "Error", "creating rules failed.");
        retval=-1;
    }
    shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 90);

    if(retval == 0)
        (void)vrprint.info("Info", "Reloading Vuurmuur completed successfully.");

    return(retval);
}


int
apply_changes(const int debuglvl, VuurmuurCtx *vctx, struct vrmr_regex *reg)
{
    if(conf.old_rulecreation_method == TRUE)
    {
        (void)vrprint.error(-1, "Internal Error", "old_rulecreation_method == TRUE");
        return(-1);
    }

    return(apply_changes_ruleset(debuglvl, vctx, reg));
}



/*  reload_services
*/
int
reload_services(const int debuglvl, struct vrmr_services *services, regex_t *servicename_regex)
{
    int                     retval=0,
                            result;
    struct vrmr_service    *ser_ptr = NULL;
    char                    name[MAX_SERVICE];
    int                     zonetype;
    struct vrmr_list_node             *d_node = NULL;

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__,  "** start **");


    /* safety */
    if(!services || !servicename_regex)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }


    /* check if we have a backend */
    if(!sf)
    {
        (void)vrprint.error(-1, "Internal Error", "backend not open (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* first reset all statusses */
    for(d_node = services->list.top; d_node; d_node = d_node->next)
    {
        if(!(ser_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        ser_ptr->status = ST_UNTOUCHED;
    }


    /* loop trough the services in the backend */
    while(sf->list(debuglvl, serv_backend, name, &zonetype, CAT_SERVICES) != NULL)
    {
        if(validate_servicename(debuglvl, name, servicename_regex, VALNAME_VERBOSE) == 0)
        {
            ser_ptr = search_service(debuglvl, services, name);
            if(ser_ptr == NULL) /* not found */
            {
                (void)vrprint.info("Info", "Service '%s' is added.", name);
                
                retval = 1;
    
                /* new service */
                result = insert_service(debuglvl, services, name);
                if(result != 0)
                {
                    (void)vrprint.error(-1, "Internal Error", "inserting data for '%s' into the list failed (in: reload_services).", name);
                    return(-1);
                }
            
                ser_ptr = search_service(debuglvl, services, name);
                if(ser_ptr == NULL) /* not found */
                {
                    (void)vrprint.error(-1, "Internal Error", "service not found (in: %s:%d).",
                                                __FUNC__, __LINE__);
                    return(-1);
                }

                result = services_check(debuglvl, ser_ptr);
                if(result != 1)
                {
                    (void)vrprint.info("Info", "Service '%s' has been deactivated because of errors while checking it.",
                                                            ser_ptr->name);
                    ser_ptr->active = FALSE;
                }
            }
            else
            {
                /* check the content of the service for changes */
                result = reload_services_check(debuglvl, ser_ptr);
                if(result == 1)
                    retval = 1;
                else if(result < 0)
                    return(-1);
            }
        }
    }


    /* the untouched services are to be removed */
    for(d_node = services->list.top; d_node; d_node = d_node->next)
    {
        /* get the service */
        if(!(ser_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        /* if status is UNTOUCHED, mark REMOVED */
        if(ser_ptr->status == ST_UNTOUCHED)
        {
            ser_ptr->status = ST_REMOVED;

            (void)vrprint.info("Info", "Service '%s' is removed.", ser_ptr->name);
        }
    }

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "** end **, result = %d", retval);

    return(retval);
}


/*  reload_services_check

    checks a service for changes

    Returncodes:
        1: changes
        0: no changes
        -1: error
*/
int
reload_services_check(const int debuglvl, struct vrmr_service *ser_ptr)
{
    int                     retval = 0,
                            result = 0,
                            status = 0;
    int                     check_result = 0;
    struct vrmr_service    *new_ser_ptr = NULL;
    /* these are for the comparisson between the portranges */
    struct vrmr_list_node             *list_node = NULL,
                            *temp_node = NULL;
    struct vrmr_portdata         *list_port = NULL,
                            *temp_port = NULL;

    /* safety */
    if(ser_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }

    /* alloc the temp mem */
    if(!(new_ser_ptr = service_malloc()))
    {
        (void)vrprint.error(-1, "Internal Error", "service_malloc() failed: %s (in: %s:%d).",
                                    strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }
    if(vrmr_list_setup(debuglvl, &new_ser_ptr->PortrangeList, free) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_list_setup() failed (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }


    /* read the service from the backend again */
    result = read_service(debuglvl, ser_ptr->name, new_ser_ptr);
    if(result != 0)
    {
        /* error! memory is freed at the end of this function */
        (void)vrprint.error(-1, "Error", "getting info for service '%s' failed (in: reload_services_check).", ser_ptr->name);
        status = ST_REMOVED;
    }
    else
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "service: %12s.", ser_ptr->name);

        /* check the interface */
        check_result = services_check(debuglvl, new_ser_ptr);

        /* we asume that the service did not change, if so we change it below */
        status = ST_KEEP;

        /* active  If check_result is not 1 we are going to set the active to false, so we dont
           care about this check. */
        if(check_result != 1 || ser_ptr->active == new_ser_ptr->active)
        {
            /* compare the protocol helpers */
            if(strcmp(ser_ptr->helper, new_ser_ptr->helper) == 0)
            {
                if(ser_ptr->PortrangeList.len == new_ser_ptr->PortrangeList.len)
                {
                    list_node = ser_ptr->PortrangeList.top;
                    temp_node = new_ser_ptr->PortrangeList.top;

                    /* both no items in the list */
                    if(!list_node && !temp_node)
                    {
                        /* no change */
                    }
                    /* if eitherone is NULL and the other not there must be a change */
                    else if((!list_node && temp_node) || (list_node && !temp_node))
                    {
                        /* change */
                        if(!list_node)
                            (void)vrprint.info("Info", "Service '%s': the service now has (a) portrange(s).", ser_ptr->name);

                        if(!temp_node)
                            (void)vrprint.info("Info", "Service '%s': the service no longer has portranges.", ser_ptr->name);

                        status = ST_CHANGED;
                    }
                    else
                    {
                        for(; list_node && temp_node; list_node = list_node->next, temp_node = temp_node->next)
                        {
                            if(!(list_port = list_node->data))
                            {
                                (void)vrprint.error(-1, "Internal Error", "reload_services_check: list_port == NULL!");
                                return(-1);
                            }

                            if(!(temp_port = temp_node->data))
                            {
                                (void)vrprint.error(-1, "Internal Error", "reload_services_check: temp_port == NULL!");
                                return(-1);
                            }

                            if((list_port->protocol == temp_port->protocol) && (list_port->src_low == temp_port->src_low) && (list_port->src_high == temp_port->src_high) && (list_port->dst_low == temp_port->dst_low) && (list_port->dst_high == temp_port->dst_high))
                            {
                                /* nothing changed */
                            }
                            else
                            {
                                (void)vrprint.info("Info", "Service '%s': one of the portranges has been changed.", ser_ptr->name);
                                status = ST_CHANGED;

                                break;
                            }
                        }
                    }
                }
                else
                {
                    (void)vrprint.info("Info", "Service '%s': the number of portranges has been changed.", ser_ptr->name);
                    status = ST_CHANGED;
                }
            }
            else
            {
                (void)vrprint.info("Info", "Service '%s': helper has been set to: '%s'.", ser_ptr->name, new_ser_ptr->helper);
                status = ST_CHANGED;
            }
        }
        else
        {
            if(new_ser_ptr->active == 1)
            {
                status = ST_ACTIVATED;
                (void)vrprint.info("Info", "Service '%s' has been activated.", ser_ptr->name);
            }
            else
            {
                status = ST_DEACTIVATED;
                (void)vrprint.info("Info", "Service '%s' has been deactivated.", ser_ptr->name);
            }
        }
    
        /* now check the result of interfaces_check() */
        if( (status == ST_CHANGED || status == ST_ACTIVATED || status == ST_DEACTIVATED) &&
            check_result != 1)
        {
            (void)vrprint.info("Info", "Service '%s' has been deactivated because of errors while checking it.",
                                            ser_ptr->name);
            new_ser_ptr->active = FALSE;
        }

    }


    /* */
    if(status == ST_CHANGED || status == ST_ACTIVATED || status == ST_DEACTIVATED)
    {
        (void)vrprint.info("Info", "Service '%s' has been changed.", ser_ptr->name);

        /* delete the old portrange list */
        vrmr_list_cleanup(debuglvl, &ser_ptr->PortrangeList);

        /* copy the data */
        *ser_ptr = *new_ser_ptr;

        /* transfer the status */
        ser_ptr->status = status;

        /* set retval to changes */
        retval = 1;
    }
    else if(status == ST_REMOVED || status == ST_KEEP)
    {
        /* destroy the portrangelist of the temp service */
        vrmr_list_cleanup(debuglvl, &new_ser_ptr->PortrangeList);

        /* set the status */
        ser_ptr->status = status;
    }

    /* free the temp data */
    free(new_ser_ptr);
    new_ser_ptr = NULL;

    return(retval);
}


// reload_zonedata
int
reload_zonedata(const int debuglvl, struct vrmr_zones *zones, struct vrmr_interfaces *interfaces, struct vrmr_regex *reg)
{
    int                 retval = 0,
                        result = 0;
    int                 check_result = 0;
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_zone    *zone_ptr = NULL;
    char                name[MAX_HOST_NET_ZONE];
    int                 zonetype;


    /* safety */
    if(interfaces == NULL || zones == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }

    /* check if we have a backend */
    if(!zf)
    {
        (void)vrprint.error(-1, "Internal Error", "backend not open (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* first reset all statusses */
    for(d_node = zones->list.top; d_node ; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        zone_ptr->status = ST_UNTOUCHED;
    }

    /* loop trough backend and check */
    while(zf->list(debuglvl, zone_backend, name, &zonetype, CAT_ZONES) != NULL)
    {
        zone_ptr = search_zonedata(debuglvl, zones, name);
        if(zone_ptr == NULL)
        {
            /* new zone */
            result = insert_zonedata(debuglvl, zones, interfaces, name, zonetype, reg);
            if(result != 0)
            {
                (void)vrprint.error(-1, "Internal Error", "inserting data for '%s' into the list failed (reload_zonedata).", name);
                return(-1);
            }

            /* print that we have a new zone */
            if(zonetype == TYPE_ZONE)
                (void)vrprint.info("Info", "Zone '%s' was added.", name);
            else if(zonetype == TYPE_NETWORK)
                (void)vrprint.info("Info", "Network '%s' was added.", name);
            else if(zonetype == TYPE_HOST)
                (void)vrprint.info("Info", "Host '%s' was added.", name);
            else if(zonetype == TYPE_GROUP)
                (void)vrprint.info("Info", "Group '%s' was added.", name);


            zone_ptr = search_zonedata(debuglvl, zones, name);
            if(zone_ptr == NULL)
            {
                (void)vrprint.error(-1, "Internal Error", "zone not found (in: %s:%d).",
                                                __FUNC__, __LINE__);
                return(-1);
            }
    

            if(zone_ptr->type == TYPE_HOST)
            {
                /* check */
                check_result = zones_check_host(debuglvl, zone_ptr);
                if(check_result != 1)
                {
                    (void)vrprint.info("Info", "Host '%s' has been deactivated because of errors while checking it.",
                                                        zone_ptr->name);
                    zone_ptr->active = FALSE;
                }
            }
            else if(zone_ptr->type == TYPE_NETWORK)
            {
                /* check */
                check_result = zones_check_network(debuglvl, zone_ptr);
                if(check_result != 1)
                {
                    (void)vrprint.info("Info", "Network '%s' has been deactivated because of errors while checking it.",
                                                        zone_ptr->name);
                    zone_ptr->active = FALSE;
                }
            }

            retval = 1;
        }
        else
        {
            result = reload_zonedata_check(debuglvl, zones, interfaces, zone_ptr, reg);
            if(result < 0)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "reload_zonedata: < 0");

                return(-1);
            }
            else if(result == 1)
                retval = 1;
        }
    }

    /* untouched means to be removed */
    for(d_node = zones->list.top; d_node ; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        if(zone_ptr->status == ST_UNTOUCHED)
        {
            /* print that we have a zone to remove */
            if(zone_ptr->type == TYPE_ZONE)
                (void)vrprint.info("Info", "Zone '%s' was removed.", zone_ptr->name);
            else if(zone_ptr->type == TYPE_NETWORK)
                (void)vrprint.info("Info", "Network '%s' was removed.", zone_ptr->name);
            else if(zone_ptr->type == TYPE_HOST)
                (void)vrprint.info("Info", "Host '%s' was removed.", zone_ptr->name);
            else if(zone_ptr->type == TYPE_GROUP)
                (void)vrprint.info("Info", "Group '%s' was removed.", zone_ptr->name);
            
            zone_ptr->status = ST_REMOVED;
            retval = 1;
        }
    }

    //zonedata_print_list(&ZonedataList);

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "** end **, retval=%d", retval);

    return(retval);
}


/*  reload_zonedata_check

    Checks the content of an host, group, network or zone for changes.
    
    Returncodes:
         1: changes
         0: no changes
        -1: error
*/
int
reload_zonedata_check(const int debuglvl, struct vrmr_zones *zones, struct vrmr_interfaces *interfaces, struct vrmr_zone *zone_ptr, struct vrmr_regex *reg)
{
    int                     result = 0,
                            retval = 0;
    int                     check_result = 0;
    struct vrmr_zone        *host_ptr_new  =NULL,
                            *host_ptr_orig,
                            *new_zone_ptr=NULL;
    struct vrmr_interface   *iface_ptr_new,
                            *iface_ptr_orig;
    struct vrmr_list_node             *d_node_orig = NULL,
                            *d_node_new  = NULL;
    struct vrmr_list_node             *protect_d_node_orig = NULL,
                            *protect_d_node_new  = NULL;
    struct vrmr_rule        *org_rule_ptr = NULL,
                            *new_rule_ptr = NULL;
    int                     status=-1;


    /* safety */
    if(!zones || !zone_ptr || !reg)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: reload_zonedata_check).");
        return(-1);
    }


    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "zone: %s, type: %d", zone_ptr->name, zone_ptr->type);


    /* alloc mem for new zone */
    if(!(new_zone_ptr = zone_malloc(debuglvl)))
    {
        (void)vrprint.error(-1, "Error", "allocating memory failed: %s.", strerror(errno));
        return(-1);
    }


    switch(zone_ptr->type)
    {
        case TYPE_ZONE:

            /* set the zone up */
            result = read_zonedata(debuglvl, zones, interfaces, zone_ptr->name, TYPE_ZONE, new_zone_ptr, reg);
            if(result != 0)
            {
                /* error! memory is freed at the end of this function */
                (void)vrprint.error(-1, "Error", "getting info for zone '%s' failed (in: reload_zonedata_check).", zone_ptr->name);
                status = ST_REMOVED;
            }

            /* now go check for differences */
            else
            {
                /* active */
                if(zone_ptr->active == new_zone_ptr->active)
                {
                    status = ST_KEEP;
                }
                else
                {
                    if(new_zone_ptr->active == 1)
                    {
                        status = ST_ACTIVATED;
                        (void)vrprint.info("Info", "Zone '%s' has been activated.", zone_ptr->name);
                    }
                    else
                    {
                        status = ST_DEACTIVATED;
                        (void)vrprint.info("Info", "Zone '%s' has been deactivated.", zone_ptr->name);
                    }
                }
            }
            break;

        case TYPE_NETWORK:

            result = read_zonedata(debuglvl, zones, interfaces, zone_ptr->name, TYPE_NETWORK, new_zone_ptr, reg);
            if(result != 0)
            {
                /* error! memory is freed at the end of this function */
                (void)vrprint.error(-1, "Error", "getting info for network '%s' failed (in: reload_zonedata_check).", zone_ptr->name);
                status = ST_REMOVED;
            }
            else
            {
                /* check */
                check_result = zones_check_network(debuglvl, new_zone_ptr);

                /* we start at keep */
                status = ST_KEEP;

                /* active If check_result is not 1 we are going to set the active to false, so we dont
                    care about this check. */
                if(check_result != 1 || zone_ptr->active == new_zone_ptr->active)
                {
                    /* network */
                    if(strcmp(zone_ptr->ipv4.network, new_zone_ptr->ipv4.network) == 0)
                    {
                        /* netmask */
                        if(strcmp(zone_ptr->ipv4.netmask, new_zone_ptr->ipv4.netmask) == 0)
                        {
                            /* interfaces */
                            if(zone_ptr->InterfaceList.len != new_zone_ptr->InterfaceList.len)
                            {
                                (void)vrprint.info("Info", "Network '%s': the number of interfaces has been changed.", zone_ptr->name);
                                status = ST_CHANGED;
                            }

                            /* now loop through the member to see if they have changes */
                            d_node_new  = new_zone_ptr->InterfaceList.top;
                            d_node_orig = zone_ptr->InterfaceList.top;

                            if(!d_node_new && !d_node_orig)
                            {
                                /* no change */
                            }
                            /* if eitherone is NULL and the other not there must be a change */
                            else if((!d_node_new && d_node_orig) || (d_node_new && !d_node_orig))
                            {
                                /* change */
                                if(!d_node_orig)
                                    (void)vrprint.info("Info", "Network '%s': network now has (an) interface(s).", zone_ptr->name);
                                if(!d_node_new)
                                    (void)vrprint.info("Info", "Network '%s': network now has (an) interface(s).", zone_ptr->name);
                                status = ST_CHANGED;
                            }
                            else
                            {
                                for(; d_node_new && d_node_orig; d_node_new = d_node_new->next, d_node_orig = d_node_orig->next)
                                {
                                    if(!(iface_ptr_new = d_node_new->data))
                                    {
                                        (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                        return(-1);
                                    }
                                    if(!(iface_ptr_orig = d_node_orig->data))
                                    {
                                        (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                        return(-1);
                                    }

                                    if(strcmp(iface_ptr_orig->name, iface_ptr_new->name) != 0)
                                    {
                                        (void)vrprint.info("Info", "Network '%s': interfaces not in the same order.", zone_ptr->name);
                                        status = ST_CHANGED;
                                    }

                                    if(iface_ptr_new->status != ST_KEEP)
                                    {
                                        (void)vrprint.info("Info", "Network '%s': interface '%s' has been changed.", zone_ptr->name, iface_ptr_new->name);
                                        status = ST_CHANGED;
                                    }
                                }
                            }


                            /* protect rules */
                            if(zone_ptr->ProtectList.len != new_zone_ptr->ProtectList.len)
                            {
                                (void)vrprint.info("Info", "Network '%s': the number of protectrules has been changed.", zone_ptr->name);
                                status = ST_CHANGED;
                            }

                            /* now loop through the member to see if they have changes */
                            protect_d_node_new  = new_zone_ptr->ProtectList.top;
                            protect_d_node_orig = zone_ptr->ProtectList.top;

                            if(!protect_d_node_new && !protect_d_node_orig)
                            {
                                /* no change */
                            }
                            /* if eitherone is NULL and the other not there must be a change */
                            else if((!protect_d_node_new && protect_d_node_orig) || (protect_d_node_new && !protect_d_node_orig))
                            {
                                /* change */
                                if(!protect_d_node_orig)
                                    (void)vrprint.info("Info", "Network '%s': network now has (an) protectrule(s).", zone_ptr->name);
                                if(!protect_d_node_new)
                                    (void)vrprint.info("Info", "Network '%s': network now has (an) protectrule(s).", zone_ptr->name);
                                status = ST_CHANGED;
                            }
                            else
                            {
                                for(; protect_d_node_new && protect_d_node_orig; protect_d_node_new = protect_d_node_new->next, protect_d_node_orig = protect_d_node_orig->next)
                                {
                                    if(!(new_rule_ptr = protect_d_node_new->data))
                                    {
                                        (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                        return(-1);
                                    }
                                    if(!(org_rule_ptr = protect_d_node_orig->data))
                                    {
                                        (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                        return(-1);
                                    }

                                    if( strcmp(org_rule_ptr->danger, new_rule_ptr->danger) != 0 ||
                                        strcmp(org_rule_ptr->source, new_rule_ptr->source) != 0)
                                    {
                                        (void)vrprint.info("Info", "Network '%s': protectrules not in the same order.", zone_ptr->name);
                                        status = ST_CHANGED;
                                    }
                                }
                            }

                        }
                        else
                        {
                            (void)vrprint.info("Info", "Network '%s': netmask changed to: '%s'.", zone_ptr->name, new_zone_ptr->ipv4.netmask);
                            status = ST_CHANGED;
                        }
                    }
                    else
                    {
                        (void)vrprint.info("Info", "Network '%s': network address changed to: '%s'.", zone_ptr->name, new_zone_ptr->ipv4.network);
                        status = ST_CHANGED;
                    }
#ifdef IPV6_ENABLED
                    /* network address */
                    if (strcmp(zone_ptr->ipv6.net6, new_zone_ptr->ipv6.net6) != 0) {
                        (void)vrprint.info("Info", "Network '%s' has a new ipv6 network address: '%s'.", zone_ptr->name, new_zone_ptr->ipv6.net6);
                        status = ST_CHANGED;
                    }
                    if (zone_ptr->ipv6.cidr6 != new_zone_ptr->ipv6.cidr6) {
                        (void)vrprint.info("Info", "Network '%s' has a new ipv6 CIDR: '%d'.", zone_ptr->name, new_zone_ptr->ipv6.cidr6);
                        status = ST_CHANGED;
                    }
#endif
                }
                else
                {
                    if(new_zone_ptr->active == 1)
                    {
                        (void)vrprint.info("Info", "Network '%s' has been activated.", zone_ptr->name);
                        status = ST_ACTIVATED;
                    }
                    else
                    {
                        (void)vrprint.info("Info", "Network '%s' has been deactivated.", zone_ptr->name);
                        status = ST_DEACTIVATED;
                    }
                }

                /* now check the result of interfaces_check() */
                if( (status == ST_CHANGED || status == ST_ACTIVATED || status == ST_DEACTIVATED) &&
                    check_result != 1)
                {
                    (void)vrprint.info("Info", "Network '%s' has been deactivated because of errors while checking it.",
                                                    zone_ptr->name);
                    new_zone_ptr->active = FALSE;
                }
            }
            break;

        case TYPE_HOST:

            result = read_zonedata(debuglvl, zones, interfaces, zone_ptr->name, TYPE_HOST, new_zone_ptr, reg);
            if(result != 0)
            {
                /* error! memory is freed at the end of this function */
                (void)vrprint.error(-1, "Error", "getting info for host '%s' failed (in: reload_zonedata_check).", zone_ptr->name);
                status = ST_REMOVED;
            }
            else
            {
                /* check */
                check_result = zones_check_host(debuglvl, new_zone_ptr);

                /* active If check_result is not 1 we are going to set the active to false, so we dont
                    care about this check. */
                if(check_result != 1 || zone_ptr->active == new_zone_ptr->active)
                {
                    /* ipaddress */
                    if(strcmp(zone_ptr->ipv4.ipaddress, new_zone_ptr->ipv4.ipaddress) == 0)
                    {
                        /* have mac */
                        if(zone_ptr->has_mac == new_zone_ptr->has_mac)
                        {
                            /* mac */
                            if(zone_ptr->has_mac == TRUE)
                            {
                                if(strcmp(zone_ptr->mac, new_zone_ptr->mac) == 0)
                                {
                                    status = ST_KEEP;
                                }
                                else
                                {
                                    (void)vrprint.info("Info", "Host '%s' has a new mac-address: '%s'.", zone_ptr->name, new_zone_ptr->mac);
                                    status = ST_CHANGED;
                                }
                            }
                            else
                            {
                                status = ST_KEEP;
                            }
                        }
                        else
                        {
                            if(zone_ptr->has_mac == FALSE)
                            {
                                (void)vrprint.info("Info", "Host '%s' now has a mac-address (%s).", zone_ptr->name, new_zone_ptr->mac);
                            }
                            else
                            {
                                (void)vrprint.info("Info", "Host '%s' no longer has a mac-address.", zone_ptr->name);
                            }
                            status = ST_CHANGED;
                        }
                    }
                    else
                    {
                        (void)vrprint.info("Info", "Host '%s' has a new ipaddress: '%s'.", zone_ptr->name, new_zone_ptr->ipv4.ipaddress);
                        status = ST_CHANGED;
                    }

#ifdef IPV6_ENABLED
                    /* ipaddress */
                    if (strcmp(zone_ptr->ipv6.ip6, new_zone_ptr->ipv6.ip6) != 0) {
                        (void)vrprint.info("Info", "Host '%s' has a new ipv6 address: '%s'.", zone_ptr->name, new_zone_ptr->ipv6.ip6);
                        status = ST_CHANGED;
                    }
#endif
                }
                else
                {
                    if(new_zone_ptr->active == TRUE)
                    {
                        (void)vrprint.info("Info", "Host '%s' has been activated.", zone_ptr->name);
                        status = ST_ACTIVATED;
                    }
                    else
                    {
                        (void)vrprint.info("Info", "Host '%s' has been deactivated.", zone_ptr->name);
                        status = ST_DEACTIVATED;
                    }
                }

                /* now check the result of zones_check_host() */
                if( (status == ST_CHANGED || status == ST_ACTIVATED || status == ST_DEACTIVATED) &&
                    check_result != 1)
                {
                    (void)vrprint.info("Info", "Host '%s' has been deactivated because of errors while checking it.",
                                                    zone_ptr->name);
                    new_zone_ptr->active = FALSE;
                }
            }
            break;

        case TYPE_GROUP:

            result = read_zonedata(debuglvl, zones, interfaces, zone_ptr->name, TYPE_GROUP, new_zone_ptr, reg);
            if(result != 0)
            {
                /* error! memory is freed at the end of this function */
                (void)vrprint.error(-1, "Error", "getting info for group '%s' failed (in: reload_zonedata_check).", zone_ptr->name);

                status = ST_REMOVED;
            }
            else
            {
                status = ST_KEEP;

                /* check */
                check_result = zones_check_group(debuglvl, new_zone_ptr);

                /* active */
                if(check_result != 1 || zone_ptr->active == new_zone_ptr->active)
                {
                    /* member count */
                    if(zone_ptr->group_member_count != new_zone_ptr->group_member_count)
                    {
                        (void)vrprint.info("Info", "Group '%s': the number of members changed.", zone_ptr->name);
                        status = ST_CHANGED;
                    }

                    /* now loop through the member to see if they have changes */
                    d_node_new  = new_zone_ptr->GroupList.top;
                    d_node_orig = zone_ptr->GroupList.top;

                    if(!d_node_new && !d_node_orig)
                    {
                        /* no change */
                    }
                    /* if eitherone is NULL and the other not there must be a change */
                    else if((!d_node_new && d_node_orig) || (d_node_new && !d_node_orig))
                    {
                        /* change */
                        status = ST_CHANGED;

                        /* change */
                        if(!d_node_orig)
                            (void)vrprint.info("Info", "Group '%s': group now has (a) member(s).", zone_ptr->name);

                        if(!d_node_new)
                            (void)vrprint.info("Info", "Group '%s': group no longer has members.", zone_ptr->name);
                    }
                    else
                    {
                        for(; d_node_new && d_node_orig; d_node_new = d_node_new->next, d_node_orig = d_node_orig->next)
                        {
                            if(!(host_ptr_new = d_node_new->data))
                            {
                                (void)vrprint.error(-1, "Internal Error", "reload_zonedata_check: host_ptr_new == NULL (and it shouldn't).");
                                return(-1);
                            }

                            if(!(host_ptr_orig = d_node_orig->data))
                            {
                                (void)vrprint.error(-1, "Internal Error", "reload_zonedata_check: host_ptr_orig == NULL (and it shouldn't).");
                                return(-1);
                            }

                            if(strcmp(host_ptr_orig->name, host_ptr_new->name) != 0)
                            {
                                (void)vrprint.info("Info", "Group '%s': members not in the same order.", zone_ptr->name);
                                status = ST_CHANGED;
                            }

                            if(host_ptr_new->status != ST_KEEP)
                            {
                                (void)vrprint.info("Info", "Group '%s': member '%s' has been changed.", zone_ptr->name, host_ptr_new->name);
                                status = ST_CHANGED;
                            }
                        }
                    }
                }
                else
                {
                    if(new_zone_ptr->active == 1)
                    {
                        (void)vrprint.info("Info", "Group '%s' has been activated.", zone_ptr->name);
                        status = ST_ACTIVATED;
                    }
                    else
                    {
                        (void)vrprint.info("Info", "Group '%s' has been deactivated.", zone_ptr->name);
                        status = ST_DEACTIVATED;
                    }
                }

                /* now check the result of zones_check_group() */
                if( (status == ST_CHANGED || status == ST_ACTIVATED || status == ST_DEACTIVATED) &&
                    check_result != 1)
                {
                    (void)vrprint.info("Info", "Group '%s' has been deactivated because of errors while checking it.",
                                                    zone_ptr->name);
                    new_zone_ptr->active = FALSE;
                }
            }
            break;
        
        default:
        
            (void)vrprint.error(-1, "Error", "unknown zone type: %d for zone %s (in: %s).", zone_ptr->type, zone_ptr->name, __FUNC__);

            retval = -1;
            break;
    }


    /* update the data in memory */
    if(status == ST_CHANGED || status == ST_ACTIVATED || status == ST_DEACTIVATED)
    {
        /* update the data */

        /* first destroy the old lists */
        if(zone_ptr->type == TYPE_GROUP)
            vrmr_list_cleanup(debuglvl, &zone_ptr->GroupList);
        if(zone_ptr->type == TYPE_NETWORK)
        {
            vrmr_list_cleanup(debuglvl, &zone_ptr->InterfaceList);
            vrmr_list_cleanup(debuglvl, &zone_ptr->ProtectList);
        }

        /* copy the zone */
        *zone_ptr = *new_zone_ptr;

        /* transfer the status */
        zone_ptr->status = status;

        /* tell the caller we have changes */
        retval = 1;
    }
    else if(status == ST_KEEP || status == ST_REMOVED)
    {
        /* first destroy the new lists, the struct will be free'd later */
        if(new_zone_ptr->type == TYPE_GROUP)
            vrmr_list_cleanup(debuglvl, &new_zone_ptr->GroupList);
        if(new_zone_ptr->type == TYPE_NETWORK)
        {
            vrmr_list_cleanup(debuglvl, &new_zone_ptr->InterfaceList);
            vrmr_list_cleanup(debuglvl, &new_zone_ptr->ProtectList);
        }
                        
        /* status to keep */
        zone_ptr->status = status;
    }

    /* now free new_zone_ptr */
    free(new_zone_ptr);
    new_zone_ptr = NULL;

    return(retval);
}

/*  reload_interfaces

    Returncodes:
         1: changes
         0: no changes
        -1: error
*/
int
reload_interfaces(const int debuglvl, struct vrmr_interfaces *interfaces)
{
    int                     retval = 0,
                            result = 0;
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;
    char                    name[MAX_INTERFACE] = "";
    int                     zonetype = 0;


    /* safety first */
    if(!interfaces)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }


    /* check if we have a backend */
    if(!af)
    {
        (void)vrprint.error(-1, "Internal Error", "backend not open (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    
    /* first reset all statusses */
    for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
    {
        if(!(iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        iface_ptr->status = ST_UNTOUCHED;
    }


    /* reset the meta data */
    interfaces->dynamic_interfaces = 0;
    interfaces->active_interfaces = 0;


    /* now loop trough the interfaces and check them */
    while(af->list(debuglvl, ifac_backend, name, &zonetype, CAT_INTERFACES) != NULL)
    {
        iface_ptr = vrmr_search_interface(debuglvl, interfaces, name);
        if(iface_ptr == NULL)
        {
            (void)vrprint.info("Info", "Interface '%s' is added.", name);

            /* this is a new interface */
            result = vrmr_insert_interface(debuglvl, interfaces, name);
            if(result != 0)
            {
                (void)vrprint.error(-1, "Internal Error", "insert_interface() failed (in: %s:%d).",
                                                __FUNC__, __LINE__);
                return(-1);
            }

            iface_ptr = vrmr_search_interface(debuglvl, interfaces, name);
            if(iface_ptr == NULL)
            {
                (void)vrprint.error(-1, "Internal Error", "interface not found (in: %s:%d).",
                                                __FUNC__, __LINE__);
                return(-1);
            }

            result = interfaces_check(debuglvl, iface_ptr);
            if(result != 1)
            {
                (void)vrprint.info("Info", "Interface '%s' has been deactivated because of errors while checking it.",
                                                        iface_ptr->name);
                iface_ptr->active = FALSE;
            }

            retval = 1;
        }
        else
        {
            /* existing interface, so check it for changes */
            result = reload_interfaces_check(debuglvl, iface_ptr);
            if(result == 1)
                retval = 1;
            else if(retval < 0)
                return(-1);
        }


        /* update the meta data */
        if(iface_ptr != NULL)
        {
            if(iface_ptr->dynamic == TRUE)
                interfaces->dynamic_interfaces = TRUE;
            if(iface_ptr->active == TRUE)
                interfaces->active_interfaces = TRUE;
        }
    }


    /* tag untouched interfaces as (to be) 'removed' */
    for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
    {
        if(!(iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(iface_ptr->status == ST_UNTOUCHED)
        {
            (void)vrprint.info("Info", "Interface '%s' is removed.", iface_ptr->name);
            iface_ptr->status = ST_REMOVED;

            retval = 1;
        }
    }


    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "** end **, result = %d", retval);

    return(retval);
}


/*  reload_interfaces_check

    Checks an individual interface for changes.

    Returncodes:
         1: changes
         0: no changes
        -1: error
*/
int
reload_interfaces_check(const int debuglvl, struct vrmr_interface *iface_ptr)
{
    int                     retval = 0;
    int                     check_result = 0;
    struct vrmr_interface   *new_iface_ptr = NULL;
    int                     status = 0;
    struct vrmr_list_node             *protect_d_node_orig = NULL,
                            *protect_d_node_new  = NULL;
    struct vrmr_rule        *org_rule_ptr = NULL,
                            *new_rule_ptr = NULL;


    /* safety */
    if(!iface_ptr)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }


    /* alloc mem for a temporary interface */
    if(!(new_iface_ptr = interface_malloc(debuglvl)))
    {
        (void)vrprint.error(-1, "Internal Error", "interface_malloc() failed: %s (in: %s:%d).",
                                    strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }


    /* set the name */
    if(strlcpy(new_iface_ptr->name, iface_ptr->name, sizeof(new_iface_ptr->name)) >= sizeof(new_iface_ptr->name))
    {
        (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* first we asume that the interface did not change, if so we change it below */
    status = ST_KEEP;


    /* get the info from the backend */
    if(read_interface_info(debuglvl, new_iface_ptr) != 0)
    {
        (void)vrprint.error(-1, "Error", "getting interface information for '%s' failed (in: %s).", iface_ptr->name, __FUNC__);
        status = ST_REMOVED;
    }
    else
    {
        /* check the interface */
        check_result = interfaces_check(debuglvl, new_iface_ptr);

        /*
            NOW CHECK for changes
        */

        /* active. If check_result is not 1 we are going to set the active to false, so we dont
           care about this check. */
        if(check_result != 1 || iface_ptr->active == new_iface_ptr->active)
        {
            /* compare device */
            if(strcmp(iface_ptr->device, new_iface_ptr->device) == 0)
            {
                if(iface_ptr->dynamic == new_iface_ptr->dynamic)
                {
                    if(iface_ptr->device_virtual == new_iface_ptr->device_virtual)
                    {
                        /* compare ipaddress */
                        if(strcmp(iface_ptr->ipv4.ipaddress, new_iface_ptr->ipv4.ipaddress) == 0)
                        {
                            /* check 'up' */
                            if(iface_ptr->up == new_iface_ptr->up)
                            {
                                /* protect rules */
                                if(iface_ptr->ProtectList.len != new_iface_ptr->ProtectList.len)
                                {
                                    (void)vrprint.info("Info", "Interface '%s': the number of protectrules has been changed.", iface_ptr->name);
                                    status = ST_CHANGED;
                                }

                                /* now loop through the member to see if they have changes */
                                protect_d_node_new  = new_iface_ptr->ProtectList.top;
                                protect_d_node_orig = iface_ptr->ProtectList.top;

                                if(!protect_d_node_new && !protect_d_node_orig)
                                {
                                    /* no change */
                                }
                                /* if eitherone is NULL and the other not there must be a change */
                                else if((!protect_d_node_new && protect_d_node_orig) || (protect_d_node_new && !protect_d_node_orig))
                                {
                                    /* change */
                                    if(!protect_d_node_orig)
                                        (void)vrprint.info("Info", "Interface '%s': interface now has (an) protectrule(s).", iface_ptr->name);
                                    if(!protect_d_node_new)
                                        (void)vrprint.info("Info", "Interface '%s': interface no longer has (an) protectrule(s).", iface_ptr->name);
                                    status = ST_CHANGED;
                                }
                                else
                                {
                                    for(; protect_d_node_new && protect_d_node_orig; protect_d_node_new = protect_d_node_new->next, protect_d_node_orig = protect_d_node_orig->next)
                                    {
                                        if(!(new_rule_ptr = protect_d_node_new->data))
                                        {
                                            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                            return(-1);
                                        }
                                        if(!(org_rule_ptr = protect_d_node_orig->data))
                                        {
                                            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                            return(-1);
                                        }

                                        if( strcmp(org_rule_ptr->danger, new_rule_ptr->danger) != 0 ||
                                            strcmp(org_rule_ptr->source, new_rule_ptr->source) != 0)
                                        {
                                            (void)vrprint.info("Info", "Interface '%s': protectrules not in the same order.", iface_ptr->name);
                                            status = ST_CHANGED;
                                            break;
                                        }
                                    }
                                }

                            }
                            else
                            {
                                (void)vrprint.info("Info", "Interface '%s' is now: %s.", iface_ptr->name, new_iface_ptr->up ? "up" : "down");
                                status = ST_CHANGED;
                            }
                        }
                        else
                        {
                            (void)vrprint.info("Info", "Interface '%s' has a new ipaddress: '%s'.", iface_ptr->name, new_iface_ptr->ipv4.ipaddress);
                            status = ST_CHANGED;
                        }

#ifdef IPV6_ENABLED
                        if (strcmp(iface_ptr->ipv6.ip6, new_iface_ptr->ipv6.ip6) != 0) {
                            (void)vrprint.info("Info", "Interface '%s' has a new ipv6 ipaddress: '%s'.", iface_ptr->name, new_iface_ptr->ipv6.ip6);
                            status = ST_CHANGED;
                        }
#endif
                    }
                    else
                    {
                        if(new_iface_ptr->dynamic == TRUE)
                            (void)vrprint.info("Info", "Interface '%s' now has a dynamic ipaddress.", iface_ptr->name);
                        else
                            (void)vrprint.info("Info", "Interface '%s' no longer has a dynamic ipaddress.", iface_ptr->name);

                        status = ST_CHANGED;
                    }
                }
                else
                {
                    if(new_iface_ptr->device_virtual == TRUE)
                        (void)vrprint.info("Info", "Interface '%s' is now 'virtual'.", iface_ptr->name);
                    else
                        (void)vrprint.info("Info", "Interface '%s' is no longer 'virtual'.", iface_ptr->name);

                    status = ST_CHANGED;
                }
            }
            else
            {
                (void)vrprint.info("Info", "Interface '%s' has a new system device: '%s'.", iface_ptr->name, new_iface_ptr->device);
                status = ST_CHANGED;
            }
        }
        else
        {
            if(new_iface_ptr->active == TRUE)
            {
                (void)vrprint.info("Info", "Interface '%s' has been activated.", iface_ptr->name);
                status = ST_ACTIVATED;
            }
            else
            {
                (void)vrprint.info("Info", "Interface '%s' has been deactivated.", iface_ptr->name);
                status = ST_DEACTIVATED;
            }
        }

        /* now check the result of interfaces_check() */
        if( (status == ST_CHANGED || status == ST_ACTIVATED || status == ST_DEACTIVATED) &&
            check_result != 1)
        {
            (void)vrprint.info("Info", "Interface '%s' has been deactivated because of errors while checking it.",
                                            iface_ptr->name);
            new_iface_ptr->active = FALSE;
        }
    }

    if(status == ST_CHANGED || status == ST_ACTIVATED || status == ST_DEACTIVATED)
    {
        vrmr_list_cleanup(debuglvl, &iface_ptr->ProtectList);

        /* copy the data */
        *iface_ptr = *new_iface_ptr;

        /* inform the caller that there were changes */
        retval = 1;
    }
    else if(status == ST_KEEP || status == ST_REMOVED)
    {
        vrmr_list_cleanup(debuglvl, &new_iface_ptr->ProtectList);
    }

    /* free the temp data */
    free(new_iface_ptr);
    new_iface_ptr = NULL;

    /* transfer the status */
    iface_ptr->status = status;

    return(retval);
}


/*  reload_blocklist

    Reloads the blocklist.

    returncodes:
        -1: error
        0: no changes
        1: changes
*/
int
reload_blocklist(const int debuglvl, struct vuurmuur_config *cfg, struct vrmr_zones *zones, struct vrmr_blocklist *blocklist)
{
    struct vrmr_blocklist   *new_blocklist = NULL;
    int         status = 0;
    struct vrmr_list_node *new_node = NULL,
                *old_node = NULL;
    char        *new_ip = NULL,
                *org_ip = NULL;

    /* safety */
    if(blocklist == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                                    __FUNC__, __LINE__);
        return(-1);
    }

    if(!(new_blocklist = malloc(sizeof(struct vrmr_blocklist))))
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s (in: %s:%d).",
                                    strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /*  and reload it (with load_ips == TRUE and no_refcnt == TRUE because
        we don't care about the refcnt now */
    if (vrmr_blocklist_init_list(debuglvl, cfg, zones, new_blocklist,
                /*load_ips*/TRUE, /*no_refcnt*/TRUE) < 0)
    {
        (void)vrprint.error(-1, "Error","reading the blocklist failed (in: %s:%d).",
                                    __FUNC__, __LINE__);

        free(new_blocklist);
        return(-1);
    }

    /* run trough the lists and compare */
    if(blocklist->list.len != new_blocklist->list.len)
    {
        (void)vrprint.info("Info", "BlockList: the number of blocklist items has been changed.");
        status = 1;
    }

    /* now loop through the member to see if they have changes */
    new_node = new_blocklist->list.top;
    old_node = blocklist->list.top;
    if(!new_node && !old_node)
    {
        /* no change */
    }
    /* if eitherone is NULL and the other not there must be a change */
    else if((!new_node && old_node) || (new_node && !old_node))
    {
        /* change */
        if(!old_node)
            (void)vrprint.info("Info", "BlockList: blocklist now has items (old: %d, new: %d).",
                                blocklist->list.len, new_blocklist->list.len);

        if(!new_node)
            (void)vrprint.info("Info", "BlockList: blocklist no longer has items (old: %d, new: %d).",
                                blocklist->list.len, new_blocklist->list.len);

        status = 1;
    }
    else
    {
        for(; new_node && old_node; new_node = new_node->next, old_node = old_node->next)
        {
            if(!(new_ip = new_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
            if(!(org_ip = old_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(strcmp(org_ip, new_ip) != 0)
            {
                (void)vrprint.info("Info", "BlockList: blocklist items not in the same order.");
                status = 1;
            }
        }
    }


    /* see if we need to swap the lists */
    if(status == 1)
    {
        vrmr_list_cleanup(debuglvl, &blocklist->list);

        /* copy the new list to the old */
        *blocklist = *new_blocklist;
    }
    else
    {
        vrmr_list_cleanup(debuglvl, &new_blocklist->list);
    }
    free(new_blocklist);


    return(status);
}


/*

    Two stages:
        1. check the rules them selves for changes
        2. check if the zones, services etc are changed
*/
int
reload_rules(const int debuglvl, VuurmuurCtx *vctx, struct vrmr_regex *reg)
{
    struct vrmr_rules       *new_rules = NULL;
    char                    status = 0,
                            changed = 0;
    struct vrmr_list_node             *new_node = NULL,
                            *old_node = NULL;
    struct vrmr_rule        *new_rule_ptr = NULL,
                            *org_rule_ptr = NULL;
    struct vrmr_zone        *new_zone_ptr = NULL;
    struct vrmr_service    *new_serv_ptr = NULL;
    struct vrmr_rule_cache       *rulecache = NULL;


    if(!(new_rules = malloc(sizeof(*new_rules))))
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s (in: %s).", strerror(errno), __FUNC__);
        return(-1);
    }

    /* stage 1 starting... */

    /* re-initialize the rules_list */
    if(vrmr_rules_init_list(debuglvl, vctx->conf, new_rules, reg) < 0)
    {
        (void)vrprint.error(-1, "Error", "rules_init_list() failed.");

        free(new_rules);
        return(-1);
    }

    /* analyzing the new rules */
    if(analyze_all_rules(debuglvl, vctx, new_rules) != 0)
    {
        (void)vrprint.error(-1, "Error", "analizing the new rules failed.");

        /* cleanups */
        rules_cleanup_list(debuglvl, new_rules);
        free(new_rules);

        return(-1);
    }

    /* run trough the lists and compare */
    if(vctx->rules->list.len != new_rules->list.len)
    {
        (void)vrprint.info("Info", "Rules: the number of rules items has been changed.");
        status = 1;
    }

    /* now loop through the member to see if they have changes */
    new_node = new_rules->list.top;
    old_node = vctx->rules->list.top;
    if(!new_node && !old_node)
    {
        /* no change */
    }
    /* if eitherone is NULL and the other not there must be a change */
    else if((!new_node && old_node) || (new_node && !old_node))
    {
        /* change */
        if(!old_node)
            (void)vrprint.info("Info", "Rules: ruleslist now has items (old: %d, new: %d).", vctx->rules->list.len, new_rules->list.len);

        if(!new_node)
            (void)vrprint.info("Info", "Rules: ruleslist no longer has items (old: %d, new: %d).", vctx->rules->list.len, new_rules->list.len);

        status = 1;
    }
    else
    {
        for(; new_node && old_node; new_node = new_node->next, old_node = old_node->next)
        {
            if(!(new_rule_ptr = new_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
            if(!(org_rule_ptr = old_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            /* active */
            if(org_rule_ptr->active != new_rule_ptr->active)
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "%d: active changed.", org_rule_ptr->number);

                status = 1;
            }

            /* action */
            if(org_rule_ptr->action != new_rule_ptr->action)
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "%d: action changed.", org_rule_ptr->number);

                status = 1;
            }

            /* service */
            if(strcmp(org_rule_ptr->service, new_rule_ptr->service) != 0)
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "%d: service changed.", org_rule_ptr->number);

                status = 1;
            }

            /* from */
            if(strcmp(org_rule_ptr->from, new_rule_ptr->from) != 0)
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "%d: from changed.", org_rule_ptr->number);

                status = 1;
            }

            /* to */
            if(strcmp(org_rule_ptr->to, new_rule_ptr->to) != 0)
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "%d: to changed.", org_rule_ptr->number);

                status = 1;
            }

            /* comparing the rule options */
            if(rules_compare_options(debuglvl, org_rule_ptr->opt, new_rule_ptr->opt, rules_itoaction(new_rule_ptr->action)) != 0)
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "%d: options changed.", org_rule_ptr->number);

                status = 1;
            }

            /* once we know that there were changes, we don't need to keep checking */
            if(changed == 1)
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "%d: %s(%s) %s(%s) %s(%s) -> %s(%s).",    org_rule_ptr->number,
                                                        rules_itoaction(org_rule_ptr->action),
                                                        rules_itoaction(new_rule_ptr->action),
                                                        org_rule_ptr->service,
                                                        new_rule_ptr->service,
                                                        org_rule_ptr->from,
                                                        new_rule_ptr->from,
                                                        org_rule_ptr->to,
                                                        new_rule_ptr->to);
                changed = 0;
            }
        }
    }

    /* see if we are already done */
    if(status == 1)
    {
        (void)vrprint.info("Info", "the rules themselves did change.");

        rules_cleanup_list(debuglvl, vctx->rules);

        /* copy the new list to the old */
        *vctx->rules = *new_rules;

        free(new_rules);
        return(1);
    }

    /* stage 1 done... */

    (void)vrprint.info("Info", "the rules themselves didn't change.");

    /* stage 2: okay, now do some deep inspection */
    
    /* loop through the member to see if they have changes */
    new_node = new_rules->list.top;
    if(!new_node)
    {
        /* no rules */
    }
    else
    {
        for(; new_node; new_node = new_node->next)
        {
            if(!(new_rule_ptr = new_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                                        __FUNC__, __LINE__);
                return(-1);
            }
            if(!(rulecache = &new_rule_ptr->rulecache))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                                        __FUNC__, __LINE__);
                return(-1);
            }

            /* from zone */
            if((new_zone_ptr = rulecache->from))
            {
                if(new_zone_ptr->status != ST_KEEP)
                    status = 1;
            }
            /* to zone */
            if((new_zone_ptr = rulecache->to))
            {
                if(new_zone_ptr->status != ST_KEEP)
                    status = 1;
            }
            /* service */
            if((new_serv_ptr = rulecache->service))
            {
                if(new_serv_ptr->status != ST_KEEP)
                    status = 1;
            }

            /* once we know that there were changes, we don't need to keep checking */
            if(status == 1)
                break;
        }
    }

    if(status == 1)
    {
        (void)vrprint.info("Info", "the rules zones and/or services did change.");

        rules_cleanup_list(debuglvl, vctx->rules);

        /* copy the new list to the old */
        *vctx->rules = *new_rules;
    }
    else
    {
        (void)vrprint.info("Info", "the rules zones and services didn't change.");

        rules_cleanup_list(debuglvl, new_rules);
    }
    free(new_rules);


    return(status);
}


/*  check_for_changed_networks

    Returncodes:
        -1: error
        0: no changes
        1: changes
*/
int
check_for_changed_networks(const int debuglvl, struct vrmr_zones *zones)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_zone    *zone_ptr = NULL;
    char                status = 0;


    /* safety */
    if(!zones)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }


    /* loop */
    for(d_node = zones->list.top; d_node; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == TYPE_NETWORK)
        {
            if(zone_ptr->status != ST_KEEP)
                status = 1;
        }

        if(status == 1)
            break;
    }

    return(status);
}


/*  check_for_changed_dynamic_ips

    Returncodes:
        -1: error
        0: no changes
        1: changes
*/
int
check_for_changed_dynamic_ips(const int debuglvl, struct vrmr_interfaces *interfaces)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;
    char                    ipaddress[16] = "";
    int                     result = 0,
                            retval = 0;

    /* safety */
    if(!interfaces)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* loop through interfaces */
    for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
    {
        if(!(iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(iface_ptr->dynamic == 1 && strcmp(iface_ptr->device, "") != 0)
        {
            result = get_dynamic_ip(debuglvl, iface_ptr->device, ipaddress, sizeof(ipaddress));
            if(result == -1)
            {
                (void)vrprint.error(-1, "Error", "getting the ipaddress failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
            else if(result == 1)
            {
                /* we got a valid answer, this means the interface is 'up'.
                   So check if the last known state was 'down' */
                if(!iface_ptr->up)
                {
                    (void)vrprint.info("Info", "dynamic interface '%s' is now up.",
                                    iface_ptr->name);
                    retval = 1;
                }

                /* compare the result with the known ipaddress */
                if(strcmp(ipaddress, iface_ptr->ipv4.ipaddress) != 0)
                {
                    
                    (void)vrprint.info("Info", "dynamic interface '%s' had ipaddress '%s' now it has '%s'.",
                                    iface_ptr->name,
                                    iface_ptr->ipv4.ipaddress,
                                    ipaddress);
                    retval = 1;
                }
            }
            else if(result == 0)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "dynamic interface '%s' is down.", iface_ptr->name);

                /* see if the last known state was 'up'. */
                if(iface_ptr->up)
                {
                    (void)vrprint.info("Info", "dynamic interface '%s' is now down.",
                                    iface_ptr->name);
                    retval = 1;
                }
            }
            else
            {
                (void)vrprint.error(-1, "Internal Error", "unknown errorcode '%d' for get_dynamic_ip() (in: %s:%d).", result, __FUNC__, __LINE__);
                return(-1);
            }
        }
    }

    return(retval);
}

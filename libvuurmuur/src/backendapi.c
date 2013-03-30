/***************************************************************************
 *   Copyright (C) 2002-2007 by Victor Julien                              *
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

/** \brief Plugin registration function
 *  To be called from plugin
 */
void
vrmr_plugin_register(struct vrmr_plugin_data *plugin_data)
{
    struct vrmr_plugin  *plugin = NULL;
    struct vrmr_list_node         *d_node = NULL;

    if (!plugin_data) {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: load_plugin).");
        return;
    }

    if (!(plugin = malloc(sizeof(struct vrmr_plugin)))) {
        (void)vrprint.error(-1, "Error", "malloc failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return;
    }
    memset(plugin, 0x00, sizeof(*plugin));

    plugin->f = plugin_data;
    plugin->ref_cnt = 1;

    /* store the name of the plugin */
    if (strlcpy(plugin->name, plugin_data->name, sizeof(plugin->name)) >= sizeof(plugin->name))
    {
        (void)vrprint.error(-1, "Internal Error", "pluginname "
                "overflow (in: %s:%d).", __FUNC__, __LINE__);
        free(plugin);
        return;
    }

    /* insert into the list */
    if (vrmr_list_append(/* no dbg */0, &vrmr_plugin_list, plugin) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() "
                "failed (in: %s:%d).", __FUNC__, __LINE__);
        free(plugin);
        return;
    }
    return;
}

/*  open_plugin

    Opens the plugin supplied with 'plugin'. Upon succes its
    returns the plugin handle, otherwise NULL.
*/

/*@null@*/
static void *
open_plugin(const int debuglvl, char *plugin)
{
    void    *ptr = NULL;

    if(!plugin)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "this is the plugin: '%s'.", plugin);

    ptr = dlopen(plugin, RTLD_NOW);
    if(ptr == NULL)
    {
        (void)vrprint.error(-1, "Error", "opening plugin '%s' failed:"
                " %s (in: %s:%d).", plugin, dlerror(),
                __FUNC__, __LINE__);
        return(NULL);
    }

    return(ptr);
}


/*  load_plugin

    Loads a plugin!

    Steps:
        Checks if the plugin is already open
            yes:    link func_ptr to existing function struct
                increment ref_cmt

            no: alloc memory for plugin struct
                open plugin and store the handle in to alloc'd struct
                store functions
                insert into pluginlist

    Returncodes:
        0: ok
        -1: error
*/
static int
load_plugin(const int debuglvl, struct vrmr_config *cfg, struct vrmr_list *plugin_list,
        char *plugin_name, struct vrmr_plugin_data **func_ptr)
{
    int                 retval=0;
    char                plugin_location[512] = "";
    struct vrmr_plugin  *plugin = NULL;
    struct vrmr_list_node         *d_node = NULL;

    if(!plugin_list || !plugin_name || !func_ptr)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: load_plugin).");
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "** start **, plugin_nane: '%s', pluginlist size: '%d'.", plugin_name, plugin_list->len);

    /* safety check */
    if(plugin_name[0] == '\0')
    {
        (void)vrprint.error(-1, "Internal Error", "plugin name not set "
                " (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /*
        first check if we already have the plugin loaded
    */
    for(d_node = plugin_list->top; d_node; d_node = d_node->next)
    {
        plugin = d_node->data;

        if(strcmp(plugin->name, plugin_name) == 0) {
            *func_ptr = plugin->f;
            plugin->ref_cnt++;
            return(0);
        }
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "opening plugin.");

    if(snprintf(plugin_location, sizeof(plugin_location), "%s/lib%s.so", cfg->plugdir, plugin_name) >= (int)sizeof(plugin_location))
    {
        (void)vrprint.error(-1, "Internal Error", "pluginpath "
                "overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    void *handle = open_plugin(debuglvl, plugin_location);
    if(!handle)
    {
        (void)vrprint.error(-1, "Internal Error", "pluginpath "
                "overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    plugin = NULL;
    for(d_node = plugin_list->top; d_node; d_node = d_node->next)
    {
        plugin = d_node->data;

        if(strcmp(plugin->name, plugin_name) == 0) {
            break;
        }
    }
    if (!plugin) {
        (void)vrprint.error(-1, "Internal Error", "plugin not registered "
                "(in: %s:%d).", __FUNC__, __LINE__);
        dlclose(handle);
        return(-1);
    }

    /* set func_ptr */
    *func_ptr = plugin->f;
    plugin->handle = handle;

    if(cfg->verbose_out == TRUE && debuglvl >= LOW)
    {
        (void)vrprint.info("Info", "Successfully loaded plugin '%s' version %s.",
                plugin_name, plugin->version);
    }

    return(retval);
}


/*  unload_plugin

    Unloads the plugin.

    Steps:
        Checks if the plugin is loaded:
            no:     should not happen - issue warning

            yes:    decrement ref_cnt
                    set func_ptr to NULL

                Check if ref_cnt is zero
                    no:     do nothing

                    yes:    unload plugin and set handle to NULL
                            remove from list
                            free memory

    Returncodes:
        0: ok
        -1: error
*/
static int
unload_plugin(const int debuglvl, struct vrmr_list *plugin_list, char *plugin_name, struct vrmr_plugin_data **func_ptr)
{
    struct vrmr_plugin  *plugin = NULL;
    struct vrmr_list_node         *d_node = NULL;

    /* safety first */
    if(!plugin_list || !plugin_name || !func_ptr)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* first check if we have the plugin loaded */
    for(d_node = plugin_list->top; d_node; d_node = d_node->next)
    {
        if(!(plugin = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        /* if we match break, so 'plugin' points to the right plugin */
        if(strcmp(plugin->name, plugin_name) == 0)
            break;

        /* if we have a match above we will not get here */
        plugin = NULL;
    }

    /* if plugin == NULL its already gone - this should not happen */
    if(!plugin)
    {
        (void)vrprint.warning("Warning", "it seems that the plugin '%s' is already unloaded, or was never loaded.", plugin_name);
    }
    /* else decrement ref_cnt, and unload if the cnt is 0. */
    else
    {
        /* decrement ref_cnt */
        plugin->ref_cnt--;

        /* set func_ptr to null */
        *func_ptr = NULL;

        /* if ref_cnt is zero, we unload the plugin */
        if(plugin->ref_cnt == 0)
        {
            if(dlclose(plugin->handle) < 0)
            {
                (void)vrprint.error(-1, "Error", "unloading plugin failed: %s (in: %s).", dlerror(), __FUNC__);
                return(-1);
            }

            /* the plugin handle is now gone, so set to NULL */
            plugin->handle = NULL;

            /* remove the plugindata from the list */
            if(vrmr_list_remove_node(debuglvl, plugin_list, d_node) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "removing plugin form list (in: %s).", __FUNC__);
                return(-1);
            }

            /* finally free the memory */
            free(plugin);
            plugin = NULL;
        }
    }

    return(0);
}


/*  load_backends

    Loads the backends for: services
                            zones
                            interfaces

    For those three it takes the following steps:
    1. load the plugin
    2. setup the plugin (alloc backend struct)
    3. configure backend/plugin
    4. open the backend

    Returncodes:
        0: ok
        -1: error
*/
int
vrmr_backends_load(const int debuglvl, struct vrmr_config *cfg)
{
    /* first the SERVICES */
    if (load_plugin(debuglvl, cfg, &vrmr_plugin_list, cfg->serv_backend_name, &sf) < 0)
        return(-1);
    if (sf->setup(debuglvl, cfg, &serv_backend) < 0)
        return(-1);
    if (sf->conf(debuglvl, serv_backend) < 0)
        return(-1);
    if (sf->open(debuglvl, serv_backend, 0, VRMR_BT_SERVICES) < 0)
        return(-1);

    /*
        second ZONES
    */
    if (load_plugin(debuglvl, cfg, &vrmr_plugin_list, cfg->zone_backend_name, &zf) < 0)
        return(-1);
    if (zf->setup(debuglvl, cfg, &zone_backend) < 0)
        return(-1);
    if (zf->conf(debuglvl, zone_backend) < 0)
        return(-1);
    if (zf->open(debuglvl, zone_backend, 0, VRMR_BT_ZONES) < 0)
        return(-1);

    /*
        third INTERFACES
    */
    if (load_plugin(debuglvl, cfg, &vrmr_plugin_list, cfg->ifac_backend_name, &af) < 0)
        return(-1);
    if (af->setup(debuglvl, cfg, &ifac_backend) < 0)
        return(-1);
    if (af->conf(debuglvl, ifac_backend) < 0)
        return(-1);
    if (af->open(debuglvl, ifac_backend, 0, VRMR_BT_INTERFACES) < 0)
        return(-1);

    /*
        last RULES
    */
    if (load_plugin(debuglvl, cfg, &vrmr_plugin_list, cfg->rule_backend_name, &rf) < 0)
        return(-1);
    if (rf->setup(debuglvl, cfg, &rule_backend) < 0)
        return(-1);
    if (rf->conf(debuglvl, rule_backend) < 0)
        return(-1);
    if (rf->open(debuglvl, rule_backend, 0, VRMR_BT_RULES) < 0)
        return(-1);

    return(0);
}


/*  unload_backends

    Unloads the backends for:   services
                                zones
                                interfaces
                                rules

    Steps:
    1. free the backend memory
    2. set backend ptr to NULL
    3. unload plugin

    Returncodes:
        0: ok
        -1: error
*/
int
vrmr_backends_unload(const int debuglvl, struct vrmr_config *cfg)
{
    /*
        SERVICES
    */
    if (sf->close(debuglvl, serv_backend, VRMR_BT_SERVICES) < 0)
        return(-1);

    free(serv_backend);
    serv_backend = NULL;

    if (unload_plugin(debuglvl, &vrmr_plugin_list, cfg->serv_backend_name, &sf) < 0)
        return(-1);

    /*
        ZONES
    */
    if (zf->close(debuglvl, zone_backend, VRMR_BT_ZONES) < 0)
        return(-1);

    free(zone_backend);
    zone_backend = NULL;

    if (unload_plugin(debuglvl, &vrmr_plugin_list, cfg->zone_backend_name, &zf) < 0)
        return(-1);

    /*
        INTERFACES
    */
    if (af->close(debuglvl, ifac_backend, VRMR_BT_INTERFACES) < 0)
        return(-1);

    free(ifac_backend);
    ifac_backend = NULL;

    if (unload_plugin(debuglvl, &vrmr_plugin_list, cfg->ifac_backend_name, &af) < 0)
        return(-1);

    /*
        RULES
    */
    if (rf->close(debuglvl, rule_backend, VRMR_BT_RULES) < 0)
        return(-1);

    free(rule_backend);
    rule_backend = NULL;

    if (unload_plugin(debuglvl, &vrmr_plugin_list, cfg->rule_backend_name, &rf) < 0)
        return(-1);

    return(0);
}

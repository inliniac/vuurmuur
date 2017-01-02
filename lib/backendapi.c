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

#include "textdir/textdir.h"

/** \brief Plugin registration function
 *  To be called from plugin
 */
void
vrmr_plugin_register(struct vrmr_plugin_data *plugin_data)
{
    struct vrmr_plugin  *plugin = NULL;

    if (!plugin_data) {
        vrmr_error(-1, "Internal Error", "parameter problem (in: load_plugin).");
        return;
    }

    if (!(plugin = malloc(sizeof(struct vrmr_plugin)))) {
        vrmr_error(-1, "Error", "malloc failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return;
    }
    memset(plugin, 0x00, sizeof(*plugin));

    plugin->f = plugin_data;
    plugin->ref_cnt = 1;

    /* store the name of the plugin */
    if (strlcpy(plugin->name, plugin_data->name, sizeof(plugin->name)) >= sizeof(plugin->name))
    {
        vrmr_error(-1, "Internal Error", "pluginname "
                "overflow (in: %s:%d).", __FUNC__, __LINE__);
        free(plugin);
        return;
    }

    /* insert into the list */
    if (vrmr_list_append(/* no dbg */0, &vrmr_plugin_list, plugin) == NULL)
    {
        vrmr_error(-1, "Internal Error", "vrmr_list_append() "
                "failed (in: %s:%d).", __FUNC__, __LINE__);
        free(plugin);
        return;
    }
    return;
}

/*  load_plugin

    returns the functions for 'plugin' <plugin_name>.

    Returncodes:
        0: ok
        -1: error
*/
static int
load_plugin(const int debuglvl, struct vrmr_config *cfg, struct vrmr_list *plugin_list,
        char *plugin_name, struct vrmr_plugin_data **func_ptr)
{
    struct vrmr_plugin  *plugin = NULL;
    struct vrmr_list_node         *d_node = NULL;

    if(!plugin_list || !plugin_name || !func_ptr)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: load_plugin).");
        return(-1);
    }

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "** start **, plugin_nane: '%s', pluginlist size: '%d'.", plugin_name, plugin_list->len);

    /* safety check */
    if(plugin_name[0] == '\0')
    {
        vrmr_error(-1, "Internal Error", "plugin name not set "
                " (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    for(d_node = plugin_list->top; d_node; d_node = d_node->next)
    {
        plugin = d_node->data;

        if(strcmp(plugin->name, plugin_name) == 0) {
            *func_ptr = plugin->f;
            plugin->ref_cnt++;
            return(0);
        }
    }
    return(-1);
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
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* first check if we have the plugin loaded */
    for(d_node = plugin_list->top; d_node; d_node = d_node->next)
    {
        if(!(plugin = d_node->data))
        {
            vrmr_error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
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
        vrmr_warning("Warning", "it seems that the plugin '%s' is already unloaded, or was never loaded.", plugin_name);
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
            /* remove the plugindata from the list */
            if(vrmr_list_remove_node(debuglvl, plugin_list, d_node) < 0)
            {
                vrmr_error(-1, "Internal Error", "removing plugin form list (in: %s).", __FUNC__);
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
vrmr_backends_load(const int debuglvl, struct vrmr_config *cfg, struct vrmr_ctx *vctx)
{
    textdir_init();

    /* first the SERVICES */
    if (load_plugin(debuglvl, cfg, &vrmr_plugin_list, cfg->serv_backend_name, &vctx->sf) < 0)
        return(-1);
    if (vctx->sf->setup(debuglvl, cfg, &vctx->serv_backend) < 0)
        return(-1);
    if (vctx->sf->conf(debuglvl, vctx->serv_backend) < 0)
        return(-1);
    if (vctx->sf->open(debuglvl, vctx->serv_backend, 0, VRMR_BT_SERVICES) < 0)
        return(-1);

    /*
        second ZONES
    */
    if (load_plugin(debuglvl, cfg, &vrmr_plugin_list, cfg->zone_backend_name, &vctx->zf) < 0)
        return(-1);
    if (vctx->zf->setup(debuglvl, cfg, &vctx->zone_backend) < 0)
        return(-1);
    if (vctx->zf->conf(debuglvl, vctx->zone_backend) < 0)
        return(-1);
    if (vctx->zf->open(debuglvl, vctx->zone_backend, 0, VRMR_BT_ZONES) < 0)
        return(-1);

    /*
        third INTERFACES
    */
    if (load_plugin(debuglvl, cfg, &vrmr_plugin_list, cfg->ifac_backend_name, &vctx->af) < 0)
        return(-1);
    if (vctx->af->setup(debuglvl, cfg, &vctx->ifac_backend) < 0)
        return(-1);
    if (vctx->af->conf(debuglvl, vctx->ifac_backend) < 0)
        return(-1);
    if (vctx->af->open(debuglvl, vctx->ifac_backend, 0, VRMR_BT_INTERFACES) < 0)
        return(-1);

    /*
        last RULES
    */
    if (load_plugin(debuglvl, cfg, &vrmr_plugin_list, cfg->rule_backend_name, &vctx->rf) < 0)
        return(-1);
    if (vctx->rf->setup(debuglvl, cfg, &vctx->rule_backend) < 0)
        return(-1);
    if (vctx->rf->conf(debuglvl, vctx->rule_backend) < 0)
        return(-1);
    if (vctx->rf->open(debuglvl, vctx->rule_backend, 0, VRMR_BT_RULES) < 0)
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
vrmr_backends_unload(const int debuglvl, struct vrmr_config *cfg, struct vrmr_ctx *vctx)
{
    /*
        SERVICES
    */
    if (vctx->sf->close(debuglvl, vctx->serv_backend, VRMR_BT_SERVICES) < 0)
        return(-1);

    free(vctx->serv_backend);
    vctx->serv_backend = NULL;

    if (unload_plugin(debuglvl, &vrmr_plugin_list, cfg->serv_backend_name, &vctx->sf) < 0)
        return(-1);

    /*
        ZONES
    */
    if (vctx->zf->close(debuglvl, vctx->zone_backend, VRMR_BT_ZONES) < 0)
        return(-1);

    free(vctx->zone_backend);
    vctx->zone_backend = NULL;

    if (unload_plugin(debuglvl, &vrmr_plugin_list, cfg->zone_backend_name, &vctx->zf) < 0)
        return(-1);

    /*
        INTERFACES
    */
    if (vctx->af->close(debuglvl, vctx->ifac_backend, VRMR_BT_INTERFACES) < 0)
        return(-1);

    free(vctx->ifac_backend);
    vctx->ifac_backend = NULL;

    if (unload_plugin(debuglvl, &vrmr_plugin_list, cfg->ifac_backend_name, &vctx->af) < 0)
        return(-1);

    /*
        RULES
    */
    if (vctx->rf->close(debuglvl, vctx->rule_backend, VRMR_BT_RULES) < 0)
        return(-1);

    free(vctx->rule_backend);
    vctx->rule_backend = NULL;

    if (unload_plugin(debuglvl, &vrmr_plugin_list, cfg->rule_backend_name, &vctx->rf) < 0)
        return(-1);

    vrmr_list_cleanup(debuglvl, &vrmr_plugin_list);
    return(0);
}

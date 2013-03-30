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

/* Setup TC rules: IPTABLES rules are created elsewhere */

#include "main.h"

static u_int32_t
shaping_convert_rate(const int debuglvl, u_int32_t rate, char *unit) {
    u_int32_t kbit_rate = 0;

    (void)vrprint.debug(__FUNC__, "rate %u, unit %s", rate, unit);

    if (strcmp(unit,"kbit") == 0) {
        kbit_rate = rate;
    } else if (strcmp(unit,"mbit") == 0) {
        kbit_rate = rate * 1024;
    } else if (strcmp(unit,"kbps") == 0) {
        kbit_rate = rate * 8;
    } else if (strcmp(unit,"mbps") == 0) {
        kbit_rate = rate * 1024 * 8;
    }

    return(kbit_rate);
}

/* structure for storing an iptables rule in the queue.
 *
 * These are the 'same':
 * /sbin/tc class add dev eth2 parent 4:2 classid 4:12 htb rate 8192kbit ceil 9216kbit prio 1
 * /sbin/tc class add dev eth2 parent 4:3 classid 4:12 htb rate 8192kbit ceil 9216kbit prio 1
 */
typedef struct
{
    u_int16_t   handle;
    u_int16_t   class;
    char        cmd[VRMR_MAX_PIPE_COMMAND];
    char        device[16];

} ShapeRule;

/*  compare two shaping rules and return 1 if they match, 0 otherwise */
static int
shaping_rulecmp(const int debuglvl, ShapeRule *r1, ShapeRule *r2)
{
    if(r1 == NULL || r2 == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if( r1->handle == r2->handle &&
        r1->class == r2->class &&
        strcmp(r1->device, r2->device) == 0)
    {
        return(1);
    }

    return(0);
}


/*  insert a new shape rule into the list, but first check if it is not
    a duplicate. If it is a dup, just drop it. */
static int
shaping_ruleinsert(const int debuglvl, struct RuleCreateData_ *rule, ShapeRule *shape_rule)
{
    struct vrmr_list_node *d_node = NULL;
    ShapeRule   *listrule = NULL;

    if(shape_rule == NULL || rule == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    for(d_node = rule->shaperulelist.top; d_node; d_node = d_node->next)
    {
        listrule = d_node->data;

        if(shaping_rulecmp(debuglvl, listrule, shape_rule) == 1)
        {
            free(shape_rule);
            return(0);
        }
    }

    if(vrmr_list_append(debuglvl, &rule->shaperulelist, shape_rule) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() "
            "failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


/*  queue the rule into the list, so we can inspect the rules for
    duplicates. We do this to prevent creating lots of duplicates
    especially for setups with lots of virtual interfaces.
    
    This function must _only_ be called from the normal rule creation
    function: shaping_shape_create_rule
    */
static int
shaping_queue_rule(const int debuglvl, struct RuleCreateData_ *rule,
        /*@null@*/RuleSet *ruleset, u_int16_t handle, u_int16_t class, char *device, char *cmd)
{
    ShapeRule *shape_rule = NULL;

    /* safety */
    if(cmd == NULL || rule == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    shape_rule = malloc(sizeof(ShapeRule));
    if(shape_rule == NULL)
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s "
            "(in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    shape_rule->handle = handle;
    shape_rule->class = class;
    strlcpy(shape_rule->cmd, cmd, sizeof(shape_rule->cmd));
    strlcpy(shape_rule->device, device, sizeof(shape_rule->device));

    if(shaping_ruleinsert(debuglvl, rule, shape_rule) < 0)
        return(-1);

    return(0);
}
static int
shaping_process_rule (const int debuglvl, struct vrmr_config *cnf, /*@null@*/RuleSet *ruleset, char *cmd) {
    char *buf = NULL;

    if (ruleset != NULL) {
        buf = strdup (cmd);
        if (buf == NULL) {
            (void)vrprint.error(-1, "Error", "strdup failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if (vrmr_list_append(debuglvl, &ruleset->tc_rules, buf) == NULL) {
            (void)vrprint.error(-1, "Internal Error", "appending rule to list failed (in: %s:%d).",
                __FUNC__, __LINE__);
            free(buf);
            return(-1);
        }
    } else {
        if(vrmr_pipe_command(debuglvl, cnf, cmd, VRMR_PIPE_VERBOSE) < 0)
            return (-1);
    }

    return (0);
}

/*  at the end of processing one vuurmuur rule, we should have a queue
    filled with tc rules, none of which are duplicate. This function
    passes them to process_rule */
int
shaping_process_queued_rules(const int debuglvl, struct vrmr_config *cnf, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule)
{
    struct vrmr_list_node *d_node = NULL;
    ShapeRule   *r = NULL;

    if(rule == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    for(d_node = rule->shaperulelist.top; d_node; d_node = d_node->next)
    {
        r = d_node->data;

        if(shaping_process_rule(debuglvl, cnf, ruleset, r->cmd) < 0)
        {
            return(-1);
        }
    }

    return(0);
}

/*
 * Remove all qdiscs from all interfaces and thus also all classes
 *
 * Returns 0: ok -1: error
 */
int
shaping_clear_interfaces (const int debuglvl, struct vrmr_config *cnf, struct vrmr_interfaces *interfaces, /*@null@*/RuleSet *ruleset) {
    struct vrmr_list_node     *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;
    char            cmd[VRMR_MAX_PIPE_COMMAND] = "";

    /* if have no tc, no shaping is possible */
    if (strcmp(cnf->tc_location, "") == 0)
        return (0);

    for (d_node = interfaces->list.top; d_node != NULL; d_node = d_node->next) {
        iface_ptr = d_node->data;

        /* ignore 'shape' flag because the shaping on this
         * interface may just be disabled */
        if (strcmp(iface_ptr->device, "") != 0 &&
            iface_ptr->device_virtual == FALSE)
        {
            snprintf(cmd, sizeof(cmd), "%s qdisc del dev %s root 2> /dev/null > /dev/null",
                cnf->tc_location, iface_ptr->device);

            (void)vrprint.debug(__FUNC__, "cmd \"%s\"", cmd);

            if (shaping_process_rule(debuglvl, cnf, ruleset, cmd) < 0)
                return(-1);
        }
    }

    /* special case: in ruleset mode, if we have no shaping configs
     * the config removal command will make the shape script return
     * an error code. So we add the 'true' command so it won't fail.
     */
    if (ruleset) {
        if (shaping_process_rule(debuglvl, cnf, ruleset, "true") < 0)
            return(-1);
    }

    return (0);
}

static int
shaping_setup_interface_classes (const int debuglvl, struct vrmr_config *cnf, struct vrmr_interfaces *interfaces, struct vrmr_interface *iface_ptr, /*@null@*/RuleSet *ruleset) {
    struct vrmr_list_node     *d_node = NULL;
    struct vrmr_interface   *inner_iface_ptr = NULL;
    char            cmd[VRMR_MAX_PIPE_COMMAND] = "";
    u_int32_t       rate = 0;
    u_int32_t       iface_rate = 0;

    /* create this interface's class */

    iface_rate = shaping_convert_rate(debuglvl, iface_ptr->bw_out, iface_ptr->bw_out_unit);

    /* tc class add dev ppp0 parent 1: classid 1:1 htb rate 512kbit */
    snprintf(cmd, sizeof(cmd), "%s class add dev %s parent %u: classid %u:1 htb rate %ukbit",
        cnf->tc_location, iface_ptr->device, iface_ptr->shape_handle,
        iface_ptr->shape_handle, iface_rate);

    (void)vrprint.debug(__FUNC__, "cmd \"%s\"", cmd);

    if (shaping_process_rule(debuglvl, cnf, ruleset, cmd) < 0)
        return(-1);

    /* create classes for the other interfaces */
    for (d_node = interfaces->list.top; d_node != NULL; d_node = d_node->next) {
        inner_iface_ptr = d_node->data;

        if (iface_ptr != inner_iface_ptr && /* don't add a class for yourself */
            vrmr_is_shape_interface(debuglvl, inner_iface_ptr) == 1)
        {
            rate = shaping_convert_rate(debuglvl, inner_iface_ptr->bw_in, inner_iface_ptr->bw_in_unit);
            if (iface_rate < rate)
                rate = iface_rate;

            /* tc class add dev ppp0 parent 1: classid 1:1 htb rate 512kbit */
            snprintf(cmd, sizeof(cmd), "%s class add dev %s parent %u: classid %u:%u htb rate %ukbit",
                cnf->tc_location, iface_ptr->device, iface_ptr->shape_handle,
                iface_ptr->shape_handle, inner_iface_ptr->shape_handle, rate);

            (void)vrprint.debug(__FUNC__, "cmd \"%s\"", cmd);

            if (shaping_process_rule(debuglvl, cnf, ruleset, cmd) < 0)
                return(-1);
        }
    }

    return(0);
}

int
shaping_setup_roots (const int debuglvl, struct vrmr_config *cnf, struct vrmr_interfaces *interfaces, /*@null@*/RuleSet *ruleset) {
    struct vrmr_list_node     *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;
    char            cmd[VRMR_MAX_PIPE_COMMAND] = "";
    u_int16_t       handle = 2; /* start at 2 so the parents can be parent:current */

    /* if have no tc, no shaping is possible */
    if (strcmp(cnf->tc_location, "") == 0)
        return (0);

    /* assign handle id's */
    for (d_node = interfaces->list.top; d_node != NULL; d_node = d_node->next) {
        iface_ptr = d_node->data;
        (void)vrprint.debug(__FUNC__, "interface %s", iface_ptr->name);

        if (vrmr_is_shape_interface(debuglvl, iface_ptr) == 1)
        {
            iface_ptr->shape_handle = handle;
            handle++;
        }
    }
    interfaces->shape_handle = handle;

    /* setup the roots and interface classes */
    for (d_node = interfaces->list.top; d_node != NULL; d_node = d_node->next) {
        iface_ptr = d_node->data;
        (void)vrprint.debug(__FUNC__, "interface %s", iface_ptr->name);

        if (vrmr_is_shape_interface(debuglvl, iface_ptr) == 1)
        {
            snprintf(cmd, sizeof(cmd), "%s qdisc add dev %s root handle %u: htb default %u",
                cnf->tc_location, iface_ptr->device, iface_ptr->shape_handle, handle);

            (void)vrprint.debug(__FUNC__, "cmd \"%s\"", cmd);

            if (shaping_process_rule(debuglvl, cnf, ruleset, cmd) < 0)
                return(-1);

            handle++;

            if (shaping_setup_interface_classes(debuglvl, cnf, interfaces, iface_ptr, ruleset) < 0)
                return (-1);
        }
    }

    return (0);
}

/* add a rate to the iface. If the rate is 0 use the default rate */
int
shaping_add_rate_to_iface(const int debuglvl, struct vrmr_interface *iface_ptr, u_int32_t rate, char *unit) {
    u_int32_t   kbit_rate = 0;

    (void)vrprint.debug(__FUNC__, "rate %u, unit %s", rate, unit);

    kbit_rate = shaping_convert_rate(debuglvl, rate, unit);

    (void)vrprint.debug(__FUNC__, "kbit rate %u", kbit_rate);

    if (kbit_rate > 0) {
        iface_ptr->total_shape_rate += kbit_rate;
        iface_ptr->total_shape_rules++;
    } else {
        iface_ptr->total_default_shape_rules++;
    }

    return(0);
}

/* Find out per interface what the minimal default rate of shaping
 * rules should be. This is used for the default rule and for rules
 * that don't define a rate (in_min or out_min options).
 *
 * We do this by looking at what part of the available bw is already
 * commited explicitly in the rules and equally dividing what is left
 * to the remaining shape rules. In case the bw is over committed,
 * we use a default rate of the max bw devided by the total number
 * of shape rules.
 *

 * call after analyzing the rules */
int
shaping_determine_minimal_default_rates(const int debuglvl, struct vrmr_interfaces *interfaces, struct vrmr_rules *rules) {
    struct vrmr_list_node         *d_node = NULL,
                        *d_node_iface = NULL;
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_interface       *iface_ptr = NULL;
    u_int32_t           rate = 0;

    for (d_node_iface = interfaces->list.top; d_node_iface != NULL; d_node_iface = d_node_iface->next) {
        iface_ptr = d_node_iface->data;

        iface_ptr->total_shape_rate = 0;
        iface_ptr->total_shape_rules = 0;
        iface_ptr->total_default_shape_rules = 0;
    }

    for (d_node = rules->list.top; d_node != NULL; d_node = d_node->next) {
        rule_ptr = d_node->data;

        if (rule_ptr->active == TRUE) {
            /* look at src */
            if (rule_ptr->opt != NULL && (  rule_ptr->opt->bw_in_min > 0 ||
                                            rule_ptr->opt->bw_in_max > 0 ||
                                            rule_ptr->opt->prio > 0))
            {
                if (rule_ptr->rulecache.from != NULL) {
                    d_node_iface = rule_ptr->rulecache.from->InterfaceList.top;
                } else if(rule_ptr->rulecache.from_any == TRUE) {
                    d_node_iface = interfaces->list.top;
                }
                if (d_node_iface != NULL) {
                    for (; d_node_iface != NULL; d_node_iface = d_node_iface->next) {
                        iface_ptr = d_node_iface->data;

                        (void)vrprint.debug(__FUNC__, "FROM iface_ptr->name %s, rate %u %s", iface_ptr->name, rule_ptr->opt->bw_in_min, rule_ptr->opt->bw_in_min_unit);

                        if (shaping_add_rate_to_iface(debuglvl, iface_ptr, rule_ptr->opt->bw_in_min, rule_ptr->opt->bw_in_min_unit) < 0)
                            return(-1);
                    }
                }
                d_node_iface = NULL;
            }

            /* look at dst */
            if (rule_ptr->opt != NULL && (  rule_ptr->opt->bw_out_min > 0 ||
                                            rule_ptr->opt->bw_out_max > 0 ||
                                            rule_ptr->opt->prio > 0))
            {
                if (rule_ptr->rulecache.to != NULL) {
                    d_node_iface = rule_ptr->rulecache.to->InterfaceList.top;
                } else if(rule_ptr->rulecache.to_any == TRUE) {
                    d_node_iface = interfaces->list.top;
                }
                if (d_node_iface != NULL) {
                    for (; d_node_iface != NULL; d_node_iface = d_node_iface->next) {
                        iface_ptr = d_node_iface->data;

                        (void)vrprint.debug(__FUNC__, "TO iface_ptr->name %s, rate %u %s", iface_ptr->name, rule_ptr->opt->bw_out_min, rule_ptr->opt->bw_out_min_unit);

                        if (shaping_add_rate_to_iface(debuglvl, iface_ptr, rule_ptr->opt->bw_out_min, rule_ptr->opt->bw_out_min_unit) < 0)
                            return(-1);
                    }
                }
                d_node_iface = NULL;
            }
        }
    }

    /* calculate the default rate per interface */
    for (d_node_iface = interfaces->list.top; d_node_iface != NULL; d_node_iface = d_node_iface->next) {
        iface_ptr = d_node_iface->data;

        if (vrmr_is_shape_interface(debuglvl, iface_ptr) == 1)
        {
            rate = shaping_convert_rate(debuglvl, iface_ptr->bw_out, iface_ptr->bw_out_unit);

            (void)vrprint.debug(__FUNC__, "total rate %u, total rules %u, rules using default rate %u",
                iface_ptr->total_shape_rate, iface_ptr->total_shape_rules, iface_ptr->total_default_shape_rules);

            /* over commit */
            if (iface_ptr->total_shape_rate > rate) {
                (void)vrprint.warning(VR_WARN, "bandwidth over committed on interface %s: %ukbit > %ukbit.", iface_ptr->name, iface_ptr->total_shape_rate, rate);

                /* the default rate will be the max interface rate / number of total rules */
                iface_ptr->shape_default_rate = rate / iface_ptr->total_shape_rules;
            }
            /* no shaping rules at all: use a simple default */
            else if (iface_ptr->total_default_shape_rules == 0) {
                iface_ptr->shape_default_rate = rate / 10;
            } else {
                /* the default rate is max interface rate minus already explictly commited rate
                 * devided by the number of rules using the default rate */
                iface_ptr->shape_default_rate = (rate - iface_ptr->total_shape_rate) / iface_ptr->total_default_shape_rules;
            }

            (void)vrprint.debug(__FUNC__, "default rate on %s is %ukbit", iface_ptr->name, iface_ptr->shape_default_rate);
        }
    }

    return(0);
}

/* create the default rule per interface. This rule will be used when
 * no class is picked. */
int
shaping_create_default_rules(const int debuglvl, struct vrmr_config *cnf, struct vrmr_interfaces *interfaces, /*@null@*/RuleSet *ruleset) {
    struct vrmr_list_node     *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;
    char            cmd[VRMR_MAX_PIPE_COMMAND] = "";
    u_int16_t       handle = 0;
    u_int32_t       rate = 0;

    handle = interfaces->shape_handle;

    for (d_node = interfaces->list.top; d_node != NULL; d_node = d_node->next) {
        iface_ptr = d_node->data;

        if (vrmr_is_shape_interface(debuglvl, iface_ptr) == 1)
        {
            rate = shaping_convert_rate(debuglvl, iface_ptr->bw_out, iface_ptr->bw_out_unit);

            /* tc class add dev ppp0 parent 1:1 classid 1:100 htb rate 15kbit ceil 512kbit prio 3
             * tc qdisc add dev ppp0 parent 1:100 handle 100: sfq perturb 10 */
            snprintf(cmd, sizeof(cmd), "%s class add dev %s parent %u:1 classid %u:%u htb rate %ukbit ceil %ukbit prio 3", /* TODO prio should configurable */
                cnf->tc_location, iface_ptr->device, iface_ptr->shape_handle,
                iface_ptr->shape_handle, handle, iface_ptr->shape_default_rate,
                rate);

            (void)vrprint.debug(__FUNC__, "cmd \"%s\"", cmd);

            if (shaping_process_rule(debuglvl, cnf, ruleset, cmd) < 0)
                return(-1);
        
            snprintf(cmd, sizeof(cmd), "%s qdisc add dev %s parent %u:%u handle %u: sfq perturb 10",
                cnf->tc_location, iface_ptr->device, iface_ptr->shape_handle, handle, handle);

            (void)vrprint.debug(__FUNC__, "cmd \"%s\"", cmd);

            if (shaping_process_rule(debuglvl, cnf, ruleset, cmd) < 0)
                return(-1);

            handle++;
        }
    }

    interfaces->shape_handle = handle;

    return(0);
}

int
shaping_shape_create_rule(const int debuglvl, struct vrmr_config *cnf,
    struct vrmr_interfaces *interfaces, struct RuleCreateData_ *rule, /*@null@*/RuleSet *ruleset,
    struct vrmr_interface *shape_iface_ptr, struct vrmr_interface *class_iface_ptr,
    u_int16_t class, u_int32_t rate, char *rate_unit, u_int32_t ceil,
    char *ceil_unit, u_int8_t prio)
{
    char        cmd[VRMR_MAX_PIPE_COMMAND] = "";
    u_int16_t   class_handle = 1;

    if (strcmp(cnf->tc_location,"") == 0)
        return(0);

    if (vrmr_is_shape_interface(debuglvl, shape_iface_ptr) == 0)
        return(0);

    (void)vrprint.debug(__FUNC__, "shape on interface %s (handle %u)",
        shape_iface_ptr->name, shape_iface_ptr->shape_handle);

    if (vrmr_is_shape_interface(debuglvl, class_iface_ptr) == 1) {
        class_handle = class_iface_ptr->shape_handle;

        (void)vrprint.debug(__FUNC__, "class of interface %s (handle %u)",
            class_iface_ptr->name, class_iface_ptr->shape_handle);
    }

    /* convert rates to kbit */
    rate = shaping_convert_rate(debuglvl, rate, rate_unit);
    ceil = shaping_convert_rate(debuglvl, ceil, ceil_unit);
    (void)vrprint.debug(__FUNC__, "rate %u, ceil %u", rate, ceil);

    /* use defaults for unused settings */
    if (prio == 0) prio = 3;
    if (rate == 0) rate = shape_iface_ptr->shape_default_rate;
    if (ceil == 0) ceil = shaping_convert_rate(debuglvl, shape_iface_ptr->bw_out, shape_iface_ptr->bw_out_unit);

    /* in some cases class_iface_ptr and shape_iface_ptr are the same
     * in that case use :1 */
    if (class_handle == shape_iface_ptr->shape_handle)
        class_handle = 1;

    /* tc class add dev eth0 parent 3:3 classid 3:160 htb rate 5mbit ceil 10mbit prio 1
     * tc qdisc add dev eth0 parent 3:160 handle 127: sfq perturb 10
     */
    snprintf(cmd, sizeof(cmd), "%s class add dev %s parent %u:%u classid %u:%u htb rate %ukbit ceil %ukbit prio %u",
        cnf->tc_location, shape_iface_ptr->device, shape_iface_ptr->shape_handle,
        class_handle, shape_iface_ptr->shape_handle,
        class, rate, ceil, prio);

    (void)vrprint.debug(__FUNC__, "cmd %s", cmd);

    if (shaping_queue_rule(debuglvl, rule, ruleset, shape_iface_ptr->shape_handle,
            class, shape_iface_ptr->device, cmd) < 0)
        return(-1);

    snprintf(cmd, sizeof(cmd), "%s qdisc add dev %s parent %u:%u handle %u: sfq perturb 10",
        cnf->tc_location, shape_iface_ptr->device, shape_iface_ptr->shape_handle,
        class, class);

    (void)vrprint.debug(__FUNC__, "cmd %s", cmd);

    if (shaping_queue_rule(debuglvl, rule, ruleset, class, 0,
            shape_iface_ptr->device, cmd) < 0)
        return(-1);

    return(0);
}


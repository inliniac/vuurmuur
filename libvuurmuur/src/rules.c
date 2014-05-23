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

/*************************************************************************** 
 * Load, parse, analyze and save the rules.                                *
 ***************************************************************************/
#include "config.h"
#include "vuurmuur.h"
#include <ctype.h>

/* - determine_action -
 * In this function we translate the 'accept' or 'drop' from the 'rules.conf' file to the
 * values that iptables understands, like 'ACCEPT, DROP, REJECT'.
 *
 * The function is called with the action from the rulesfile 'query' and returns the iptables
 * action trough 'action'.
 *
 * Returncodes:
 *      0: ok, found
 *     -1: invalid query
 */
static int
determine_action(const int debuglvl, struct vrmr_config *cfg, char *query, char *action, size_t size, struct vrmr_rule_options *option)
{
    int action_type = 0;

    /* safety */
    if(query == NULL || action == NULL || option == NULL || cfg == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    action_type = vrmr_rules_actiontoi(query);
    if(action_type <= VRMR_AT_ERROR || action_type >= VRMR_AT_TOO_BIG)
    {
        vrmr_error(-1, "Error", "unknown action '%s' "
            "(in: %s:%d).", query, __FUNC__, __LINE__);
        return(-1);
    }

    if(action_type == VRMR_AT_ACCEPT)
    {
        (void)strlcpy(action, "NEWACCEPT", size);
    }
    else if(action_type == VRMR_AT_DROP)
    {
        (void)strlcpy(action, "DROP", size);
    }
    else if(action_type == VRMR_AT_REJECT)
    {
        (void)strlcpy(action, "REJECT", size);
        if(option->reject_option == 1)
        {
            if(debuglvl >= MEDIUM)
                vrmr_debug(__FUNC__, "reject option: "
                        "'%s'.", option->reject_type);

            if(strcmp(option->reject_type, "tcp-reset") == 0)
            {
                (void)strlcpy(action, "TCPRESET", size);
            }
            else
            {
                snprintf(action, size, "REJECT --reject-with "
                        "%s", option->reject_type);
            }
        }
    }
    else if(action_type == VRMR_AT_CHAIN)
    {
        (void)strlcpy(action, option->chain, size);
    }
    else if(action_type == VRMR_AT_REDIRECT)
    {
        (void)strlcpy(action, "REDIRECT", size);
        if(option->redirectport > 0)
        {
            if(debuglvl >= MEDIUM)
                vrmr_debug(__FUNC__, "redirect "
                        "option: '%d'.", option->redirectport);

            snprintf(action, size, "REDIRECT --to-ports "
                    "%d", option->redirectport);
        }
        else
        {
            vrmr_error(-1, "Error", "target REDIRECT "
                    "requires option 'redirectport'.");
            return(-1);
        }
    }
    else if(action_type == VRMR_AT_LOG)
    {
        if(strcmp(cfg->loglevel, "") == 0)
            (void)strlcpy(action, "LOG", size);
        else
            snprintf(action, size, "LOG --log-level %s",
                    cfg->loglevel);

        /* when action is LOG, the log option must not be set */
        option->rule_log = FALSE;

        if(debuglvl >= MEDIUM)
            vrmr_debug(__FUNC__, "set option->rule_log "
                    "to FALSE because action is LOG.");
    }
    else if(action_type == VRMR_AT_MASQ)
    {
        (void)strlcpy(action, "MASQUERADE", size);
    }
    else if(action_type == VRMR_AT_SNAT)
    {
        (void)strlcpy(action, "SNAT", size);
    }
    else if(action_type == VRMR_AT_PORTFW ||
        action_type == VRMR_AT_DNAT ||
        action_type == VRMR_AT_BOUNCE)
    {
        (void)strlcpy(action, "DNAT", size);
    }
    else if(action_type == VRMR_AT_QUEUE)
    {
        (void)strlcpy(action, "NEWQUEUE", size);
    }
    else if(action_type == VRMR_AT_NFQUEUE)
    {
        (void)strlcpy(action, "NEWNFQUEUE", size);
    }
    else if(action_type == VRMR_AT_NFLOG)
    {
        (void)strlcpy(action, "NEWNFLOG", size);
    }
    else
    {
        vrmr_error(-1, "Error", "unknown action '%s' "
            "(in: %s:%d).", query, __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}

/*  rules_analyse_rule

    Function for gathering the info for creation of the rule
    and for sanity checking the rule.

    Returncodes:
         0: ok
        -1: error
 */
int
vrmr_rules_analyze_rule( const int debuglvl,
                    struct vrmr_rule *rule_ptr,
                    struct vrmr_rule_cache *create,
                    struct vrmr_services *services,
                    struct vrmr_zones *zones,
                    struct vrmr_interfaces *interfaces,
                    struct vrmr_config *cnf)
{
    int     result = 0;
    char    network[VRMR_MAX_NET_ZONE] = "";


    /* safety */
    if( rule_ptr == NULL || create == NULL || services == NULL ||
        zones == NULL || interfaces == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* first the protect rule */
    if(rule_ptr->action == VRMR_AT_PROTECT)
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "action: %s, who: %s, danger: %s, source: %s",
                    vrmr_rules_itoaction(rule_ptr->action), rule_ptr->who,
                    rule_ptr->danger, rule_ptr->source);

        /* get who */
        if(strcmp(rule_ptr->who, "") != 0)
        {
            if(rule_ptr->type == VRMR_PROT_IPTABLES)
            {
                create->who_int = NULL;

                if(!(create->who = vrmr_search_zonedata(debuglvl, zones, rule_ptr->who)))
                {
                    vrmr_error(-1, "Error", "zone '%s' not found (in: %s).", rule_ptr->who, __FUNC__);
                    return(-1);
                }
            }
            else if(rule_ptr->type == VRMR_PROT_PROC_INT)
            {
                create->who = NULL;
                create->who_int = NULL;

                if(!(create->who_int = vrmr_search_interface(debuglvl, interfaces, rule_ptr->who)))
                {
                    vrmr_error(-1, "Error", "interface '%s' not found (in: %s).", rule_ptr->who, __FUNC__);
                    return(-1);
                }
            }
            else
            {
                create->who = NULL;
                vrmr_error(-1, "Error", "don't know what to do with '%s' for rule type '%d' (in: %s).", rule_ptr->who, rule_ptr->type, __FUNC__);
                return(-1);
            }
        }

        if(debuglvl >= MEDIUM)
            vrmr_debug(__FUNC__, "calling vrmr_get_danger_info() for danger...");

        result = vrmr_get_danger_info(debuglvl, rule_ptr->danger, rule_ptr->source, &create->danger);
        if(result == 0)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "vrmr_get_danger_info successfull.");
        }
        else
        {
            vrmr_error(-1, "Error", "getting danger '%s' failed (in: %s).",
                    rule_ptr->danger, __FUNC__);
            return(-1);
        }

        /* set the action */
        if(strlcpy(create->action, "protect", sizeof(create->action)) > sizeof(create->action))
        {
            vrmr_error(-1, "Error", "buffer overflow (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    /* network accept rule */
    else if(rule_ptr->type == VRMR_PROT_IPTABLES &&
        (rule_ptr->action == VRMR_AT_ACCEPT || rule_ptr->action == VRMR_AT_QUEUE))
    {
        create->danger.solution = VRMR_PROT_IPTABLES;

        /* get who */
        if(strcmp(rule_ptr->who, "") != 0)
        {
            if(rule_ptr->type == VRMR_PROT_IPTABLES)
            {
                create->who_int = NULL;

                if(!(create->who = vrmr_search_zonedata(debuglvl, zones, rule_ptr->who)))
                {
                    vrmr_error(-1, "Error", "zone '%s' not found (in: %s).", rule_ptr->who, __FUNC__);
                    return(-1);
                }
            }
        }

        if( strcasecmp(rule_ptr->service, "dhcp-client") == 0 ||
            strcasecmp(rule_ptr->service, "dhcp-server") == 0)
        {
            /* not much here */
            if(debuglvl >= MEDIUM)
                vrmr_debug(__FUNC__, "network rule service '%s'", rule_ptr->service);
        }
        else
        {
            vrmr_error(-1, "Error", "unknown service '%s' in network rule (in: %s:%d).",
                    rule_ptr->service, __FUNC__, __LINE__);
            return(-1);
        }
    }
    /* separator */
    else if(rule_ptr->action == VRMR_AT_SEPARATOR)
    {
        /* not much here */
        if(debuglvl >= MEDIUM)
            vrmr_debug(__FUNC__, "rule is a separator");
    }
    /* normal rule */
    else
    {
        /* this is the rule */
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "action: %s, service: %s, from: %s, to: %s",
                    vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service,
                    rule_ptr->from, rule_ptr->to);

        /*
            GATHERING INFO FOR CREATING THE RULE
        */
        create->active = rule_ptr->active;

        create->from = NULL;
        create->to = NULL;

        /*
            get 'from' if not firewall
        */
        if(strncasecmp(rule_ptr->from, "firewall", 8) == 0)
        {
            /* we get the data later */
            create->from_firewall = TRUE;

            if(strcasecmp(rule_ptr->from, "firewall(any)") == 0)
                create->from_firewall_any = TRUE;
        }
        else if(strcasecmp(rule_ptr->from, "any") == 0)
        {
            /* we get the data later */
            create->from_any = TRUE;
        }
        else
        {
            /* get the pointer to the zonedata in the ZonedataList */
            if(!(create->from = vrmr_search_zonedata(debuglvl, zones, rule_ptr->from)))
            {
                vrmr_error(-1, "Error", "'from' zone '%s' not found (in: %s).",
                        rule_ptr->from, __FUNC__);
                return(-1);
            }
        }

        /* normal network */
        if(strncasecmp(rule_ptr->to, "firewall", 8) == 0)
        {
            /* first check if we don't have two firewalls */
            if(create->from_firewall == TRUE)
            {
                vrmr_error(-1, "Error", "'from' and 'to' are both set to firewall (%s service %s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service,
                        rule_ptr->from, rule_ptr->to);
                return(-1);
            }

            /* if 'from' is 'any' we cannot get the interfaces for it */
            if(create->from_any == FALSE && create->from->type != VRMR_TYPE_ZONE)
            {
                /* assemble the network name */
                snprintf(network, sizeof(network), "%s.%s", create->from->network_name, create->from->zone_name);

                if(!(create->to = vrmr_search_zonedata(debuglvl, zones, network)))
                {
                    vrmr_error(-1, "Error", "'to' zone '%s' not found (in: %s).",
                            network, __FUNC__);
                    return(-1);
                }
            }

            create->to_firewall = TRUE;

            if(strcasecmp(rule_ptr->to, "firewall(any)") == 0)
                create->to_firewall_any = TRUE;
        }
        else if(strcasecmp(rule_ptr->to, "any") == 0)
        {
            /* we get the data later */
            create->to_any = TRUE;
        }
        else
        {
            /* get the pointer to the zonedata in the ZonedataList */
            if(!(create->to = vrmr_search_zonedata(debuglvl, zones, rule_ptr->to)))
            {
                vrmr_error(-1, "Error", "'to' zone '%s' not found (in: %s).", rule_ptr->to, __FUNC__);
                return(-1);
            }
        }

        /* now get the data for the from-firewall */
        if(create->from_firewall == TRUE)
        {
            /* first check if we don't have two firewalls */
            if(create->to_firewall == TRUE)
            {
                vrmr_error(-1, "Error", "'from' and 'to' are both set to firewall (%s service %s from %s to %s).", vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service, rule_ptr->from, rule_ptr->to);
                return(-1);
            }

            /* if to is any we cannot get the interfaces from it */
            if(create->to_any == FALSE && create->to->type != VRMR_TYPE_ZONE)
            {
                /* get the pointer to the zonedata in the ZonedataList */
                snprintf(network, sizeof(network), "%s.%s", create->to->network_name, create->to->zone_name);

                if(!(create->from = vrmr_search_zonedata(debuglvl, zones, network)))
                {
                    vrmr_error(-1, "Error", "'from' zone '%s' not found (in: %s).", network, __FUNC__);
                    return(-1);
                }
            }
        }

        /* get the pointer to the services in the ServicesList */
        if(strcasecmp(rule_ptr->service, "any") == 0 || strcasecmp(rule_ptr->service, "all") == 0)
        {
            create->service_any = TRUE;
        }
        else
        {
            if(!(create->service = vrmr_search_service(debuglvl, services, rule_ptr->service)))
            {
                vrmr_error(-1, "Error", "service '%s' not found (in: %s).", rule_ptr->service, __FUNC__);
                return(-1);
            }
        }

        /* get the rule options */
        if(rule_ptr->opt != NULL)
            create->option = *rule_ptr->opt;

        /* determine which action to take (ACCEPT, DROP, REJECT etc.). */
        if(determine_action(debuglvl, cnf, vrmr_rules_itoaction(rule_ptr->action), create->action, sizeof(create->action), &create->option) == 0)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "determine_action succes, create->action = %s",
                        create->action);
        }
        else
        {
            vrmr_error(-1, "Error", "could not determine action (in: %s).", __FUNC__);
            return(-1);
        }

        /* determine which ruletype to use. */
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "calling vrmr_rules_determine_ruletype()...");

        create->ruletype = vrmr_rules_determine_ruletype(debuglvl, rule_ptr);
        if(create->ruletype == VRMR_RT_ERROR)
        {
            vrmr_error(-1, "Error", "could not determine "
                    "ruletype (in: %s:d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* QUEUE-ing can only be in input, output and forward rules */
        if( rule_ptr->action == VRMR_AT_QUEUE &&
            (create->ruletype != VRMR_RT_INPUT && create->ruletype != VRMR_RT_OUTPUT && create->ruletype != VRMR_RT_FORWARD))
        {
            vrmr_error(-1, "Error", "the QUEUE target can only be used in the input, output and forward chains (in: %s).", __FUNC__);
            return(-1);
        }

        if( rule_ptr->action == VRMR_AT_CHAIN &&
            (rule_ptr->opt == NULL || rule_ptr->opt->chain[0] == '\0'))
        {
            vrmr_error(-1, "Error", "the CHAIN target needs option 'chain' to be set (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /* make sure we only porfw to a host */
        if(create->ruletype == VRMR_RT_PORTFW)
        {
            if(create->from_firewall == TRUE)
            {
                vrmr_error(-1, "Error", "portforwarding is not allowed from the firewall (%s service %s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service,
                        rule_ptr->from, rule_ptr->to);
                return(-1);
            }

            if(create->to == NULL || create->to->type != VRMR_TYPE_HOST)
            {
                vrmr_error(-1, "Error", "portforwarding is only allowed to a host (%s service %s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service,
                        rule_ptr->from, rule_ptr->to);
                return(-1);
            }
        }

        /* make sure we dont redirect from the firewall */
        if(create->ruletype == VRMR_RT_REDIRECT)
        {
            if(create->from_firewall == TRUE)
            {
                vrmr_error(-1, "Error", "redirecting is not allowed from the firewall (%s service %s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service,
                        rule_ptr->from, rule_ptr->to);
                return(-1);
            }
        }

        /* don't snat to 'Any' */
        if(create->ruletype == VRMR_RT_SNAT)
        {
            if(create->to_any == TRUE)
            {
                vrmr_error(-1, "Error", "snat is not possible to 'Any' (%s service %s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service,
                        rule_ptr->from, rule_ptr->to);
                return(-1);
            }
        }

        /* don't masq to 'Any' */
        if(create->ruletype == VRMR_RT_MASQ)
        {
            if(create->to_any == TRUE)
            {
                vrmr_error(-1, "Error", "masq is not possible to 'Any' (%s service %s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service,
                        rule_ptr->from, rule_ptr->to);
                return(-1);
            }
        }

        /* make sure we only dnat to a host */
        if(create->ruletype == VRMR_RT_DNAT)
        {
            if(create->from_firewall == TRUE)
            {
                vrmr_error(-1, "Error", "dnat is not "
                        "allowed from the firewall (%s service "
                        "%s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action),
                        rule_ptr->service, rule_ptr->from,
                        rule_ptr->to);
                return(-1);
            }

            if(create->to == NULL || create->to->type != VRMR_TYPE_HOST)
            {
                vrmr_error(-1, "Error", "dnat "
                        "is only allowed to a host (%s service "
                        "%s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action),
                        rule_ptr->service, rule_ptr->from,
                        rule_ptr->to);
                return(-1);
            }
        }

        /* make sure we only bounce to a host */
        if(create->ruletype == VRMR_RT_BOUNCE)
        {
            if(rule_ptr->opt == NULL || rule_ptr->opt->via_int[0] == '\0')
            {
                vrmr_error(-1, "Error", "bounce "
                        "requires the 'via' option to be set "
                        "(%s service %s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action),
                        rule_ptr->service, rule_ptr->from,
                        rule_ptr->to);
                return(-1);
            }

            create->via_int = vrmr_search_interface(debuglvl, interfaces,
                rule_ptr->opt->via_int);
            if(create->via_int == NULL)
            {
                vrmr_error(-1, "Error", "bounce "
                        "'via' interface '%s' not found "
                        "(%s service %s from %s to %s).",
                        rule_ptr->opt->via_int,
                        vrmr_rules_itoaction(rule_ptr->action),
                        rule_ptr->service, rule_ptr->from,
                        rule_ptr->to);
                return(-1);
            }

            if(create->via_int->ipv4.ipaddress[0] == '\0')
            {
                vrmr_error(-1, "Error", "bounce "
                        "'via' interface '%s' does not have "
                        "an ipaddress set "
                        "(%s service %s from %s to %s).",
                        rule_ptr->opt->via_int,
                        vrmr_rules_itoaction(rule_ptr->action),
                        rule_ptr->service, rule_ptr->from,
                        rule_ptr->to);
                return(-1);
            }

            if(create->from_firewall == TRUE)
            {
                vrmr_error(-1, "Error", "bounce is not "
                        "allowed from the firewall (%s service "
                        "%s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action),
                        rule_ptr->service, rule_ptr->from,
                        rule_ptr->to);
                return(-1);
            }

            if(create->to == NULL || create->to->type != VRMR_TYPE_HOST)
            {
                vrmr_error(-1, "Error", "bounce "
                        "is only allowed to a host (%s service "
                        "%s from %s to %s).",
                        vrmr_rules_itoaction(rule_ptr->action),
                        rule_ptr->service, rule_ptr->from,
                        rule_ptr->to);
                return(-1);
            }
        }
    } /* end else-protect */


    /* if were on bash mode, alloc mem for the description */
    if(cnf->bash_out == TRUE)
    {
        if(!(create->description = malloc(VRMR_MAX_BASH_DESC)))
        {
            vrmr_error(-1, "Error", "malloc failed: %s "
                    "(in: %s:%d).", strerror(errno),
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        create->description = NULL;
    }

    if(rule_ptr->action == VRMR_AT_PROTECT)
    {
        /* description */
        if(cnf->bash_out && create->description != NULL)
        {
            snprintf(create->description, VRMR_MAX_BASH_DESC,
                    "rule: action: %s, who: %s, danger: %s, source: %s",
                    vrmr_rules_itoaction(rule_ptr->action), rule_ptr->who,
                    rule_ptr->danger, rule_ptr->source);
        }
    }
    else if(rule_ptr->type == VRMR_PROT_IPTABLES &&
        (rule_ptr->action == VRMR_AT_ACCEPT || rule_ptr->action == VRMR_AT_QUEUE))
    {
        /* description */
        if(cnf->bash_out && create->description != NULL)
        {
            snprintf(create->description, VRMR_MAX_BASH_DESC,
                    "rule: action: %s, service: %s",
                    vrmr_rules_itoaction(rule_ptr->action),
                    rule_ptr->service);
        }
    }
    /* separator */
    else if(cnf->bash_out == TRUE && rule_ptr->action == VRMR_AT_SEPARATOR)
    {
        char *str = NULL;

        /* see if we have a comment as well */
        if(rule_ptr->opt != NULL && rule_ptr->opt->comment[0] != '\0')
        {
            str = rule_ptr->opt->comment;
        }

        snprintf(create->description, VRMR_MAX_BASH_DESC,
            "rule %u: separator%s %s",
            rule_ptr->number, str ? ":" : "", str ? str : "");
    }
    /* normal rule */
    else
    {
        /* description */
        if(cnf->bash_out == TRUE && create->description != NULL)
        {
            char    *action_ptr = NULL; /* pointer to action name in static array */
            char    *option_ptr = NULL; /* pointer to assembled and alloced option string */

            action_ptr = vrmr_rules_itoaction(rule_ptr->action);
            if(action_ptr != NULL)
                option_ptr = vrmr_rules_assemble_options_string(debuglvl, rule_ptr->opt, action_ptr);

            snprintf(create->description, VRMR_MAX_BASH_DESC,
                    "rule %u: %s service %s from %s to %s %s",
                    rule_ptr->number,
                    action_ptr, rule_ptr->service,
                    rule_ptr->from, rule_ptr->to,
                    option_ptr ? option_ptr : "");

            if(option_ptr != NULL)
                free(option_ptr);
        }
    }

    return(0);
}


/*  rules_init_list

    loads the rules from the backend

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_rules_init_list(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_config *cfg, struct vrmr_rules *rules, struct vrmr_regex *reg)
{
    FILE                *fp = NULL;
    int                 retval = 0;
    char                line[VRMR_MAX_RULE_LENGTH] = "";
    struct vrmr_rule    *rule_ptr = NULL;
    char                protect_warning_shown = FALSE;
    char                rule_name[32] = "";
    char                rules_found = FALSE;
    int                 type = 0;
    unsigned int        count = 1;


    /* safety */
    if(rules == NULL || reg == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* init */
    memset(rules, 0, sizeof(*rules));

    /*  setup the list: the cleanup function is set to NULL
        so it's the users responsibility to free memory. */
    if(vrmr_list_setup(debuglvl, &rules->list, NULL) < 0)
    {
        vrmr_error(-1, "Internal Error", "vrmr_list_setup() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= MEDIUM)
        vrmr_debug(__FUNC__, "rules_location: '%s'", cfg->rules_location);

    /* open the rulesfile */
    if((fp = fopen(cfg->rules_location, "r")))
    {
        rules->old_rulesfile_used = TRUE;

        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "opening rulesfile succeded.");

        /* run trough the file */
        while(fgets(line, (int)sizeof(line), fp) != NULL)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "strlen(line) = %d", strlen(line));

            /* check if the line is a comment */
        //TODO what? what? what?
            if((strlen(line) <= 1) || (line[0] == '#'))
            {
                if(debuglvl >= HIGH)
                    vrmr_debug(__FUNC__, "skipping line because its a comment or its empty.");
            }
            /* no comment */
            else
            {
                /* alloc memory for the rule */
                if(!(rule_ptr = vrmr_rule_malloc()))
                {
                    vrmr_error(-1, "Internal Error", "vrmr_rule_malloc() failed: %s (in: %s:%d).",
                            strerror(errno), __FUNC__, __LINE__);
                    return(-1);
                }

                /* parse the line. We don't really care if it fails, we just ignore it. */
                if(vrmr_rules_parse_line(debuglvl, line, rule_ptr, reg) < 0)
                {
                    vrmr_debug(__FUNC__, "parsing rule failed: %s", line);
                }
                else
                {
                    /* protect rules are no longer supported in the main rules list */
                    if(rule_ptr->action == VRMR_AT_PROTECT)
                    {
                        if(protect_warning_shown == FALSE)
                        {
                            vrmr_warning("Warning", "please note that the protect rules (e.g. anti-spoof) have been changed. Please recheck your networks and interfaces.");
                            protect_warning_shown = TRUE;
                        }

                        free(rule_ptr);
                        rule_ptr = NULL;
                    }
                    else
                    {
                        /* append to the rules list */
                        if(!(vrmr_list_append(debuglvl, &rules->list, rule_ptr)))
                        {
                            vrmr_error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                                    __FUNC__, __LINE__);
                            return(-1);
                        }

                        /* set the rule number */
                        rule_ptr->number = count;
                        count++;
                    }
                }
            }
        }

        vrmr_info("Info", "%d rules loaded.", count-1);

        if(fclose(fp) < 0)
        {
            vrmr_error(-1, "Error", "closing rules file failed: %s (in: %s).", strerror(errno), __FUNC__);
            retval = -1;
        }
    }
    /* try to use the backend instead of the flat file */
    else
    {
        rules->old_rulesfile_used = FALSE;

        /* see if the rulesfile already exists in the backend */
        while(vctx->rf->list(debuglvl, vctx->rule_backend, rule_name, &type, VRMR_BT_RULES) != NULL)
        {
            if(debuglvl >= MEDIUM)
                vrmr_debug(__FUNC__, "loading rules: '%s', type: %d",
                        rule_name, type);

            if(strcmp(rule_name, "rules") == 0)
                rules_found = TRUE;
        }

        if(rules_found == FALSE)
        {
            if(vctx->rf->add(debuglvl, vctx->rule_backend, "rules", VRMR_TYPE_RULE) < 0)
            {
                vrmr_error(-1, "Internal Error", "rf->add() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }
        }

        while((vctx->rf->ask(debuglvl, vctx->rule_backend, "rules", "RULE", line, sizeof(line), VRMR_TYPE_RULE, 1)) == 1)
        {
            /* check if the line is a comment */
        //TODO what? what? what?
            if((strlen(line) <= 1) || (line[0] == '#'))
            {
                if(debuglvl >= HIGH)
                    vrmr_debug(__FUNC__, "skipping line because its a comment or its empty.");
            }
            /* no comment */
            else
            {
                /* alloc memory for the rule */
                if(!(rule_ptr = vrmr_rule_malloc()))
                {
                    vrmr_error(-1, "Internal Error", "vrmr_rule_malloc() failed: %s (in: %s:%d).",
                            strerror(errno), __FUNC__, __LINE__);
                    return(-1);
                }

                /* parse the line. We don't really care if it fails, we just ignore it. */
                if(vrmr_rules_parse_line(debuglvl, line, rule_ptr, reg) < 0)
                {
                    vrmr_debug(__FUNC__, "parsing rule failed: %s", line);
                }
                else
                {
                    /* protect rules are no longer supported in the main rules list */
                    if(rule_ptr->action == VRMR_AT_PROTECT)
                    {
                        if(protect_warning_shown == FALSE)
                        {
                            vrmr_warning("Warning", "please note that the protect rules (e.g. anti-spoof) have been changed. Please recheck your networks and interfaces.");
                            protect_warning_shown = TRUE;
                        }

                        free(rule_ptr);
                        rule_ptr = NULL;
                    }
                    else
                    {
                        /* append to the rules list */
                        if(!(vrmr_list_append(debuglvl, &rules->list, rule_ptr)))
                        {
                            vrmr_error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                                    __FUNC__, __LINE__);
                            return(-1);
                        }

                        /* set the rule number */
                        rule_ptr->number = count;
                        count++;
                    }
                }
            }
        }

        vrmr_info("Info", "%d rules loaded.", count-1);
    }

    return(retval);
}


/*  vrmr_rules_parse_line

    Returncodes:
        0: ok
        -1: error
*/
int
vrmr_rules_parse_line(const int debuglvl, char *line, struct vrmr_rule *rule_ptr, struct vrmr_regex *reg)
{
    size_t  line_pos = 0,   // position in line
            var_pos = 0;    // position in varible
    char    options[VRMR_MAX_OPTIONS_LENGTH] = "";
    char    action_str[32] = "";


    /* safety first */
    if(line == NULL || rule_ptr == NULL || reg == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* decode the line */
    if(vrmr_rules_decode_rule(debuglvl, line, VRMR_MAX_RULE_LENGTH) < 0)
    {
        vrmr_error(-1, "Internal Error", "decode rule failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* this should not happen, but it can't hurt to check, right? */
    if(strlen(line) > VRMR_MAX_RULE_LENGTH)
    {
        vrmr_error(-1, "Internal Error", "rule is too long (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    /* strip the newline */
    if(line[strlen(line)-1] == '\n')
        line[strlen(line)-1] = '\0';

    memset(options, 0, sizeof(options));

    if(debuglvl >= LOW)
        vrmr_debug(__FUNC__, "rule: '%s'.", line);

    /* see if the rule is active */
    if(line[0] == ';')
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "rule is in-active.");

        rule_ptr->active = FALSE;

        line_pos = 1; 
    }
    else
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "rule is active.");

        rule_ptr->active = TRUE;
    }

    /* get the action */
    for(var_pos = 0; line_pos < sizeof(action_str)-1 && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
    {
        action_str[var_pos] = line[line_pos];
    }
    action_str[var_pos] = '\0';

    rule_ptr->action = vrmr_rules_actiontoi(action_str);
    if(rule_ptr->action <= VRMR_AT_ERROR || rule_ptr->action >= VRMR_AT_TOO_BIG)
        return(-1);

    /*
        now we analyze the action
    */
    if(rule_ptr->action == VRMR_AT_PROTECT)
    {
        /*
            get the who, or 'against'
        */
        for(line_pos++, var_pos = 0; var_pos < sizeof(rule_ptr->who) && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
        {
            rule_ptr->who[var_pos] = line[line_pos];
        }
        rule_ptr->who[var_pos] = '\0';

        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "protect: who: '%s'", rule_ptr->who);

        /*
            now check what kind of rule we have
        */
        if(strcasecmp(rule_ptr->who, "against") == 0)
        {
            /*
                clear who, because we don't use it
            */
            strcpy(rule_ptr->who, "");

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "rule is a VRMR_PROT_PROC_SYS");

            /*
                okay, now lets see what kind of danger we are talking about
            */
            for(line_pos++, var_pos = 0; var_pos < sizeof(rule_ptr->danger) && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
            {
                rule_ptr->danger[var_pos] = line[line_pos];
            }
            rule_ptr->danger[var_pos] = '\0';

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "protect: danger: '%s'", rule_ptr->danger);
        }
        else
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "now we know who (%s), let get the danger (but first check who).", rule_ptr->who);

            /*
                validate the who-zone
            */
            if(vrmr_validate_zonename(debuglvl, rule_ptr->who, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) != 0)
            {
                vrmr_error(-1, "Error", "invalid zonename: '%s' (in: %s).", rule_ptr->who, __FUNC__);
                return(-1);
            }

            /*
                get the keyword 'against'
            */
            for(line_pos++, var_pos = 0; var_pos < strlen("against") && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
            {
                rule_ptr->danger[var_pos] = line[line_pos];
            }
            rule_ptr->danger[var_pos] = '\0';

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "protect: keyword against: '%s'", rule_ptr->danger);

            /*
                if 'against' is missing, the rule is malformed, so we bail out screaming & kicking
            */
            if(strcasecmp(rule_ptr->danger, "against") != 0)
            {
                vrmr_error(-1, "Error", "bad rule syntax, keyword 'against' is missing: %s (in: %s).", line, __FUNC__);
                return(-1);
            }

            /*
                okay, now lets see what kind of danger we are talking about
            */
            for(line_pos++, var_pos = 0; var_pos < sizeof(rule_ptr->danger) && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
            {
                rule_ptr->danger[var_pos] = line[line_pos];
            }
            rule_ptr->danger[var_pos] = '\0';

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "protect: danger: '%s'", rule_ptr->danger);

            /*
                now determine if the danger is 'spoofing'
            */
            if(strcasecmp(rule_ptr->danger, "spoofing") == 0)
            {
                /*
                    get the 'from'
                */
                for(line_pos++, var_pos = 0; var_pos < strlen("from") && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
                {
                    rule_ptr->source[var_pos] = line[line_pos];
                }
                rule_ptr->source[var_pos] = '\0';

                if(debuglvl >= HIGH)
                    vrmr_debug(__FUNC__, "%s: protect: keyword from: '%s'", __FUNC__, rule_ptr->source);

                /*
                    if 'from' is missing, the rule is malformed, so we bail out screaming & kicking
                */
                if(strcasecmp(rule_ptr->source, "from") != 0)
                {
                    vrmr_error(-1, "Error", "bad rule syntax, keyword 'from' is missing: %s (in: %s).", line, __FUNC__);
                    return(-1);
                }

                /*
                    get the source
                */
                for(line_pos++, var_pos = 0; var_pos < sizeof(rule_ptr->source) && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
                {
                    rule_ptr->source[var_pos] = line[line_pos];
                }
                rule_ptr->source[var_pos] = '\0';

                if(debuglvl >= HIGH)
                    vrmr_debug(__FUNC__, "protect: source: '%s'", rule_ptr->source);
            }

            /*
                if don't use rule_ptr->source, clear it (just to be sure).
            */
            else
            {
                strcpy(rule_ptr->source, "");
            }
        }
    }
    else
    {
        if(rule_ptr->action != VRMR_AT_SEPARATOR)
        {
            /*
                first check for the keyword 'service'
            */
            for(line_pos++, var_pos = 0;
                    var_pos < sizeof(rule_ptr->service) &&
                    line[line_pos] != ' ' &&
                    line[line_pos] != '\0' &&
                    line[line_pos] != '\n' &&
                    line_pos < strlen(line);
                line_pos++, var_pos++)
            {
                rule_ptr->service[var_pos] = line[line_pos];
            }
            rule_ptr->service[var_pos] = '\0';

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "keyword service: '%s'.", rule_ptr->service);

            if(strcasecmp(rule_ptr->service, "service") != 0)
            {
                vrmr_error(-1, "Error", "bad rule syntax, keyword 'service' is missing: %s (in: %s).", line, __FUNC__);
                return(-1);
            }

            /*
                get the service itself
            */
            for(line_pos++, var_pos = 0;
                    var_pos < sizeof(rule_ptr->service) &&
                    line[line_pos] != ' ' &&
                    line[line_pos] != '\0' &&
                    line[line_pos] != '\n' &&
                    line_pos < strlen(line);
                line_pos++, var_pos++)
            {
                rule_ptr->service[var_pos] = line[line_pos];
            }
            rule_ptr->service[var_pos] = '\0';

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "service: '%s'.", rule_ptr->service);

            if(strcmp(rule_ptr->service, "from") == 0)
            {
                vrmr_error(-1, "Error", "bad rule syntax, keyword 'service' found, but has no value: %s (in: %s).", line, __FUNC__);
                return(-1);
            }

            /*
                validate the service name
            */
            if(vrmr_validate_servicename(debuglvl, rule_ptr->service, reg->servicename, VRMR_QUIET) != 0)
            {
                vrmr_error(-1, "Error", "invalid servicename: '%s' (in: %s:%d).", rule_ptr->service, __FUNC__, __LINE__);
                return(-1);
            }

            /*
                first check for the keyword 'from'
            */
            for(line_pos++, var_pos = 0;
                    var_pos < sizeof(rule_ptr->from) &&
                    line[line_pos] != ' ' &&
                    line[line_pos] != '\0' &&
                    line[line_pos] != '\n' &&
                    line_pos < strlen(line);
                line_pos++, var_pos++)
            {
                rule_ptr->from[var_pos] = line[line_pos];
            }
            rule_ptr->from[var_pos] = '\0';

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "keyword from: '%s'.", rule_ptr->from);

            if(strcasecmp(rule_ptr->from, "from") != 0)
            {
                vrmr_error(-1, "Error", "bad rule syntax, keyword 'from' is missing: %s (in: %s).", line, __FUNC__);
                return(-1);
            }

            /*
                get the from itself
            */
            for(line_pos++, var_pos = 0;
                    var_pos < sizeof(rule_ptr->from) &&
                    line[line_pos] != ' ' &&
                    line[line_pos] != '\0' &&
                    line[line_pos] != '\n' &&
                    line_pos < strlen(line);
                line_pos++, var_pos++)
            {
                rule_ptr->from[var_pos] = line[line_pos];
            }
            rule_ptr->from[var_pos] = '\0';

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "from: '%s'.", rule_ptr->from);

            /*
                see if the from is actually the to keyword
            */
            if(strcmp(rule_ptr->from, "to") == 0)
            {
                vrmr_error(-1, "Error", "bad rule syntax, keyword 'from' found, but has no value: %s (in: %s).", line, __FUNC__);
                return(-1);
            }

            if(strncasecmp(rule_ptr->from, "firewall", 8) != 0)
            {
                /*
                    now validate the from-zone
                */
                if(vrmr_validate_zonename(debuglvl, rule_ptr->from, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) != 0)
                {
                    vrmr_error(-1, "Error", "invalid from-zonename: '%s' (in: %s).", rule_ptr->from, __FUNC__);
                    return(-1);
                }
            }

            /*
                first check for the keyword 'to'
            */
            for(line_pos++, var_pos = 0;
                    var_pos < sizeof(rule_ptr->to) &&
                    line[line_pos] != ' ' &&
                    line[line_pos] != '\0' &&
                    line[line_pos] != '\n' &&
                    line_pos < strlen(line);
                line_pos++, var_pos++)
            {
                rule_ptr->to[var_pos] = line[line_pos];
            }
            rule_ptr->to[var_pos] = '\0';

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "keyword to: '%s'.", rule_ptr->to);

            if(strcasecmp(rule_ptr->to, "to") != 0)
            {
                vrmr_error(-1, "Error", "bad rule syntax, keyword 'to' is missing: %s (in: %s).", line, __FUNC__);
                return(-1);
            }

            /*
                get to
            */
            for(line_pos++, var_pos = 0;
                    var_pos < sizeof(rule_ptr->to) &&
                    line[line_pos] != ' ' &&
                    line[line_pos] != '\0' &&
                    line[line_pos] != '\n' &&
                    line_pos < strlen(line);
                line_pos++, var_pos++)
            {
                rule_ptr->to[var_pos] = line[line_pos];
            }
            rule_ptr->to[var_pos] = '\0';

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "to: '%s'.", rule_ptr->to);

            /*
                see that to is not the keyword options
            */
            if(strcmp(rule_ptr->to, "options") == 0)
            {
                vrmr_error(-1, "Error", "bad rule syntax, keyword 'to' found, but has no value: %s (in: %s).", line, __FUNC__);
                return(-1);
            }

            if(strncasecmp(rule_ptr->to, "firewall", 8) != 0)
            {
                /*
                    now validate the to-zone
                */
                if(vrmr_validate_zonename(debuglvl, rule_ptr->to, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) != 0)
                {
                    vrmr_error(-1, "Error", "invalid zonename: '%s' (in: %s).", rule_ptr->to, __FUNC__);
                    return(-1);
                }
            }
        }

        /*
            first check for the keyword 'options'
        */
        for(line_pos++, var_pos = 0;
                var_pos < sizeof(options) &&
                line[line_pos] != ' ' &&
                line[line_pos] != '\0' &&
                line[line_pos] != '\n' &&
                line_pos < strlen(line);
            line_pos++, var_pos++)
        {
            options[var_pos] = line[line_pos];
        }
        options[var_pos] = '\0';

        if(debuglvl >= MEDIUM)
            vrmr_debug(__FUNC__, "keyword options: '%s'.", options);

        /*
            if this keyword exists we have options
        */
        if(strcasecmp(options, "options") == 0)
        {
            /*
                get options: NOTE: whitespaces are allowed!
            */
            for(line_pos++, var_pos = 0;
                    var_pos < sizeof(options) &&
                    line[line_pos] != '\0' &&
                    line[line_pos] != '\n' &&
                    line_pos < VRMR_MAX_RULE_LENGTH &&
                    line_pos < strlen(line);
                line_pos++, var_pos++)
            {
                options[var_pos] = line[line_pos];
            }
            options[var_pos] = '\0';

            if(debuglvl >= LOW)
                vrmr_debug(__FUNC__, "options: '%s'.", options);

            /* alloc options struct */
            if(!(rule_ptr->opt = vrmr_rule_option_malloc(debuglvl)))
            {
                vrmr_error(-1, "Error", "malloc failed: %s (in: %s:%d).",
                        strerror(errno), __FUNC__, __LINE__);
                return(-1);
            }

            /*
                now split them up
            */
            if(vrmr_rules_read_options(debuglvl, options, rule_ptr->opt) < 0)
            {
                vrmr_error(-1, "Error", "parsing rule options failed for: '%s'.", line);

                free(rule_ptr->opt);
                rule_ptr->opt = NULL;

                return(-1);
            }
        }
        /*
            no options
        */
        else
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "rule has no options.");

            strcpy(options, "");

            rule_ptr->opt = NULL;
        }
    }

    return(0);
}


/*
    returns a pointer to the assembled line
*/
char *
vrmr_rules_assemble_rule(const int debuglvl, struct vrmr_rule *rule_ptr)
{
    char    *line = NULL,
            buf[512] = "",
            *option_ptr = NULL;
    size_t  bufsize = 0;

    /* safety */
    if(!rule_ptr)
    {
        vrmr_error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    /* assemble the line */
    if( rule_ptr->action == VRMR_AT_SEPARATOR)
    {
        snprintf(buf, sizeof(buf), "separator");
    }
    else
    {
        if(rule_ptr->active == TRUE)
        {
            snprintf(buf, sizeof(buf), "%s service %s from %s to %s",
                    vrmr_rules_itoaction(rule_ptr->action),
                    rule_ptr->service, rule_ptr->from,
                    rule_ptr->to);
        }
        else
        {
            snprintf(buf, sizeof(buf), ";%s service %s from %s to %s",
                    vrmr_rules_itoaction(rule_ptr->action),
                    rule_ptr->service, rule_ptr->from,
                    rule_ptr->to);
        }
    }

    option_ptr = vrmr_rules_assemble_options_string(debuglvl, rule_ptr->opt, vrmr_rules_itoaction(rule_ptr->action));
    if(option_ptr != NULL)
    {
        if(strlcat(buf, " ", sizeof(buf)) >= sizeof(buf))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            free(option_ptr);
            return(NULL);
        }
        if(strlcat(buf, option_ptr, sizeof(buf)) >= sizeof(buf))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            free(option_ptr);
            return(NULL);
        }
        free(option_ptr);
    }

    if(strlcat(buf, "\n", sizeof(buf)) >=  sizeof(buf))
    {
        vrmr_error(-1, "Internal Error", "string "
            "overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    /* assembling done */
    bufsize = strlen(buf) + 1; /* size of the line + nul */

    if(!(line = malloc(bufsize)))
    {
        vrmr_error(-1, "Error", "malloc failed: %s "
            "(in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(NULL);
    }

    if(strlcpy(line, buf, bufsize) >= bufsize)
    {
        vrmr_error(-1, "Internal Error", "string "
            "overflow (in: %s:%d).", __FUNC__, __LINE__);
        free(line);
        return(NULL);
    }

    return(line);
}


/*
    TODO: mask! it should we only read/write for owner root, and nothing to the others
*/
static int
rules_write_file(const int debuglvl, const struct vrmr_config *cnf, struct vrmr_rules *rules, const char *rulesfile_location)
{
    FILE                *fp = NULL;
    int                 retval = 0;
    struct vrmr_list_node         *d_node = NULL;
    char                *line = NULL;
    struct vrmr_rule    *rule_ptr = NULL;

    /* safety */
    if(rulesfile_location == NULL || rules == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* open the rulesfile */
    if(!(fp = vrmr_rules_file_open(debuglvl, cnf, rulesfile_location, "w+", 0)))
    {
        vrmr_error(-1, "Error", "opening rulesfile '%s' failed: %s (in: %s).",
                rulesfile_location, strerror(errno), __FUNC__);
        return(-1);
    }

    if(debuglvl >= LOW)
        vrmr_debug(__FUNC__, "number of rules %d.", rules->list.len);

    /* starting banner */
    fprintf(fp, "# Vuurmuur configfile, do not place comments in it, for they will be overwritten\n");

    /* loop trough the list */
    for(d_node = rules->list.top; d_node ; d_node = d_node->next)
    {
        if(!(rule_ptr = d_node->data))
        {
            vrmr_error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__);

            (void)vrmr_rules_file_close(fp, rulesfile_location);
            return(-1);
        }

        if(!(line = vrmr_rules_assemble_rule(debuglvl, rule_ptr)))
        {
            vrmr_error(-1, "Internal Error", "assembling rule failed (in: %s:%d).", __FUNC__);

            (void)vrmr_rules_file_close(fp, rulesfile_location);
            return(-1);
        }

        /* now print the rule to the file */
        fprintf(fp, "%s", line);

        free(line);
        line = NULL;
    }

    /* print the end-of-file so we know all went fine */
    fprintf(fp, "# end of file\n");
    fflush(fp);

    /* close the rulesfile */
    retval = vrmr_rules_file_close(fp, rulesfile_location);
    return(retval);
}


int
vrmr_rules_save_list(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_rules *rules, struct vrmr_config *cnf)
{
    int                 result = 0;
    char                *line = NULL,
                        eline[1024] = "";
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_rule    *rule_ptr = NULL;
    char                overwrite = FALSE;


    /* safety */
    if(cnf == NULL || rules == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(rules->old_rulesfile_used == TRUE)
    {
        result = rules_write_file(debuglvl, cnf, rules, cnf->rules_location);
        if(result < 0)
            return(-1);
    }
    else
    {
        /* empty list, so clear all */
        if(rules->list.len == 0)
        {
            if(vctx->rf->tell(debuglvl, vctx->rule_backend, "rules", "RULE", "", 1, VRMR_TYPE_RULE) < 0)
            {
                vrmr_error(-1, "Internal Error", "rf->tell() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }
        }
        else
        {
            overwrite = TRUE;

            /* loop trough the list */
            for(d_node = rules->list.top; d_node ; d_node = d_node->next)
            {
                if(!(rule_ptr = d_node->data))
                {
                    vrmr_error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }

                if(!(line = vrmr_rules_assemble_rule(debuglvl, rule_ptr)))
                {
                    vrmr_error(-1, "Internal Error", "vrmr_rules_assemble_rule() failed (in: %s:%d).",
                            __FUNC__, __LINE__);

                    return(-1);
                }

                if(line[strlen(line)-1] == '\n')
                    line[strlen(line)-1] = '\0';

                if(strlcpy(eline, line, sizeof(eline)) >= sizeof(eline))
                {
                    vrmr_error(-1, "Internal Error", "copy rule failed: buffer to small (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }

                free(line);
                line = NULL;


                /* encode */
                if(vrmr_rules_encode_rule(debuglvl, eline, sizeof(eline)) < 0)
                {
                    vrmr_error(-1, "Internal Error", "encode rule failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }

                /* write to the backend */
                if (vctx->rf->tell(debuglvl, vctx->rule_backend, "rules", "RULE", eline, overwrite, VRMR_TYPE_RULE) < 0)
                {
                    vrmr_error(-1, "Internal Error", "rf->tell() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }

                overwrite = FALSE;
            }
        }
    }

    return(0);
}


/*  cleanup_ruleslist

    O(n) function: with n is the number of rules

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_rules_cleanup_list(const int debuglvl, struct vrmr_rules *rules)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_rule    *rule_ptr = NULL;


    /* safety */
    if(!rules)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /*
        loop trough the list to remove the options
    */
    for(d_node = rules->list.top; d_node; d_node = d_node->next)
    {
        if(!(rule_ptr = d_node->data))
        {
            vrmr_error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        /*  free the options. If there are none the
            'free_options' functions will take care
            of that.
        */
        vrmr_rules_free_options(debuglvl, rule_ptr->opt);
        rule_ptr->opt = NULL;

        free(rule_ptr);
        rule_ptr = NULL;
    }

    /*
        cleanup the list
    */
    if(vrmr_list_cleanup(debuglvl, &rules->list) < 0)
        return(-1);

    return(0);
}


/*  vrmr_rules_insert_list

    inserts a rule into the ruleslist at position 'place'.

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_rules_insert_list(const int debuglvl, struct vrmr_rules *rules, unsigned int place, struct vrmr_rule *rule_ptr)
{
    struct vrmr_rule    *listrule_ptr = NULL;
    int                 retval = 0;
    struct vrmr_list_node         *d_node = NULL;


    /* safety */
    if(!rules || !rule_ptr)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }


    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "insert at: %d. (list len is %d), number: %d, action: %s, service: %s, from: %s, to: %s, danger: %s, who: %s, source: %s.",
                place, 
                rules->list.len,
                rule_ptr->number,
                vrmr_rules_itoaction(rule_ptr->action),
                rule_ptr->service,
                rule_ptr->from,
                rule_ptr->to,
                rule_ptr->danger,
                rule_ptr->who,
                rule_ptr->source);


    /* if we insert into empty list, we always insert at the top */
    if(rules->list.len == 0)
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "inserting into an empty list. Setting place to 1 (place was: %d).", place);

        place = 1;
    }

    /* handle inserting at the bottom of the list */
    if(place > rules->list.len)
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "place > rules_list->len (%d, %d). Setting place to %d.", place, rules->list.len, rules->list.len + 1);

        place = rules->list.len + 1;
    }


    /* handle insertion at the top of the list */
    if(place == 1)
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "place to insert: top");

        if(!(vrmr_list_prepend(debuglvl, &rules->list, rule_ptr)))
        {
            vrmr_error(-1, "Internal Error", "inserting the data to the top of list failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "vrmr_list_prepend succes, now update numbers (place: %d)", place);

        vrmr_rules_update_numbers(debuglvl, rules, place, 1);

        /* set number to 1 */
        rule_ptr->number = 1;

        /* we're done */
        return(0);
    }


    /*  now loop trough the list

        count: counts the number of rules we already processed
    */
    for(d_node = rules->list.top; d_node ; d_node = d_node->next)
    {
        if(!(listrule_ptr = d_node->data))
        {
            vrmr_error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "entry: %s %s %s %s %s", vrmr_rules_itoaction(listrule_ptr->action), listrule_ptr->service, listrule_ptr->danger, listrule_ptr->who, listrule_ptr->source);

        if(listrule_ptr->number == place - 1)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "place to insert: place: %d, %s %s %s %s %s", place, vrmr_rules_itoaction(listrule_ptr->action), listrule_ptr->service, listrule_ptr->danger, listrule_ptr->who, listrule_ptr->source);

            if(!(vrmr_list_insert_after(debuglvl, &rules->list, d_node, rule_ptr)))
            {
                vrmr_error(-1, "Internal Error", "inserting the data into the list failed.");
                return(-1);
            }

            /* update numbers after count */
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "vrmr_list_insert_after succes, now update numbers (place: %d)", place);

            vrmr_rules_update_numbers(debuglvl, rules, place - 1, 1);

            /* set the number */
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "vrmr_list_insert_after succes, now set rule_ptr->number to place: %d.", place);

            rule_ptr->number = place;

            /* we're done now */
            return(0);
        }
        /* we're not just there yet */
        else
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "not the right place: %d, %s %s %s %s %s", place, vrmr_rules_itoaction(listrule_ptr->action), listrule_ptr->service, listrule_ptr->danger, listrule_ptr->who, listrule_ptr->source);
        }
    }

    return(retval);
}


char *
vrmr_rules_assemble_options_string(const int debuglvl, struct vrmr_rule_options *opt,
                                const char *action)
{
    char    *option_ptr = NULL,
            options[VRMR_MAX_OPTIONS_LENGTH] = "",
            *ports_ptr = NULL;
    char    redirect_port[6] = "",
            limit_string[11] = "", /* 6 for the number, 1 for / 4 for hour = 11 */
            nfmark_string[9] = "";
    /* out_int="rtl8193", : out_int (7) = (1) " (1) " (1) , (1) \0 (1) = 12 */
    char    interfacestr[VRMR_MAX_INTERFACE+12] = "";
    char    chainstr[48] = "";
    int     action_type = 0;
    /* nfqueuenum="50000", : nfqueue (10) = (1) " (1) 65535 (5) " (1) , (1) \0 (1) = 20 */
    char    nfqueue_string[20] = "";
    char    nflog_string[20] = "";
    /* in_max="1000000000kbit" = 23 */
    char    bw_string[24] = "";

    /* safety - this is not an error! */
    if(opt == NULL || action == NULL)
        return(NULL);

    if(debuglvl >= LOW)
        vrmr_debug(__FUNC__, "action: '%s'.", action);

    action_type = vrmr_rules_actiontoi(action);
    if(action_type <= VRMR_AT_ERROR || action_type >= VRMR_AT_TOO_BIG)
    {
        vrmr_error(-1, "Error", "unknown action '%s' "
                "(in: %s:%d).", action, __FUNC__, __LINE__);
        return(NULL);
    }

    /* init */
    if(strlcpy(options, "options ", sizeof(options)) >= sizeof(options))
    {
        vrmr_error(-1, "Internal Error", "string "
            "overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    /* this one comes first so it's clearly visible in vuurmuur_conf */
    if(opt->via_int[0] != '\0' && action_type == VRMR_AT_BOUNCE)
    {
        snprintf(interfacestr, sizeof(interfacestr),
                "via_int=\"%s\",", opt->via_int);

        if(strlcat(options, interfacestr, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    if(opt->in_int[0] != '\0')
    {
        snprintf(interfacestr, sizeof(interfacestr),
                "in_int=\"%s\",", opt->in_int);

        if(strlcat(options, interfacestr, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }
    /* this one comes first so it's clearly visible in vuurmuur_conf */
    if(opt->out_int[0] != '\0')
    {
        snprintf(interfacestr, sizeof(interfacestr),
                "out_int=\"%s\",", opt->out_int);

        if(strlcat(options, interfacestr, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    if(action_type == VRMR_AT_NFQUEUE)
    {
        snprintf(nfqueue_string, sizeof(nfqueue_string),
                "nfqueuenum=\"%u\",", opt->nfqueue_num);

        if(strlcat(options, nfqueue_string, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    if(action_type == VRMR_AT_NFLOG)
    {
        snprintf(nflog_string, sizeof(nflog_string),
                "nflognum=\"%u\",", opt->nflog_num);

        if(strlcat(options, nflog_string, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    if(opt->chain[0] != '\0' && action_type == VRMR_AT_CHAIN)
    {
        snprintf(chainstr, sizeof(chainstr),
                "chain=\"%s\",", opt->chain);

        if(strlcat(options, chainstr, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    /* the log options are also valid for the action LOG */
    if((opt->rule_log == TRUE || action_type == VRMR_AT_LOG) && action_type != VRMR_AT_SEPARATOR)
    {
        /* log option is only valid when action is not LOG */
        if( opt->rule_log == TRUE &&
            action_type != VRMR_AT_LOG)
        {
            if(strlcat(options, "log,", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
        }

        /* loglimit */
        if(opt->loglimit > 0)
        {
            snprintf(limit_string, sizeof(limit_string), "%u", opt->loglimit);

            if(strlcat(options, "loglimit=\"", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, limit_string, sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
        }

        /* log prefix */
        if(opt->rule_logprefix == 1 && strcmp(opt->logprefix, "") != 0)
        {
            if(strlcat(options, "logprefix=\"", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, opt->logprefix, sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
        }
    }

    /* queue, for portfw and redirect */
    if(opt->queue == 1 && (action_type == VRMR_AT_PORTFW || action_type == VRMR_AT_REDIRECT))
    {
        if(strlcat(options, "queue,", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    /* listenport and remoteport */
    if(action_type == VRMR_AT_PORTFW || action_type == VRMR_AT_DNAT)
    {
        if(opt->listenport == 1)
        {
            ports_ptr = vrmr_list_to_portopts(debuglvl, &opt->ListenportList, "listenport");
            if(ports_ptr != NULL)
            {
                if(strlcat(options, ports_ptr, sizeof(options)) >= sizeof(options))
                {
                    vrmr_error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    free(ports_ptr);
                    return(NULL);
                }
                free(ports_ptr);

                if(strlcat(options, ",", sizeof(options)) >= sizeof(options))
                {
                    vrmr_error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(NULL);
                }
            }
        }
        if(opt->remoteport == 1)
        {
            ports_ptr = vrmr_list_to_portopts(debuglvl, &opt->RemoteportList, "remoteport");
            if(ports_ptr != NULL)
            {
                if(strlcat(options, ports_ptr, sizeof(options)) >= sizeof(options))
                {
                    vrmr_error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    free(ports_ptr);
                    return(NULL);
                }
                free(ports_ptr);

                if(strlcat(options, ",", sizeof(options)) >= sizeof(options))
                {
                    vrmr_error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(NULL);
                }
            }
        }
    }

    if(opt->reject_option == 1)
    {
        if(action_type == VRMR_AT_REJECT)
        {
            if(strlcat(options, "rejecttype=\"", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, opt->reject_type, sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
        }
    }

    if(opt->redirectport > 0 && opt->redirectport <= 65535)
    {
        if(action_type == VRMR_AT_REDIRECT)
        {
            snprintf(redirect_port, sizeof(redirect_port), "%d", opt->redirectport);

            if(strlcat(options, "redirectport=\"", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, redirect_port, sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
        }
    }

    if(opt->nfmark > 0)
    {
        snprintf(nfmark_string, sizeof(nfmark_string), "%lu", opt->nfmark);

        if(strlcat(options, "nfmark=\"", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, nfmark_string, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    /* limit */
    if(opt->limit > 0)
    {
        snprintf(limit_string, sizeof(limit_string), "%u/%s", opt->limit, opt->limit_unit[0] ? opt->limit_unit : "sec");

        if(strlcat(options, "limit=\"", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, limit_string, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }

        if(opt->burst > 0)
        {
            snprintf(limit_string, sizeof(limit_string), "%u", opt->burst);

            if(strlcat(options, "burst=\"", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, limit_string, sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
            if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }
        }
    }

    if (opt->bw_in_max > 0 && strcmp(opt->bw_in_max_unit,"") != 0)
    {
        snprintf(bw_string, sizeof(bw_string), "%u%s", opt->bw_in_max, opt->bw_in_max_unit);

        if(strlcat(options, "in_max=\"", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, bw_string, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }
    if (opt->bw_out_max > 0 && strcmp(opt->bw_out_max_unit,"") != 0)
    {
        snprintf(bw_string, sizeof(bw_string), "%u%s", opt->bw_out_max, opt->bw_out_max_unit);

        if(strlcat(options, "out_max=\"", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, bw_string, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }
    if (opt->bw_in_min > 0 && strcmp(opt->bw_in_min_unit,"") != 0)
    {
        snprintf(bw_string, sizeof(bw_string), "%u%s", opt->bw_in_min, opt->bw_in_min_unit);

        if(strlcat(options, "in_min=\"", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, bw_string, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }
    if (opt->bw_out_min > 0 && strcmp(opt->bw_out_min_unit,"") != 0)
    {
        snprintf(bw_string, sizeof(bw_string), "%u%s", opt->bw_out_min, opt->bw_out_min_unit);

        if(strlcat(options, "out_min=\"", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, bw_string, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }
    if (opt->prio > 0)
    {
        snprintf(bw_string, sizeof(bw_string), "%u", opt->prio);

        if(strlcat(options, "prio=\"", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, bw_string, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    if (opt->random == TRUE)
    {
        if (strlcat(options, "random,", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    /* comment */
    if(opt->rule_comment == 1 && strcmp(opt->comment, "") != 0)
    {
        if(strlcat(options, "comment=\"", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, opt->comment, sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
        if(strlcat(options, "\",", sizeof(options)) >= sizeof(options))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }
    }

    /* terminate the string */
    options[strlen(options)-1] = '\0';

    /* check if we did anything */
    if(strcmp(options, "options") != 0)
    {
        if(!(option_ptr = malloc(strlen(options)+1)))
        {
            vrmr_error(-1, "Error", "malloc failed: %s.", strerror(errno));
            return(NULL);
        }
        else
        {
            if(strlcpy(option_ptr, options, strlen(options)+1) >= strlen(options)+1)
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(NULL);
            }

            if(debuglvl >= MEDIUM)
                vrmr_debug(__FUNC__, "'%s'.", option_ptr);
        }
    }

    if(debuglvl >= MEDIUM)
        vrmr_debug(__FUNC__, "option_ptr: '%s'.", option_ptr);

    return(option_ptr);
}


/*
    Returncodes:
        -1: error
         0: no change
         1: change
*/
int
vrmr_rules_compare_options(const int debuglvl, struct vrmr_rule_options *old_opt, struct vrmr_rule_options *new_opt, char *action)
{
    char    *old_str = NULL,
            *new_str = NULL;
    int     retval = 0;

    /* both NULL: no change */
    if(!old_opt && !new_opt)
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "options not changed (both NULL)");

        return(0);
    }

    /* if they are not the same: change */
    if((!old_opt && new_opt) || (old_opt && !new_opt))
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "options changed! (one NULL, other not)");

        return(1);
    }

    /* from here on, we are sure we have two options */
    if(!(old_str = vrmr_rules_assemble_options_string(debuglvl, old_opt, action)))
        return(-1);

    if(!(new_str = vrmr_rules_assemble_options_string(debuglvl, new_opt, action)))
    {
        free(old_str);
        return(-1);
    }

    if(strcmp(old_str, new_str) == 0)
        retval = 0;
    else
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "options changed! (str compare)");

        retval = 1;
    }

    /* free the mem */
    free(old_str);
    free(new_str);

    return(retval);
}


/*
    TODO: compare active
*/
void *
vrmr_search_rule(const int debuglvl, struct vrmr_rules *rules, struct vrmr_rule *searchrule_ptr)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_rule    *listrule_ptr = NULL;

    /* safety */
    if(!rules || !searchrule_ptr)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    for(d_node = rules->list.top; d_node ; d_node = d_node->next)
    {
        if(!(listrule_ptr = d_node->data))
        {
            vrmr_error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }

        if(listrule_ptr->action == searchrule_ptr->action)
        {
            /* protect rule */
            if(searchrule_ptr->action == VRMR_AT_PROTECT)
            {
                /* compare who */
                if(strcmp(listrule_ptr->who, searchrule_ptr->who) == 0)
                {
                    /* compare source */
                    if(strcmp(listrule_ptr->source, searchrule_ptr->source) == 0)
                    {
                        /* compare the danger */
                        if(strcmp(listrule_ptr->danger, searchrule_ptr->danger) == 0)
                        {
                            return(listrule_ptr);
                        }
                    }
                }
            }

            /* normal rule */
            else
            {
                /* first compare the service-names */
                if(strcmp(listrule_ptr->service, searchrule_ptr->service) == 0)
                {
                    /* comparing the 'from'-name */
                    if(strcmp(listrule_ptr->from, searchrule_ptr->from) == 0)
                    {
                        /* comparing the 'to'-name */
                        if(strcmp(listrule_ptr->to, searchrule_ptr->to) == 0)
                        {
                            /* comparing the rule options */
                            if(vrmr_rules_compare_options(debuglvl, listrule_ptr->opt, searchrule_ptr->opt, vrmr_rules_itoaction(listrule_ptr->action)) == 0)
                            {
                                return(listrule_ptr);
                            }
                        }
                    }
                }
            }
        }
    }

    return(NULL);
}


/* vrmr_rules_read_options

    Call with the string with options and ouputs the option structure.

    TODO: this needs to be totally redesigned

*/
int
vrmr_rules_read_options(const int debuglvl, char *optstr, struct vrmr_rule_options *op)
{
    int     retval = 0,
            trema = 0;
    char    curopt[512] = "",
            portstring[512] = "";
    size_t  x = 0,
            cur_pos = 0,
            o = 0,
            p = 0;

    /* safety */
    if(optstr == NULL || op == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "options: '%s', strlen(optstr): %d", optstr, strlen(optstr));

    /* check if we even got a string to disassemble */
    if(strlen(optstr) == 0)
    {
        if(debuglvl >= MEDIUM)
            vrmr_debug(__FUNC__, "no options.");

        return(0);
    }


    while((strlen(optstr) >= x))
    {
        curopt[cur_pos] = optstr[x];
        cur_pos++;

        /* between the trema's (") don't use the comma as a separator. */
        if((optstr[x] == '"') && (trema == 1))
        {
            trema = 2;
        }
        if((optstr[x] == '"') && (trema == 0))
        {
            trema = 1;
        }

        if(((optstr[x] == ',') && ((trema == 0) || (trema == 2))) || (optstr[x] == '\0'))
        {
            curopt[cur_pos - 1] = '\0';
            cur_pos = 0;
        }
        x++;

        /* reset trema, so we can have more trema pairs. */
        if(trema == 2)
            trema = 0;

        /* we are done */
        if(cur_pos == 0)
        {
            if(debuglvl >= LOW)
                vrmr_debug(__FUNC__, "curopt: '%s'.", curopt);

            /* error message for a missing trema */
            if(trema == 1)
            {
                vrmr_error(-1, "Error", "unbalanced \" in rule (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }


            /*
                start parsing the options
            */

            /* log - log the rule? */
            if(strcmp(curopt, "log") == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "logging enabled.");

                op->rule_log = 1;
            }
            /* random */
            else if(strcmp(curopt, "random") == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "random enabled.");

                op->random = 1;
            }
            /* loglimit */
            else if(strncmp(curopt, "loglimit", strlen("loglimit")) == 0)
            {
                for(p = 0, o = strlen("loglimit") + 1;
                        o < strlen(curopt) && p < sizeof(portstring);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        portstring[p] = curopt[o];
                        p++;
                    }
                }
                portstring[p] = '\0';

                op->loglimit = (unsigned int)atoi(portstring);
                op->logburst = op->loglimit * 2;

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "loglimit: %d, logburst %d.", op->loglimit, op->logburst);
            }
            /* limit */
            else if(strncmp(curopt, "limit", strlen("limit")) == 0)
            {
                char *ptr = NULL;

                ptr = strstr(curopt, "/");

                if(ptr == NULL) {
                    strlcpy(op->limit_unit,"sec",sizeof(op->limit_unit));
                } else {
                    for(p = 0, o = ptr - curopt + 1;
                            o < strlen(curopt) && p < sizeof(op->limit_unit);
                            o++)
                    {
                        if(curopt[o] != '\"')
                        {
                            op->limit_unit[p] = curopt[o];
                            p++;
                        }
                    }
                    op->limit_unit[p] = '\0';

                    if (strcasecmp(op->limit_unit,"sec") != 0  &&
                        strcasecmp(op->limit_unit,"min") != 0 &&
                        strcasecmp(op->limit_unit,"hour") != 0 &&
                        strcasecmp(op->limit_unit,"day") != 0)
                    {
                        vrmr_error(-1, "Error", "parsing limit option timeunit failed. Please check the syntax of the rule.");
                        op->limit_unit[0] = '\0';
                        return(-1);
                    }
                }

                for(p = 0, o = strlen("limit") + 1;
                        o < strlen(curopt) && p < sizeof(portstring) && curopt[0] != '/';
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        portstring[p] = curopt[o];
                        p++;
                    }
                }
                portstring[p] = '\0';

                op->limit = (unsigned int)atoi(portstring);

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "limit: %d / %s.", op->limit, op->limit_unit);
            }
            /* burst */
            else if(strncmp(curopt, "burst", strlen("burst")) == 0)
            {
                for(p = 0, o = strlen("burst") + 1;
                        o < strlen(curopt) && p < sizeof(portstring);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        portstring[p] = curopt[o];
                        p++;
                    }
                }
                portstring[p] = '\0';

                op->burst = (unsigned int)atoi(portstring);

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "burst: %d.", op->burst);
            }
            /* obsolete: mark the iptablesstate? */
            else if(strcmp(curopt, "markiptstate") == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "obsolete option 'markiptstate'.");
            }
            /* queue instead of accept (portfw and redirect)
                         *
                         * TODO: just a nat rule + separate queue rule is
                         * a better solution. 
                         * */
            else if(strcmp(curopt, "queue") == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "queue'ing enabled.");

                op->queue = 1;
            }
            /* int */
            else if(strncmp(curopt, "int", 3) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "int (old for in_int) option.");

                for(p = 0, o = strlen("int") + 2;
                        p < sizeof(op->in_int) && o < strlen(curopt) - 1;
                        o++, p++)
                {
                    op->in_int[p] = curopt[o];
                }
                op->in_int[p] = '\0';

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "in_int: '%s'.", op->in_int);
            }
            /* in_int */
            else if(strncmp(curopt, "in_int", 6) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "in_int option.");

                for(p = 0, o = strlen("in_int") + 2;
                        p < sizeof(op->in_int) && o < strlen(curopt) - 1;
                        o++, p++)
                {
                    op->in_int[p] = curopt[o];
                }
                op->in_int[p] = '\0';

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "in_int: '%s'.", op->in_int);
            }
            /* out_int */
            else if(strncmp(curopt, "out_int", 7) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "out_int option.");

                for(p = 0, o = strlen("out_int") + 2;
                        p < sizeof(op->out_int) && o < strlen(curopt) - 1;
                        o++, p++)
                {
                    op->out_int[p] = curopt[o];
                }
                op->out_int[p] = '\0';

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "out_int: '%s'.", op->out_int);
            }
            /* via_int */
            else if(strncmp(curopt, "via_int", 7) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "via_int option.");

                for(p = 0, o = strlen("via_int") + 2;
                        p < sizeof(op->via_int) && o < strlen(curopt) - 1;
                        o++, p++)
                {
                    op->via_int[p] = curopt[o];
                }
                op->via_int[p] = '\0';

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "via_int: '%s'.", op->via_int);
            }
            /* remoteport - for portforwarding */
            else if(strncmp(curopt, "remoteport", strlen("remoteport")) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "remoteport specified.");

                /* copy the string containing the ports */
                for(p = 0, o = strlen("remoteport") + 1;
                        o <= strlen(curopt) && p < sizeof(portstring);
                        o++, p++)
                {
                    portstring[p] = curopt[o];
                }
//TODO: no NULL?

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "remoteport string: '%s'.", portstring);

                if(vrmr_portopts_to_list(debuglvl, portstring, &op->RemoteportList) < 0)
                {
                    vrmr_error(-1, "Error", "parsing remoteport option failed. Please check the syntax of the rule.");
                    return(-1);
                }

                op->remoteport = 1;
            }
            /* listenport - for portforwarding */
            else if(strncmp(curopt, "listenport", strlen("listenport")) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "listenport specified.");

                /* copy the string containing the ports */
                for(p = 0, o = strlen("listenport") + 1;
                        o <= strlen(curopt) && p < sizeof(portstring);
                        o++, p++)
                {
                    portstring[p] = curopt[o];
                }
//TODO: no NULL?
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "listenport string: '%s'.", portstring);

                if(vrmr_portopts_to_list(debuglvl, portstring, &op->ListenportList) < 0)
                {
                    vrmr_error(-1, "Error", "parsing listenport option failed. Please check the syntax of the rule.");
                    return(-1);
                }

                op->listenport = 1;
            }
            /* rule comment */
            else if(strncmp(curopt, "comment", strlen("comment")) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "comment.");

                for(p = 0, o = strlen("comment") + 2;
                        o < strlen(curopt) - 1 && p < sizeof(op->comment);
                        o++, p++)
                {
                    op->comment[p] = curopt[o];
                }
                op->comment[p] = '\0';
                op->rule_comment = 1;
            }
            /* logprefix, max 29 characters long. */
            else if(strncmp(curopt, "logprefix", strlen("logprefix")) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "logprefix.");

                for(p = 0, o = strlen("logprefix") + 2;
                        p < 12 && o < strlen(curopt) - 1 && p < sizeof(op->logprefix);
                        o++, p++)
                {
                    op->logprefix[p] = curopt[o];
                }
                op->logprefix[p] = '\0';

                if(strlen(op->logprefix) > 14)
                {
//TODO: not disable, but truncate */
                    vrmr_warning("Warning", "logprefix is too long. Maximum length is 14 characters.");
                    op->rule_logprefix = 0;
                    op->logprefix[0] = '\0';
                }
                else
                {
                    op->rule_logprefix=1;
                }
            }
            /* redirectport */
            else if(strncmp(curopt, "redirectport", strlen("redirectport")) == 0)
            {
                for(p = 0, o = strlen("redirectport") + 1;
                        o < strlen(curopt) && p < sizeof(portstring);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        portstring[p] = curopt[o];
                        p++;
                    }
                }
                portstring[p] = '\0';

                op->redirectport = atoi(portstring);
                if(op->redirectport <= 0 || op->redirectport > 65535)
                {
                    vrmr_error(-1, "Error", "redirectport must be 1-65535.");
                    op->redirectport = 0;
                    return(-1);
                }

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "redirectport: %d, %s", op->redirectport, portstring);
            }
            /* nfmark */
            else if(strncmp(curopt, "nfmark", strlen("nfmark")) == 0)
            {
                for(p = 0, o = strlen("nfmark") + 1;
                        o < strlen(curopt) && p < sizeof(portstring);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        portstring[p] = curopt[o];
                        p++;
                    }
                }
                portstring[p] = '\0';

                op->nfmark = strtoul(portstring, (char **)NULL, 10);

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "nfmark: %lu, %s", op->nfmark, portstring);
            }
            /* reject type */
            else if(strncmp(curopt, "rejecttype", strlen("rejecttype")) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "rejecttype.");

                for(p = 0, o = strlen("rejecttype") + 1;
                        o < strlen(curopt) && o < 23 + strlen("rejecttype") + 1 && p < sizeof(op->reject_type);
                        o++)
                { /* 23 is from the length of the string */

                    if(curopt[o] != '\"')
                    {
                        op->reject_type[p] = curopt[o];
                        p++;
                    }
                }
                op->reject_type[p] = '\0';
                op->reject_option = 1;

                /* check if the option is valid. */
                if( strcmp(op->reject_type, "icmp-net-unreachable") == 0 ||
                    strcmp(op->reject_type, "icmp-host-unreachable") == 0 ||
                    strcmp(op->reject_type, "icmp-proto-unreachable") == 0 ||
                    strcmp(op->reject_type, "icmp-port-unreachable") == 0 ||
                    strcmp(op->reject_type, "icmp-net-prohibited") == 0 ||
                    strcmp(op->reject_type, "icmp-host-prohibited") == 0 ||
                    strcmp(op->reject_type, "tcp-reset") == 0)
                {
                    if(debuglvl >= HIGH)
                        vrmr_debug(__FUNC__, "valid reject type %s", op->reject_type);
                }
                else
                {
                    vrmr_error(-1, "Error", "%s is not a valid reject-type.", op->reject_type);

                    op->reject_option = 0;
                    return(-1);
                }
            }
            /* chain */
            else if(strncmp(curopt, "chain", strlen("chain")) == 0)
            {
                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "chain.");

                for(p = 0, o = strlen("chain") + 2;
                        o < strlen(curopt) - 1 && p < sizeof(op->chain);
                        o++, p++)
                {
                    op->chain[p] = curopt[o];
                }
                op->chain[p] = '\0';
            }
            /* nfqueuenum */
            else if(strncmp(curopt, "nfqueuenum", strlen("nfqueuenum")) == 0)
            {
                for(p = 0, o = strlen("nfqueuenum") + 1;
                        o < strlen(curopt) && p < sizeof(portstring);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        portstring[p] = curopt[o];
                        p++;
                    }
                }
                portstring[p] = '\0';

                op->nfqueue_num = atoi(portstring);

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "nfqueuenum: %d, %s", op->nfqueue_num, portstring);
            }
            /* nflognum */
            else if(strncmp(curopt, "nflognum", strlen("nflognum")) == 0)
            {
                for(p = 0, o = strlen("nflognum") + 1;
                        o < strlen(curopt) && p < sizeof(portstring);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        portstring[p] = curopt[o];
                        p++;
                    }
                }
                portstring[p] = '\0';

                op->nflog_num = atoi(portstring);

                if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "nflognum: %d, %s", op->nflog_num, portstring);
            }
            /* prio */
            else if(strncmp(curopt, "prio", strlen("prio")) == 0)
            {
                for(p = 0, o = strlen("prio") + 1;
                        o < strlen(curopt) && p < sizeof(portstring);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        portstring[p] = curopt[o];
                        p++;
                    }
                }
                portstring[p] = '\0';

                op->prio = atoi(portstring);

                //if(debuglvl >= MEDIUM)
                    vrmr_debug(__FUNC__, "prio: %d, %s", op->prio, portstring);
            }
            /* in_max */
            else if(strncmp(curopt, "in_max", strlen("in_max")) == 0)
            {
                char    bw_string[24] = "",
                        value_string[11] = "",
                        unit_string[5] = "";
                size_t  i = 0;

                for(p = 0, o = strlen("in_max") + 1;
                        o < strlen(curopt) && p < sizeof(bw_string);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        bw_string[p] = curopt[o];
                        p++;
                    }
                }
                bw_string[p] = '\0';

                /* split the value and the unit */
                for (p = 0, i = 0; p < sizeof(value_string) && i < strlen(bw_string) && isdigit(bw_string[i]); i++, p++)
                {
                    value_string[p] = bw_string[i];
                }
                value_string[p] = '\0';

                for (p = 0, i = strlen(value_string); p < sizeof(unit_string) && i < strlen(bw_string) && isalpha(bw_string[i]); i++, p++)
                {
                    unit_string[p] = bw_string[i];
                }
                unit_string[p] = '\0';

                if (strcmp(unit_string, "kbit") == 0 ||
                    strcmp(unit_string, "mbit") == 0 ||
                    strcmp(unit_string, "kbps") == 0 ||
                    strcmp(unit_string, "mbps") == 0)
                {
                    op->bw_in_max = atoi(value_string);
                    strlcpy(op->bw_in_max_unit, unit_string, sizeof(op->bw_in_max_unit));

                    vrmr_debug(__FUNC__, "value_string %s unit_string %s", value_string, unit_string);
                } else {
                    vrmr_error(-1, "Error", "%s is not a valid unit for shaping.", unit_string);
                    return(-1);
                }
            }
            /* in_min */
            else if(strncmp(curopt, "in_min", strlen("in_min")) == 0)
            {
                char    bw_string[24] = "",
                        value_string[11] = "",
                        unit_string[5] = "";
                size_t  i = 0;

                for(p = 0, o = strlen("in_min") + 1;
                        o < strlen(curopt) && p < sizeof(bw_string);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        bw_string[p] = curopt[o];
                        p++;
                    }
                }
                bw_string[p] = '\0';

                /* split the value and the unit */
                for (p = 0, i = 0; p < sizeof(value_string) && i < strlen(bw_string) && isdigit(bw_string[i]); i++, p++)
                {
                    value_string[p] = bw_string[i];
                }
                value_string[p] = '\0';

                for (p = 0, i = strlen(value_string); p < sizeof(unit_string) && i < strlen(bw_string) && isalpha(bw_string[i]); i++, p++)
                {
                    unit_string[p] = bw_string[i];
                }
                unit_string[p] = '\0';

                if (strcmp(unit_string, "kbit") == 0 ||
                    strcmp(unit_string, "mbit") == 0 ||
                    strcmp(unit_string, "kbps") == 0 ||
                    strcmp(unit_string, "mbps") == 0)
                {
                    op->bw_in_min = atoi(value_string);
                    strlcpy(op->bw_in_min_unit, unit_string, sizeof(op->bw_in_min_unit));

                    vrmr_debug(__FUNC__, "value_string %s unit_string %s", value_string, unit_string);
                } else {
                    vrmr_error(-1, "Error", "%s is not a valid unit for shaping.", unit_string);
                    return(-1);
                }
            }
            /* out_max */
            else if(strncmp(curopt, "out_max", strlen("out_max")) == 0)
            {
                char    bw_string[24] = "",
                        value_string[11] = "",
                        unit_string[5] = "";
                size_t  i = 0;

                for(p = 0, o = strlen("out_max") + 1;
                        o < strlen(curopt) && p < sizeof(bw_string);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        bw_string[p] = curopt[o];
                        p++;
                    }
                }
                bw_string[p] = '\0';

                /* split the value and the unit */
                for (p = 0, i = 0; p < sizeof(value_string) && i < strlen(bw_string) && isdigit(bw_string[i]); i++, p++)
                {
                    value_string[p] = bw_string[i];
                }
                value_string[p] = '\0';

                for (p = 0, i = strlen(value_string); p < sizeof(unit_string) && i < strlen(bw_string) && isalpha(bw_string[i]); i++, p++)
                {
                    unit_string[p] = bw_string[i];
                }
                unit_string[p] = '\0';

                if (strcmp(unit_string, "kbit") == 0 ||
                    strcmp(unit_string, "mbit") == 0 ||
                    strcmp(unit_string, "kbps") == 0 ||
                    strcmp(unit_string, "mbps") == 0)
                {
                    op->bw_out_max = atoi(value_string);
                    strlcpy(op->bw_out_max_unit, unit_string, sizeof(op->bw_out_max_unit));

                    vrmr_debug(__FUNC__, "value_string %s unit_string %s", value_string, unit_string);
                } else {
                    vrmr_error(-1, "Error", "%s is not a valid unit for shaping.", unit_string);
                    return(-1);
                }
            }
            /* out_min */
            else if(strncmp(curopt, "out_min", strlen("out_min")) == 0)
            {
                char    bw_string[24] = "",
                        value_string[11] = "",
                        unit_string[5] = "";
                size_t  i = 0;

                for(p = 0, o = strlen("out_min") + 1;
                        o < strlen(curopt) && p < sizeof(bw_string);
                        o++)
                {
                    if(curopt[o] != '\"')
                    {
                        bw_string[p] = curopt[o];
                        p++;
                    }
                }
                bw_string[p] = '\0';

                /* split the value and the unit */
                for (p = 0, i = 0; p < sizeof(value_string) && i < strlen(bw_string) && isdigit(bw_string[i]); i++, p++)
                {
                    value_string[p] = bw_string[i];
                }
                value_string[p] = '\0';

                for (p = 0, i = strlen(value_string); p < sizeof(unit_string) && i < strlen(bw_string) && isalpha(bw_string[i]); i++, p++)
                {
                    unit_string[p] = bw_string[i];
                }
                unit_string[p] = '\0';

                if (strcmp(unit_string, "kbit") == 0 ||
                    strcmp(unit_string, "mbit") == 0 ||
                    strcmp(unit_string, "kbps") == 0 ||
                    strcmp(unit_string, "mbps") == 0)
                {
                    op->bw_out_min = atoi(value_string);
                    strlcpy(op->bw_out_min_unit, unit_string, sizeof(op->bw_out_min_unit));

                    vrmr_debug(__FUNC__, "value_string %s unit_string %s", value_string, unit_string);
                } else {
                    vrmr_error(-1, "Error", "%s is not a valid unit for shaping.", unit_string);
                    return(-1);
                }
            }
            /* unknown option */
            else
            {
                vrmr_warning("Warning", "unknown rule option '%s'.", curopt);
                //return(-1);
            }
        }
    }

    if(debuglvl >= MEDIUM)
        vrmr_debug(__FUNC__, "** end **, return = %d", retval);

    return(retval);
}


/*
    VRMR_AT_ERROR = -1,
    VRMR_AT_ACCEPT,
    VRMR_AT_DROP,
    VRMR_AT_REJECT,
    VRMR_AT_LOG,
    VRMR_AT_PORTFW,
    VRMR_AT_REDIRECT,
    VRMR_AT_SNAT,
    VRMR_AT_MASQ,
    VRMR_AT_QUEUE,
    VRMR_AT_CHAIN,

    VRMR_AT_SEPARATOR,
*/

char *actions[] =
{
    "Accept",
    "Drop",
    "Reject",
    "Log",
    "Portfw",
    "Redirect",
    "Snat",
    "Masq",
    "Queue",
    "Chain",
    "Dnat",
    "Bounce",
    "NFQueue",
    "NFLog",
    "Protect",
    "Separator",
    "ERROR",
};


char *
vrmr_rules_itoaction(int i)
{
    /* i needs to be smaller than the number of items in the array */
    if(i >= ( (int)sizeof(actions) / (int)sizeof(actions[0]) ) -1 )
        return(NULL);

    return(actions[i]);
}


char *actions_cap[] =
{
    "ACCEPT",
    "DROP",
    "REJECT",
    "LOG",
    "PORTFW",
    "REDIRECT",
    "SNAT",
    "MASQ",
    "QUEUE",
    "CHAIN",
    "DNAT",
    "BOUNCE",
    "NFQUEUE",
    "NFLOG",
    "PROTECT",
    "SEPARATOR",
    "ERROR",
};


char *
vrmr_rules_itoaction_cap(int i)
{
    /* status needs to be smaller than the number of items in the array */
    if(i >= ( (int)sizeof(actions_cap) / (int)sizeof(actions_cap[0]) ) -1 )
        return(NULL);

    return(actions_cap[i]);
}


/*  vrmr_rules_actiontoi

    Converts the action into an int as defined by enum action_types.
*/
int
vrmr_rules_actiontoi(const char *action)
{
    if(action == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(VRMR_AT_ERROR);
    }

    if(strcasecmp(action, "accept") == 0)
        return(VRMR_AT_ACCEPT);
    else if(strcasecmp(action, "drop") == 0)
        return(VRMR_AT_DROP);
    else if(strcasecmp(action, "reject") == 0)
        return(VRMR_AT_REJECT);
    else if(strcasecmp(action, "log") == 0)
        return(VRMR_AT_LOG);
    else if(strcasecmp(action, "portfw") == 0)
        return(VRMR_AT_PORTFW);
    else if(strcasecmp(action, "redirect") == 0)
        return(VRMR_AT_REDIRECT);
    else if(strcasecmp(action, "snat") == 0)
        return(VRMR_AT_SNAT);
    else if(strcasecmp(action, "masq") == 0)
        return(VRMR_AT_MASQ);
    else if(strcasecmp(action, "queue") == 0)
        return(VRMR_AT_QUEUE);
    else if(strcasecmp(action, "chain") == 0)
        return(VRMR_AT_CHAIN);
    else if(strcasecmp(action, "dnat") == 0)
        return(VRMR_AT_DNAT);
    else if(strcasecmp(action, "bounce") == 0)
        return(VRMR_AT_BOUNCE);
    else if(strcasecmp(action, "nfqueue") == 0)
        return(VRMR_AT_NFQUEUE);
    else if(strcasecmp(action, "nflog") == 0)
        return(VRMR_AT_NFLOG);
    else if(strcasecmp(action, "sepparator") == 0 ||
        strcasecmp(action, "separator") == 0)
        return(VRMR_AT_SEPARATOR);
    else if(strcasecmp(action, "protect") == 0)
        return(VRMR_AT_PROTECT);
    else
    {
        vrmr_error(-1, "Error", "unknown action '%s' (in: %s:%d).",
                action, __FUNC__, __LINE__);
        return(VRMR_AT_ERROR);
    }
}


struct vrmr_rule *
rules_create_protect_rule(const int debuglvl, char *action, /*@null@*/ char *who, char *danger, /*@null@*/ char *source)
{
    struct vrmr_rule    *rule_ptr = NULL;

    /* safety */
    if(!danger || !action)
    {
        vrmr_error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    /* get mem (vrmr_rule_malloc will report error) */
    if(!(rule_ptr = vrmr_rule_malloc()))
        return(NULL);

    rule_ptr->action = vrmr_rules_actiontoi(action);
    if(rule_ptr->action <= VRMR_AT_ERROR || rule_ptr->action >= VRMR_AT_TOO_BIG)
    {
        free(rule_ptr);
        return(NULL);
    }

    if(rule_ptr->action == VRMR_AT_ACCEPT)
    {
        /* who do we protect */
        if(strlcpy(rule_ptr->service, danger, sizeof(rule_ptr->service)) >= sizeof(rule_ptr->service))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            free(rule_ptr);
            return(NULL);
        }
    }
    else
    {
        /* who do we protect */
        if(strlcpy(rule_ptr->who, who, sizeof(rule_ptr->who)) >= sizeof(rule_ptr->who))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            free(rule_ptr);
            return(NULL);
        }

        /* and against what? */
        if(strlcpy(rule_ptr->danger, danger, sizeof(rule_ptr->danger)) >= sizeof(rule_ptr->danger))
        {
            vrmr_error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            free(rule_ptr);
            return(NULL);
        }

        if(source != NULL)
        {
            /* from which source */
            if(strlcpy(rule_ptr->source, source, sizeof(rule_ptr->source)) >= sizeof(rule_ptr->source))
            {
                vrmr_error(-1, "Internal Error", "string "
                        "overflow (in: %s:%d).", __FUNC__, __LINE__);
                free(rule_ptr);
                return(NULL);
            }
        }
    }

    return(rule_ptr);
}


/*  vrmr_rules_chain_in_list

    returns:
         1: if chain is in the list
         0: if not
        -1: error
*/
int
vrmr_rules_chain_in_list(const int debuglvl, struct vrmr_list *list, char *chainname)
{
    char        *str = NULL;
    struct vrmr_list_node *d_node = NULL;

    /* safety */
    if(list == NULL || chainname == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    for(d_node = list->top; d_node; d_node = d_node->next)
    {
        if(!(str = d_node->data))
        {
            vrmr_error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        if(strcmp(str, chainname) == 0)
        {
            return(1);
        }
    }

    return(0);
}


/*  vrmr_rules_get_custom_chains

    Looks at all rules a puts all custom chain names
    as strings in a list.

    returncodes:
         0: ok
        -1: error
*/
int
vrmr_rules_get_custom_chains(const int debuglvl, struct vrmr_rules *rules)
{
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;
    char                *str = NULL;
    size_t              size = 0;

    /* safety */
    if(rules == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(vrmr_list_setup(debuglvl, &rules->custom_chain_list, free) < 0)
    {
        vrmr_error(-1, "Internal Error", "vrmr_list_setup() "
            "failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    for(d_node = rules->list.top; d_node; d_node = d_node->next)
    {
        if(!(rule_ptr = d_node->data))
        {
            vrmr_error(-1, "Internal Error", "NULL "
                    "pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(rule_ptr->opt != NULL)
        {
            if(rule_ptr->opt->chain[0] != '\0')
            {
                /* see if the chain is already in our list */
                if(vrmr_rules_chain_in_list(debuglvl, &rules->custom_chain_list, rule_ptr->opt->chain) == 0)
                {
                    size = strlen(rule_ptr->opt->chain) + 1;

                    str = malloc(size);
                    if(str == NULL)
                    {
                        vrmr_error(-1, "Error", "malloc failed: %s (in: %s:%d).",
                                strerror(errno), __FUNC__, __LINE__);
                        return(-1);
                    }

                    if(strlcpy(str, rule_ptr->opt->chain, size) >= size)
                    {
                        vrmr_error(-1, "Internal Error", "string "
                                "overflow (in: %s:%d).", __FUNC__, __LINE__);
                        free(str);
                        return(-1);
                    }

                    if(vrmr_list_append(debuglvl, &rules->custom_chain_list, str) == NULL)
                    {
                        vrmr_error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
                        free(str);
                        return(-1);
                    }
                }
            }
        }
    }

    return(0);
}

/* get the actual chains for the table */
static int
vrmr_rules_get_system_chains_per_table(const int debuglvl, char *tablename,
        struct vrmr_list *list, struct vrmr_config *cnf, int ipv)
{
    char    line[128] = "",
            cmd[128] = "";
    FILE    *p = NULL;
    char    chainname[32] = "";
    char    *name = NULL;
    size_t  size = 0;

    /* safety */
    if(list == NULL || tablename == NULL || cnf == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* commandline */
    if (ipv == VRMR_IPV4) {
        snprintf(cmd, sizeof(cmd), "%s -t %s -nL",
                cnf->iptables_location, tablename);
    } else {
        snprintf(cmd, sizeof(cmd), "%s -t %s -nL",
                cnf->ip6tables_location, tablename);
    }

    /* open the pipe to the command */
    if((p = popen(cmd, "r")))
    {
        /* loop through the result */
        while(fgets(line, (int)sizeof(line), p) != NULL)
        {
            if(strncmp("Chain", line, 5) == 0)
            {
                sscanf(line, "Chain %32s", chainname);

                size = strlen(chainname) + 1;

                name = malloc(size);
                if(name == NULL)
                {
                    vrmr_error(-1, "Error", "malloc "
                            "failed: %s (in: %s:%d).",
                            strerror(errno), __FUNC__, __LINE__);
                    pclose(p);
                    return(-1);
                }

                if(strlcpy(name, chainname, size) >= size)
                {
                    vrmr_error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    free(name);
                    pclose(p);
                    return(-1);
                }

                if(vrmr_list_append(debuglvl, list, name) == NULL)
                {
                    vrmr_error(-1, "Internal Error",
                            "vrmr_list_append() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    free(name);
                    pclose(p);
                    return(-1);
                }
            }
        }

        /* finally close the pipe */
        pclose(p);
    }
    else
    {
        if(debuglvl >= MEDIUM)
            vrmr_debug(__FUNC__, "popen() failed");
    }

    return(0);
}


/*  vrmr_rules_get_system_chains

    Gets all chain currently in the filter table on the system.

    Returncodes:
        -1: error
         0: ok
*/
int
vrmr_rules_get_system_chains(const int debuglvl, struct vrmr_rules *rules, struct vrmr_config *cnf, int ipv)
{
    /* safety */
    if(cnf == NULL || rules == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* initialize the lists */
    if(vrmr_list_setup(debuglvl, &rules->system_chain_filter, free) < 0) {
        vrmr_error(-1, "Internal Error", "vrmr_list_setup() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    if(vrmr_list_setup(debuglvl, &rules->system_chain_mangle, free) < 0) {
        vrmr_error(-1, "Internal Error", "vrmr_list_setup() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    if (ipv == VRMR_IPV4) {
        if(vrmr_list_setup(debuglvl, &rules->system_chain_nat, free) < 0) {
            vrmr_error(-1, "Internal Error", "vrmr_list_setup() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    //if(vrmr_list_setup(debuglvl, &rules->system_chain_raw, free) < 0) {
    //    vrmr_error(-1, "Internal Error", "vrmr_list_setup() failed (in: %s:%d).",
    //            __FUNC__, __LINE__);
    //    return(-1);
    //}

    if(cnf->iptables_location[0] == '\0')
    {
        vrmr_error(-1, "Internal Error", "cnf->iptables_location is empty (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    if(vrmr_rules_get_system_chains_per_table(debuglvl, "filter",
                &rules->system_chain_filter, cnf, ipv) < 0)
        return(-1);
    if(vrmr_rules_get_system_chains_per_table(debuglvl, "mangle",
                &rules->system_chain_mangle, cnf, ipv) < 0)
        return(-1);

    if (ipv == VRMR_IPV4) {
        if(vrmr_rules_get_system_chains_per_table(debuglvl, "nat",
                    &rules->system_chain_nat, cnf, ipv) < 0)
            return(-1);
    }
    //if(vrmr_rules_get_system_chains_per_table(debuglvl, "raw", &rules->system_chain_raw, cnf) < 0)
    //    return(-1);

    return(0);
}


/*  vrmr_rules_encode_rule

    convert all " to \"

    Return
        -1: error
         0: ok
*/
int
vrmr_rules_encode_rule(const int debuglvl, char *rulestr, size_t size)
{
    char    line[1024] = "";
    size_t  i = 0,
            x = 0;

    /* safety */
    if(rulestr == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    for(i = 0, x = 0; i < strlen(rulestr) && x < size; i++, x++)
    {
        if( rulestr[i] == '\"' &&
            (i == 0 || rulestr[i-1] != '\\')) /* check for not double encoding */
        {
            line[x] = '\\';
            x++;
        }

        line[x] = rulestr[i];
    }
    line[x] = '\0';

    if(strlcpy(rulestr, line, size) >= size)
    {
        vrmr_error(-1, "Internal Error", "encoding rule failed: buffer to small (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}

int
vrmr_rules_decode_rule(const int debuglvl, char *rulestr, size_t size)
{
    char    line[1024] = "";
    size_t  i = 0,
            x = 0;
    size_t  len = 0;

    /* safety */
    if(rulestr == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    for(i = 0, x = 0; i < strlen(rulestr) && x < size; i++)
    {
        if(rulestr[i] == '\\' && rulestr[i+1] == '\"')
        {
            /* nothing */
        }
        else
        {
            line[x] = rulestr[i];
            x++;
        }
    }
    line[x] = '\0';

    /* this error should be impossible... thats why we check ;-) */
    len = strlcpy(rulestr, line, size);
    if(len >= size)
    {
        vrmr_error(-1, "Internal Error", "decoding rule failed: buffer to small: %u>=%u (in: %s:%d).",
                len, size, __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


/*  determine_ruletype

    Returncodes:
         -1: error
         else the ruletype
*/
int
vrmr_rules_determine_ruletype(const int debuglvl, struct vrmr_rule *rule_ptr)
{
    int ruletype;

    /* safety */
    if(rule_ptr == NULL)
    {
        vrmr_error(VRMR_RT_ERROR, "Internal Error", "parameter "
            "problem (in: %s:%d).", __FUNC__, __LINE__);
        return(VRMR_RT_ERROR);
    }

    /* output */
    if(strncasecmp(rule_ptr->from, "firewall", 8) == 0)
    {
        ruletype = VRMR_RT_OUTPUT;
    }
    /* input */
    else if(strncasecmp(rule_ptr->to, "firewall", 8) == 0)
    {
        ruletype = VRMR_RT_INPUT;
    }
    /* forward */
    else if((strncasecmp(rule_ptr->to, "firewall", 8) != 0) &&
        (strncasecmp(rule_ptr->from, "firewall", 8) != 0))
    {
        ruletype = VRMR_RT_FORWARD;
    }
    else
    {
        vrmr_error(VRMR_RT_ERROR, "Internal Error", "could not "
            "determine chain (in: %s:%d).", __FUNC__, __LINE__);
        return(VRMR_RT_ERROR);
    }

    /* for some actions, we have special chains */
    if(rule_ptr->action == VRMR_AT_MASQ)
    {
        ruletype = VRMR_RT_MASQ;
    }
    else if(rule_ptr->action == VRMR_AT_SNAT)
    {
        ruletype = VRMR_RT_SNAT;
    }
    /* prerouting chain for portfw/dnat */
    else if(rule_ptr->action == VRMR_AT_PORTFW)
    {
        ruletype = VRMR_RT_PORTFW;
    }
    /* prerouting for redirect */
    else if(rule_ptr->action == VRMR_AT_REDIRECT)
    {
        ruletype = VRMR_RT_REDIRECT;
    }
    else if(rule_ptr->action == VRMR_AT_DNAT)
    {
        ruletype = VRMR_RT_DNAT;
    }
    else if(rule_ptr->action == VRMR_AT_BOUNCE)
    {
        ruletype = VRMR_RT_BOUNCE;
    }

    return(ruletype);
}

/* remove_list

    Remove a rule from the list.
*/
int
vrmr_rules_remove_rule_from_list(const int debuglvl, struct vrmr_rules *rules, unsigned int place, int updatenumbers)
{
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;


    /* safety */
    if(rules == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= LOW)
        vrmr_debug(__FUNC__, "start: place: %d, updatenumbers: %d, listsize: %d", place, updatenumbers, rules->list.len);

    for(d_node = rules->list.top; d_node ; d_node = d_node->next)
    {
        if(!(rule_ptr = d_node->data))
        {
            vrmr_error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "rule_ptr->number: %d, place: %d", rule_ptr->number, place);

        if(rule_ptr->number != place)
        {
            //fprintf(stdout, "do nothing\n");
        }
        else
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "now we have to remove (query_ptr->number: %d, place: %d)", rule_ptr->number, place);

            if(vrmr_list_node_is_bot(debuglvl, d_node))
            {
                if(debuglvl >= HIGH)
                    vrmr_debug(__FUNC__, "removing last entry");

                if(vrmr_list_remove_bot(debuglvl, &rules->list) < 0)
                {
                    vrmr_error(-1, "Internal Error", "vrmr_list_remove_bot() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }

            }
            else
            {
                if(debuglvl >= HIGH)
                    vrmr_debug(__FUNC__, "removing normal entry");

                if(vrmr_list_remove_node(debuglvl, &rules->list, d_node) < 0)
                {
                    vrmr_error(-1, "Internal Error", "vrmr_list_remove_node() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }

                if(updatenumbers == 1)
                {
                    if(debuglvl >= HIGH)
                        vrmr_debug(__FUNC__, "updatenumbers: %d, %d", place, 0);

                    vrmr_rules_update_numbers(debuglvl, rules, place, 0);
                }
            }

            /* we only remove one rule at a time */
            break;
        }
    }

    return(0);
}


/*  query_update_numbers

    action:
        0: decrease
        1: increase
*/
void
vrmr_rules_update_numbers(const int debuglvl, struct vrmr_rules *rules, unsigned int place, int action)
{
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;
    unsigned int        i = 0;

    /* safety */
    if(rules == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return;
    }

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "Update higher (or equal) than: %d, action = %d. (list len is %d)", place, action, rules->list.len);

    for(d_node = rules->list.top, i = 1; d_node ; d_node = d_node->next, i++)
    {
        rule_ptr = d_node->data;

        if(i > place)
        {
            if(action == 1)
                rule_ptr->number++;
        }

        if(i >= place)
        {
            if(action == 0 && rule_ptr->number != 0)
                rule_ptr->number--;
        }
    }

    return;
}


/*- vrmr_rules_print_list - */
void
vrmr_rules_print_list(const struct vrmr_rules *rules)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_rule    *rule_ptr = NULL;

    for(d_node = rules->list.top; d_node ; d_node = d_node->next)
    {
        rule_ptr = d_node->data;

        vrmr_debug(__FUNC__, "%3d, %-8s, %s, %s, %s, %s, %s, %s, status: %d",
                rule_ptr->number, vrmr_rules_itoaction(rule_ptr->action),
                rule_ptr->service, rule_ptr->from,
                rule_ptr->to, rule_ptr->who,
                rule_ptr->source, rule_ptr->danger,
                rule_ptr->status);
    }

    return;
}


void
vrmr_rules_free_options(const int debuglvl, struct vrmr_rule_options *opt)
{
    struct vrmr_list_node     *d_node = NULL;
    struct portdata *port_ptr = NULL;

    if(!opt)
        return;

    if(opt->RemoteportList.len > 0)
    {
        /*
            free all portranges
        */
        for(d_node = opt->RemoteportList.top; d_node; d_node = d_node->next)
        {
            port_ptr = d_node->data;
            free(port_ptr);
        }

        vrmr_list_cleanup(debuglvl, &opt->RemoteportList);
    }

    if(opt->ListenportList.len > 0)
    {
        /*
            free all portranges
        */
        for(d_node = opt->ListenportList.top; d_node; d_node = d_node->next)
        {
            port_ptr = d_node->data;
            free(port_ptr);
        }

        vrmr_list_cleanup(debuglvl, &opt->ListenportList);
    }

    free(opt);
}

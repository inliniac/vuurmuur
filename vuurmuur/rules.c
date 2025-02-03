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
/***************************************************************************
 * Here we try to create the actual rule.                                  *
 ***************************************************************************/
#include "main.h"

/* iptables tables */
#define TB_FILTER "-t filter"
#define TB_MANGLE "-t mangle"
#define TB_NAT "-t nat"

void create_logprefix_string(struct vrmr_config *conf ATTR_UNUSED,
        char *resultstr, size_t size, int ruletype, char *action,
        char *userprefix, ...)
{
    char str[33] = "", tmp_str[33] = "";
    va_list ap;

    assert(resultstr && action && userprefix);

    /* clear */
    memset(resultstr, 0, size);

    /* copy the userprefix-prefix */
    (void)strlcpy(str, LOGPREFIX_PREFIX, LOGPREFIX_LOG_MAXLEN);

    /* we dont want 'TCPRESET' in the log, just 'REJECT' */
    if (strcmp(action, "TCPRESET") == 0)
        (void)strlcat(str, "REJECT", LOGPREFIX_LOG_MAXLEN);
    /* we dont want 'MASQUERADE' in the log, just 'MASQ' */
    else if (strcmp(action, "MASQUERADE") == 0)
        (void)strlcat(str, "MASQ", LOGPREFIX_LOG_MAXLEN);
    else if (strcmp(action, "NEWACCEPT") == 0)
        (void)strlcat(str, "ACCEPT", LOGPREFIX_LOG_MAXLEN);
    else if (strcmp(action, "NEWQUEUE") == 0)
        (void)strlcat(str, "QUEUE", LOGPREFIX_LOG_MAXLEN);
    else if (strcmp(action, "NEWNFQUEUE") == 0)
        (void)strlcat(str, "NFQUEUE", LOGPREFIX_LOG_MAXLEN);
    else if (strncmp(action, "DNAT", 4) == 0) {
        if (ruletype == VRMR_RT_PORTFW)
            (void)strlcat(str, "PORTFW", LOGPREFIX_LOG_MAXLEN);
        else if (ruletype == VRMR_RT_DNAT)
            (void)strlcat(str, "DNAT", LOGPREFIX_LOG_MAXLEN);
        else if (ruletype == VRMR_RT_BOUNCE)
            (void)strlcat(str, "BOUNCE", LOGPREFIX_LOG_MAXLEN);
        else
            (void)strlcat(str, "DNAT", LOGPREFIX_LOG_MAXLEN);
    } else
        (void)strlcat(str, action, LOGPREFIX_LOG_MAXLEN);

    (void)strlcat(str, " ", LOGPREFIX_LOG_MAXLEN);

    /* copy the userprefix */
    va_start(ap, userprefix);
    vsnprintf(tmp_str, sizeof(tmp_str), userprefix, ap);
    (void)strlcat(str, tmp_str, LOGPREFIX_LOG_MAXLEN);
    va_end(ap);

    /* create the prefix */
    snprintf(resultstr, size, "--nflog-prefix \"%s \"", str);

    vrmr_debug(HIGH, "str: '%s', resultstr: '%s'.", str, resultstr);
    return;
}

int oldrules_create_custom_chains(
        struct vrmr_rules *rules, struct vrmr_config *cnf)
{
    const char *chain = NULL;
    struct vrmr_list_node *d_node = NULL;
    char cmd[256] = "";

    assert(rules && cnf);

    /* get the current chains */
    (void)vrmr_rules_get_system_chains(rules, cnf, VRMR_IPV4);
    /* get the custom chains we have to create */
    if (vrmr_rules_get_custom_chains(rules) < 0) {
        vrmr_error(-1, "Internal Error", "rules_get_chains() failed");
        return (-1);
    }

    for (d_node = rules->custom_chain_list.top; d_node; d_node = d_node->next) {
        if (!(chain = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (vrmr_rules_chain_in_list(&rules->system_chain_filter, chain) == 0) {
            snprintf(cmd, sizeof(cmd), "%s -N %s", cnf->iptables_location,
                    chain);
            (void)vrmr_pipe_command(cnf, cmd, VRMR_PIPE_QUIET);
        }
    }

    /* list of chains in the system */
    vrmr_list_cleanup(&rules->system_chain_filter);
    vrmr_list_cleanup(&rules->system_chain_mangle);
    vrmr_list_cleanup(&rules->system_chain_nat);
    // vrmr_list_cleanup(&rules->system_chain_raw);
    /* cleanup */
    vrmr_list_cleanup(&rules->custom_chain_list);

    return (0);
}

int analyze_interface_rules(struct vrmr_config *conf, struct vrmr_rules *rules,
        struct vrmr_zones *zones, struct vrmr_services *services,
        struct vrmr_interfaces *interfaces)
{
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL, *if_d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    assert(rules && zones && services && interfaces);

    /* first analyze the protectrules in the interfaces */
    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        if (!(iface_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        for (if_d_node = iface_ptr->ProtectList.top; if_d_node;
                if_d_node = if_d_node->next) {
            if (!(rule_ptr = if_d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            if (vrmr_interfaces_analyze_rule(rule_ptr, &rule_ptr->rulecache,
                        interfaces, conf) == 0) {
                vrmr_debug(HIGH, "analizing protectrule success, active = 1.");
                rule_ptr->active = 1;
            } else {
                vrmr_debug(HIGH, "analizing protectrule failed, active = 0.");
                rule_ptr->active = 0;
            }
        }
    }

    return (0);
}

int analyze_network_protect_rules(struct vrmr_config *conf,
        struct vrmr_rules *rules, struct vrmr_zones *zones,
        struct vrmr_services *services, struct vrmr_interfaces *interfaces)
{
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL, *net_d_node = NULL;
    struct vrmr_zone *zone_ptr = NULL;

    assert(rules && zones && services && interfaces);

    /* first analyze the protectrules in the network */
    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        if (!(zone_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (zone_ptr->type == VRMR_TYPE_NETWORK) {
            for (net_d_node = zone_ptr->ProtectList.top; net_d_node;
                    net_d_node = net_d_node->next) {
                if (!(rule_ptr = net_d_node->data)) {
                    vrmr_error(-1, "Internal Error", "NULL pointer");
                    return (-1);
                }

                if (vrmr_zones_network_analyze_rule(
                            rule_ptr, &rule_ptr->rulecache, zones, conf) == 0) {
                    vrmr_debug(
                            HIGH, "analizing protectrule success, active = 1.");
                    rule_ptr->active = 1;
                } else {
                    vrmr_debug(
                            HIGH, "analizing protectrule failed, active = 0.");
                    rule_ptr->active = 0;
                }
            }
        }
    }

    return (0);
}

static void track_helper(
        const struct vrmr_rule *rule_ptr, struct vrmr_rules *rules)
{
    if (!rule_ptr->rulecache.service) {
        return;
    }

    const char *helper = rule_ptr->rulecache.service->helper;
    if (strcmp(helper, "") != 0) {
        bool found = false;
        struct vrmr_list_node *n = NULL;
        for (n = rules->helpers.top; n; n = n->next) {
            const char *list_helper = n->data;
            if (strcmp(helper, list_helper) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            char *copy = strdup(helper);
            if (copy) {
                vrmr_list_append(&rules->helpers, copy);
            }
        }
    }
}

int analyze_normal_rules(struct vrmr_config *conf, struct vrmr_rules *rules,
        struct vrmr_zones *zones, struct vrmr_services *services,
        struct vrmr_interfaces *interfaces)
{
    struct vrmr_rule *rule_ptr = NULL;
    unsigned int rulescount = 0;
    struct vrmr_list_node *d_node = NULL;

    assert(rules && zones && services && interfaces);

    for (d_node = rules->list.top; d_node;) {
        rulescount++;

        if (!(rule_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        /* analyze! */
        if (vrmr_rules_analyze_rule(rule_ptr, &rule_ptr->rulecache, services,
                    zones, interfaces, conf) == 0) {
            vrmr_debug(MEDIUM, "vrmr_rules_analyze_rule %3u ok.", rulescount);

            track_helper(rule_ptr, rules);

            /* update d_node */
            d_node = d_node->next;
        } else {
            vrmr_warning("Warning", "Analyzing rule %u failed.", rulescount);

            /* update node before removing */
            struct vrmr_list_node *next_d_node = d_node->next;

            /* remove the failed rule from the list */
            if (vrmr_list_remove_node(&rules->list, d_node) < 0) {
                vrmr_error(
                        -1, "Internal Error", "vrmr_list_remove_node() failed");
                return (-1);
            }

            vrmr_rules_free_options(rule_ptr->opt);
            free(rule_ptr);
            rule_ptr = NULL;

            /* set d_node to the next_d_node */
            d_node = next_d_node;
        }
    }

    return (0);
}

/**
 *  \brief analyzes all rules
 *
 *  \param vcxt Vuurmuur context
 *  \param rules Rules. Can be different from vctx->rules
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int analyze_all_rules(struct vrmr_ctx *vctx, struct vrmr_rules *rules)
{
    vrmr_info("Info", "Analyzing the rules... ");

    /* interface rules */
    if (analyze_interface_rules(&vctx->conf, rules, &vctx->zones,
                &vctx->services, &vctx->interfaces) < 0)
        return (-1);

    /* network rules */
    if (analyze_network_protect_rules(&vctx->conf, &vctx->rules, &vctx->zones,
                &vctx->services, &vctx->interfaces) < 0)
        return (-1);

    /* normal rules */
    if (analyze_normal_rules(&vctx->conf, rules, &vctx->zones, &vctx->services,
                &vctx->interfaces) < 0)
        return (-1);

    if (shaping_determine_minimal_default_rates(&vctx->interfaces, rules) < 0)
        return (-1);

    return (0);
}

/*  create_all_rules

    Creates all rules.

    If 'create_prerules' is set to 1, prerules() will be called.

    Returncodes:
         0: ok
        -1: error
*/
int create_all_rules(struct vrmr_ctx *vctx, int create_prerules)
{
    int result = 0;
    char forward_rules = 0;

    /* setup shaping roots */
    vrmr_info("Info", "Clearing existing shaping settings...");
    if (shaping_clear_interfaces(
                &vctx->conf, &vctx->interfaces, /*ruleset*/ NULL) < 0) {
        vrmr_error(-1, "Error", "shaping clear interfaces failed.");
    }
    vrmr_info("Info", "Setting up shaping roots for interfaces...");
    if (shaping_setup_roots(&vctx->conf, &vctx->interfaces, /*ruleset*/ NULL) <
            0) {
        vrmr_error(-1, "Error", "shaping setup roots failed.");
    }
    if (shaping_create_default_rules(
                &vctx->conf, &vctx->interfaces, /*ruleset*/ NULL) < 0) {
        vrmr_error(-1, "Error", "shaping setup default rules failed.");
    }

    vrmr_info("Info", "Creating the rules... (rules to create: %u)",
            vctx->rules.list.len);

    /* create the prerules if were called with it */
    if (create_prerules) {
        result =
                pre_rules(&vctx->conf, NULL, &vctx->interfaces, &vctx->iptcaps);
        if (result < 0)
            return (-1);
    }

    /* create the nfqueue state rules */
    if (create_newnfqueue_rules(&vctx->conf, NULL, &vctx->rules, &vctx->iptcaps,
                VRMR_IPV4) < 0) {
        vrmr_error(-1, "Error", "create nfqueue state failed.");
    }
#ifdef IPV6_ENABLED
    if (create_newnfqueue_rules(&vctx->conf, NULL, &vctx->rules, &vctx->iptcaps,
                VRMR_IPV6) < 0) {
        vrmr_error(-1, "Error", "create nfqueue state failed.");
    }
#endif
    if (create_estrelnfqueue_rules(&vctx->conf, NULL, &vctx->rules,
                &vctx->iptcaps, VRMR_IPV4) < 0) {
        vrmr_error(-1, "Error", "create nfqueue state failed.");
    }
#ifdef IPV6_ENABLED
    if (create_estrelnfqueue_rules(&vctx->conf, NULL, &vctx->rules,
                &vctx->iptcaps, VRMR_IPV6) < 0) {
        vrmr_error(-1, "Error", "create nfqueue state failed.");
    }
#endif

    /* create the nflog state rules */
    if (create_newnflog_rules(&vctx->conf, NULL, &vctx->rules, &vctx->iptcaps,
                VRMR_IPV4) < 0) {
        vrmr_error(-1, "Error", "create nflog state failed.");
    }
#ifdef IPV6_ENABLED
    if (create_newnflog_rules(&vctx->conf, NULL, &vctx->rules, &vctx->iptcaps,
                VRMR_IPV6) < 0) {
        vrmr_error(-1, "Error", "create nflog state failed.");
    }
#endif
    if (create_estrelnflog_rules(&vctx->conf, NULL, &vctx->rules,
                &vctx->iptcaps, VRMR_IPV4) < 0) {
        vrmr_error(-1, "Error", "create nflog state failed.");
    }
#ifdef IPV6_ENABLED
    if (create_estrelnflog_rules(&vctx->conf, NULL, &vctx->rules,
                &vctx->iptcaps, VRMR_IPV6) < 0) {
        vrmr_error(-1, "Error", "create nflog state failed.");
    }
#endif

    /* create the blocklist */
    if (create_block_rules(&vctx->conf, NULL, &vctx->blocklist) < 0) {
        vrmr_error(-1, "Error", "create blocklist failed.");
    }

    /* create the interface rules */
    if (create_interface_rules(
                &vctx->conf, NULL, &vctx->iptcaps, &vctx->interfaces) < 0) {
        vrmr_error(-1, "Error", "create protectrules failed.");
    }
    /* create the network protect rules (anti-spoofing) */
    if (create_network_protect_rules(
                &vctx->conf, NULL, &vctx->zones, &vctx->iptcaps) < 0) {
        vrmr_error(-1, "Error", "create protectrules failed.");
    }
    /* system protect rules (proc) */
    if (create_system_protectrules(&vctx->conf) < 0) {
        vrmr_error(-1, "Error", "create protectrules failed.");
    }
    /* create custom chains if needed */
    if (oldrules_create_custom_chains(&vctx->rules, &vctx->conf) < 0) {
        vrmr_error(-1, "Error", "create custom chains failed.");
    }
    /* normal rules, ruleset == NULL */
    if (create_normal_rules(vctx, NULL, &forward_rules) < 0) {
        vrmr_error(-1, "Error", "create normal rules failed.");
    }

    /* post rules: enable logging */
    if (post_rules(&vctx->conf, NULL, &vctx->iptcaps, forward_rules,
                VRMR_IPV4) < 0)
        return (-1);
#ifdef IPV6_ENABLED
    if (post_rules(&vctx->conf, NULL, &vctx->iptcaps, forward_rules,
                VRMR_IPV6) < 0)
        return (-1);
#endif

    vrmr_info("Info", "Creating rules finished.");
    return (0);
}

static int create_rule_set_ports(
        struct rule_scratch *rule, struct vrmr_portdata *portrange_ptr)
{
    /* from */
    if (portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17) {
        if (portrange_ptr->src_high == 0)
            snprintf(rule->temp_src_port, sizeof(rule->temp_src_port),
                    "--sport %d", portrange_ptr->src_low);
        else
            snprintf(rule->temp_src_port, sizeof(rule->temp_src_port),
                    "--sport %d:%d", portrange_ptr->src_low,
                    portrange_ptr->src_high);
    } else if (portrange_ptr->protocol == 1 || portrange_ptr->protocol == 47 ||
               portrange_ptr->protocol == 50 || portrange_ptr->protocol == 51)
        snprintf(rule->temp_src_port, sizeof(rule->temp_src_port), " ");

    /* to */
    if (portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17) {
        if (portrange_ptr->dst_high == 0)
            snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port),
                    "--dport %d", portrange_ptr->dst_low);
        else
            snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port),
                    "--dport %d:%d", portrange_ptr->dst_low,
                    portrange_ptr->dst_high);
    } else if (portrange_ptr->protocol == 1) {
        if (portrange_ptr->dst_high == -1)
            snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port),
                    "--icmp-type %d", portrange_ptr->dst_low);
        else
            snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port),
                    "--icmp-type %d/%d", portrange_ptr->dst_low,
                    portrange_ptr->dst_high);
    } else if (portrange_ptr->protocol == 47 || portrange_ptr->protocol == 50 ||
               portrange_ptr->protocol == 51)
        snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), " ");

    return (0);
}

static int create_rule_set_proto(
        struct rule_scratch *rule, struct vrmr_rule_cache *create)
{
    assert(rule && create);

    if (rule->portrange_ptr != NULL) {
        /* tcp */
        if (rule->portrange_ptr->protocol == 6)
            (void)strlcpy(
                    rule->proto, "-p tcp -m tcp --syn", sizeof(rule->proto));
        /* udp */
        else if (rule->portrange_ptr->protocol == 17)
            (void)strlcpy(rule->proto, "-p udp -m udp", sizeof(rule->proto));
        /* icmp */
        else if (rule->portrange_ptr->protocol == 1)
            (void)strlcpy(rule->proto, "-p icmp -m icmp", sizeof(rule->proto));
        /* gre */
        else if (rule->portrange_ptr->protocol == 47)
            (void)strlcpy(rule->proto, "-p gre", sizeof(rule->proto));
        else {
            if (rule->portrange_ptr->protocol > 0 &&
                    rule->portrange_ptr->protocol <= 255)
                snprintf(rule->proto, sizeof(rule->proto), "-p %d",
                        rule->portrange_ptr->protocol);
            else
                (void)strlcpy(rule->proto, "", sizeof(rule->proto));
        }
    }

    /* handle service 'any' */
    if (create->service_any == TRUE) {
        memset(rule->proto, 0, sizeof(rule->proto));
        memset(rule->temp_src_port, 0, sizeof(rule->temp_src_port));
        memset(rule->temp_dst_port, 0, sizeof(rule->temp_dst_port));
    }

    return (0);
}

static int rulecreate_call_create_funcs(struct vrmr_config *conf,
        struct rule_scratch *rule, struct vrmr_rule_cache *create,
        struct vrmr_iptcaps *iptcap)
{
    int retval = 0;

    /* normal input rules */
    if (create->ruletype == VRMR_RT_INPUT) {
        if (create_rule_input(conf, rule, create, iptcap) < 0) {
            vrmr_error(-1, "Error", "creating input rule failed");
            retval = -1;
        }
    }
    /* normal output rules */
    else if (create->ruletype == VRMR_RT_OUTPUT) {
        if (create->to_broadcast) {
            if (create_rule_output_broadcast(conf, rule, create, iptcap) < 0) {
                vrmr_error(-1, "Error", "creating output rule failed");
                retval = -1;
            }
            if (create_rule_input_broadcast(conf, rule, create, iptcap) < 0) {
                vrmr_error(-1, "Error", "creating forward rule failed");
                retval = -1;
            }
        } else {
            if (create_rule_output(conf, rule, create, iptcap) < 0) {
                vrmr_error(-1, "Error", "creating output rule failed");
                retval = -1;
            }
        }
    }
    /* normal forward rules */
    else if (create->ruletype == VRMR_RT_FORWARD) {
        if (create->to_broadcast) {
            if (create_rule_input_broadcast(conf, rule, create, iptcap) < 0) {
                vrmr_error(-1, "Error", "creating forward rule failed");
                retval = -1;
            }
        } else {
            if (create_rule_forward(conf, rule, create, iptcap) < 0) {
                vrmr_error(-1, "Error", "creating forward rule failed");
                retval = -1;
            }
            /*  a bit of a hack: if from is any we need output as well
                because from 'any' can be firewall as well.
             */
            if (create->from_any == TRUE) {
                if (create_rule_output(conf, rule, create, iptcap) < 0) {
                    vrmr_error(-1, "Error", "creating output rule failed");
                    retval = -1;
                }
            }
            /*  a bit of a hack: if to is any we need input as well
                because to 'any' can be firewall as well.
             */
            if (create->to_any == TRUE) {
                if (create_rule_input(conf, rule, create, iptcap) < 0) {
                    vrmr_error(-1, "Error", "creating input rule failed");
                    retval = -1;
                }
            }
        }
    }
    /* masq rules */
    else if (create->ruletype == VRMR_RT_MASQ) {
        if (create->option.random == TRUE) {
            if (conf->vrmr_check_iptcaps == FALSE ||
                    iptcap->target_nat_random == TRUE) {
                snprintf(rule->random, sizeof(rule->random), "--random");
            } else {
                vrmr_debug(NONE,
                        "MASQ random option not supported: "
                        "iptcap->target_nat_random %s.",
                        iptcap->target_nat_random ? "TRUE" : "FALSE");
            }
        }

        if (create_rule_masq(conf, rule, create, iptcap) < 0) {
            vrmr_error(-1, "Error", "creating masq rule failed");
            retval = -1;
        }
    }
    /* snat rules */
    else if (create->ruletype == VRMR_RT_SNAT) {
        if (create->to_any == FALSE || create->option.out_int[0] != '\0') {
            /* copy the ipaddress of the to-interface to rule->serverip so snat
             * can use it */
            if (rule->to_if_ptr == NULL) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }
            snprintf(rule->serverip, sizeof(rule->serverip), "%s",
                    rule->to_if_ptr->ipv4.ipaddress);
            vrmr_debug(HIGH, "SNAT: rule->serverip = '%s' (interface: %s).",
                    rule->serverip, rule->to_if_ptr->name);
        }

        if (create->option.random == TRUE) {
            if (conf->vrmr_check_iptcaps == FALSE ||
                    iptcap->target_nat_random == TRUE) {
                snprintf(rule->random, sizeof(rule->random), "--random");
            } else {
                vrmr_debug(NONE,
                        "SNAT random option not supported: "
                        "iptcap->target_nat_random %s.",
                        iptcap->target_nat_random ? "TRUE" : "FALSE");
            }
        }

        if (create_rule_snat(conf, rule, create, iptcap) < 0) {
            vrmr_error(-1, "Error", "creating snat rule failed");
            retval = -1;
        }
    }
    /* portforward rules */
    else if (create->ruletype == VRMR_RT_PORTFW) {
        if (create->from_any == FALSE || create->option.in_int[0] != '\0') {
            /* copy the ipaddress of the from-interface to rule->serverip so
             * portfw can use it */
            if (rule->from_if_ptr == NULL) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }
            snprintf(rule->serverip, sizeof(rule->serverip), "%s",
                    rule->from_if_ptr->ipv4.ipaddress);
            vrmr_debug(HIGH, "PORTFW: rule->serverip = '%s' (interface: %s).",
                    rule->serverip, rule->from_if_ptr->name);
        }

        if (create->option.random == TRUE) {
            if (conf->vrmr_check_iptcaps == FALSE ||
                    iptcap->target_nat_random == TRUE) {
                snprintf(rule->random, sizeof(rule->random), "--random");
            } else {
                vrmr_debug(NONE,
                        "PORTFW random option not supported: "
                        "iptcap->target_nat_random %s.",
                        iptcap->target_nat_random ? "TRUE" : "FALSE");
            }
        }

        if (create_rule_portfw(conf, rule, create, iptcap) < 0) {
            vrmr_error(-1, "Error", "creating portfw rule failed");
            retval = -1;
        }
    } else if (create->ruletype == VRMR_RT_REDIRECT) {
        if (create_rule_redirect(conf, rule, create, iptcap) < 0) {
            vrmr_error(-1, "Error", "creating redirect rule failed");
            retval = -1;
        }
    } else if (create->ruletype == VRMR_RT_DNAT) {
        if (create->from_any == FALSE || create->option.in_int[0] != '\0') {
            /* copy the ipaddress of the from-interface to rule->serverip so
             * portfw can use it */
            if (rule->from_if_ptr == NULL) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }
            snprintf(rule->serverip, sizeof(rule->serverip), "%s",
                    rule->from_if_ptr->ipv4.ipaddress);
            vrmr_debug(HIGH, "DNAT: rule->serverip = '%s' (interface: %s).",
                    rule->serverip, rule->from_if_ptr->name);
        }

        if (create->option.random == TRUE) {
            if (conf->vrmr_check_iptcaps == FALSE ||
                    iptcap->target_nat_random == TRUE) {
                snprintf(rule->random, sizeof(rule->random), "--random");
            } else {
                vrmr_debug(NONE,
                        "DNAT random option not supported: "
                        "iptcap->target_nat_random %s.",
                        iptcap->target_nat_random ? "TRUE" : "FALSE");
            }
        }

        if (create_rule_dnat(conf, rule, create, iptcap) < 0) {
            vrmr_error(-1, "Error", "creating dnat rule failed");
            retval = -1;
        }
    } else if (create->ruletype == VRMR_RT_BOUNCE) {
        if (create->from_any == FALSE || create->option.in_int[0] != '\0') {
            /* copy the ipaddress of the from-interface to rule->serverip so
             * portfw can use it */
            if (rule->from_if_ptr == NULL) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }
            snprintf(rule->serverip, sizeof(rule->serverip), "%s",
                    rule->from_if_ptr->ipv4.ipaddress);
            vrmr_debug(HIGH, "BOUNCE: rule->serverip = '%s' (interface: %s).",
                    rule->serverip, rule->from_if_ptr->name);
        }

        if (create->option.random == TRUE) {
            if (conf->vrmr_check_iptcaps == FALSE ||
                    iptcap->target_nat_random == TRUE) {
                snprintf(rule->random, sizeof(rule->random), "--random");
            } else {
                vrmr_debug(NONE,
                        "BOUNCE random option not supported: "
                        "iptcap->target_nat_random %s.",
                        iptcap->target_nat_random ? "TRUE" : "FALSE");
            }
        }

        if (create_rule_bounce(conf, rule, create, iptcap) < 0) {
            vrmr_error(-1, "Error", "creating bounce rule failed");
            retval = -1;
        }
    } else {
        vrmr_error(-1, "Internal Error", "unknown ruletype '%d'",
                create->ruletype);
        return (-1);
    }

    return (retval);
}

static int rulecreate_create_rule_and_options(struct vrmr_config *conf,
        struct rule_scratch *rule, struct vrmr_rule_cache *create,
        struct vrmr_iptcaps *iptcap)
{
    char action[64] = ""; /* if changes to size: see sscanf below as well */
    char logprefix[64] = "";
    unsigned int limit = 0;
    unsigned int burst = 0;
    char *unit = NULL;
    int retval = 0;

    assert(rule && create);

    /*  clear rule->limit because we only use it with log rules and if loglimit
       > 0 and if iptables has the capability
    */
    memset(rule->limit, 0, sizeof(rule->limit));

    /* get the first part of the action, because action can be like this: REJECT
     * --reject-type icmp-adm.... */
    sscanf(create->action, "%63s", action);

    if (rule->ipv == VRMR_IPV4) {
        (void)strlcpy(rule->from_ip, rule->ipv4_from.ipaddress,
                sizeof(rule->from_ip));
        (void)strlcpy(rule->from_netmask, rule->ipv4_from.netmask,
                sizeof(rule->from_netmask));
#ifdef IPV6_ENABLED
    } else {
        (void)strlcpy(
                rule->from_ip, rule->ipv6_from.ip6, sizeof(rule->from_ip));
        snprintf(rule->from_netmask, sizeof(rule->from_netmask), "%d",
                rule->ipv6_from.cidr6);
#endif
    }

    /* if we want to log a rule, but havent done it yet: */
    if (create->option.rule_log == TRUE) {
        /* create the limitstring */
        if (conf->vrmr_check_iptcaps == FALSE || iptcap->match_limit == TRUE) {
            if (create->option.loglimit > 0) {
                limit = create->option.loglimit;
                unit = "sec";
            } else {
                limit = create->option.limit;
                unit = create->option.limit_unit;
            }

            if (create->option.logburst > 0)
                burst = create->option.logburst;
            else
                burst = create->option.burst;

            /* set the limit */
            if (limit > 0 && burst > 0)
                snprintf(rule->limit, sizeof(rule->limit),
                        "-m limit --limit %u/%s --limit-burst %u", limit, unit,
                        burst);
            else if (limit > 0 && burst == 0)
                snprintf(rule->limit, sizeof(rule->limit),
                        "-m limit --limit %u/%s", limit, unit);
        }

        /* create the logprefix string */
        create_logprefix_string(conf, logprefix, sizeof(logprefix),
                create->ruletype, action, "%s", create->option.logprefix);

        /* create the action */
        snprintf(rule->action, sizeof(rule->action),
                "NFLOG %s --nflog-group %u", logprefix, conf->nfgrp);

        /* set ip and netmask */
        if (rule->ipv == VRMR_IPV4) {
            (void)strlcpy(
                    rule->to_ip, rule->ipv4_to.ipaddress, sizeof(rule->to_ip));
            (void)strlcpy(rule->to_netmask, rule->ipv4_to.netmask,
                    sizeof(rule->to_netmask));
#ifdef IPV6_ENABLED
        } else {
            (void)strlcpy(rule->to_ip, rule->ipv6_to.ip6, sizeof(rule->to_ip));
            snprintf(rule->to_netmask, sizeof(rule->to_netmask), "%d",
                    rule->ipv6_to.cidr6);
#endif
        }

        /* create the rule */
        vrmr_debug(NONE,
                "log the rule, create->option.rule_log == TRUE. rule->action = "
                "%s",
                rule->action);

        retval = rulecreate_call_create_funcs(conf, rule, create, iptcap);
        if (retval < 0) {
            vrmr_error(retval, "Error", "creating log rule failed");
            return (retval);
        }

        memset(rule->limit, 0, sizeof(rule->limit));
    }

    if (rule->ipv == VRMR_IPV4 && create->to_broadcast == FALSE) {
        /* if we have a broadcasting protocol and want logging, and haven't
         * logged yet */
        if (create->service != NULL && create->service->broadcast == TRUE &&
                create->option.rule_log == TRUE) {
            vrmr_debug(HIGH, "create the log rule for broadcast.");

            if (conf->vrmr_check_iptcaps == 0 || iptcap->match_limit == 1) {
                if (create->option.loglimit > 0) {
                    limit = create->option.loglimit;
                    unit = "sec";
                } else {
                    limit = create->option.limit;
                    unit = create->option.limit_unit;
                }

                if (create->option.logburst > 0)
                    burst = create->option.logburst;
                else
                    burst = create->option.burst;

                /* set the limit */
                if (limit > 0 && burst > 0)
                    snprintf(rule->limit, sizeof(rule->limit),
                            "-m limit --limit %u/%s --limit-burst %u", limit,
                            unit, burst);
                else if (limit > 0 && burst == 0)
                    snprintf(rule->limit, sizeof(rule->limit),
                            "-m limit --limit %u/%s", limit, unit);
            }

            /* create the logprefix string */
            create_logprefix_string(conf, logprefix, sizeof(logprefix),
                    create->ruletype, action, "%s", create->option.logprefix);

            /* action */
            snprintf(rule->action, sizeof(rule->action),
                    "NFLOG %s --nflog-group %u", logprefix, conf->nfgrp);

            /* set ip and netmask */
            (void)strlcpy(
                    rule->to_ip, rule->ipv4_to.broadcast, sizeof(rule->to_ip));
            (void)strlcpy(rule->to_netmask, "255.255.255.255",
                    sizeof(rule->to_netmask));

            /* create the rule */
            retval = rulecreate_call_create_funcs(conf, rule, create, iptcap);
            if (retval < 0) {
                vrmr_error(
                        retval, "Error", "creating broadcast log rule failed.");
                return (retval);
            }

            memset(rule->limit, 0, sizeof(rule->limit));
        }

        /* broadcasting */
        if (create->service != NULL && create->service->broadcast == TRUE) {
            vrmr_debug(HIGH, "create the broadcast rule.");

            (void)strlcpy(rule->action, create->action, sizeof(rule->action));

            /* set ip and netmask */
            (void)strlcpy(
                    rule->to_ip, rule->ipv4_to.broadcast, sizeof(rule->to_ip));
            (void)strlcpy(rule->to_netmask, "255.255.255.255",
                    sizeof(rule->to_netmask));

            /* create the rule */
            retval = rulecreate_call_create_funcs(conf, rule, create, iptcap);
            if (retval < 0) {
                vrmr_error(retval, "Error", "creating broadcast rule failed.");
                return (retval);
            }
        }
    }

    vrmr_debug(HIGH, "finally create the normal rule.");

    /* create the logprefix string */
    create_logprefix_string(conf, logprefix, sizeof(logprefix),
            create->ruletype, action, "%s", create->option.logprefix);

    /* action LOG requires some extra attention */
    if (strncasecmp(create->action, "LOG", 3) == 0 ||
            strncasecmp(create->action, "NFLOG", 5) == 0) {
        if (conf->vrmr_check_iptcaps == 0 || iptcap->match_limit == 1) {
            limit = create->option.limit;
            burst = create->option.burst;
            unit = create->option.limit_unit;

            /* set the limit */
            if (limit > 0 && burst > 0)
                snprintf(rule->limit, sizeof(rule->limit),
                        "-m limit --limit %u/%s --limit-burst %u", limit, unit,
                        burst);
            else if (limit > 0 && burst == 0)
                snprintf(rule->limit, sizeof(rule->limit),
                        "-m limit --limit %u/%s", limit, unit);
        }
        int s = snprintf(rule->action, sizeof(rule->action), "%s %s",
                create->action, logprefix);
        if (s >= (int)sizeof(rule->action)) {
            vrmr_error(-1, VR_INTERR, "creating rule action failed.");
            return (-1);
        }
    } else {
        if (conf->vrmr_check_iptcaps == 0 || iptcap->match_limit == 1) {
            limit = create->option.limit;
            burst = create->option.burst;
            unit = create->option.limit_unit;

            /* set the limit */
            if (limit > 0 && burst > 0)
                snprintf(rule->limit, sizeof(rule->limit),
                        "-m limit --limit %u/%s --limit-burst %u", limit, unit,
                        burst);
            else if (limit > 0 && burst == 0)
                snprintf(rule->limit, sizeof(rule->limit),
                        "-m limit --limit %u/%s", limit, unit);
        }

        (void)strlcpy(rule->action, create->action, sizeof(rule->action));
#ifdef IPV6_ENABLED
        if (rule->ipv == VRMR_IPV6) {
            /* rules can explicitly set a the reject option, which will be IPv4
             * only. */
            if (strncasecmp(rule->action, "REJECT --reject-with", 20) == 0 &&
                    strncasecmp(rule->action, "REJECT --reject-with tcp-reset",
                            30) != 0)
                strlcpy(rule->action, "REJECT", sizeof(rule->action));
        }
#endif
    }

    /* set ip and netmask */
    if (rule->ipv == VRMR_IPV4) {
        (void)strlcpy(
                rule->to_ip, rule->ipv4_to.ipaddress, sizeof(rule->to_ip));
        (void)strlcpy(rule->to_netmask, rule->ipv4_to.netmask,
                sizeof(rule->to_netmask));
#ifdef IPV6_ENABLED
    } else {
        (void)strlcpy(rule->to_ip, rule->ipv6_to.ip6, sizeof(rule->to_ip));
        snprintf(rule->to_netmask, sizeof(rule->to_netmask), "%d",
                rule->ipv6_to.cidr6);
#endif
    }

    /* create the rule */
    retval = rulecreate_call_create_funcs(conf, rule, create, iptcap);
    if (retval < 0) {
        vrmr_error(retval, "Error", "creating rule failed.");
        return (retval);
    }

    return (0);
}

static int rulecreate_dst_loop(struct vrmr_config *conf,
        struct rule_scratch *rule, struct vrmr_rule_cache *create,
        struct vrmr_iptcaps *iptcap)
{
    struct vrmr_list_node *d_node = NULL;
    int retval = 0;
    struct vrmr_zone *host_ptr = NULL;

    assert(create);

    /* any */
    if (create->to_any == TRUE) {
        /* clear */

        retval = rulecreate_create_rule_and_options(conf, rule, create, iptcap);
    }
    /* firewall */
    else if (create->to_firewall == TRUE) {
        if (create->to_firewall_any == TRUE || create->from_any == TRUE) {
            /* clear */
        } else if (create->from->type == VRMR_TYPE_ZONE) {
            vrmr_debug(NONE, "source firewall, dest zone");

            if (rule->ipv == VRMR_IPV4) {
                /* set addresses */
                (void)strlcpy(rule->ipv4_to.ipaddress,
                        rule->from_if_ptr->ipv4.ipaddress,
                        sizeof(rule->ipv4_to.ipaddress));
                (void)strlcpy(rule->ipv4_to.netmask, "255.255.255.255",
                        sizeof(rule->ipv4_to.netmask));
#ifdef IPV6_ENABLED
            } else {
                (void)strlcpy(rule->ipv6_to.ip6, rule->from_if_ptr->ipv6.ip6,
                        sizeof(rule->ipv6_to.ip6));
                rule->ipv6_to.cidr6 = rule->from_if_ptr->ipv6.cidr6;
#endif
            }

            /* set interface */
            if (rule->from_if_ptr->device_virtual_oldstyle == TRUE) {
                memset(rule->from_int, 0, sizeof(rule->from_int));
            } else {
                (void)strlcpy(rule->from_int, rule->from_if_ptr->device,
                        sizeof(rule->from_int));
            }
        } else {
            if (rule->ipv == VRMR_IPV4) {
                /* set addresses */
                (void)strlcpy(rule->ipv4_to.ipaddress,
                        rule->to_if_ptr->ipv4.ipaddress,
                        sizeof(rule->ipv4_to.ipaddress));
                (void)strlcpy(rule->ipv4_to.netmask, "255.255.255.255",
                        sizeof(rule->ipv4_to.netmask));
#ifdef IPV6_ENABLED
            } else {
                (void)strlcpy(rule->ipv6_to.ip6, rule->to_if_ptr->ipv6.ip6,
                        sizeof(rule->ipv6_to.ip6));
                rule->ipv6_to.cidr6 = rule->to_if_ptr->ipv6.cidr6;
#endif
            }

            /* set interface */
            if (rule->to_if_ptr->device_virtual_oldstyle == TRUE) {
                memset(rule->from_int, 0, sizeof(rule->from_int));
            } else {
                (void)strlcpy(rule->from_int, rule->to_if_ptr->device,
                        sizeof(rule->from_int));
            }
        }

        /*  if dst is firewall and src is any _and_
            the in_int option was set, we need some magic
            to make sure the dst ipaddress is set */
        if (create->to_firewall == TRUE && create->from_any == TRUE &&
                create->option.in_int[0] != '\0') {
            if (rule->ipv == VRMR_IPV4) {
                (void)strlcpy(rule->ipv4_to.ipaddress,
                        rule->from_if_ptr->ipv4.ipaddress,
                        sizeof(rule->ipv4_to.ipaddress));
                (void)strlcpy(rule->ipv4_to.netmask, "255.255.255.255",
                        sizeof(rule->ipv4_to.netmask));
#ifdef IPV6_ENABLED
            } else {
                (void)strlcpy(rule->ipv6_to.ip6, rule->from_if_ptr->ipv6.ip6,
                        sizeof(rule->ipv6_to.ip6));
                rule->ipv6_to.cidr6 = 128;
#endif
            }
        }
        retval = rulecreate_create_rule_and_options(conf, rule, create, iptcap);
    }
    /* host */
    else if (create->to->type == VRMR_TYPE_HOST) {
        if (rule->ipv == VRMR_IPV4) {
            (void)strlcpy(rule->ipv4_to.ipaddress, create->to->ipv4.ipaddress,
                    sizeof(rule->ipv4_to.ipaddress));
            (void)strlcpy(rule->ipv4_to.netmask, create->to->ipv4.netmask,
                    sizeof(rule->ipv4_to.netmask));
#ifdef IPV6_ENABLED
        } else {
            (void)strlcpy(rule->ipv6_to.ip6, create->to->ipv6.ip6,
                    sizeof(rule->ipv6_to.ip6));
            rule->ipv6_to.cidr6 = create->to->ipv6.cidr6;
#endif
        }

        if (create->to->active == 1) {
            retval = rulecreate_create_rule_and_options(
                    conf, rule, create, iptcap);
        }
    }
    /* group */
    else if (create->to->type == VRMR_TYPE_GROUP) {

        if (create->to->active == 1) {
            for (d_node = create->to->GroupList.top; d_node != NULL;
                    d_node = d_node->next) {
                host_ptr = d_node->data;

                if (rule->ipv == VRMR_IPV4) {
                    (void)strlcpy(rule->ipv4_to.ipaddress,
                            host_ptr->ipv4.ipaddress,
                            sizeof(rule->ipv4_to.ipaddress));
                    (void)strlcpy(rule->ipv4_to.netmask, host_ptr->ipv4.netmask,
                            sizeof(rule->ipv4_to.netmask));
#ifdef IPV6_ENABLED
                } else {
                    (void)strlcpy(rule->ipv6_to.ip6, host_ptr->ipv6.ip6,
                            sizeof(rule->ipv6_to.ip6));
                    rule->ipv6_to.cidr6 = host_ptr->ipv6.cidr6;
#endif
                }

                if (host_ptr->active == 1) {
                    retval = rulecreate_create_rule_and_options(
                            conf, rule, create, iptcap);
                }
            }
        }
    }
    /* network */
    else if (create->to->type == VRMR_TYPE_NETWORK &&
             create->to_broadcast == FALSE) {
        if (rule->ipv == VRMR_IPV4) {
            (void)strlcpy(rule->ipv4_to.ipaddress, create->to->ipv4.network,
                    sizeof(rule->ipv4_to.ipaddress));
            (void)strlcpy(rule->ipv4_to.netmask, create->to->ipv4.netmask,
                    sizeof(rule->ipv4_to.netmask));
#ifdef IPV6_ENABLED
        } else {
            (void)strlcpy(rule->ipv6_to.ip6, create->to->ipv6.net6,
                    sizeof(rule->ipv6_to.ip6));
            rule->ipv6_to.cidr6 = create->to->ipv6.cidr6;
#endif
        }

        if (create->to->active == 1) {
            retval = rulecreate_create_rule_and_options(
                    conf, rule, create, iptcap);
        }
    }
    /* network broadcast address (ipv4 only) */
    else if (create->to->type == VRMR_TYPE_NETWORK &&
             create->to_broadcast == TRUE) {
        if (rule->ipv == VRMR_IPV4) {
            (void)strlcpy(rule->ipv4_to.ipaddress, create->to->ipv4.broadcast,
                    sizeof(rule->ipv4_to.ipaddress));
            (void)strlcpy(rule->ipv4_to.netmask, "255.255.255.255",
                    sizeof(rule->ipv4_to.netmask));

            if (create->to->active == 1) {
                retval = rulecreate_create_rule_and_options(
                        conf, rule, create, iptcap);
            }
        }
    } else if (create->to->type == VRMR_TYPE_ZONE) {
        if (rule->ipv == VRMR_IPV4) {
            (void)strlcpy(rule->ipv4_to.ipaddress,
                    rule->to_network->ipv4.network,
                    sizeof(rule->ipv4_to.ipaddress));
            (void)strlcpy(rule->ipv4_to.netmask, rule->to_network->ipv4.netmask,
                    sizeof(rule->ipv4_to.netmask));
#ifdef IPV6_ENABLED
        } else {
            (void)strlcpy(rule->ipv6_to.ip6, rule->to_network->ipv6.net6,
                    sizeof(rule->ipv6_to.ip6));
            rule->ipv6_to.cidr6 = rule->to_network->ipv6.cidr6;
#endif
        }

        if (create->to->active == 1 && rule->to_network->active == 1) {
            retval = rulecreate_create_rule_and_options(
                    conf, rule, create, iptcap);
        }
    }

    return (retval);
}

static int rulecreate_src_loop(struct vrmr_config *conf,
        struct rule_scratch *rule, struct vrmr_rule_cache *create,
        struct vrmr_iptcaps *iptcap)
{
    char from_has_mac = FALSE;
    char from_mac[19] = "";
    struct vrmr_list_node *d_node = NULL;
    int retval = 0;
    struct vrmr_zone *host_ptr = NULL;

    assert(create);

    /* any */
    if (create->from_any == TRUE) {
        /* clear */

        vrmr_debug(NONE, "source 'any'");

        retval = rulecreate_dst_loop(conf, rule, create, iptcap);
    }
    /* firewall */
    else if (create->from_firewall == TRUE) {
        if (create->from_firewall_any == TRUE || create->to_any == TRUE) {
            /* clear */
            vrmr_debug(NONE, "source firewall(any)");
        } else if (create->to->type == VRMR_TYPE_ZONE) {
            vrmr_debug(NONE, "source firewall, dest zone");

            if (rule->ipv == VRMR_IPV4) {
                assert(rule->to_if_ptr);

                /* set addresses */
                (void)strlcpy(rule->ipv4_from.ipaddress,
                        rule->to_if_ptr->ipv4.ipaddress,
                        sizeof(rule->ipv4_from.ipaddress));
                (void)strlcpy(rule->ipv4_from.netmask, "255.255.255.255",
                        sizeof(rule->ipv4_from.netmask));
#ifdef IPV6_ENABLED
            } else {
                (void)strlcpy(rule->ipv6_from.ip6, rule->to_if_ptr->ipv6.ip6,
                        sizeof(rule->ipv6_from.ip6));
                rule->ipv6_from.cidr6 = rule->to_if_ptr->ipv6.cidr6;
#endif
            }

            /* set interface */
            if (rule->to_if_ptr->device_virtual_oldstyle == TRUE) {
                memset(rule->to_int, 0, sizeof(rule->to_int));
            } else {
                (void)strlcpy(rule->to_int, rule->to_if_ptr->device,
                        sizeof(rule->to_int));
            }
        } else {
            vrmr_debug(NONE, "source firewall");

            if (rule->ipv == VRMR_IPV4) {
                if (rule->from_if_ptr == NULL)
                    abort();

                /* set addresses */
                (void)strlcpy(rule->ipv4_from.ipaddress,
                        rule->from_if_ptr->ipv4.ipaddress,
                        sizeof(rule->ipv4_from.ipaddress));
                (void)strlcpy(rule->ipv4_from.netmask, "255.255.255.255",
                        sizeof(rule->ipv4_from.netmask));
#ifdef IPV6_ENABLED
            } else {
                (void)strlcpy(rule->ipv6_from.ip6, rule->from_if_ptr->ipv6.ip6,
                        sizeof(rule->ipv6_from.ip6));
                rule->ipv6_from.cidr6 = rule->from_if_ptr->ipv6.cidr6;
#endif
            }

            /* set interface */
            if (rule->from_if_ptr->device_virtual_oldstyle == TRUE) {
                memset(rule->to_int, 0, sizeof(rule->to_int));
            } else {
                (void)strlcpy(rule->to_int, rule->from_if_ptr->device,
                        sizeof(rule->to_int));
            }
        }

        /*  if source is firewall and dest is any _and_
            the out_int option was set, we need some magic
            to make sure the source ipaddress is set */
        if (create->from_firewall == TRUE && create->to_any == TRUE &&
                create->option.out_int[0] != '\0') {
            if (rule->ipv == VRMR_IPV4) {
                (void)strlcpy(rule->ipv4_from.ipaddress,
                        rule->from_if_ptr->ipv4.ipaddress,
                        sizeof(rule->ipv4_from.ipaddress));
                (void)strlcpy(rule->ipv4_from.netmask, "255.255.255.255",
                        sizeof(rule->ipv4_from.netmask));
#ifdef IPV6_ENABLED
            } else {
                (void)strlcpy(rule->ipv6_from.ip6, rule->from_if_ptr->ipv6.ip6,
                        sizeof(rule->ipv6_from.ip6));
                rule->ipv6_from.cidr6 = rule->from_if_ptr->ipv6.cidr6;
#endif
            }
        }
        retval = rulecreate_dst_loop(conf, rule, create, iptcap);
    }
    /* host */
    else if (create->from->type == VRMR_TYPE_HOST) {
        if (rule->ipv == VRMR_IPV4) {
            (void)strlcpy(rule->ipv4_from.ipaddress,
                    create->from->ipv4.ipaddress,
                    sizeof(rule->ipv4_from.ipaddress));
            (void)strlcpy(rule->ipv4_from.netmask, create->from->ipv4.netmask,
                    sizeof(rule->ipv4_from.netmask));
#ifdef IPV6_ENABLED
        } else {
            (void)strlcpy(rule->ipv6_from.ip6, create->from->ipv6.ip6,
                    sizeof(rule->ipv6_from.ip6));
            rule->ipv6_from.cidr6 = create->from->ipv6.cidr6;
#endif
        }

        if (create->from->has_mac) {
            from_has_mac = TRUE;
            (void)strlcpy(from_mac, create->from->mac, sizeof(from_mac));
        }

        /* add mac-address if we happen to know it, only 'from' is supported by
         * iptables */
        if (from_has_mac == TRUE) {
            if (conf->vrmr_check_iptcaps == FALSE || iptcap->match_mac == TRUE)
                snprintf(rule->from_mac, sizeof(rule->from_mac),
                        "-m mac --mac-source %s", from_mac);
            else {
                vrmr_warning("Warning", "not using macaddress. Mac-match not "
                                        "supported by system.");
                memset(rule->from_mac, 0, sizeof(rule->from_mac));
            }
        } else
            memset(rule->from_mac, 0, sizeof(rule->from_mac));

        if (create->from->active == 1) {
            retval = rulecreate_dst_loop(conf, rule, create, iptcap);
        }
    }
    /* group */
    else if (create->from->type == VRMR_TYPE_GROUP) {

        for (d_node = create->from->GroupList.top; d_node != NULL;
                d_node = d_node->next) {
            host_ptr = d_node->data;

            if (rule->ipv == VRMR_IPV4) {
                (void)strlcpy(rule->ipv4_from.ipaddress,
                        host_ptr->ipv4.ipaddress,
                        sizeof(rule->ipv4_from.ipaddress));
                (void)strlcpy(rule->ipv4_from.netmask, host_ptr->ipv4.netmask,
                        sizeof(rule->ipv4_from.netmask));
#ifdef IPV6_ENABLED
            } else {
                (void)strlcpy(rule->ipv6_from.ip6, host_ptr->ipv6.ip6,
                        sizeof(rule->ipv6_from.ip6));
                rule->ipv6_from.cidr6 = host_ptr->ipv6.cidr6;
#endif
            }

            if (host_ptr->has_mac) {
                (void)strlcpy(from_mac, host_ptr->mac, sizeof(from_mac));

                /* add mac-address if we happen to know it, only 'from' is
                 * supported by iptables */
                if (conf->vrmr_check_iptcaps == FALSE ||
                        iptcap->match_mac == TRUE)
                    snprintf(rule->from_mac, sizeof(rule->from_mac),
                            "-m mac --mac-source %s", from_mac);
                else {
                    vrmr_warning("Warning", "not using macaddress. Mac-match "
                                            "not supported by system.");
                    memset(rule->from_mac, 0, sizeof(rule->from_mac));
                }
            } else {
                memset(rule->from_mac, 0, sizeof(rule->from_mac));
            }

            if (host_ptr->active == 1) {
                retval = rulecreate_dst_loop(conf, rule, create, iptcap);
                if (retval < 0) {
                    return (retval);
                }
            }
        }
    }
    /* network */
    else if (create->from->type == VRMR_TYPE_NETWORK) {
        if (rule->ipv == VRMR_IPV4) {
            (void)strlcpy(rule->ipv4_from.ipaddress, create->from->ipv4.network,
                    sizeof(rule->ipv4_from.ipaddress));
            (void)strlcpy(rule->ipv4_from.netmask, create->from->ipv4.netmask,
                    sizeof(rule->ipv4_from.netmask));
#ifdef IPV6_ENABLED
        } else {
            (void)strlcpy(rule->ipv6_from.ip6, create->from->ipv6.net6,
                    sizeof(rule->ipv6_from.ip6));
            rule->ipv6_from.cidr6 = create->from->ipv6.cidr6;
#endif
        }

        if (create->from->active == 1) {
            retval = rulecreate_dst_loop(conf, rule, create, iptcap);
        }
    } else if (create->from->type == VRMR_TYPE_ZONE) {
        if (rule->ipv == VRMR_IPV4) {
            (void)strlcpy(rule->ipv4_from.ipaddress,
                    rule->from_network->ipv4.network,
                    sizeof(rule->ipv4_from.ipaddress));
            (void)strlcpy(rule->ipv4_from.netmask,
                    rule->from_network->ipv4.netmask,
                    sizeof(rule->ipv4_from.netmask));
#ifdef IPV6_ENABLED
        } else {
            (void)strlcpy(rule->ipv6_from.ip6, rule->from_network->ipv6.net6,
                    sizeof(rule->ipv6_from.ip6));
            rule->ipv6_from.cidr6 = rule->from_network->ipv6.cidr6;
#endif
        }

        if (create->from->active == 1 && rule->from_network->active == 1) {
            retval = rulecreate_dst_loop(conf, rule, create, iptcap);
        }
    }

    return (retval);
}

static int rulecreate_service_loop(struct vrmr_config *conf,
        struct rule_scratch *rule, struct vrmr_rule_cache *create,
        struct vrmr_iptcaps *iptcap)
{
    int retval = 0;
    struct vrmr_list_node *port_d_node = NULL;
    struct vrmr_list_node *listenport_d_node = NULL;
    struct vrmr_list_node *remoteport_d_node = NULL;

    /* handle 'any' service first */
    if (create->service == NULL || create->service_any == TRUE) {

        /* set protocol */
        if (create_rule_set_proto(rule, create) < 0) {
            vrmr_error(-1, "Internal Error", "create_rule_set_proto() failed");
            return (-1);
        }

        retval = rulecreate_src_loop(conf, rule, create, iptcap);

        vrmr_debug(NONE, "service 'any'");

        return (retval);
    }

    /* 'any' is now gone */

    if (create->service->active == 0) {
        return (0);
    }

    /* listenport option */
    if (create->option.listenport == TRUE)
        listenport_d_node = create->option.ListenportList.top;
    else
        listenport_d_node = NULL;

    /* remoteport option */
    if (create->option.remoteport == TRUE)
        remoteport_d_node = create->option.RemoteportList.top;
    else
        remoteport_d_node = NULL;

    /* loop here */
    for (port_d_node = create->service->PortrangeList.top; port_d_node != NULL;
            port_d_node = port_d_node->next) {
        /* get the current portrange */
        if (!(rule->portrange_ptr = port_d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        /* TODO check what protos need to be supported */
        if (create->to_broadcast &&
                (rule->ipv == VRMR_IPV6 ||
                        rule->portrange_ptr->protocol != 17)) {
            continue;
        }

        /* skip ICMP for IPv6 */
        if (rule->ipv == VRMR_IPV6 && rule->portrange_ptr->protocol == 1)
            continue;

        /* skip ICMPv6 for IPv4 */
        if (rule->ipv == VRMR_IPV4 && rule->portrange_ptr->protocol == 58)
            continue;

        /* set rule->listenport_ptr */
        if (create->option.listenport == TRUE && listenport_d_node != NULL)
            rule->listenport_ptr = listenport_d_node->data;
        else
            rule->listenport_ptr = NULL;

        /* set rule->remoteport_ptr */
        if (create->option.remoteport == TRUE && remoteport_d_node != NULL)
            rule->remoteport_ptr = remoteport_d_node->data;
        else
            rule->remoteport_ptr = NULL;

        /* now load the ports to the rule struct */
        if (create_rule_set_ports(rule, rule->portrange_ptr) < 0) {
            vrmr_error(-1, "Internal Error", "setting up the ports failed");
            return (-1);
        }

        /* set protocol */
        if (create_rule_set_proto(rule, create) < 0) {
            vrmr_error(-1, "Internal Error", "create_rule_set_proto() failed");
            return (-1);
        }

        vrmr_debug(NONE, "service %s %s %s", rule->proto, rule->temp_src_port,
                rule->temp_dst_port);

        retval = rulecreate_src_loop(conf, rule, create, iptcap);
        if (retval < 0) {
            return (retval);
        }

        /* listenport and remoteport move to the next range */
        if (create->option.listenport == TRUE) {
            if (listenport_d_node != NULL && listenport_d_node->next != NULL)
                listenport_d_node = listenport_d_node->next;
        }
        if (create->option.remoteport == TRUE) {
            if (remoteport_d_node != NULL && remoteport_d_node->next != NULL)
                remoteport_d_node = remoteport_d_node->next;
        }
    }

    return (retval);
}

static int rulecreate_dst_iface_loop(struct vrmr_ctx *vctx,
        struct rule_scratch *rule, struct vrmr_rule_cache *create)
{
    int retval = 0;
    struct vrmr_list_node *d_node = NULL;
    char active = 0;

    /* handle firewall -> any and firewall(any) */
    if (create->to_firewall_any == TRUE ||
            (create->to_firewall == TRUE && create->from_any == TRUE)) {
        /* clear the from_int to be sure */
        memset(rule->to_int, 0, sizeof(rule->to_int));

        /* assume active */
        active = 1;

        if (create->option.in_int[0] != '\0') /* interface option is set */
        {
            rule->to_if_ptr = vrmr_search_interface(
                    &vctx->interfaces, create->option.in_int);
            if (rule->to_if_ptr == NULL) {
                vrmr_error(-1, "Error", "interface '%s' not found",
                        create->option.out_int);
                return (-1);
            }

            active = rule->to_if_ptr->active;

            if (rule->to_if_ptr->device_virtual_oldstyle == FALSE)
                (void)strlcpy(rule->to_int, rule->to_if_ptr->device,
                        sizeof(rule->to_int));
            else
                memset(rule->to_int, 0, sizeof(rule->to_int));

            if (rule->to_if_ptr->dynamic == TRUE &&
                    rule->to_if_ptr->up == FALSE) {
                vrmr_info("Info",
                        "not creating rule: 'to'-interface '%s' is dynamic and "
                        "down.",
                        rule->to_if_ptr->name);
                active = 0;
            }
        }
        if (active == 1) {
            vrmr_debug(NONE, "dst interface %s",
                    rule->to_if_ptr ? rule->to_if_ptr->name : "any");

            retval = rulecreate_service_loop(
                    &vctx->conf, rule, create, &vctx->iptcaps);

            /* shaping rules */
            if (vrmr_is_shape_outgoing_rule(&create->option) == 1) {
                /* at this point we can create the tc rules */
                retval = shaping_shape_create_rule(&vctx->conf, rule,
                        rule->to_if_ptr, rule->from_if_ptr,
                        rule->shape_class_out, create->option.bw_in_min,
                        create->option.bw_in_min_unit, create->option.bw_in_max,
                        create->option.bw_in_max_unit, create->option.prio);
                if (retval < 0) {
                    return (retval);
                }
            }
            if (vrmr_is_shape_incoming_rule(&create->option) == 1) {
                /* at this point we can create the tc rules */
                retval = shaping_shape_create_rule(&vctx->conf, rule,
                        rule->from_if_ptr, rule->to_if_ptr,
                        rule->shape_class_in, create->option.bw_out_min,
                        create->option.bw_out_min_unit,
                        create->option.bw_out_max,
                        create->option.bw_out_max_unit, create->option.prio);
                if (retval < 0) {
                    return (retval);
                }
            }
        }
        return (retval);
    }

    /* handle any */
    if (create->to_any || create->to == NULL) {
        /* clear the from_int to be sure */
        memset(rule->to_int, 0, sizeof(rule->to_int));

        /* assume active */
        active = 1;

        if (create->option.out_int[0] != '\0') /* interface option is set */
        {
            rule->to_if_ptr = vrmr_search_interface(
                    &vctx->interfaces, create->option.out_int);
            if (rule->to_if_ptr == NULL) {
                vrmr_error(-1, "Error", "interface '%s' not found",
                        create->option.out_int);
                return (-1);
            }

            active = rule->to_if_ptr->active;

            if (rule->to_if_ptr->device_virtual_oldstyle == FALSE)
                (void)strlcpy(rule->to_int, rule->to_if_ptr->device,
                        sizeof(rule->to_int));
            else
                memset(rule->to_int, 0, sizeof(rule->to_int));

            if (rule->to_if_ptr->dynamic == TRUE &&
                    rule->to_if_ptr->up == FALSE) {
                vrmr_info("Info",
                        "not creating rule: 'to'-interface '%s' is dynamic and "
                        "down.",
                        rule->to_if_ptr->name);
                active = 0;
            }
        }
        if (active == 1) {
            vrmr_debug(NONE, "dst interface %s",
                    rule->to_if_ptr ? rule->to_if_ptr->name : "any");

            retval = rulecreate_service_loop(
                    &vctx->conf, rule, create, &vctx->iptcaps);

            /* shaping rules */
            if (vrmr_is_shape_outgoing_rule(&create->option) == 1) {
                /* at this point we can create the tc rules */
                retval = shaping_shape_create_rule(&vctx->conf, rule,
                        rule->to_if_ptr, rule->from_if_ptr,
                        rule->shape_class_out, create->option.bw_in_min,
                        create->option.bw_in_min_unit, create->option.bw_in_max,
                        create->option.bw_in_max_unit, create->option.prio);
                if (retval < 0) {
                    return (retval);
                }
            }
            if (vrmr_is_shape_incoming_rule(&create->option) == 1) {
                /* at this point we can create the tc rules */
                retval = shaping_shape_create_rule(&vctx->conf, rule,
                        rule->from_if_ptr, rule->to_if_ptr,
                        rule->shape_class_in, create->option.bw_out_min,
                        create->option.bw_out_min_unit,
                        create->option.bw_out_max,
                        create->option.bw_out_max_unit, create->option.prio);
                if (retval < 0) {
                    return (retval);
                }
            }
        }
        return (retval);
    }

    /* any is gone now */

    int iterations = 0;
    if (create->to->type == VRMR_TYPE_HOST ||
            create->to->type == VRMR_TYPE_GROUP) {
        iterations = 1;
    } else if (create->to->type == VRMR_TYPE_NETWORK) {
        iterations = 1;
    } else if (create->to->type == VRMR_TYPE_ZONE) {
        for (d_node = vctx->zones.list.top; d_node != NULL;
                d_node = d_node->next) {
            struct vrmr_zone *zone_ptr = (struct vrmr_zone *)d_node->data;
            if (zone_ptr != NULL && zone_ptr->type == VRMR_TYPE_NETWORK &&
                    strcmp(zone_ptr->zone_name, create->to->name) == 0) {
                vrmr_list_append(&rule->to_network_list, zone_ptr);
            }
        }

        iterations = rule->to_network_list.len;
    }

    struct vrmr_list_node *net_d_node = NULL;
    int iter;
    for (iter = 0; iter < iterations; iter++) {
        d_node = NULL;

        if (create->to->type == VRMR_TYPE_HOST ||
                create->to->type == VRMR_TYPE_GROUP) {
            d_node = create->to->network_parent->InterfaceList.top;
        } else if (create->to->type == VRMR_TYPE_NETWORK) {
            d_node = create->to->InterfaceList.top;
        } else if (create->to->type == VRMR_TYPE_ZONE) {
            if (net_d_node == NULL)
                net_d_node = rule->to_network_list.top;
            else
                net_d_node = net_d_node->next;

            if (net_d_node != NULL) {
                rule->to_network = (struct vrmr_zone *)net_d_node->data;
                d_node = rule->to_network->InterfaceList.top;
            }
        }

        /* Loop through the interfaces */
        for (; d_node != NULL; d_node = d_node->next) {
            /* get the interface */
            if (!(rule->to_if_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            active = rule->to_if_ptr->active;

            /*  set the interface
                if the device is virtual (oldstyle) we don't want it in our
                iptables commands
             */
            if (rule->to_if_ptr->device_virtual_oldstyle == FALSE)
                (void)strlcpy(rule->to_int, rule->to_if_ptr->device,
                        sizeof(rule->to_int));
            else
                memset(rule->to_int, 0, sizeof(rule->to_int));

            if (rule->to_if_ptr->dynamic == TRUE &&
                    rule->to_if_ptr->up == FALSE) {
                vrmr_info("Info",
                        "not creating rule: 'to'-interface '%s' is dynamic and "
                        "down.",
                        rule->to_if_ptr->name);
                active = 0;
            }

#ifdef IPV6_ENABLED
            if (rule->ipv == VRMR_IPV6 &&
                    !vrmr_interface_ipv6_enabled(rule->to_if_ptr)) {
                active = 0;
            }
#endif
            if (active == 1) {
                /*  check for the 'out_int' rule option:
                    3 possibilities:

                    1. interface option set and match
                    2. interface option not set
                    3. to is 'any'
                 */
                vrmr_debug(HIGH,
                        "create->to_any '%s', "
                        "create->option.out_int '%s' "
                        "rule->to_if_ptr->name '%s'",
                        create->to_any ? "TRUE" : "FALSE",
                        create->option.out_int,
                        rule->to_if_ptr ? rule->to_if_ptr->name : "(null)");

                if ((create->to_any == FALSE && /* to is not any */
                            create->option.out_int[0] !=
                                    '\0' && /* interface option is set */
                            strcmp(create->option.out_int,
                                    rule->to_if_ptr->name) ==
                                    0) /* interface matches */
                        ||
                        (create->to_any == FALSE && /* to is not any */
                                create->option.out_int[0] ==
                                        '\0') /* interface option is not set */
                        || create->to_any ==
                                   TRUE /* 'any' doesn't use this filter */
                ) {
                    vrmr_debug(NONE, "dst interface %s", rule->to_if_ptr->name);

                    /* ok, continue */
                    retval = rulecreate_service_loop(
                            &vctx->conf, rule, create, &vctx->iptcaps);
                    if (retval < 0) {
                        return (retval);
                    }

                    /* shaping rules */
                    if (vrmr_is_shape_outgoing_rule(&create->option) == 1) {
                        /* at this point we can create the tc rules */
                        retval = shaping_shape_create_rule(&vctx->conf, rule,
                                rule->to_if_ptr, rule->from_if_ptr,
                                rule->shape_class_out, create->option.bw_in_min,
                                create->option.bw_in_min_unit,
                                create->option.bw_in_max,
                                create->option.bw_in_max_unit,
                                create->option.prio);
                        if (retval < 0) {
                            return (retval);
                        }
                    }
                    if (vrmr_is_shape_incoming_rule(&create->option) == 1) {
                        /* at this point we can create the tc rules */
                        retval = shaping_shape_create_rule(&vctx->conf, rule,
                                rule->from_if_ptr, rule->to_if_ptr,
                                rule->shape_class_in, create->option.bw_out_min,
                                create->option.bw_out_min_unit,
                                create->option.bw_out_max,
                                create->option.bw_out_max_unit,
                                create->option.prio);
                        if (retval < 0) {
                            return (retval);
                        }
                    }
                }
            }
        }
    }

    return (retval);
}

/** \internal
 *  \brief create rules for each src interface
 */
static int rulecreate_src_iface_loop(struct vrmr_ctx *vctx,
        struct rule_scratch *rule, struct vrmr_rule_cache *create)
{
    int retval = 0;
    struct vrmr_list_node *d_node = NULL;
    char active = 0;

    /* handle firewall -> any & firewall(any) */
    if (create->from_firewall_any == TRUE ||
            (create->from_firewall == TRUE && create->to_any == TRUE)) {
        /* clear the from_int to be sure */
        memset(rule->from_int, 0, sizeof(rule->from_int));

        /* assume active */
        active = 1;

        if (create->option.out_int[0] != '\0') /* interface option is set */
        {
            vrmr_debug(
                    NONE, "create->option.out_int %s", create->option.out_int);

            rule->from_if_ptr = vrmr_search_interface(
                    &vctx->interfaces, create->option.out_int);
            if (rule->from_if_ptr == NULL) {
                vrmr_error(-1, "Error", "interface '%s' not found",
                        create->option.in_int);
                return (-1);
            }

            active = rule->from_if_ptr->active;

            if (rule->from_if_ptr->device_virtual_oldstyle == FALSE)
                (void)strlcpy(rule->from_int, rule->from_if_ptr->device,
                        sizeof(rule->from_int));
            else
                memset(rule->from_int, 0, sizeof(rule->from_int));

            if (rule->from_if_ptr->dynamic == TRUE &&
                    rule->from_if_ptr->up == FALSE) {
                vrmr_info("Info",
                        "not creating rule: 'from'-interface '%s' is dynamic "
                        "and down.",
                        rule->from_if_ptr->name);
                active = 0;
            }
        }

        if (active == 1) {
            vrmr_debug(NONE, "src interface %s. Interface is active.",
                    rule->from_if_ptr ? rule->from_if_ptr->name : "any");

            retval = rulecreate_dst_iface_loop(vctx, rule, create);
        } else {
            vrmr_debug(NONE, "src interface %s. Interface is INACTIVE.",
                    rule->from_if_ptr ? rule->from_if_ptr->name : "any");
        }

        return (retval);
    }

    /* handle any */
    if (create->from_any == TRUE || create->from == NULL) {
        /* clear the from_int to be sure */
        memset(rule->from_int, 0, sizeof(rule->from_int));

        /* assume active */
        active = 1;

        if (create->option.in_int[0] != '\0') /* interface option is set */
        {
            rule->from_if_ptr = vrmr_search_interface(
                    &vctx->interfaces, create->option.in_int);
            if (rule->from_if_ptr == NULL) {
                vrmr_error(-1, "Error", "interface '%s' not found",
                        create->option.in_int);
                return (-1);
            }

            active = rule->from_if_ptr->active;

            if (rule->from_if_ptr->device_virtual_oldstyle == FALSE)
                (void)strlcpy(rule->from_int, rule->from_if_ptr->device,
                        sizeof(rule->from_int));
            else
                memset(rule->from_int, 0, sizeof(rule->from_int));

            if (rule->from_if_ptr->dynamic == TRUE &&
                    rule->from_if_ptr->up == FALSE) {
                vrmr_info("Info",
                        "not creating rule: 'from'-interface '%s' is dynamic "
                        "and down.",
                        rule->from_if_ptr->name);
                active = 0;
            }
        }

        if (active == 1) {
            vrmr_debug(NONE, "src interface %s. Interface is active.",
                    rule->from_if_ptr ? rule->from_if_ptr->name : "any");

            retval = rulecreate_dst_iface_loop(vctx, rule, create);
        } else {
            vrmr_debug(NONE,
                    "src interface %s. Interface is INACTIVE (any loop).",
                    rule->from_if_ptr ? rule->from_if_ptr->name : "any");
        }

        return (retval);
    }

    int iterations = 0;
    /* any is gone now */
    if (create->from->type == VRMR_TYPE_HOST ||
            create->from->type == VRMR_TYPE_GROUP) {
        iterations = 1;
    } else if (create->from->type == VRMR_TYPE_NETWORK) {
        iterations = 1;
    } else if (create->from->type == VRMR_TYPE_ZONE) {
        for (d_node = vctx->zones.list.top; d_node != NULL;
                d_node = d_node->next) {
            struct vrmr_zone *zone_ptr = (struct vrmr_zone *)d_node->data;
            if (zone_ptr != NULL && zone_ptr->type == VRMR_TYPE_NETWORK &&
                    strcmp(zone_ptr->zone_name, create->from->name) == 0) {
                vrmr_list_append(&rule->from_network_list, zone_ptr);
            }
        }

        iterations = rule->from_network_list.len;
    }

    struct vrmr_list_node *net_d_node = NULL;
    int iter;
    for (iter = 0; iter < iterations; iter++) {
        d_node = NULL;

        if (create->from->type == VRMR_TYPE_HOST ||
                create->from->type == VRMR_TYPE_GROUP) {
            d_node = create->from->network_parent->InterfaceList.top;
        } else if (create->from->type == VRMR_TYPE_NETWORK) {
            d_node = create->from->InterfaceList.top;
        } else if (create->from->type == VRMR_TYPE_ZONE) {
            if (net_d_node == NULL)
                net_d_node = rule->from_network_list.top;
            else
                net_d_node = net_d_node->next;

            if (net_d_node != NULL) {
                rule->from_network = (struct vrmr_zone *)net_d_node->data;
                d_node = rule->from_network->InterfaceList.top;
            }
        }

        /* Loop through the interfaces */
        for (; d_node != NULL; d_node = d_node->next) {
            /* get the interface */
            if (!(rule->from_if_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            active = rule->from_if_ptr->active;
            vrmr_debug(NONE, "active %d", active);

            /*  set the interface
                if the device is virtual (oldstyle) we don't want it in our
                iptables commands
             */
            if (rule->from_if_ptr->device_virtual_oldstyle == FALSE)
                (void)strlcpy(rule->from_int, rule->from_if_ptr->device,
                        sizeof(rule->from_int));
            else
                memset(rule->from_int, 0, sizeof(rule->from_int));

            if (rule->from_if_ptr->dynamic == TRUE &&
                    rule->from_if_ptr->up == FALSE) {
                vrmr_info("Info",
                        "not creating rule: 'from'-interface '%s' is dynamic "
                        "and down.",
                        rule->from_if_ptr->name);
                active = 0;
                vrmr_debug(NONE, "active %d (dynamic up check)", active);
            }
#ifdef IPV6_ENABLED
            if (rule->ipv == VRMR_IPV6 &&
                    !vrmr_interface_ipv6_enabled(rule->from_if_ptr)) {
                active = 0;
                vrmr_debug(NONE, "active %d (ipv6)", active);
            }
#endif
            if (active == 1) {
                /*  check for the 'in_int' rule option:
                    3 possibilities:

                    1. interface option set and match
                    2. interface option not set
                    3. from is 'any'
                 */
                vrmr_debug(HIGH,
                        "create->from_any '%s', "
                        "create->option.in_int '%s' rule->from_if_ptr->name "
                        "'%s'",
                        create->from_any ? "TRUE" : "FALSE",
                        create->option.in_int,
                        rule->from_if_ptr ? rule->from_if_ptr->name : "(null)");

                if ((create->from_any == FALSE && /* from is not any */
                            create->option.in_int[0] !=
                                    '\0' && /* interface option is set */
                            strcmp(create->option.in_int,
                                    rule->from_if_ptr->name) ==
                                    0) /* interface matches */
                        ||
                        (create->from_any == FALSE && /* from is not any */
                                create->option.in_int[0] ==
                                        '\0') /* interface option is not set */
                        || create->from_any ==
                                   TRUE /* 'any' doesn't use this filter */
                ) {
                    vrmr_debug(
                            NONE, "src interface %s", rule->from_if_ptr->name);

                    /* ok, continue */
                    retval = rulecreate_dst_iface_loop(vctx, rule, create);
                    if (retval < 0) {
                        return (retval);
                    }
                } else {
                    vrmr_debug(NONE, "src interface %s. Interface is FILTERED.",
                            rule->from_if_ptr->name);
                }
            } else {
                vrmr_debug(NONE,
                        "src interface %s. Interface is INACTIVE (final loop).",
                        rule->from_if_ptr->name);
            }
        }
    }

    return (retval);
}

/** \internal
 *  \brief create IPv4 and IPv6 rules
 *  \retval 0 ok */
static int rulecreate_ipv4ipv6_loop(struct vrmr_ctx *vctx,
        /*@null@*/ struct rule_set *ruleset, struct rule_scratch *rule,
        struct vrmr_rule_cache *create)
{
    if (ruleset == NULL || ruleset->ipv == VRMR_IPV4) {
        rule->ipv = VRMR_IPV4;

        if (rulecreate_src_iface_loop(vctx, rule, create) < 0) {
            vrmr_error(-1, "Error", "rulecreate_src_iface_loop() failed");
        }
    }

#ifdef IPV6_ENABLED
    if (ruleset == NULL || ruleset->ipv == VRMR_IPV6) {
        rule->ipv = VRMR_IPV6;

        /* rules can explicitly set a the reject option, which will be IPv4
         * only. */
        if (strncasecmp(rule->action, "REJECT --reject-with", 20) == 0 &&
                strncasecmp(rule->action, "REJECT --reject-with tcp-reset",
                        30) != 0)
            strlcpy(rule->action, "REJECT", sizeof(rule->action));

        if (rulecreate_src_iface_loop(vctx, rule, create) < 0) {
            vrmr_error(-1, "Error", "rulecreate_src_iface_loop() failed");
        }
    }
#endif

    return 0;
}

/*  create_rule

    This fuctions creates the actual rule.

    Returncodes:
         0: ok
        -1: error
*/
int create_rule(struct vrmr_ctx *vctx,
        /*@null@*/ struct rule_set *ruleset, struct vrmr_rule_cache *create)
{
    int retval = 0;
    struct rule_scratch *rule = NULL;

    vrmr_debug(HIGH, "** start ** (create->action: %s).", create->action);

    /* here we print the description if we are in bashmode */
    if (vctx->conf.bash_out == TRUE && create->description != NULL) {
        fprintf(stdout, "\n# %s\n", create->description);
    }

    /* clear counters */
    create->iptcount.input = 0, create->iptcount.output = 0,
    create->iptcount.forward = 0, create->iptcount.preroute = 0,
    create->iptcount.postroute = 0;

    /* if bash, print comment (if any) */
    if (create->option.rule_comment == TRUE && vctx->conf.bash_out == TRUE) {
        fprintf(stdout, "# comment: '%s'%s\n", create->option.comment,
                create->active ? "" : " (rule inactive)");
    }

    if (create->active == 0)
        return (0);

    /* alloc the temp rule data */
    if (!(rule = malloc(sizeof(struct rule_scratch)))) {
        vrmr_error(-1, "Error", "malloc failed: %s", strerror(errno));
        return (-1);
    }
    /* init */
    memset(rule, 0, sizeof(struct rule_scratch));
    vrmr_list_setup(&rule->iptrulelist, free);
    vrmr_list_setup(&rule->shaperulelist, free);
    vrmr_list_setup(&rule->from_network_list, NULL);
    vrmr_list_setup(&rule->to_network_list, NULL);

    /* copy the helper */
    if (create->service != NULL)
        (void)strlcpy(
                rule->helper, create->service->helper, sizeof(rule->helper));

    /* SHAPING PREPARATION */
    if (vrmr_is_shape_rule(&create->option) == 1) {
        rule->shape_class_out = vctx->interfaces.shape_handle;
        vctx->interfaces.shape_handle++;
        rule->shape_class_in = vctx->interfaces.shape_handle;
        vctx->interfaces.shape_handle++;

        vrmr_debug(NONE, "rule->shape_class_out %u rule->shape_class_in %u",
                rule->shape_class_out, rule->shape_class_in);
    }

    if (rulecreate_ipv4ipv6_loop(vctx, ruleset, rule, create) < 0) {
        vrmr_error(-1, "Error", "rulecreate_src_iface_loop() failed");
    }

    /* process the rules */
    process_queued_rules(&vctx->conf, ruleset, rule);
    shaping_process_queued_rules(&vctx->conf, ruleset, rule);

    /* free the temp data */
    vrmr_list_cleanup(&rule->iptrulelist);
    vrmr_list_cleanup(&rule->shaperulelist);
    vrmr_list_cleanup(&rule->from_network_list);
    vrmr_list_cleanup(&rule->to_network_list);
    free(rule);

    return (retval);
}

/*  remove_rule

    Function for removing iptables rules.

    Returncodes:
         0: ok
        -1: error
*/
int remove_rule(
        struct vrmr_config *conf, int chaintype, int first_ipt_rule, int rules)
{
    int retval = 0, i;
    char cmd[VRMR_MAX_PIPE_COMMAND];
    char chain[64];

    vrmr_debug(HIGH, "** start **");
    vrmr_debug(HIGH, "chain: %d, ipt: %d, rules: %d", chaintype, first_ipt_rule,
            rules);

    /* determine from which chain to delete */
    if (chaintype == VRMR_RT_INPUT) {
        (void)strlcpy(chain, "-D INPUT", sizeof(chain));
    } else if (chaintype == VRMR_RT_OUTPUT) {
        (void)strlcpy(chain, "-D OUTPUT", sizeof(chain));
    } else if (chaintype == VRMR_RT_FORWARD) {
        (void)strlcpy(chain, "-D FORWARD", sizeof(chain));
    } else if (chaintype == VRMR_RT_PORTFW || chaintype == VRMR_RT_REDIRECT) {
        (void)strlcpy(chain, "-t nat -D PREROUTING", sizeof(chain));
    } else if (chaintype == VRMR_RT_MASQ || chaintype == VRMR_RT_SNAT) {
        (void)strlcpy(chain, "-t nat -D POSTROUTING", sizeof(chain));
    } else {
        vrmr_error(
                -1, "Error", "unknown chaintype %d (remove_rule).", chaintype);
        return (-1);
    }

    for (i = 0; i < rules; i++) {
        vrmr_debug(HIGH, "cmd: %s %s %d", conf->iptables_location, chain,
                first_ipt_rule);

        snprintf(cmd, sizeof(cmd), "%s %s %d", conf->iptables_location, chain,
                first_ipt_rule);
        if (vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE) != 0) {
            vrmr_error(-1, "Error",
                    "remove_rule: pipe error. This command failed: '%s'.", cmd);
            return (-1);
        }
    }

    vrmr_debug(HIGH, "** end **, return=%d", retval);
    return (retval);
}

int create_system_protectrules(struct vrmr_config *conf)
{
    assert(conf);

    vrmr_debug(HIGH, "protect proc systemwide... ");

    /* syncookies */
    vrmr_debug(MEDIUM, "Setting '%d' to '%s'... ", conf->protect_syncookie,
            "/proc/sys/net/ipv4/tcp_syncookies");

    int result = vrmr_set_proc_entry(conf, "/proc/sys/net/ipv4/tcp_syncookies",
            conf->protect_syncookie, NULL);
    if (result != 0) {
        /* if it fails, we dont really care, its not fatal */
        vrmr_error(-1, "Error", "vrmr_set_proc_entry failed");
    }

    /* echo broadcasts */
    vrmr_debug(MEDIUM, "Setting '%d' to '%s'... ", conf->protect_echobroadcast,
            "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts");

    result = vrmr_set_proc_entry(conf,
            "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
            conf->protect_echobroadcast, NULL);
    if (result != 0) {
        /* if it fails, we dont really care, its not fatal */
        vrmr_error(-1, "Error", "vrmr_set_proc_entry failed");
    }

    return (0);
}

int create_normal_rules(struct vrmr_ctx *vctx,
        /*@null@*/ struct rule_set *ruleset, char *forward_rules)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_rule *rule_ptr = NULL;
    char active = 0;
    int rulescount = 0;

    /* walk trough the ruleslist and create the rules */
    for (d_node = vctx->rules.list.top; d_node; d_node = d_node->next) {
        if (!(rule_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        /* asume active when we begin */
        active = TRUE;

        /* count the rules */
        rulescount++;

        /* check normal rule */
        if (rule_ptr->rulecache.from != NULL &&
                rule_ptr->rulecache.from->active == FALSE)
            active = FALSE;
        if (rule_ptr->rulecache.to != NULL &&
                rule_ptr->rulecache.to->active == FALSE)
            active = FALSE;
        if (rule_ptr->rulecache.service != NULL &&
                rule_ptr->rulecache.service->active == FALSE)
            active = FALSE;

        /* check protect rule */
        if (rule_ptr->rulecache.who != NULL) {
            if (rule_ptr->rulecache.who->active == FALSE) {
                active = FALSE;
            }
        }

        /* create the rule */
        if (active == TRUE) {
            if (rule_ptr->action == VRMR_AT_SEPARATOR) {
                /* here we print the description if we are in bashmode */
                if (vctx->conf.bash_out == TRUE &&
                        rule_ptr->rulecache.description != NULL) {
                    fprintf(stdout, "\n#\n# %s\n#\n",
                            rule_ptr->rulecache.description);
                }
            } else {
                if (create_rule(vctx, ruleset, &rule_ptr->rulecache) == 0) {
                    vrmr_debug(HIGH, "rule created succesfully.");

                    if (rule_ptr->rulecache.iptcount.forward > 0)
                        *forward_rules = 1;
                } else {
                    vrmr_warning(
                            "Warning", "Creating rule %d failed.", rulescount);
                }
            }
        } else {
            vrmr_info("Note", "Rule %d not created: inactive.", rulescount);
        }

        /* make sure the bash comment memory is cleared */
        if (rule_ptr->rulecache.description != NULL) {
            free(rule_ptr->rulecache.description);
            rule_ptr->rulecache.description = NULL;
        }
    }

    return (0);
}

/*  clear_vuurmuur_iptables_rule

    Clears vuurmuur rules and chains created by Vuurmuur.
    For use with the -Y commandline option.

    Returncodes:
        -1: error
         0: ok
*/
static int clear_vuurmuur_iptables_rules_ipv4(struct vrmr_config *conf)
{
    int retval = 0, result = 0;
    struct vrmr_rules rules;
    char *chainname = NULL;
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_list_node *chains[3];
    char *tables[] = {"mangle", "filter", "nat"};
    int table;
    char PRE_VRMR_CHAINS_PREFIX[] = "PRE-VRMR-";
    char cmd[VRMR_MAX_PIPE_COMMAND] = "";

    assert(conf);

    /* get the current chains */
    (void)vrmr_rules_get_system_chains(&rules, conf, VRMR_IPV4);

    /* prepare chains tab with nodes for loop */
    chains[0] = rules.system_chain_mangle.top;
    chains[1] = rules.system_chain_filter.top;
    chains[2] = rules.system_chain_nat.top;

    for (table = 0; table < 3; table++) {
        for (d_node = chains[table]; d_node; d_node = d_node->next) {
            if (!(chainname = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            if (strncmp(chainname, PRE_VRMR_CHAINS_PREFIX,
                        strlen(PRE_VRMR_CHAINS_PREFIX)) != 0) {
                vrmr_debug(LOW,
                        "flushing %s chain in %s "
                        "table.",
                        chainname, tables[table]);

                snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s -t %s --flush %s",
                        conf->iptables_location, tables[table], chainname);

                result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
                if (result < 0)
                    retval = -1;
            } else {
                vrmr_debug(LOW,
                        "skipping flush of %s "
                        "chain in %s table.",
                        chainname, tables[table]);
            }
        }
    }

    /* set default polices to ACCEPT */
    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy INPUT ACCEPT",
            conf->iptables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy OUTPUT ACCEPT",
            conf->iptables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy FORWARD ACCEPT",
            conf->iptables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    return (retval);
}

#ifdef IPV6_ENABLED
/*  clear_vuurmuur_iptables_rule

    Clears vuurmuur rules and chains created by Vuurmuur.
    For use with the -Y commandline option.

    Returncodes:
        -1: error
         0: ok
*/
static int clear_vuurmuur_iptables_rules_ipv6(struct vrmr_config *conf)
{
    int retval = 0, result = 0;
    struct vrmr_rules rules;
    char *chainname = NULL;
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_list_node *chains[2];
    char *tables[] = {"mangle", "filter"};
    int table;
    char PRE_VRMR_CHAINS_PREFIX[] = "PRE-VRMR-";
    char cmd[VRMR_MAX_PIPE_COMMAND] = "";

    assert(conf);

    /* get the current chains */
    (void)vrmr_rules_get_system_chains(&rules, conf, VRMR_IPV6);

    /* prepare chains tab with nodes for loop */
    chains[0] = rules.system_chain_mangle.top;
    chains[1] = rules.system_chain_filter.top;

    for (table = 0; table < 2; table++) {
        for (d_node = chains[table]; d_node; d_node = d_node->next) {
            if (!(chainname = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            if (strncmp(chainname, PRE_VRMR_CHAINS_PREFIX,
                        strlen(PRE_VRMR_CHAINS_PREFIX)) != 0) {
                vrmr_debug(LOW,
                        "flushing %s chain in %s "
                        "table.",
                        chainname, tables[table]);

                snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s -t %s --flush %s",
                        conf->ip6tables_location, tables[table], chainname);

                result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
                if (result < 0)
                    retval = -1;
            } else {
                vrmr_debug(LOW,
                        "skipping flush of %s "
                        "chain in %s table.",
                        chainname, tables[table]);
            }
        }
    }

    /* set default polices to ACCEPT */
    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy INPUT ACCEPT",
            conf->ip6tables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy OUTPUT ACCEPT",
            conf->ip6tables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy FORWARD ACCEPT",
            conf->ip6tables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    return (retval);
}
#endif

/*  clear_vuurmuur_iptables_rule

    Clears vuurmuur rules and chains created by Vuurmuur.
    For use with the -Y commandline option.

    Returncodes:
        -1: error
         0: ok
*/
int clear_vuurmuur_iptables_rules(struct vrmr_config *cnf)
{
    int retval = 0;

    if (clear_vuurmuur_iptables_rules_ipv4(cnf) < 0) {
        vrmr_error(-1, "Error", "clearing IPv4 rules failed.");
        retval = -1;
    }

#ifdef IPV6_ENABLED
    if (clear_vuurmuur_iptables_rules_ipv6(cnf) < 0) {
        vrmr_error(-1, "Error", "clearing IPv6 rules failed.");
        retval = -1;
    }
#endif

    return (retval);
}

static int clear_all_iptables_rules_ipv4(struct vrmr_config *conf)
{
    int retval = 0, result = 0;
    char cmd[VRMR_MAX_PIPE_COMMAND] = "";

    /* flush everything */
    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s -t filter --flush",
            conf->iptables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s -t nat --flush",
            conf->iptables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s -t mangle --flush",
            conf->iptables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    /* this will remove the all chains in {filter,nat,mangle} tables */
    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s %s -X 2>/dev/null",
            conf->iptables_location, TB_FILTER);
    (void)vrmr_pipe_command(conf, cmd, VRMR_PIPE_QUIET);

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s %s -X 2>/dev/null",
            conf->iptables_location, TB_NAT);
    (void)vrmr_pipe_command(conf, cmd, VRMR_PIPE_QUIET);

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s %s -X 2>/dev/null",
            conf->iptables_location, TB_MANGLE);
    (void)vrmr_pipe_command(conf, cmd, VRMR_PIPE_QUIET);

    /* set default polices to ACCEPT */
    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy INPUT ACCEPT",
            conf->iptables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy OUTPUT ACCEPT",
            conf->iptables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy FORWARD ACCEPT",
            conf->iptables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    return (retval);
}

#ifdef IPV6_ENABLED
static int clear_all_iptables_rules_ipv6(struct vrmr_config *conf)
{
    int retval = 0, result = 0;
    char cmd[VRMR_MAX_PIPE_COMMAND] = "";

    /* flush everything */
    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s -t filter --flush",
            conf->ip6tables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s -t mangle --flush",
            conf->ip6tables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    /* this will remove the all chains in {filter,nat,mangle} tables */
    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s %s -X 2>/dev/null",
            conf->ip6tables_location, TB_FILTER);
    (void)vrmr_pipe_command(conf, cmd, VRMR_PIPE_QUIET);

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s %s -X 2>/dev/null",
            conf->ip6tables_location, TB_MANGLE);
    (void)vrmr_pipe_command(conf, cmd, VRMR_PIPE_QUIET);

    /* set default polices to ACCEPT */
    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy INPUT ACCEPT",
            conf->ip6tables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy OUTPUT ACCEPT",
            conf->ip6tables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    snprintf(cmd, VRMR_MAX_PIPE_COMMAND, "%s --policy FORWARD ACCEPT",
            conf->ip6tables_location);
    result = vrmr_pipe_command(conf, cmd, VRMR_PIPE_VERBOSE);
    if (result < 0)
        retval = -1;

    return (retval);
}
#endif

/*  clear_all_iptables_rule

    Clears all rules and chains created by Vuurmuur.
    For use with the -C commandline option.

    Returncodes:
        -1: error
         0: ok
*/
int clear_all_iptables_rules(struct vrmr_config *conf)
{
    int retval = 0;

    if (clear_all_iptables_rules_ipv4(conf) < 0) {
        vrmr_error(-1, "Error", "clearing IPv4 rules failed");
        retval = -1;
    }

#ifdef IPV6_ENABLED
    if (clear_all_iptables_rules_ipv6(conf) < 0) {
        vrmr_error(-1, "Error", "clearing IPv4 rules failed");
        retval = -1;
    }
#endif

    return (retval);
}

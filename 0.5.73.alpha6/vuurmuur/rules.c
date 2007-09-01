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
 * Here we try to create the actual rule.                                  *
 ***************************************************************************/
#include "main.h"

/* iptables tables */
#define TB_FILTER		"-t filter"
#define TB_MANGLE		"-t mangle"
#define TB_NAT			"-t nat"


void
create_loglevel_string(const int debuglvl, struct vuurmuur_config *cnf, char *resultstr, size_t size)
{
	/* safety */
	if(resultstr == NULL || cnf == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return;
	}
	/* clear */
	memset(resultstr, 0, size);

	/* do it man */
	if(strcmp(cnf->loglevel, "") != 0)
	{
		/* create the loglevel string */
		if(snprintf(resultstr, size, "--log-level %s", cnf->loglevel) >= (int)size)
		{
			(void)vrprint.error(-1, "Error", "buffer overrun (in: %s:%d).", __FUNC__, __LINE__);
			return;
		}
	}

	return;
}


void
create_logtcpoptions_string(const int debuglvl, struct vuurmuur_config *cnf, char *resultstr, size_t size)
{
	/* safety */
	if(resultstr == NULL || cnf == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return;
	}
	/* clear */
	memset(resultstr, 0, size);

	/* do it man */
	if(cnf->log_tcp_options == 1)
	{
		/* create the loglevel string */
		if(snprintf(resultstr, size, "--log-tcp-options") >= (int)size)
		{
			(void)vrprint.error(-1, "Error", "buffer overrun (in: %s:%d).", __FUNC__, __LINE__);
			return;
		}
	}

	return;
}


void
create_logprefix_string(const int debuglvl, char *resultstr, size_t size,
			int ruletype, char *action, char *userprefix, ...)
{
	char		str[33] = "",
			tmp_str[33] = "";
	va_list		ap;

	/* safety */
	if(resultstr == NULL || action == NULL || userprefix == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return;
	}
	/* clear */
	memset(resultstr, 0, size);

	/* copy the userprefix-prefix */
	(void)strlcpy(str, LOGPREFIX_PREFIX, LOGPREFIX_LOG_MAXLEN);

	/* we dont want 'TCPRESET' in the log, just 'REJECT' */
	if(strcmp(action, "TCPRESET") == 0)
		(void)strlcat(str, "REJECT", LOGPREFIX_LOG_MAXLEN);
	/* we dont want 'MASQUERADE' in the log, just 'MASQ' */
	else if(strcmp(action, "MASQUERADE") == 0)
		(void)strlcat(str, "MASQ", LOGPREFIX_LOG_MAXLEN);
	else if(strcmp(action, "NEWACCEPT") == 0)
		(void)strlcat(str, "ACCEPT", LOGPREFIX_LOG_MAXLEN);
	else if(strcmp(action, "NEWQUEUE") == 0)
		(void)strlcat(str, "QUEUE", LOGPREFIX_LOG_MAXLEN);
	else if(strcmp(action, "NEWNFQUEUE") == 0)
		(void)strlcat(str, "NFQUEUE", LOGPREFIX_LOG_MAXLEN);
	else if(strncmp(action, "DNAT", 4) == 0)
	{
		if(ruletype == RT_PORTFW)
			(void)strlcat(str, "PORTFW", LOGPREFIX_LOG_MAXLEN);
		else if(ruletype == RT_DNAT)
			(void)strlcat(str, "DNAT", LOGPREFIX_LOG_MAXLEN);
		else if(ruletype == RT_BOUNCE)
			(void)strlcat(str, "BOUNCE", LOGPREFIX_LOG_MAXLEN);
		else
			(void)strlcat(str, "DNAT", LOGPREFIX_LOG_MAXLEN);
	}
	else
		(void)strlcat(str, action, LOGPREFIX_LOG_MAXLEN);

	(void)strlcat(str, " ", LOGPREFIX_LOG_MAXLEN);

	/* copy the userprefix */
	va_start(ap, userprefix);
	vsnprintf(tmp_str, sizeof(tmp_str), userprefix, ap);
	(void)strlcat(str, tmp_str, LOGPREFIX_LOG_MAXLEN);
	va_end(ap);

	/* create the prefix */
	snprintf(resultstr, size, "--log-prefix \"%s \"", str);

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "str: '%s', resultstr: '%s'.", str, resultstr);

	return;
}


int
oldrules_create_custom_chains(const int debuglvl, Rules *rules, struct vuurmuur_config *cnf)
{
	char		*chainname = NULL;
	d_list_node	*d_node = NULL;
	char		cmd[128] = "";

	/* safety */
	if(rules == NULL || cnf == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
									__FUNC__, __LINE__);
		return(-1);
	}

	/* get the current chains */
	(void)rules_get_system_chains(debuglvl, rules, cnf);
	/* get the custom chains we have to create */
	if(rules_get_custom_chains(debuglvl, rules) < 0)
	{
		(void)vrprint.error(-1, "Internal Error", "rules_get_chains() failed (in: %s:%d).",
									__FUNC__, __LINE__);
		return(-1);
	}

	for(d_node = rules->custom_chain_list.top; d_node; d_node = d_node->next)
	{
		if(!(chainname = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
									__FUNC__, __LINE__);
			return(-1);
		}

		if(rules_chain_in_list(debuglvl, &rules->system_chain_filter, chainname) == 0)
		{
			snprintf(cmd, sizeof(cmd), "%s -N %s", cnf->iptables_location, chainname);
			(void)pipe_command(debuglvl, cnf, cmd, PIPE_QUIET);
		}
	}

	/* list of chains in the system */
	d_list_cleanup(debuglvl, &rules->system_chain_filter);
	d_list_cleanup(debuglvl, &rules->system_chain_mangle);
	d_list_cleanup(debuglvl, &rules->system_chain_nat);
	//d_list_cleanup(debuglvl, &rules->system_chain_raw);
	/* cleanup */
	d_list_cleanup(debuglvl, &rules->custom_chain_list);

	return(0);
}


int
analyze_interface_rules(const int debuglvl,
				Rules *rules,
				Zones *zones,
				Services *services,
				Interfaces *interfaces)
{
	struct RuleData_	*rule_ptr = NULL;
	d_list_node		*d_node = NULL,
				*if_d_node = NULL;
	struct InterfaceData_	*iface_ptr = NULL;

	/* safety */
	if(rules == NULL || zones == NULL || services == NULL || interfaces == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
									__FUNC__, __LINE__);
		return(-1);
	}


	/* first analyze the protectrules in the interfaces */
	for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
	{
		if(!(iface_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}
	
		for(if_d_node = iface_ptr->ProtectList.top; if_d_node; if_d_node = if_d_node->next)
		{
			if(!(rule_ptr = if_d_node->data))
			{
				(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
				return(-1);
			}

			if(interfaces_analyze_rule(debuglvl, rule_ptr, &rule_ptr->rulecache, interfaces, &conf) == 0)
			{
				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "analizing protectrule success, active = 1.");

				rule_ptr->active = 1;
			}
			else
			{
				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "analizing protectrule failed, active = 0.");

				rule_ptr->active = 0;
			}
		}
	}

	return(0);
}


int
analyze_network_protect_rules(const int debuglvl, Rules *rules, Zones *zones, Services *services, Interfaces *interfaces)
{
	struct RuleData_	*rule_ptr = NULL;
	d_list_node		*d_node = NULL,
				*net_d_node = NULL;
	struct ZoneData_	*zone_ptr = NULL;

	/* safety */
	if(!rules || !zones || !services || !interfaces)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}


	/* first analyze the protectrules in the network */
	for(d_node = zones->list.top; d_node; d_node = d_node->next)
	{
		if(!(zone_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}
	
		if(zone_ptr->type == TYPE_NETWORK)
		{
			for(net_d_node = zone_ptr->ProtectList.top; net_d_node; net_d_node = net_d_node->next)
			{
				if(!(rule_ptr = net_d_node->data))
				{
					(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
					return(-1);
				}

				if(zones_network_analyze_rule(debuglvl, rule_ptr, &rule_ptr->rulecache, zones, &conf) == 0)
				{
					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "analizing protectrule success, active = 1.");

					rule_ptr->active = 1;
				}
				else
				{
					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "analizing protectrule failed, active = 0.");

					rule_ptr->active = 0;
				}
			}
		}
	}

	return(0);
}


int
analyze_normal_rules(const int debuglvl, Rules *rules, Zones *zones, Services *services, Interfaces *interfaces)
{
	struct RuleData_	*rule_ptr = NULL;
	unsigned int		rulescount = 0,
				rulesfailedcount = 0;
	d_list_node		*d_node = NULL,
				*next_d_node = NULL;

	/* safety */
	if(!rules || !zones || !services || !interfaces)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
									__FUNC__, __LINE__);
		return(-1);
	}

	/* check if the list is not empty. If it is, d_node will be NULL. */
	if(rules->list.len > 0)
	{
		/*	Get the top of the list. This should never fail because
			we already checked the listsize.
		*/
		if(!(d_node = rules->list.top))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
									__FUNC__, __LINE__);
			return(-1);
		}
	}

	/* if we have a node, continue */
	for(;d_node;)
	{
		rulescount++;

		if(!(rule_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
									__FUNC__, __LINE__);
			return(-1);
		}

		/* analyze! */
		if(rules_analyze_rule(debuglvl, rule_ptr, &rule_ptr->rulecache, services, zones, interfaces, &conf) == 0)
		{
			if(debuglvl >= MEDIUM)
				(void)vrprint.debug(__FUNC__, "rules_analyze_rule %3u ok.", rulescount);

			/* update d_node */
			d_node = d_node->next;
		}
		else
		{
			(void)vrprint.warning("Warning", "Analyzing rule %u failed.", rulescount);
			rulesfailedcount++;

			/* update node before removing */
			next_d_node = d_node->next;

			/* remove the failed rule from the list */
			if(d_list_remove_node(debuglvl, &rules->list, d_node) < 0)
			{
				(void)vrprint.error(-1, "Internal Error", "d_list_remove_node() failed (in: %s:%d).",
												__FUNC__, __LINE__);
				return(-1);
			}

			/* now update the number in the list */
			//rules_update_numbers(debuglvl, rules, rulescount - rulesfailedcount + 1, 0);

			free_options(debuglvl, rule_ptr->opt);
			free(rule_ptr);
			rule_ptr = NULL;

			/* set d_node to the next_d_node */
			d_node = next_d_node;
		}
	}

	return(0);
}


/*	analyze_all_rules

	Analyzes all rules :-)

	Returncodes:
		 0: ok
		-1: error
*/
int
analyze_all_rules(const int debuglvl, Rules *rules, Zones *zones, Services *services, Interfaces *interfaces)
{
	/* safety */
	if(!rules || !zones || !services || !interfaces)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	(void)vrprint.info("Info", "Analyzing the rules... ");

	/* interface rules */
	if(analyze_interface_rules(debuglvl, rules, zones, services, interfaces) < 0)
		return(-1);

	/* network rules */
	if(analyze_network_protect_rules(debuglvl, rules, zones, services, interfaces) < 0)
		return(-1);

	/* normal rules */
	if(analyze_normal_rules(debuglvl, rules, zones, services, interfaces) < 0)
		return(-1);

	return(0);
}


/*	create_all_rules

	Creates all rules.

	If 'create_prerules' is set to 1, prerules() will be called.

	Returncodes:
		 0: ok
		-1: error
*/
int
create_all_rules(	const int debuglvl,
			Rules *rules,
			Zones *zones,
			Interfaces *interfaces,
			BlockList *blocklist,
			IptCap *iptcap,
			struct vuurmuur_config *cnf,
			int create_prerules)
{
	int		result = 0;
	char		forward_rules = 0;

	/* safety */
	if(rules == NULL || interfaces == NULL || blocklist == NULL || iptcap == NULL || cnf == NULL || create_prerules < 0 || create_prerules > 1)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
									__FUNC__, __LINE__);
		return(-1);
	}

	(void)vrprint.info("Info", "Creating the rules... (rules to create: %d)", rules->list.len);

	/* create the prerules if were called with it */
	if(create_prerules)
	{
		result = pre_rules(debuglvl, NULL, interfaces, iptcap);
		if(result < 0)
			return(-1);
	}

	/* create the nfqueue state rules */
	if(create_newnfqueue_rules(debuglvl, NULL, rules) < 0)
	{
		(void)vrprint.error(-1, "Error", "create nfqueue state failed.");
	}
	if(create_estrelnfqueue_rules(debuglvl, NULL, rules) < 0)
	{
		(void)vrprint.error(-1, "Error", "create nfqueue state failed.");
	}

	/* create the blocklist */
	if(create_block_rules(debuglvl, NULL, blocklist) < 0)
	{
		(void)vrprint.error(-1, "Error", "create blocklist failed.");
	}

	/* create the interface rules */
	if(create_interface_rules(debuglvl, NULL, interfaces) < 0)
	{
		(void)vrprint.error(-1, "Error", "create protectrules failed.");
	}
	/* create the network protect rules (anti-spoofing) */
	if(create_network_protect_rules(debuglvl, NULL, zones, iptcap) < 0)
	{
		(void)vrprint.error(-1, "Error", "create protectrules failed.");
	}
	/* system protect rules (proc) */
	if(create_system_protectrules(debuglvl, &conf) < 0)
	{
		(void)vrprint.error(-1, "Error", "create protectrules failed.");
	}
	/* create custom chains if needed */
	if(oldrules_create_custom_chains(debuglvl, rules, cnf) < 0)
	{
		(void)vrprint.error(-1, "Error", "create custom chains failed.");
	}
	/* normal rules, ruleset == NULL */
	if(create_normal_rules(debuglvl, NULL, rules, interfaces, iptcap, &forward_rules) < 0)
	{
		(void)vrprint.error(-1, "Error", "create normal rules failed.");
	}

	/* post rules: enable logging */
	if(post_rules(debuglvl, NULL, iptcap, forward_rules) < 0)
		return(-1);

	(void)vrprint.info("Info", "Creating rules finished.");
	return(0);
}


static int
create_rule_set_ports(struct RuleCreateData_ *rule, struct portdata *portrange_ptr)
{
	/* from */
	if(portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17)
	{
		if(portrange_ptr->src_high == 0)
			snprintf(rule->temp_src_port, sizeof(rule->temp_src_port), "--sport %d", portrange_ptr->src_low);
		else
			snprintf(rule->temp_src_port, sizeof(rule->temp_src_port), "--sport %d:%d", portrange_ptr->src_low, portrange_ptr->src_high);
	}
	else if(portrange_ptr->protocol == 1 || portrange_ptr->protocol == 47 || portrange_ptr->protocol == 50 || portrange_ptr->protocol == 51)
		snprintf(rule->temp_src_port, sizeof(rule->temp_src_port), " ");

	/* to */
	if(portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17)
	{
		if(portrange_ptr->dst_high == 0)
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d", portrange_ptr->dst_low);
		else
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d:%d", portrange_ptr->dst_low, portrange_ptr->dst_high);
	}
	else if(portrange_ptr->protocol == 1)
	{
		if(portrange_ptr->dst_high == -1)
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--icmp-type %d", portrange_ptr->dst_low);
		else
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--icmp-type %d/%d", portrange_ptr->dst_low, portrange_ptr->dst_high);
	}
	else if(portrange_ptr->protocol == 47 || portrange_ptr->protocol == 50 || portrange_ptr->protocol == 51)
		snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), " ");

	return(0);
}


static int
create_rule_set_proto(struct RuleCreateData_ *rule, struct RuleCache_ *create)
{
	/* safety */
	if(rule == NULL || create == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	if(rule->portrange_ptr != NULL)
	{
		/* tcp */
		if(rule->portrange_ptr->protocol == 6)
			(void)strlcpy(rule->proto, "-p tcp -m tcp --syn", sizeof(rule->proto));
		/* udp */
		else if(rule->portrange_ptr->protocol == 17)
			(void)strlcpy(rule->proto, "-p udp -m udp", sizeof(rule->proto));
		/* icmp */
		else if(rule->portrange_ptr->protocol == 1)
			(void)strlcpy(rule->proto, "-p icmp -m icmp", sizeof(rule->proto));
		/* gre */
		else if(rule->portrange_ptr->protocol == 47)
			(void)strlcpy(rule->proto, "-p gre", sizeof(rule->proto));
		else
		{
			if(rule->portrange_ptr->protocol > 0 && rule->portrange_ptr->protocol <= 255)
				snprintf(rule->proto, sizeof(rule->proto), "-p %d", rule->portrange_ptr->protocol);
			else
				(void)strlcpy(rule->proto, "", sizeof(rule->proto));
		}
	}
	
	/* handle service 'any' */
	if(create->service_any == TRUE)
	{
		memset(rule->proto, 0, sizeof(rule->proto));
		memset(rule->temp_src_port, 0, sizeof(rule->temp_src_port));
		memset(rule->temp_dst_port, 0, sizeof(rule->temp_dst_port));
	}

	return(0);
}


static int
create_rule_set_action_and_ip(const int debuglvl, struct RuleCreateData_ *rule, struct RuleCache_ *create, IptCap *iptcap)
{
	char		action[64] = ""; /* if changes to size: see sscanf below as well */
	char		logprefix[64] = "";
	unsigned int	limit = 0;
	unsigned int	burst = 0;
	char		*unit = NULL;

	/* safety */
	if(!rule || !create)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/*	clear rule->limit because we only use it with log rules and if loglimit > 0
		and if iptables has the capability
	*/
	memset(rule->limit, 0, sizeof(rule->limit));

	/* get the first part of the action, because action can be like this: REJECT --reject-type icmp-adm.... */
	sscanf(create->action, "%64s", action);

	/* if we want to log a rule, but havent done it yet: */
	if(create->option.rule_log && !rule->logged)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "log the rule.");

		/* create the limitstring */
		if(conf.check_iptcaps == FALSE || iptcap->match_limit == TRUE)
		{
			if(create->option.loglimit > 0) {
				limit = create->option.loglimit;
                                unit = "sec";
                        } else {
				limit = create->option.limit;
                                unit = create->option.limit_unit;
                        }

			if(create->option.logburst > 0)
				burst = create->option.logburst;
			else
				burst = create->option.burst;

			/* set the limit */
			if(limit > 0 && burst > 0)
				snprintf(rule->limit, sizeof(rule->limit), "-m limit --limit %u/%s --limit-burst %u",
											limit, unit, burst);
			else if(limit > 0 && burst == 0)
				snprintf(rule->limit, sizeof(rule->limit), "-m limit --limit %u/%s",
											limit, unit);
		}

		/* create the logprefix string */
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), create->ruletype, action, "%s", create->option.logprefix);

		/* create the action */
		snprintf(rule->action, sizeof(rule->action), "LOG %s %s %s",
								logprefix,
								loglevel,
								log_tcp_options);

		/* set ip and netmask */
		(void)strlcpy(rule->to_ip,      rule->ipv4_to.ipaddress, sizeof(rule->to_ip));
		(void)strlcpy(rule->to_netmask, rule->ipv4_to.netmask,   sizeof(rule->to_netmask));

		/* tag logged done */
		rule->logged = 1;
	}
	/* now create the normal rule */
	else if(!rule->normal)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "create the normal rule.");

		/* create the logprefix string */
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), create->ruletype, action, "%s", create->option.logprefix);

		/* action LOG requires some extra attention */
		if(strncasecmp(create->action, "LOG", 3) == 0)
		{
			if(conf.check_iptcaps == 0 || iptcap->match_limit == 1)
			{
				limit = create->option.limit;
				burst = create->option.burst;
                                unit  = create->option.limit_unit;

				/* set the limit */
				if(limit > 0 && burst > 0)
					snprintf(rule->limit, sizeof(rule->limit), "-m limit --limit %u/%s --limit-burst %u",
												limit, unit, burst);
				else if(limit > 0 && burst == 0)
					snprintf(rule->limit, sizeof(rule->limit), "-m limit --limit %u/%s",
												limit, unit);
			}

			snprintf(rule->action, sizeof(rule->action), "%s %s",
									create->action,
									logprefix);
		}
		else
		{
			if(conf.check_iptcaps == 0 || iptcap->match_limit == 1)
			{
				limit = create->option.limit;
				burst = create->option.burst;
                                unit  = create->option.limit_unit;

				/* set the limit */
				if(limit > 0 && burst > 0)
					snprintf(rule->limit, sizeof(rule->limit), "-m limit --limit %u/%s --limit-burst %u",
												limit, unit, burst);
				else if(limit > 0 && burst == 0)
					snprintf(rule->limit, sizeof(rule->limit), "-m limit --limit %u/%s",
												limit, unit);
			}

			(void)strlcpy(rule->action, create->action, sizeof(rule->action));
		}

		/* set ip and netmask */
		(void)strlcpy(rule->to_ip,      rule->ipv4_to.ipaddress, sizeof(rule->to_ip));
		(void)strlcpy(rule->to_netmask, rule->ipv4_to.netmask,   sizeof(rule->to_netmask));

		/* tag normal rule done */
		rule->normal = 1;
	}
	/* if we have a broadcasting protocol and want logging, and haven't logged yet */
	else if((create->service->broadcast == 1) && (create->option.rule_log == 1) && (rule->broadlog == 0))
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "create the log rule for broadcast.");

		if(conf.check_iptcaps == 0 || iptcap->match_limit == 1)
		{
			if(create->option.loglimit > 0) {
				limit = create->option.loglimit;
				unit = "sec";
                        } else {
				limit = create->option.limit;
                                unit = create->option.limit_unit;
                        }

			if(create->option.logburst > 0)
				burst = create->option.logburst;
			else
				burst = create->option.burst;

			/* set the limit */
			if(limit > 0 && burst > 0)
				snprintf(rule->limit, sizeof(rule->limit), "-m limit --limit %u/%s --limit-burst %u",
											limit, unit, burst);
			else if(limit > 0 && burst == 0)
				snprintf(rule->limit, sizeof(rule->limit), "-m limit --limit %u/%s",
											limit, unit);
		}

		/* create the logprefix string */
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), create->ruletype, action, "%s", create->option.logprefix);

		/* action */
		snprintf(rule->action, sizeof(rule->action), "LOG %s %s %s",
								logprefix,
								loglevel,
								log_tcp_options);

		/* set ip and netmask */
		(void)strlcpy(rule->to_ip,      rule->ipv4_to.broadcast, sizeof(rule->to_ip));
		(void)strlcpy(rule->to_netmask, "255.255.255.255", sizeof(rule->to_netmask));

		/* tag broadcast logging done */
		rule->broadlog = 1;
	}
	/* broadcasting */
	else if((create->service->broadcast == 1) && (rule->broadcasted == 0))
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "create the broadcast rule.");

		(void)strlcpy(rule->action, create->action, sizeof(rule->action));

		/* set ip and netmask */
		(void)strlcpy(rule->to_ip,      rule->ipv4_to.broadcast, sizeof(rule->to_ip));
		(void)strlcpy(rule->to_netmask, "255.255.255.255", sizeof(rule->to_netmask));

		/* tag broadcasting done */
		rule->broadcasted = 1;
	}

	/* all the above stuff is only for 'to'. */
	(void)strlcpy(rule->from_ip,      rule->ipv4_from.ipaddress, sizeof(rule->from_ip));
	(void)strlcpy(rule->from_netmask, rule->ipv4_from.netmask, sizeof(rule->from_netmask));

	return(0);
}


int
create_rule_set_ipaddresses2(	const int debuglvl, struct RuleCache_ *create,
				struct RuleCreateData_ *rule, IptCap *iptcap)
{
	char	from_has_mac = FALSE;
	char	from_mac[19] = "";

	/*	from is any or from is firewall(any) or from is
		firewall and to is any. In this case we need to
		keep the source ipaddress empty */
	if(	create->from_any == TRUE ||
		create->from_firewall_any == TRUE ||
		(create->to_any == TRUE   && create->from_firewall == TRUE))
	{
		/*	if source is firewall and dest is any _and_
			the out_int option was set, we need some magic
			to make sure the source ipaddress is set */
		if(	create->from_firewall == TRUE &&
			create->to_any == TRUE &&
			create->option.out_int[0] != '\0')
		{
			(void)strlcpy(rule->ipv4_from.ipaddress,
				rule->to_if_ptr->ipv4.ipaddress,
				sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,
				"255.255.255.255",
				sizeof(rule->ipv4_from.netmask));
		}
	}
	else
	{
		/*	set the ipaddress and netmask and mac
							
			FROM

			first host
		*/
		if(create->from->type == TYPE_HOST)
		{
			(void)strlcpy(rule->ipv4_from.ipaddress,
				create->from->ipv4.ipaddress,
				sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,
				create->from->ipv4.netmask,
				sizeof(rule->ipv4_from.netmask));

			if(create->from->has_mac)
			{
				from_has_mac = TRUE;
				(void)strlcpy(from_mac,
					create->from->mac, sizeof(from_mac));
			}
		}
		/* network */
		else if(create->from->type == TYPE_NETWORK && create->from_firewall == 0)
		{
			(void)strlcpy(rule->ipv4_from.ipaddress,
				create->from->ipv4.network,
				sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,
				create->from->ipv4.netmask,
				sizeof(rule->ipv4_from.netmask));
		}
		/* firewall (this host) */
		else if(create->from->type == TYPE_NETWORK && create->from_firewall == 1)
		{
			(void)strlcpy(rule->ipv4_from.ipaddress,
				rule->from_if_ptr->ipv4.ipaddress,
				sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,
				"255.255.255.255",
				sizeof(rule->ipv4_from.netmask));

			if(rule->from_if_ptr->device_virtual_oldstyle == TRUE)
			{
				memset(rule->to_int, 0, sizeof(rule->to_int));
			}
			else
			{
				(void)strlcpy(rule->to_int,
					rule->from_if_ptr->device,
					sizeof(rule->to_int));
			}
		}
		/* finally group */
		else if(create->from->type == TYPE_GROUP)
		{
			(void)strlcpy(rule->ipv4_from.ipaddress,
				rule->from_member_ptr->ipv4.ipaddress,
				sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,
				rule->from_member_ptr->ipv4.netmask,
				sizeof(rule->ipv4_from.netmask));

			if(rule->from_member_ptr->has_mac)
			{
				from_has_mac = 1;
				(void)strlcpy(from_mac,
					rule->from_member_ptr->mac,
					sizeof(from_mac));
			}
		}
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "(from) ipaddress: %s, netmask: %s (pre createloop)", rule->ipv4_from.ipaddress, rule->ipv4_from.netmask);

		/* add mac-address if we happen to know it, only 'from' is supported by iptables */
		if(from_has_mac == TRUE)
		{
			if(conf.check_iptcaps == FALSE || iptcap->match_mac == TRUE)
				snprintf(rule->from_mac, sizeof(rule->from_mac), "-m mac --mac-source %s", from_mac);
			else
			{
				(void)vrprint.warning("Warning", "not using macaddress. Mac-match not supported by system.");
				memset(rule->from_mac, 0, sizeof(rule->from_mac));
			}
		}
		else
			memset(rule->from_mac, 0, sizeof(rule->from_mac));

	} /* end if create->from_any == FALSE */

	/*	to is any or to is firewall(any) or to is
		firewall and from is any. In this case we need to
		keep the destination ipaddress empty */
	if(	create->to_any == TRUE ||
		create->to_firewall_any == TRUE ||
		(create->from_any == TRUE && create->to_firewall == TRUE))
	{
		/*	if dest is firewall and source is any _and_
			the in_int option was set, we need some magic
			to make sure the destination ipaddress is set */
		if(	create->to_firewall == TRUE &&
			create->from_any == TRUE &&
			create->option.in_int[0] != '\0')
		{
			/* use from_if_ptr (was to_if_ptr) */
			(void)strlcpy(rule->ipv4_to.ipaddress, rule->from_if_ptr->ipv4.ipaddress,  sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   "255.255.255.255",          sizeof(rule->ipv4_to.netmask));
		}
	}
	else
	{
		/*	TO

		first host
		*/
		if(create->to->type == TYPE_HOST)
		{
			(void)strlcpy(rule->ipv4_to.ipaddress, create->to->ipv4.ipaddress, sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   create->to->ipv4.netmask,   sizeof(rule->ipv4_to.netmask));
			(void)strlcpy(rule->ipv4_to.broadcast, create->to->network_parent->ipv4.broadcast, sizeof(rule->ipv4_to.broadcast));
			/* to has no mac, because it is not supported by iptables */
		}
		/* network */
		else if(create->to->type == TYPE_NETWORK && create->to_firewall == 0)
		{
			(void)strlcpy(rule->ipv4_to.ipaddress, create->to->ipv4.network,   sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   create->to->ipv4.netmask,   sizeof(rule->ipv4_to.netmask));
			(void)strlcpy(rule->ipv4_to.broadcast, create->to->ipv4.broadcast, sizeof(rule->ipv4_to.broadcast));
		}
		/* firewall (this host) */
		else if(create->to->type == TYPE_NETWORK && create->to_firewall == 1)
		{
			/* use from_if_ptr (was to_if_ptr) */
			(void)strlcpy(rule->ipv4_to.ipaddress, rule->to_if_ptr->ipv4.ipaddress,  sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   "255.255.255.255",          sizeof(rule->ipv4_to.netmask));
			(void)strlcpy(rule->ipv4_to.broadcast, create->to->ipv4.broadcast, sizeof(rule->ipv4_to.broadcast));

			if(rule->to_if_ptr->device_virtual_oldstyle == TRUE)
			{
				memset(rule->from_int, 0, sizeof(rule->from_int));
			}
			else
			{
				(void)strlcpy(rule->from_int,
					rule->to_if_ptr->device,
					sizeof(rule->from_int));
			}
		}
		else if(create->to->type == TYPE_GROUP)
		{
			(void)strlcpy(rule->ipv4_to.ipaddress, rule->to_member_ptr->ipv4.ipaddress, sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   rule->to_member_ptr->ipv4.netmask,   sizeof(rule->ipv4_to.netmask));
			(void)strlcpy(rule->ipv4_to.broadcast, create->to->network_parent->ipv4.broadcast,    sizeof(rule->ipv4_to.broadcast));
			/* to has no mac, because it is not supported by iptables */
		}
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "( to ) ipaddress: '%s', netmask: '%s', broadcast: '%s' (pre createloop)", rule->ipv4_to.ipaddress, rule->ipv4_to.netmask, rule->ipv4_to.broadcast);
	} /* end if create->to_any == FALSE */

	return(0);
}


int
create_rule_set_ipaddresses(	const int debuglvl, struct RuleCache_ *create,
				struct RuleCreateData_ *rule, IptCap *iptcap)
{
	char	from_has_mac = FALSE;
	char	from_mac[19] = "";

	/*	from is any or from is firewall(any) or from is
		firewall and to is any. In this case we need to
		keep the source ipaddress empty */
	if(	create->from_any == TRUE ||
		create->from_firewall_any == TRUE ||
		(create->to_any == TRUE   && create->from_firewall == TRUE))
	{
		/*	if source is firewall and dest is any _and_
			the out_int option was set, we need some magic
			to make sure the source ipaddress is set */
		if(	create->from_firewall == TRUE &&
			create->to_any == TRUE &&
			create->option.out_int[0] != '\0')
		{
			(void)strlcpy(rule->ipv4_from.ipaddress, rule->to_if_ptr->ipv4.ipaddress, sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,   "255.255.255.255",           sizeof(rule->ipv4_from.netmask));
		}
	}
	else
	{
		/*	set the ipaddress and netmask and mac
							
			FROM

			first host
		*/
		if(create->from->type == TYPE_HOST)
		{
			(void)strlcpy(rule->ipv4_from.ipaddress, create->from->ipv4.ipaddress, sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,   create->from->ipv4.netmask,   sizeof(rule->ipv4_from.netmask));

			if(create->from->has_mac)
			{
				from_has_mac = 1;
				(void)strlcpy(from_mac, create->from->mac, sizeof(from_mac));
			}
		}
		/* network */
		else if(create->from->type == TYPE_NETWORK && create->from_firewall == 0)
		{
			(void)strlcpy(rule->ipv4_from.ipaddress, create->from->ipv4.network, sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,   create->from->ipv4.netmask, sizeof(rule->ipv4_from.netmask));
		}
		/* firewall (this host) */
		else if(create->from->type == TYPE_NETWORK && create->from_firewall == 1)
		{
			(void)strlcpy(rule->ipv4_from.ipaddress, rule->from_if_ptr->ipv4.ipaddress, sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,   "255.255.255.255",           sizeof(rule->ipv4_from.netmask));
		}
		/* finally group */
		else if(create->from->type == TYPE_GROUP)
		{
			(void)strlcpy(rule->ipv4_from.ipaddress, rule->from_member_ptr->ipv4.ipaddress, sizeof(rule->ipv4_from.ipaddress));
			(void)strlcpy(rule->ipv4_from.netmask,   rule->from_member_ptr->ipv4.netmask,   sizeof(rule->ipv4_from.netmask));

			if(rule->from_member_ptr->has_mac)
			{
				from_has_mac = 1;
				(void)strlcpy(from_mac, rule->from_member_ptr->mac, sizeof(from_mac));
			}
		}
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "(from) ipaddress: %s, netmask: %s (pre createloop)", rule->ipv4_from.ipaddress, rule->ipv4_from.netmask);

		/* add mac-address if we happen to know it, only 'from' is supported by iptables */
		if(from_has_mac == TRUE)
		{
			if(conf.check_iptcaps == FALSE || iptcap->match_mac == TRUE)
				snprintf(rule->from_mac, sizeof(rule->from_mac), "-m mac --mac-source %s", from_mac);
			else
			{
				(void)vrprint.warning("Warning", "not using macaddress. Mac-match not supported by system.");
				memset(rule->from_mac, 0, sizeof(rule->from_mac));
			}
		}
		else
			memset(rule->from_mac, 0, sizeof(rule->from_mac));

	} /* end if create->from_any == FALSE */

	/*	to is any or to is firewall(any) or to is
		firewall and from is any. In this case we need to
		keep the destination ipaddress empty */
	if(	create->to_any == TRUE ||
		create->to_firewall_any == TRUE ||
		(create->from_any == TRUE && create->to_firewall == TRUE))
	{
		/*	if dest is firewall and source is any _and_
			the in_int option was set, we need some magic
			to make sure the destination ipaddress is set */
		if(	create->to_firewall == TRUE &&
			create->from_any == TRUE &&
			create->option.in_int[0] != '\0')
		{
			/* use from_if_ptr (was to_if_ptr) */
			(void)strlcpy(rule->ipv4_to.ipaddress, rule->from_if_ptr->ipv4.ipaddress,  sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   "255.255.255.255",          sizeof(rule->ipv4_to.netmask));
		}
	}
	else
	{
		/*	TO

		first host
		*/
		if(create->to->type == TYPE_HOST)
		{
			(void)strlcpy(rule->ipv4_to.ipaddress, create->to->ipv4.ipaddress, sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   create->to->ipv4.netmask,   sizeof(rule->ipv4_to.netmask));
			(void)strlcpy(rule->ipv4_to.broadcast, create->to->network_parent->ipv4.broadcast, sizeof(rule->ipv4_to.broadcast));
			/* to has no mac, because it is not supported by iptables */
		}
		/* network */
		else if(create->to->type == TYPE_NETWORK && create->to_firewall == 0)
		{
			(void)strlcpy(rule->ipv4_to.ipaddress, create->to->ipv4.network,   sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   create->to->ipv4.netmask,   sizeof(rule->ipv4_to.netmask));
			(void)strlcpy(rule->ipv4_to.broadcast, create->to->ipv4.broadcast, sizeof(rule->ipv4_to.broadcast));
		}
		/* firewall (this host) */
		else if(create->to->type == TYPE_NETWORK && create->to_firewall == 1)
		{
			/* use from_if_ptr (was to_if_ptr) */
			(void)strlcpy(rule->ipv4_to.ipaddress, rule->to_if_ptr->ipv4.ipaddress,  sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   "255.255.255.255",          sizeof(rule->ipv4_to.netmask));
			(void)strlcpy(rule->ipv4_to.broadcast, create->to->ipv4.broadcast, sizeof(rule->ipv4_to.broadcast));
		}
		else if(create->to->type == TYPE_GROUP)
		{
			(void)strlcpy(rule->ipv4_to.ipaddress, rule->to_member_ptr->ipv4.ipaddress, sizeof(rule->ipv4_to.ipaddress));
			(void)strlcpy(rule->ipv4_to.netmask,   rule->to_member_ptr->ipv4.netmask,   sizeof(rule->ipv4_to.netmask));
			(void)strlcpy(rule->ipv4_to.broadcast, create->to->network_parent->ipv4.broadcast,    sizeof(rule->ipv4_to.broadcast));
			/* to has no mac, because it is not supported by iptables */
		}
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "( to ) ipaddress: '%s', netmask: '%s', broadcast: '%s' (pre createloop)", rule->ipv4_to.ipaddress, rule->ipv4_to.netmask, rule->ipv4_to.broadcast);
	} /* end if create->to_any == FALSE */

	return(0);
}


/*	create_rule

	This fuctions creates the actual rule.

	Returncodes:
		 0: ok
		-1: error
*/
int
create_rule(const int debuglvl, /*@null@*/RuleSet *ruleset,
		struct RuleCache_ *create, Interfaces *interfaces,
		IptCap *iptcap)
{
	int			retval = 0;
	unsigned int		z = 0;
	unsigned int		from_loop_cnt = 0,
				to_loop_cnt = 0,
				from_nor,
				to_nor;
	unsigned int		portrange_count = 0;
	unsigned int		linescreated = 0,
				createloop = 0;

	struct RuleCreateData_ 	*rule = NULL;

	d_list_node		*from_d_node = NULL,
				*to_d_node = NULL;

	d_list_node		*from_if_node = NULL,
				*to_if_node = NULL;

	struct ZoneData_ 	*from_zone_ptr = NULL,
				*to_zone_ptr = NULL;

	char 			from_active = FALSE,
				to_active = FALSE,
				active = FALSE;

	d_list_node		*port_d_node = NULL,
				*listenport_d_node = NULL,
				*remoteport_d_node = NULL;


	/* safety checks */
	if(iptcap == NULL || create == NULL || interfaces == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "** start ** (create->action: %s).", create->action);

	/* here we print the description if we are in bashmode */
	if(conf.bash_out == TRUE && create->description != NULL)
	{
		fprintf(stdout, "\n# %s\n", create->description);
	}

	/* clear counters */
	create->iptcount.input = 0,
	create->iptcount.output = 0,
	create->iptcount.forward = 0,
	create->iptcount.preroute = 0,
	create->iptcount.postroute = 0;

	/* at start we asume that both from and to are active */
	from_active = 1;
	to_active = 1;
	active = create->active;

	if(debuglvl >= MEDIUM)
	{
		if(create->service != NULL)
		{
			(void)vrprint.debug(__FUNC__, "service '%s'.", create->service->name);
		}
		else
		{
			(void)vrprint.debug(__FUNC__, "service == NULL (so service is any)");
		}
	}

	/* if bash, print comment (if any) */
	if(create->option.rule_comment == TRUE && conf.bash_out == TRUE)
	{
		fprintf(stdout, "# comment: '%s'\n", create->option.comment);
	}

	/* alloc the temp rule data */
	if(!(rule = malloc(sizeof(struct RuleCreateData_))))
	{
		(void)vrprint.error(-1, "Error", "malloc failed: %s "
			"(in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
		return(-1);
	}

	/* init */
	memset(rule, 0, sizeof(struct RuleCreateData_));
	d_list_setup(debuglvl, &rule->iptrulelist, free);

	/* copy the helper */
	if(create->service != NULL)
		(void)strlcpy(rule->helper, create->service->helper, sizeof(rule->helper));

////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// LOOP CONTROL /////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

	/* FROM zone, network, host or group */
	if(create->from != NULL && create->from->type == TYPE_GROUP)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "groupmembercount: from: %d.", create->from->group_member_count);

		/* set the from-loop counter to the group-member-count */
		from_loop_cnt = create->from->group_member_count;

		/* set the first member */
		from_d_node = create->from->GroupList.top;

		/* see if it is not NULL */
		if(from_d_node != NULL)
		{
			if(!(rule->from_member_ptr = from_d_node->data))
			{
				(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
				return(-1);
			}

			/* active check */
			if(rule->from_member_ptr->active == FALSE)
			{
				if(debuglvl >= MEDIUM)
					(void)vrprint.debug(__FUNC__, "groupmember '%s' is inactive.", rule->from_member_ptr->name);

				from_active = FALSE;
			}
			else
			{
				if(debuglvl >= MEDIUM)
					(void)vrprint.debug(__FUNC__, "groupmember '%s' is active.", rule->from_member_ptr->name);

				from_active = TRUE;
			}
		}
		/* safety check */
		else if(from_d_node == NULL && from_loop_cnt > 0)
		{
			(void)vrprint.error(-1, "Internal Error", "from_loop_cnt: %d, but from_d_node == NULL for group %s (in: %s:%d).",
									from_loop_cnt, create->from->name, __FUNC__, __LINE__);
			return(-1);
		}
	}
	/* not a group */
	else
	{
		/* just one from_loop_cnt */
		from_loop_cnt = 1;
	}

	/* TO zone, network, host or group */
	if(create->to != NULL && create->to->type == TYPE_GROUP)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "groupmembercount: to: %d.", create->to->group_member_count);

		/* set the to-loop counter to the group-member-count */
		to_loop_cnt = create->to->group_member_count;

		/* set the first member */
		to_d_node = create->to->GroupList.top;

		/* see if it is not NULL */
		if(to_d_node != NULL)
		{
			if(!(rule->to_member_ptr = to_d_node->data))
			{
				(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
											__FUNC__, __LINE__);
				return(-1);
			}

			/* active check */
			if(rule->to_member_ptr->active == FALSE)
			{
				if(debuglvl >= MEDIUM)
					(void)vrprint.debug(__FUNC__, "groupmember '%s' is inactive.", rule->to_member_ptr->name);

				to_active = FALSE;
			}
			else
			{
				if(debuglvl >= MEDIUM)
					(void)vrprint.debug(__FUNC__, "groupmember '%s' is active.", rule->to_member_ptr->name);

				to_active = TRUE;
			}
		}
		/* safety check */
		else if(!to_d_node && to_loop_cnt > 0)
		{
			(void)vrprint.error(-1, "Internal Error", "to_loop_cnt: %d, but to_d_node == NULL for group %s (in: %s:%d).",
										to_loop_cnt, create->to->name, __FUNC__, __LINE__);
			return(-1);
		}
	}
	/* not a group */
	else
	{
		/* to_loop_cnt is one if it's not a group */
		to_loop_cnt = 1;
	}

	/*	determine how many times we are going to run the next loops

		multiply by the number of interfaces - we need to make sure
		that interfaces are not counted twice
	*/

	/* from zone */
	if(	create->from_firewall == TRUE) {
		/* nothing: interfaces of 'to' are used */
	}
	else if(create->from != NULL &&
		(create->from->type == TYPE_HOST || create->from->type == TYPE_GROUP))
	{
		from_loop_cnt = from_loop_cnt * create->from->network_parent->InterfaceList.len;
	}
	else if(create->from != NULL &&
		create->from->type == TYPE_NETWORK)
	{
		from_loop_cnt = from_loop_cnt * create->from->InterfaceList.len;
	}

	/* to zone */
	if(	create->to_firewall == TRUE) {
		/* nothing: interfaces of 'from' are used */
	}
	else if(create->to != NULL &&
		(create->to->type == TYPE_HOST || create->to->type == TYPE_GROUP))
	{
		to_loop_cnt = to_loop_cnt * create->to->network_parent->InterfaceList.len;
	}
	else if(create->to != NULL &&
		create->to->type == TYPE_NETWORK)
	{
		to_loop_cnt = to_loop_cnt * create->to->InterfaceList.len;
	}


	if(debuglvl >= MEDIUM)
		(void)vrprint.debug(__FUNC__, "from_loop_cnt: %d, to_loop_cnt: %d.", from_loop_cnt, to_loop_cnt);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////// MAIN LOOP ///////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// BEGIN LOOP INTERFACES
////

	/*
	 * ==== FROM LOOP ====
	 */
	/* run this loop 'from' times */
	for(from_nor = 0;  from_nor < from_loop_cnt; from_nor++)
	{
		if(	create->from_any == TRUE ||
			(create->to_any == TRUE &&
			 create->from_firewall == TRUE))
		{
			if(debuglvl >= HIGH)
				(void)vrprint.debug(__FUNC__, "not running from interface loop: from is any.");

			/* clear the from_int to be sure */
			memset(rule->from_int, 0, sizeof(rule->from_int));

			/* set to NULL to be sure */
			from_if_node = NULL;
			from_zone_ptr = NULL;
			rule->from_if_ptr = NULL;

			if(create->option.in_int[0] != '\0') /* interface option is set */
			{
				rule->from_if_ptr = search_interface(debuglvl, interfaces, create->option.in_int);
				if(rule->from_if_ptr == NULL)
				{
					(void)vrprint.error(-1, "Error", "interface '%s' not found (in: %s:%d).",
							create->option.in_int, __FUNC__, __LINE__);
					free(rule);
					return(-1);
				}

				if(rule->from_if_ptr->device_virtual_oldstyle == FALSE)
					(void)strlcpy(rule->from_int, rule->from_if_ptr->device, sizeof(rule->from_int));
				else
					memset(rule->from_int, 0, sizeof(rule->from_int));

				/*	if the interface is not active we set
					the to zone inactive. */
				if(active == TRUE)
					active = rule->from_if_ptr->active;

				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "active = %d (because of rule->from_if_ptr->active).", active);

				/*	if the interface is dynamic _and_ down,
					we set inactive. Only check if we
					are active until now */
				if(active == TRUE)
				{
					if(rule->from_if_ptr->dynamic == TRUE &&
						rule->from_if_ptr->up == FALSE)
					{
						if(debuglvl >= HIGH)
							(void)vrprint.debug(__FUNC__, "active = %d (because of rule->from_if_ptr->dynamic == 1 and rule->from_if_ptr->up == 0).", active);

						(void)vrprint.info("Info", "not creating rule: 'from'-interface '%s' is dynamic and down.", rule->from_if_ptr->name);
						active = FALSE;
					}
				}

				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "from is any and 'from' interface option is set to '%s'.", rule->from_int);
			}
		}
		else
		{
			/* network or host, group */
			if(create->from->type == TYPE_NETWORK)
				from_zone_ptr = create->from;
			else
				from_zone_ptr = create->from->network_parent;

			if(!from_zone_ptr)
			{
				(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
				return(-1);
			}

			/* get the ifac ptr */
			if(!from_if_node)
				from_if_node = from_zone_ptr->InterfaceList.top;
			else
				from_if_node = from_if_node->next;

			/* safety check */
			if(!from_if_node)
			{
				(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
				return -1;
			}

			/* reset from_zone_ptr */
			from_zone_ptr = NULL;

			if(!(rule->from_if_ptr = from_if_node->data))
			{
				(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
				return(-1);
			}

			/*	set the interface

				if the device is virtual (oldstyle) we don't want it in our
				iptables commands
			*/
			if(rule->from_if_ptr->device_virtual_oldstyle == FALSE)
				(void)strlcpy(rule->from_int, rule->from_if_ptr->device, sizeof(rule->from_int));
			else
				memset(rule->from_int, 0, sizeof(rule->from_int));

			if(debuglvl >= HIGH)
				(void)vrprint.debug(__FUNC__, "rule->from_if_ptr->name: '%s', "
					"rule->from_if_ptr->ipv4.ipaddress: '%s', "
					"rule->from_if_ptr->device: '%s', "
					"rule->from_int: '%s', virtual(old)? %s.",
					rule->from_if_ptr->name,
					rule->from_if_ptr->ipv4.ipaddress,
					rule->from_if_ptr->device,
					rule->from_int,
					rule->from_if_ptr->device_virtual_oldstyle ? "Yes" : "No");

			/*	if the interface is not active we set the to zone
				inactive. But only if its already active. */
			if(active == TRUE)
				active = rule->from_if_ptr->active;

			if(debuglvl >= HIGH)
				(void)vrprint.debug(__FUNC__, "active = %d (because of rule->from_if_ptr->active).", active);

			/* if the interface is dynamic _and_ down, we set inactive. Only check if we are active until now */
			if(active == TRUE)
			{
				if(rule->from_if_ptr->dynamic == TRUE && rule->from_if_ptr->up == FALSE)
				{
					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "active = %d (because of rule->from_if_ptr->dynamic == 1 and rule->from_if_ptr->up == 0).", active);

					(void)vrprint.info("Info", "not creating rule: 'from'-interface '%s' is dynamic and down.", rule->from_if_ptr->name);
					active = FALSE;
				}
			}

			/* if were at the end of the ifac list, set to null */
			if(d_list_node_is_bot(debuglvl, from_if_node))
				from_if_node = NULL;

			if(debuglvl >= HIGH)
				(void)vrprint.debug(__FUNC__, "create->from.group_member_count: %d.", create->from->group_member_count);
		}


		/*	check for the 'in_int' rule option:
 
		 	3 possibilities:
 
		 	1. interface option set and interface match
		 	2. interface option not set
			3. from is 'any'
		 */
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "create->from_any '%s', "
				"create->option.in_int '%s' "
				"rule->from_if_ptr->name '%s'",
				create->from_any ? "TRUE" : "FALSE",
				create->option.in_int,
				rule->from_if_ptr ? rule->from_if_ptr->name : "(null)");

		if(	(create->from_any == FALSE &&					/* don't check if from is any */
			create->option.in_int[0] != '\0' &&				/* interface option is set */
			strcmp(create->option.in_int, rule->from_if_ptr->name) == 0)	/* interface matches */
				||
			(create->from_any == FALSE &&					/* don't check if from is any */
			create->option.in_int[0] == '\0')				/* interface option is not set */
				||
			create->from_any == TRUE					/* 'any' doesn't use this filter */
		)
		{
			/*
			 * ==== TO LOOP ====
			 */
			/* run this loop 'to_loop_cnt' times */
			for(to_nor = 0; to_nor < to_loop_cnt; to_nor++)
			{
				if(	create->to_any == TRUE ||
					(create->from_any == TRUE &&
					 create->to_firewall == TRUE))
				{
					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "not running from interface loop: to is any.");

					/* clear the from_int to be sure */
					memset(rule->to_int, 0, sizeof(rule->to_int));

					/* set to NULL to be sure */
					to_if_node = NULL;
					to_zone_ptr = NULL;
					rule->to_if_ptr = NULL;

					if(create->option.out_int[0] != '\0') /* interface option is set */
					{
						rule->to_if_ptr = search_interface(debuglvl, interfaces, create->option.out_int);
						if(rule->to_if_ptr == NULL)
						{
							(void)vrprint.error(-1, "Error", "interface '%s' not found (in: %s:%d).",
								create->option.out_int, __FUNC__, __LINE__);
							free(rule);
							return(-1);
						}

						if(rule->to_if_ptr->device_virtual_oldstyle == FALSE)
							(void)strlcpy(rule->to_int, rule->to_if_ptr->device, sizeof(rule->to_int));
						else
							memset(rule->to_int, 0, sizeof(rule->to_int));

						/*	if the interface is not active we set
							the to zone inactive. */
						if(active == TRUE)
						{
							active = rule->to_if_ptr->active;

							if(debuglvl >= HIGH)
								(void)vrprint.debug(__FUNC__, "active = %d (because of rule->to_if_ptr->active).", active);
						}

						/*	if the interface is dynamic _and_ down,
							we set inactive. Only check if we
							are active until now */
						if(active == TRUE)
						{
							if(rule->to_if_ptr->dynamic == TRUE &&
							   rule->to_if_ptr->up == FALSE)
							{
								if(debuglvl >= HIGH)
									(void)vrprint.debug(__FUNC__, "active = %d (because of rule->to_if_ptr->dynamic == 1 and rule->to_if_ptr->up == 0).", active);

								(void)vrprint.info("Info", "not creating rule: 'to'-interface '%s' is dynamic and down.", rule->to_if_ptr->name);
								active = FALSE;
							}
						}

						if(debuglvl >= HIGH)
							(void)vrprint.debug(__FUNC__, "to is any and 'to' interface option is set to '%s'.", rule->to_int);
					}
				}
				else
				{
					/* set to zone pointer to the network of this zone */
					if(create->to->type == TYPE_NETWORK)
						to_zone_ptr = create->to;
					else
						to_zone_ptr = create->to->network_parent;

					/* check */
					if(!to_zone_ptr)
					{
						(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
													__FUNC__, __LINE__);
						return(-1);
					}

					/* get the ifac node */
					if(!to_if_node)
						to_if_node = to_zone_ptr->InterfaceList.top;
					else
						to_if_node = to_if_node->next;

					/* safety check */
					if(!to_if_node)
					{
						(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
													__FUNC__, __LINE__);
						return -1;
					}

					/* reset to_zone_ptr */
					to_zone_ptr = NULL;

					/* get the interface */
					if(!(rule->to_if_ptr = to_if_node->data))
					{
						(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
													__FUNC__, __LINE__);
						return(-1);
					}

					/*	set the interface

						if the device is virtual (oldstyle) we don't want it in our
						iptables commands
					*/
					if(rule->to_if_ptr->device_virtual_oldstyle == FALSE)
						(void)strlcpy(rule->to_int, rule->to_if_ptr->device, sizeof(rule->to_int));
					else
						memset(rule->to_int, 0, sizeof(rule->to_int));

					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "rule->to_int: '%s', virtual? %s.", rule->to_int, rule->to_if_ptr->device_virtual_oldstyle ? "Yes" : "No");

					/* if the interface is not active we set the rule inactive. */
					if(active == TRUE)
					{
						active = rule->to_if_ptr->active;

						if(debuglvl >= HIGH)
							(void)vrprint.debug(__FUNC__, "active = %d (because of rule->to_if_ptr->active).", active);
					}
					else
					{
						if(debuglvl >= HIGH)
							(void)vrprint.debug(__FUNC__, "active = %d (so not checking the to_int).", active);
					}

					/* if the interface is dynamic _and_ down, we set inactive. Only check if we are active until now */
					if(active == TRUE)
					{
						if(rule->to_if_ptr->dynamic == TRUE && rule->to_if_ptr->up == FALSE)
						{
							if(debuglvl >= HIGH)
								(void)vrprint.debug(__FUNC__, "active = %d (because of rule->to_if_ptr->dynamic == 1 and rule->to_if_ptr->up == 0).", active);

							(void)vrprint.info("Info", "not creating rule: 'to'-interface '%s' is dynamic and down.", rule->to_if_ptr->name);
							active = FALSE;
						}
					}

					/* if were at the end of the ifac list, set to null so we can rewind at the next run */
					if(d_list_node_is_bot(debuglvl, to_if_node))
						to_if_node = NULL;
				}

				/*	check for the 'out_int' rule option:
 
		 			3 possibilities:
 
		 			1. interface option set and match
		 			2. interface option not set
					3. to is 'any'
		 		*/
				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__,
						"create->to_any '%s', "
						"create->option.out_int '%s' "
						"rule->to_if_ptr->name '%s'",
						create->to_any ? "TRUE" : "FALSE",
						create->option.out_int,
						rule->to_if_ptr ? rule->to_if_ptr->name : "(null)");

				if(	(create->to_any == FALSE &&					/* to is not any */
					create->option.out_int[0] != '\0' &&				/* interface option is set */
					strcmp(create->option.out_int, rule->to_if_ptr->name) == 0)	/* interface matches */
						||
					(create->to_any == FALSE &&					/* to is not any */
					create->option.out_int[0] == '\0')				/* interface option is not set */
						||
					create->to_any == TRUE						/* 'any' doesn't use this filter */
				)
				{
					/*
					 * ==== ACTIVE CHECK ====
					 */
					if(from_active == TRUE && to_active == TRUE && active == TRUE)
					{
						if(create->service_any == FALSE)
						{
							/* SET PORTS */
							if(create->service->PortrangeList.len > 0)
							{
								/* top of the list */
								if(!(port_d_node = create->service->PortrangeList.top))
								{
									(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
									return -1;
								}

								/* listenport option */
								if(create->option.listenport == 1)
									listenport_d_node = create->option.ListenportList.top;
								else
									listenport_d_node = NULL;

								/* remoteport option */
								if(create->option.remoteport == 1)
									remoteport_d_node = create->option.RemoteportList.top;
								else
									remoteport_d_node = NULL;
							}
							else
							{
								/* if there are no portranges set port_d_node to NULL */
								port_d_node = NULL;
							}
					
							portrange_count = create->service->PortrangeList.len;
						}
						/* service is any */
						else
						{
							/* rather safe then sorry */
							port_d_node = NULL;

							portrange_count = 1;
						}

						for(linescreated = 0; portrange_count > linescreated; linescreated++)
						{
							/* start with creating 1 rule */
							createloop = 1;

							/* set ports */
							if(port_d_node)
							{
								/* get the current portrange */
								if(!(rule->portrange_ptr = port_d_node->data))
								{
									(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
									return -1;
								}

								/* set rule->listenport_ptr */
								if(create->option.listenport && listenport_d_node)
									rule->listenport_ptr = listenport_d_node->data;
								else
									rule->listenport_ptr = NULL;

								/* set rule->remoteport_ptr */
								if(create->option.remoteport && remoteport_d_node)
									rule->remoteport_ptr = remoteport_d_node->data;
								else
									rule->remoteport_ptr = NULL;

								/* now load the ports to the rule struct */
								if(create_rule_set_ports(rule, rule->portrange_ptr) < 0)
								{
									(void)vrprint.error(-1, "Internal Error", "setting up the ports failed (in: %s).", __FUNC__);
									retval = -1;
								}
							}
							else
							{
								/* no portrange */
								rule->portrange_ptr = NULL;
							}

							if(debuglvl >= MEDIUM)
								(void)vrprint.debug(__FUNC__, "portrange_count: %d, linescreated: %d",
													portrange_count, linescreated);

							/* set protocol */
							if(create_rule_set_proto(rule, create) < 0)
							{
								(void)vrprint.error(-1, "Internal Error", "create_rule_set_proto() failed (in: %s:%d).", __FUNC__, __LINE__);
								retval = -1;
							}

					//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
					/////////////////////////////// okay, we are going to create something////////////////////////////////////////////////////////
					//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

							create_rule_set_ipaddresses2(debuglvl, create, rule, iptcap);

							/* some special actions for a few actions */
							if(create->ruletype == RT_SNAT &&
								(create->to_any == FALSE || create->option.out_int[0] != '\0'))
							{
								/* copy the ipaddress of the to-interface to rule->serverip so snat can use it */
								if(rule->to_if_ptr == NULL)
								{
									(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
									return(-1);
								}
								
								snprintf(rule->serverip, sizeof(rule->serverip), "%s", rule->to_if_ptr->ipv4.ipaddress);
								if(debuglvl >= HIGH)
									(void)vrprint.debug(__FUNC__, "SNAT: rule->serverip = '%s' (interface: %s).", rule->serverip, rule->to_if_ptr->name);
							}
							else if((create->ruletype == RT_PORTFW || create->ruletype == RT_DNAT || create->ruletype == RT_BOUNCE ) &&
								(create->from_any == FALSE || create->option.in_int[0] != '\0'))
							{
								/* copy the ipaddress of the from-interface to rule->serverip so portfw can use it */
								if(rule->from_if_ptr == NULL)
								{
									(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
									return(-1);
								}

								snprintf(rule->serverip, sizeof(rule->serverip), "%s", rule->from_if_ptr->ipv4.ipaddress);
								if(debuglvl >= HIGH)
									(void)vrprint.debug(__FUNC__, "PORTFW: rule->serverip = '%s' (interface: %s).", rule->serverip, rule->from_if_ptr->name);
							}

							/* broadcast means twice as many rule */
							if(rule->portrange_ptr && rule->portrange_ptr->protocol == 17 && create->service->broadcast == 1)
								createloop = createloop * 2;

							/* if we log we need to create twice as many rules */
							if(create->option.rule_log)
								createloop = createloop * 2;

							if(debuglvl >= HIGH)
								(void)vrprint.debug(__FUNC__, "createloop = %d", createloop);

							/* reset counters */
							rule->logged = 0, rule->normal = 0, rule->broadlog = 0, rule->broadcasted = 0;

					//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
					////////////////////////////////////////// enter createloop //////////////////////////////////////////////////////
					//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
							for(z = 0; z < createloop; z++)
							{
								if(create_rule_set_action_and_ip(debuglvl, rule, create, iptcap) < 0)
								{
									(void)vrprint.error(-1, "Error", "create_rule_set_action_and_ip failed.");
									retval = -1;
								}

								/* rule count */
								ipt_rulecount++;

								if(debuglvl >= HIGH)
								{
									(void)vrprint.debug(__FUNC__, "(from) ipaddress: %s, netmask: %s (in createloop)", rule->from_ip, rule->from_netmask);
									(void)vrprint.debug(__FUNC__, "( to ) ipaddress: %s, netmask: %s (in createloop)", rule->to_ip, rule->to_netmask);
								}

								/* here we create the iptables commands */
								if(debuglvl >= HIGH)
									(void)vrprint.debug(__FUNC__, "action: %s, chain: %s, fromip: %s, toip: %s, ruletype: %d", rule->action, rule->chain, rule->from_ip, rule->to_ip, create->ruletype);

								/* normal input rules */
								if(create->ruletype == RT_INPUT)
								{
									if(create_rule_input(debuglvl, ruleset, rule, create, iptcap) < 0)
									{
										(void)vrprint.error(-1, "Error", "creating input rule failed (in: %s).", __FUNC__);
										retval = -1;
									}
								}
								/* normal output rules */
								else if(create->ruletype == RT_OUTPUT)
								{
									if(create_rule_output(debuglvl, ruleset, rule, create, iptcap) < 0)
									{
										(void)vrprint.error(-1, "Error", "creating output rule failed (in: %s).", __FUNC__);
										retval = -1;
									}
								}
								/* normal forward rules */
								else if(create->ruletype == RT_FORWARD)
								{
									if(create_rule_forward(debuglvl, ruleset, rule, create, iptcap) < 0)
									{
										(void)vrprint.error(-1, "Error", "creating forward rule failed (in: %s).", __FUNC__);
										retval = -1;
									}

									/*	a bit of a hack: if from is any we need output as well
										because from 'any' can be firewall as well.
									*/
									if(create->from_any == TRUE)
									{
										if(create_rule_output(debuglvl, ruleset, rule, create, iptcap) < 0)
										{
											(void)vrprint.error(-1, "Error", "creating output rule failed (in: %s).", __FUNC__);
											retval = -1;
										}
									}

									/*	a bit of a hack: if to is any we need input as well
										because to 'any' can be firewall as well.
									*/
									if(create->to_any == TRUE)
									{
										if(create_rule_input(debuglvl, ruleset, rule, create, iptcap) < 0)
										{
											(void)vrprint.error(-1, "Error", "creating input rule failed (in: %s).", __FUNC__);
											retval = -1;
										}
									}
								}
								/* masq rules */
								else if(create->ruletype == RT_MASQ)
								{
									if(create_rule_masq(debuglvl, ruleset, rule, create, iptcap) < 0)
									{
										(void)vrprint.error(-1, "Error", "creating masq rule failed (in: %s).", __FUNC__);
										retval = -1;
									}
								}
								/* snat rules */
								else if(create->ruletype == RT_SNAT)
								{
									if(create_rule_snat(debuglvl, ruleset, rule, create, iptcap) < 0)
									{
										(void)vrprint.error(-1, "Error", "creating snat rule failed (in: %s).", __FUNC__);
										retval = -1;
									}
								}
								/* portforward rules */
								else if(create->ruletype == RT_PORTFW)
								{
									if(create_rule_portfw(debuglvl, ruleset, rule, create, iptcap) < 0)
									{
										(void)vrprint.error(-1, "Error", "creating portfw rule failed (in: %s).", __FUNC__);
										retval = -1;
									}
								}
								else if(create->ruletype == RT_REDIRECT)
								{
									if(create_rule_redirect(debuglvl, ruleset, rule, create, iptcap) < 0)
									{
										(void)vrprint.error(-1, "Error", "creating redirect rule failed (in: %s).", __FUNC__);
										retval = -1;
									}
								}
								else if(create->ruletype == RT_DNAT)
								{
									if(create_rule_dnat(debuglvl, ruleset, rule, create, iptcap) < 0)
									{
										(void)vrprint.error(-1, "Error", "creating dnat rule failed (in: %s).", __FUNC__);
										retval = -1;
									}
								}
								else if(create->ruletype == RT_BOUNCE)
								{
									if(create_rule_bounce(debuglvl, ruleset, rule, create, iptcap) < 0)
									{
										(void)vrprint.error(-1, "Error", "creating bounce rule failed (in: %s).", __FUNC__);
										retval = -1;
									}
								}
								else
								{
									(void)vrprint.error(-1, "Internal Error", "unknown ruletype '%d' (in: %s:%d).", create->ruletype, __FUNC__, __LINE__);
									return(-1);
								}
							} /* end createloop */

							/* get the next service/portrange */
							if(create->service_any == FALSE)
							{
								if(create->service->PortrangeList.len > 0)
								{
									if(d_list_node_is_bot(debuglvl, port_d_node))
									{
										/* rewind */
										port_d_node = create->service->PortrangeList.top;
									}
									else
									{
										/* next */
										port_d_node = port_d_node->next;
									}

									/* listport option */
									if(create->option.listenport == 1)
									{
										if(listenport_d_node->next != NULL)
											listenport_d_node = listenport_d_node->next;
									}

									/* remoteport  option */
									if(create->option.remoteport == 1)
									{
										if(remoteport_d_node->next != NULL)
											remoteport_d_node = remoteport_d_node->next;
									}
								}
							}
						}
					} /* end if active */
					else
					{
						if(debuglvl >= LOW)
							(void)vrprint.debug(__FUNC__, "rule not created, not active.");
					}
				}
				/*	not creating because of 'out_int='
					option in the rule */
				else
				{
					if(debuglvl >= LOW)
						(void)vrprint.debug(__FUNC__,
							"don't create because "
							"of interface option "
							"'%s'.", create->option.out_int);
				}

				if(create->to_any == TRUE || (create->from_any == TRUE && create->to_firewall == TRUE))
				{
					/* to is any */
				}
				else
				{
					/* set the next group member TO GROUP */
					if(create->to->type == TYPE_GROUP)
					{
						if(debuglvl >= HIGH)
							(void)vrprint.debug(__FUNC__, "TO: set the next (or prev) group member.");

						/*	get the new to_d_node
							if we have reached the bot of the list, start all over again
					 	*/
						if(!d_list_node_is_bot(debuglvl, to_d_node))
							to_d_node = to_d_node->next;
						else
							to_d_node = create->to->GroupList.top;

						if(to_d_node != NULL)
						{
							if(!(rule->to_member_ptr = to_d_node->data))
							{
								(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
								return(-1);
							}

							if(rule->to_member_ptr->active == FALSE)
							{
								if(debuglvl >= MEDIUM)
									(void)vrprint.debug(__FUNC__, "group member '%s' is inactive", rule->to_member_ptr->name);

								to_active = FALSE;
							}
							else
							{
								if(debuglvl >= MEDIUM)
									(void)vrprint.debug(__FUNC__, "group member '%s' is active", rule->to_member_ptr->name);

								to_active = TRUE;
							}
						}
					}
				} /* end if create->to_any == FALSE */
			}

			if(create->from_any == TRUE || (create->to_any == TRUE && create->from_firewall == TRUE))
			{
				/* from is any */
			}
			else
			{
				/* set the next group member of the FROM GROUP */
				if(create->from->type == TYPE_GROUP)
				{
					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "FROM: set the next (or prev) group member.");
				
					/*	get the new from_d_node
						if we have reached the bot of the list, start all over again
				 	*/
					if(!d_list_node_is_bot(debuglvl, from_d_node))
						from_d_node = from_d_node->next;
					else
						from_d_node = create->from->GroupList.top;

					if(from_d_node != NULL)
					{
						if(!(rule->from_member_ptr = from_d_node->data))
						{
							(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
							return(-1);
						}

						if(rule->from_member_ptr->active == FALSE)
						{
							if(debuglvl >= MEDIUM)
								(void)vrprint.debug(__FUNC__, "group member '%s' is inactive", rule->from_member_ptr->name);

							from_active = FALSE;
						}
						else
						{
							if(debuglvl >= MEDIUM)
								(void)vrprint.debug(__FUNC__, "group member '%s' is active", rule->from_member_ptr->name);

							from_active = TRUE;
						}
					}
				}
			} /* end if create->from_any == FALSE */
		}
		/* not creating because of 'in_int=' option in the rule */
		else
		{
			if(debuglvl >= LOW)
				(void)vrprint.debug(__FUNC__, "don't create because of interface option '%s'.", create->option.in_int);
		}

		if(debuglvl >= MEDIUM)
			(void)vrprint.debug(__FUNC__, "rules created: (i: %2d, o: %2d, f: %2d, e: %2d, p: %2d)",
								create->iptcount.input,
								create->iptcount.output,
								create->iptcount.forward,
								create->iptcount.preroute,
								create->iptcount.postroute);
	} /* end interface from loop */

	/* process the rules */
	process_queued_rules(debuglvl, ruleset, rule);

	/* free the temp data */
	d_list_cleanup(debuglvl, &rule->iptrulelist);
	free(rule);

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "** end **, return=%d", retval);
	
	return(retval);
}


/*	remove_rule

	Function for removing iptables rules.

	Returncodes:
		 0: ok
		-1: error
*/
int
remove_rule(const int debuglvl, int chaintype, int first_ipt_rule, int rules)
{
	int	retval=0,
		i;
	char	cmd[MAX_PIPE_COMMAND];
	char	chain[64];

	if(debuglvl >= HIGH)
	{
		(void)vrprint.debug(__FUNC__, "** start **");
		(void)vrprint.debug(__FUNC__, "chain: %d, ipt: %d, rules: %d", chaintype, first_ipt_rule, rules);
	}

	/* determine from which chain to delete */
	if(chaintype == RT_INPUT)
	{
		(void)strlcpy(chain, "-D INPUT", sizeof(chain));
	}
	else if(chaintype == RT_OUTPUT)
	{
		(void)strlcpy(chain, "-D OUTPUT", sizeof(chain));
	}
	else if(chaintype == RT_FORWARD)
	{
		(void)strlcpy(chain, "-D FORWARD", sizeof(chain));
	}
	else if(chaintype == RT_PORTFW || chaintype == RT_REDIRECT)
	{
		(void)strlcpy(chain, "-t nat -D PREROUTING", sizeof(chain));
	}
	else if(chaintype == RT_MASQ || chaintype == RT_SNAT)
	{
		(void)strlcpy(chain, "-t nat -D POSTROUTING", sizeof(chain));
	}
	else
	{
		(void)vrprint.error(-1, "Error", "unknown chaintype %d (remove_rule).", chaintype);
		return(-1);
	}

	for(i = 0; i < rules; i++)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "cmd: %s %s %d", conf.iptables_location, chain, first_ipt_rule);

		snprintf(cmd, sizeof(cmd), "%s %s %d", conf.iptables_location, chain, first_ipt_rule);
		if(pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE) != 0)
		{
			(void)vrprint.error(-1, "Error", "remove_rule: pipe error. This command failed: '%s'.", cmd);
			return(-1);
		}
	}

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "** end **, return=%d", retval);

	return(retval);
}


int
create_system_protectrules(const int debuglvl, struct vuurmuur_config *conf)
{
	int	result = 0;

	/* safety */
	if(!conf)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "protect proc systemwide... ");


	/* syncookies */
	if(debuglvl >= MEDIUM)
		(void)vrprint.debug(__FUNC__, "Setting '%d' to '%s'... ", conf->protect_syncookie, "/proc/sys/net/ipv4/tcp_syncookies");

	result = set_proc_entry(debuglvl, conf, "/proc/sys/net/ipv4/tcp_syncookies", conf->protect_syncookie, NULL);
	if(result != 0)
	{
		/* if it fails, we dont really care, its not fatal */
		(void)vrprint.error(-1, "Error", "set_proc_entry failed (in: create_rule, prot_proc_sys).");
	}


	/* echo broadcasts */
	if(debuglvl >= MEDIUM)
		(void)vrprint.debug(__FUNC__, "Setting '%d' to '%s'... ", conf->protect_echobroadcast, "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts");

	result = set_proc_entry(debuglvl, conf, "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", conf->protect_echobroadcast, NULL);
	if(result != 0)
	{
		/* if it fails, we dont really care, its not fatal */
		(void)vrprint.error(-1, "Error", "set_proc_entry failed (in: create_rule, prot_proc_sys).");
	}

	return(0);
}


int
create_normal_rules(	const int debuglvl,
			/*@null@*/RuleSet *ruleset,
			Rules *rules,
			Interfaces *interfaces,
			IptCap *iptcap,
			char *forward_rules)
{
	d_list_node		*d_node = NULL;
	struct RuleData_	*rule_ptr = NULL;
	char			active = 0;
	int			rulescount = 0;


	/* safety */
	if(rules == NULL || interfaces == NULL || iptcap == NULL || !forward_rules)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
									__FUNC__, __LINE__);
		return(-1);
	}

	/* walk trough the ruleslist and create the rules */
	for(d_node = rules->list.top; d_node; d_node = d_node->next)
	{
		if(!(rule_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer "
				"(in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}

		/* asume active when we begin */
		active = TRUE;

		/* count the rules */
		rulescount++;

		/* check normal rule */
		if(rule_ptr->rulecache.from != NULL && rule_ptr->rulecache.from->active == FALSE)
			active = FALSE;
		if(rule_ptr->rulecache.to != NULL && rule_ptr->rulecache.to->active == FALSE)
			active = FALSE;
		if(rule_ptr->rulecache.service != NULL && rule_ptr->rulecache.service->active == FALSE)
			active = FALSE;

		/* check protect rule */
		if(rule_ptr->rulecache.who != NULL)
		{
			if(rule_ptr->rulecache.who->active == FALSE)
			{
				active = FALSE;
			}
		}

		/* create the rule */
		if(active == TRUE)
		{
			if(rule_ptr->action == AT_SEPARATOR)
			{
				/* here we print the description if we are in bashmode */
				if(conf.bash_out == TRUE && rule_ptr->rulecache.description != NULL)
				{
					fprintf(stdout, "\n#\n# %s\n#\n", rule_ptr->rulecache.description);
				}
			}
			else if(	(rule_ptr->rulecache.from != NULL    || rule_ptr->rulecache.from_any == TRUE || 
					(rule_ptr->rulecache.from_firewall == TRUE && rule_ptr->rulecache.to_any == TRUE))
						 &&
				(rule_ptr->rulecache.to != NULL      || rule_ptr->rulecache.to_any == TRUE   ||
					(rule_ptr->rulecache.to_firewall == TRUE && rule_ptr->rulecache.from_any == TRUE))
						&&
				(rule_ptr->rulecache.service != NULL || rule_ptr->rulecache.service_any == TRUE))
			{
				if(create_rule(debuglvl, ruleset, &rule_ptr->rulecache, interfaces, iptcap) == 0)
				{
					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "rule created succesfully.");

					if(rule_ptr->rulecache.iptcount.forward > 0)
						*forward_rules = 1;
				}
				else
				{
					(void)vrprint.warning("Warning", "Creating rule %d failed.", rulescount);
				}
			}
		}
		else
		{
			(void)vrprint.info("Note", "Rule %d not created: inactive.", rulescount);
		}

		/* make sure the bash comment memory is cleared */
		if(rule_ptr->rulecache.description != NULL)
		{
			free(rule_ptr->rulecache.description);
			rule_ptr->rulecache.description = NULL;
		}
	}

	return(0);
}


/*	clear_vuurmuur_iptables_rule

	Clears vuurmuur rules and chains created by Vuurmuur.
	For use with the -Y commandline option.

	Returncodes:
		-1: error
		 0: ok
*/
int
clear_vuurmuur_iptables_rules(const int debuglvl, struct vuurmuur_config *cnf)
{
	int	      retval = 0,
        	      result = 0;
	Rules         rules;
	char	      *chainname = NULL;
	d_list_node   *d_node = NULL;
	d_list_node   *chains[3];
	char          *tables[] = {"mangle", "filter", "nat"};
	int           table;
	char          PRE_VRMR_CHAINS_PREFIX[] = "PRE-VRMR-";
	char	      cmd[MAX_PIPE_COMMAND] = "";

	/* safety */
	if(cnf == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
									__FUNC__, __LINE__);
		return(-1);
	}

	/* get the current chains */
	(void)rules_get_system_chains(debuglvl, &rules, cnf);

	/* prepare chains tab with nodes for loop */
	chains[0]=rules.system_chain_mangle.top;
	chains[1]=rules.system_chain_filter.top;
	chains[2]=rules.system_chain_nat.top;

	for(table=0 ; table<3 ; table++)
	{
		for(d_node = chains[table]; d_node; d_node = d_node->next)
		{
			if(!(chainname = d_node->data))
			{
				(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
										__FUNC__, __LINE__);
				return(-1);
			}
        
			if(strncmp(chainname,PRE_VRMR_CHAINS_PREFIX,strlen(PRE_VRMR_CHAINS_PREFIX)))
			{
				if(debuglvl >= LOW)
					(void)vrprint.debug(__FUNC__, "flushing %s chain in %s table.", chainname, tables[table]);
				snprintf(cmd, MAX_PIPE_COMMAND, "%s -t %s --flush %s", conf.iptables_location, tables[table], chainname);
				result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
				if(result < 0)
					retval = -1;
			}
			else
			{
				if(debuglvl >= LOW)
					(void)vrprint.debug(__FUNC__, "skipping flush of %s chain in %s table.", chainname, tables[table]);
			}
		}
	}


	/* set default polices to ACCEPT */
	snprintf(cmd, MAX_PIPE_COMMAND, "%s --policy INPUT ACCEPT", conf.iptables_location);
	result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
	if(result < 0)
		retval=-1;
	snprintf(cmd, MAX_PIPE_COMMAND, "%s --policy OUTPUT ACCEPT", conf.iptables_location);
	result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
	if(result < 0)
		retval=-1;
	snprintf(cmd, MAX_PIPE_COMMAND, "%s --policy FORWARD ACCEPT", conf.iptables_location);
	result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
	if(result < 0)
		retval=-1;

	return(retval);
}


/*	clear_all_iptables_rule

	Clears all rules and chains created by Vuurmuur.
	For use with the -C commandline option.

	Returncodes:
		-1: error
		 0: ok
*/
int
clear_all_iptables_rules(const int debuglvl)
{
	int	retval = 0,
		result = 0;
	char	cmd[MAX_PIPE_COMMAND] = "";

	/* flush everything */
	snprintf(cmd, MAX_PIPE_COMMAND, "%s -t filter --flush", conf.iptables_location);
	result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
	if(result < 0)
		retval = -1;
	snprintf(cmd, MAX_PIPE_COMMAND, "%s -t nat --flush", conf.iptables_location);
	result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
	if(result < 0)
		retval = -1;
	snprintf(cmd, MAX_PIPE_COMMAND, "%s -t mangle --flush", conf.iptables_location);
	result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
	if(result < 0)
		retval = -1;

	/* this will remove the all chains in {filter,nat,mangle} tables */
	snprintf(cmd, MAX_PIPE_COMMAND, "%s %s -X 2>/dev/null", conf.iptables_location, TB_FILTER);
	(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);

	snprintf(cmd, MAX_PIPE_COMMAND, "%s %s -X 2>/dev/null", conf.iptables_location, TB_NAT);
	(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);

	snprintf(cmd, MAX_PIPE_COMMAND, "%s %s -X 2>/dev/null", conf.iptables_location, TB_MANGLE);
	(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);

	/* set default polices to ACCEPT */
	snprintf(cmd, MAX_PIPE_COMMAND, "%s --policy INPUT ACCEPT", conf.iptables_location);
	result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
	if(result < 0)
		retval=-1;
	snprintf(cmd, MAX_PIPE_COMMAND, "%s --policy OUTPUT ACCEPT", conf.iptables_location);
	result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
	if(result < 0)
		retval=-1;
	snprintf(cmd, MAX_PIPE_COMMAND, "%s --policy FORWARD ACCEPT", conf.iptables_location);
	result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
	if(result < 0)
		retval=-1;

	return(retval);
}

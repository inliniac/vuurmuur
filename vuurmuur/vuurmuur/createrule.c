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

#include "main.h"

/* iptables tables */
#define TB_FILTER		"-t filter"
#define TB_MANGLE		"-t mangle"
#define TB_NAT			"-t nat"

/* iptables chains */
#define CH_PREROUTING		"-A PREROUTING"
#define CH_INPUT		"-A INPUT"
#define CH_FORWARD		"-A FORWARD"
#define CH_OUTPUT		"-A OUTPUT"
#define CH_POSTROUTING		"-A POSTROUTING"
#define CH_BLOCKLIST		"-A BLOCKLIST"
#define CH_BLOCKTARGET		"-A BLOCK"
#define CH_ANTISPOOF		"-A ANTISPOOF"
#define CH_BADTCP		"-A BADTCP"
#define CH_SYNLIMITTARGET	"-A SYNLIMIT"
#define CH_UDPLIMITTARGET	"-A UDPLIMIT"
#define CH_TCPRESETTARGET	"-A TCPRESET"
#define CH_NEWACCEPT		"-A NEWACCEPT"
#define CH_NEWQUEUE		"-A NEWQUEUE"
#define CH_NEWNFQUEUE		"-A NEWNFQUEUE"
#define CH_ESTRELNFQUEUE	"-A ESTRELNFQUEUE"

#define SRCDST_SOURCE		(char)0
#define SRCDST_DESTINATION	(char)1


/*	structure for storing an iptables rule in the queue. */
typedef struct
{
	char			*table;
	char			*chain;
	char			cmd[MAX_PIPE_COMMAND];
	unsigned long long	packets;
	unsigned long long	bytes;

} IptRule;


/*
	this function empties the string if either ipaddress and/or netmask are empty.
 */
static void
create_srcdst_string(const int debuglvl, char mode, const char *ipaddress, const char *netmask, char *resultstr, size_t size)
{
	int	result = 0;

	/* safety */
	if(resultstr == NULL || ipaddress == NULL || netmask == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return;
	}
	/* clear */
	memset(resultstr, 0, size);

	/* handle here that ipaddress or netmask */
	if(ipaddress[0] != '\0' && netmask[0] != '\0')
	{
		/* create the string */
		if(mode == SRCDST_SOURCE)
			result = snprintf(resultstr, size, "-s %s/%s", ipaddress, netmask);
		else
			result = snprintf(resultstr, size, "-d %s/%s", ipaddress, netmask);

		if(result >= (int)size)
		{
			(void)vrprint.error(-1, "Error", "buffer overrun (in: %s:%d).", __FUNC__, __LINE__);
			return;
		}
	}
}


static int
pipe_iptables_command(const int debuglvl, char *table, char *chain, char *cmd)
{
	char	str[MAX_PIPE_COMMAND] = "";

	/* safety */
	if(cmd == NULL || table == NULL || chain == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/*
		assemble the command string
	*/
	if(snprintf(str, sizeof(str), "%s %s %s %s", conf.iptables_location, table, chain, cmd) >= (int)sizeof(str))
	{
		(void)vrprint.error(-1, "Error", "iptables command creation overflow (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/*
		finally try to create the rule
	*/
	if(pipe_command(debuglvl, &conf, str, PIPE_VERBOSE) < 0)
	{
		(void)vrprint.error(-1, "Error", "creating rule failed (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	return(0);
}


/*	compare two IptRule structs and return 1 if they match, 0 otherwise */
static int
iptrulecmp(const int debuglvl, IptRule *r1, IptRule *r2)
{
	if(r1 == NULL || r2 == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	if(	r1->table == r2->table &&
		r1->chain == r2->chain &&
		strcmp(r1->cmd, r2->cmd) == 0 &&
		r1->packets == r2->packets &&
		r1->bytes == r2->bytes)
	{
		return(1);
	}

	return(0);
}


/*	insert a new IptRule struct into the list, but first check if it is not
	a duplicate. If it is a dup, just drop it. */
static int
iptrule_insert(const int debuglvl, struct RuleCreateData_ *rule,
		IptRule *iptrule)
{
	d_list_node	*d_node = NULL;
	IptRule		*listrule = NULL;

	if(iptrule == NULL || rule == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	for(d_node = rule->iptrulelist.top; d_node; d_node = d_node->next)
	{
		listrule = d_node->data;

		if(iptrulecmp(debuglvl, listrule, iptrule) == 1)
		{
			free(iptrule);
			return(0);
		}
	}

	if(d_list_append(debuglvl, &rule->iptrulelist, iptrule) == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "d_list_append() "
			"failed (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	return(0);
}


/*	queue the rule into the list, so we can inspect the rules for
	duplicates. We do this to prevent creating lots of duplicates
	especially for setups with lots of virtual interfaces.
	
	This function must _only_ be called from the normal rule creation
	functions, not from pre-rules, post-rules, etc.
	*/
static int
queue_rule(const int debuglvl, struct RuleCreateData_ *rule,
		/*@null@*/RuleSet *ruleset,
		char *table, char *chain, char *cmd,
		unsigned long long packets, unsigned long long bytes)
{
	IptRule	*iptrule = NULL;

	/* safety */
	if(cmd == NULL || table == NULL || chain == NULL || rule == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}
	if(strncmp(chain, "-A ACC-", 7) == 0)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem: "
				"cannot use this function for custom chains "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	iptrule = malloc(sizeof(IptRule));
	if(iptrule == NULL)
	{
		(void)vrprint.error(-1, "Error", "malloc failed: %s "
			"(in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
		return(-1);
	}

	iptrule->table = table;
	iptrule->chain = chain;
	strlcpy(iptrule->cmd, cmd, sizeof(iptrule->cmd));
	iptrule->packets = packets;
	iptrule->bytes = bytes;

	if(iptrule_insert(debuglvl, rule, iptrule) < 0)
		return(-1);

	return(0);
}


/*	pass the rule to either the ruleset or to pipe-command */
static int
process_rule(const int debuglvl, /*@null@*/RuleSet *ruleset, char *table,
		char *chain, char *cmd,
		unsigned long long packets, unsigned long long bytes)
{
	/* safety */
	if(cmd == NULL || table == NULL || chain == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	if(ruleset == NULL)
	{
		/* not in ruleset mode */
		return(pipe_iptables_command(debuglvl, table, chain, cmd));
	}

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "packets: %llu, bytes: %llu.", packets, bytes);

	if(table == TB_FILTER)
	{
		if(chain == CH_INPUT)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_input, chain, cmd, packets, bytes));
		else if(chain == CH_FORWARD)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_forward, chain, cmd, packets, bytes));
		else if(chain == CH_OUTPUT)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_output, chain, cmd, packets, bytes));

		else if(chain == CH_BLOCKTARGET)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_blocktarget, chain, cmd, packets, bytes));
		else if(chain == CH_BLOCKLIST)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_blocklist, chain, cmd, packets, bytes));

		else if(chain == CH_BADTCP)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_badtcp, chain, cmd, packets, bytes));
		else if(chain == CH_ANTISPOOF)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_antispoof, chain, cmd, packets, bytes));

		else if(chain == CH_SYNLIMITTARGET)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_synlimittarget, chain, cmd, packets, bytes));
		else if(chain == CH_UDPLIMITTARGET)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_udplimittarget, chain, cmd, packets, bytes));

		else if(chain == CH_NEWACCEPT)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_newaccepttarget, chain, cmd, packets, bytes));
		else if(chain == CH_NEWQUEUE)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_newqueuetarget, chain, cmd, packets, bytes));
		else if(chain == CH_NEWNFQUEUE)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_newnfqueuetarget, chain, cmd, packets, bytes));
		else if(chain == CH_ESTRELNFQUEUE)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_estrelnfqueuetarget, chain, cmd, packets, bytes));

		else if(chain == CH_TCPRESETTARGET)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_tcpresettarget, chain, cmd, packets, bytes));

		/* accounting have dynamic chain names */
		else if(strncmp(chain, "-A ACC-", 7) == 0)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->filter_accounting, chain, cmd, packets, bytes));
	}
	else if(table == TB_MANGLE)
	{
		if(chain == CH_PREROUTING)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->mangle_preroute, chain, cmd, packets, bytes));
		else if(chain == CH_INPUT)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->mangle_input, chain, cmd, packets, bytes));
		else if(chain == CH_FORWARD)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->mangle_forward, chain, cmd, packets, bytes));
		else if(chain == CH_OUTPUT)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->mangle_output, chain, cmd, packets, bytes));
		else if(chain == CH_POSTROUTING)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->mangle_postroute, chain, cmd, packets, bytes));
	}
	else if(table == TB_NAT)
	{
		if(chain == CH_PREROUTING)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->nat_preroute, chain, cmd, packets, bytes));
		else if(chain == CH_OUTPUT)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->nat_output, chain, cmd, packets, bytes));
		else if(chain == CH_POSTROUTING)
			return(ruleset_add_rule_to_set(debuglvl, &ruleset->nat_postroute, chain, cmd, packets, bytes));
	}

	/* default case, should never happen */
	return(-1);
}


/*	at the end of processing one vuurmuur rule, we should have a queue
	filled with iptables rules, none of which are duplicate. This function
	passes them to process_rule */
int
process_queued_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule)
{
	d_list_node	*d_node = NULL;
	IptRule		*r = NULL;

	if(rule == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	for(d_node = rule->iptrulelist.top; d_node; d_node = d_node->next)
	{
		r = d_node->data;

		if(process_rule(debuglvl, ruleset, r->table, r->chain,
				r->cmd, r->packets, r->bytes) < 0)
		{
			return(-1);
		}
	}

	return(0);
}


/*	create_rule_input

	Creates a rule in the input chain.

	Returncodes:
		-1: error
		 0: ok
*/
int
create_rule_input(const int debuglvl, /*@null@*/RuleSet *ruleset,
			struct RuleCreateData_ *rule,
			struct RuleCache_ *create, IptCap *iptcap)
{
	int		retval = 0;
	char		cmd[MAX_PIPE_COMMAND] = "",
			stripped_proto[16] = "";				/* proto stripped from --syn */
	char		temp_src_port[sizeof(rule->temp_src_port)] = "",
			temp_dst_port[sizeof(rule->temp_dst_port)] = "";
	char		input_device[sizeof(rule->from_int) + 3] = "";
	char		reverse_input_device[sizeof(rule->from_int) + 3] = "";
	unsigned long	nfmark = 0;


	/* safety */
	if(rule == NULL || create == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check caps */
	if(conf.check_iptcaps == TRUE)
	{
		if(	iptcap->target_queue == FALSE &&
			strcmp(rule->action, "NEWQUEUE") == 0)
		{
			(void)vrprint.warning("Warning", "input rule not "
					"created: QUEUE not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
		else if(iptcap->target_nfqueue == FALSE &&
			strcmp(rule->action, "NEWNFQUEUE") == 0)
		{
			(void)vrprint.warning("Warning", "input rule not "
					"created: NFQUEUE not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
		else if(iptcap->target_log == FALSE &&
			strncmp(rule->action, "LOG", 3) == 0)
		{
			(void)vrprint.warning("Warning", "input rule not "
					"created: LOG not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
		else if(iptcap->target_reject == FALSE &&
			strncmp(rule->action, "REJECT", 6) == 0)
		{
			(void)vrprint.warning("Warning", "input rule not "
					"created: REJECT not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
	}

	/* handle empty device (virtual) */
	if(rule->from_int[0] != '\0')
		snprintf(input_device, sizeof(input_device), "-i %s",
				rule->from_int);

	/* create source and destination strings */
	create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip,
			rule->from_netmask, rule->temp_src,
			sizeof(rule->temp_src));
	create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip,
			rule->to_netmask, rule->temp_dst,
			sizeof(rule->temp_dst));

	/* create the rule */
	snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s %s -m state --state NEW -j %s",
			input_device, rule->proto, rule->temp_src,
			rule->temp_src_port, rule->temp_dst,
			rule->temp_dst_port, rule->from_mac, rule->limit,
			rule->action);

	/* add it to the list */
	if(queue_rule(debuglvl, rule, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		return(-1);

	create->iptcount.input++;

	/*	if the target is NEWQUEUE we connmark the traffic */
	if(strcasecmp(rule->action, "NEWNFQUEUE") == 0)
	{
		if(debuglvl >= MEDIUM)
			(void)vrprint.debug(__FUNC__, "nfqueue_num '%u'.", create->option.nfqueue_num);

		/* check cap */
		if(conf.check_iptcaps == TRUE)
		{
			if(iptcap->target_connmark == FALSE)
			{
				(void)vrprint.warning("Warning", "connmark rules not created: CONNMARK not supported by this system.");
				return(0); /* this is not an error */
			}
		}

		/* create mangle rules for NFQUEUE using CONNMARK */

		/* new, related */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state NEW,RELATED -j CONNMARK --set-mark %u",
			input_device, rule->proto, rule->temp_src,
			rule->temp_src_port, rule->temp_dst, rule->temp_dst_port,
			rule->from_mac, create->option.nfqueue_num + 1);

		if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
			return(-1);

		/* related, established */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state RELATED -j CONNMARK --set-mark %u",
			reverse_input_device, rule->proto, rule->temp_src,
			temp_dst_port, rule->temp_dst, temp_src_port,
			create->option.nfqueue_num + 1);

		if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
			return(-1);

		if(strcmp(rule->helper, "") != 0)
		{
			/* check cap */
			if(conf.check_iptcaps == TRUE)
			{
				if(iptcap->match_helper == FALSE)
				{
					(void)vrprint.warning("Warning", "mark rules not created: helper-match not supported by this system.");
					return(0); /* this is not an error */
				}
			}

			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j CONNMARK --set-mark %u",
				input_device, rule->proto, rule->temp_src,
				rule->temp_dst, rule->from_mac, rule->helper,
				create->option.nfqueue_num + 1);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
				return(-1);

			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j CONNMARK --set-mark %u",
				reverse_input_device, rule->proto, rule->temp_src,
				rule->temp_dst, rule->helper, create->option.nfqueue_num + 1);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
				return(-1);
		}
	}

	/*	if the target is NEWQUEUE we mark the traffic

		if nfmark is set as well, unless we handle the LOG rule

		if the protocol is ICMP, we dont create mark rules
	*/
	if(	(strcasecmp(rule->action, "NEWQUEUE") == 0
			||
		(create->option.nfmark > 0 && strncasecmp(rule->action, "LOG", 3) != 0))
			&&
		(rule->portrange_ptr == NULL || rule->portrange_ptr->protocol != 1))
	{
		/* see what nfmark we use, either the option or the queue default 20000000. */
		if(create->option.nfmark > 0)
			nfmark = create->option.nfmark;
		else
			nfmark = 20000000;

		if(debuglvl >= MEDIUM)
			(void)vrprint.debug(__FUNC__, "nfmark '%lu'.", nfmark);

		/* check cap */
		if(conf.check_iptcaps == TRUE)
		{
			if(iptcap->target_mark == FALSE)
			{
				(void)vrprint.warning("Warning", "mark rules not created: MARK not supported by this system.");
				return(0); /* this is not an error */
			}
		}

		/* swap source ports and dest ports for the rules in the opposite direction */
		(void)strlcpy(temp_src_port, rule->temp_src_port, sizeof(temp_src_port));
		temp_src_port[2] = 'd';
		(void)strlcpy(temp_dst_port, rule->temp_dst_port, sizeof(temp_dst_port));
		temp_dst_port[2] = 's';

		/* swap devices, check if non empty device first */
		if(input_device[0] != '\0')
		{
			(void)strlcpy(reverse_input_device, input_device, sizeof(reverse_input_device));
			reverse_input_device[1] = 'o';
		}

		/* create mangle rules for markiptstate */
		if(create->option.markiptstate == TRUE && (strcasecmp(rule->action, "NEWQUEUE") == 0))
		{
			/* new, related */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state NEW,RELATED -j MARK --set-mark 19999998",
								input_device,
								rule->proto,
								rule->temp_src,
								rule->temp_src_port,
								rule->temp_dst,
								rule->temp_dst_port,
								rule->from_mac);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
				return(-1);

			/* related */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state RELATED -j MARK --set-mark 19999998",
								reverse_input_device,
								rule->proto,
								rule->temp_src,
								temp_dst_port,
								rule->temp_dst,
								temp_src_port);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
				return(-1);
	
			/* we dont want --syn in the next rules */
			if(strcmp(rule->proto, "-p tcp -m tcp --syn") == 0)
				(void)strlcpy(stripped_proto, "-p tcp -m tcp", sizeof(stripped_proto));
			else
				(void)strlcpy(stripped_proto, rule->proto, sizeof(stripped_proto));

			/* establised */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state ESTABLISHED -j MARK --set-mark 19999999",
								input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_src_port,
								rule->temp_dst,
								rule->temp_dst_port,
								rule->from_mac);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
				return(-1);

			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state ESTABLISHED -j MARK --set-mark 19999999",
								reverse_input_device,
								stripped_proto,
								rule->temp_src,
								temp_dst_port,
								rule->temp_dst,
								temp_src_port);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
				return(-1);

			if(strcmp(rule->helper, "") != 0)
			{
				/* check cap */
				if(conf.check_iptcaps == TRUE)
				{
					if(iptcap->match_helper == FALSE)
					{
						(void)vrprint.warning("Warning", "mark rules not created: helper-match not supported by this system.");
						return(0); /* this is not an error */
					}
				}

				/* RELATED */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j MARK --set-mark 19999998",
								input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->from_mac,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
					return(-1);

				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j MARK --set-mark 19999998",
								reverse_input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
					return(-1);
									
				/* ESTABLISHED */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED -j MARK --set-mark 19999999",
								input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->from_mac,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
					return(-1);

				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED -j MARK --set-mark 19999999",
								reverse_input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
					return(-1);
			}
		}
		/* create mangle rules for 'normal' QUEUE, or just set nfmark */
		else
		{
			/* we dont want '--syn' in the next rules */
			if(strcmp(rule->proto, "-p tcp -m tcp --syn") == 0)
				(void)strlcpy(stripped_proto, "-p tcp -m tcp", sizeof(stripped_proto));
			else
				(void)strlcpy(stripped_proto, rule->proto, sizeof(stripped_proto));

			/* new, related, established */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state NEW,RELATED,ESTABLISHED -j MARK --set-mark %lu",
							input_device,
							stripped_proto,
							rule->temp_src,
							rule->temp_src_port,
							rule->temp_dst,
							rule->temp_dst_port,
							rule->from_mac,
							nfmark);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
				return(-1);

			/* related, established */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state RELATED,ESTABLISHED -j MARK --set-mark %lu",
							reverse_input_device,
							stripped_proto,
							rule->temp_src,
							temp_dst_port,
							rule->temp_dst,
							temp_src_port,
							nfmark);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
				return(-1);

			if(strcmp(rule->helper, "") != 0)
			{
				/* check cap */
				if(conf.check_iptcaps == TRUE)
				{
					if(iptcap->match_helper == FALSE)
					{
						(void)vrprint.warning("Warning", "mark rules not created: helper-match not supported by this system.");
						return(0); /* this is not an error */
					}
				}

				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED,RELATED -j MARK --set-mark %lu",
								input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->from_mac,
								rule->helper,
								nfmark);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
					return(-1);

				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED,RELATED -j MARK --set-mark %lu",
								reverse_input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper,
								nfmark);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
					return(-1);
			}
		}
	}


	return(retval);
}


/*	create_rule_output

	Creates a rule in the output chain.

	Returncodes:
		-1: error
		 0: ok
*/
int
create_rule_output(const int debuglvl, /*@null@*/RuleSet *ruleset,
			struct RuleCreateData_ *rule,
			struct RuleCache_ *create, IptCap *iptcap)
{
	int		retval = 0;
	char		cmd[MAX_PIPE_COMMAND] = "",
			stripped_proto[16] = "";				/* proto stripped from --syn */
	char		temp_src_port[sizeof(rule->temp_src_port)] = "",
			temp_dst_port[sizeof(rule->temp_dst_port)] = "";
	char		output_device[sizeof(rule->to_int) + 3] = "";
	char		reverse_output_device[sizeof(rule->to_int) + 3] = "";
	unsigned long	nfmark = 0;

	/* safety */
	if(rule == NULL || create == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check caps */
	if(conf.check_iptcaps == TRUE)
	{
		if(	iptcap->target_queue == FALSE && 
			strcmp(rule->action, "NEWQUEUE") == 0)
		{
			(void)vrprint.warning("Warning", "output rule not "
					"created: QUEUE not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
		else if(iptcap->target_nfqueue == FALSE && 
			strcmp(rule->action, "NEWNFQUEUE") == 0)
		{
			(void)vrprint.warning("Warning", "output rule not "
					"created: NFQUEUE not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
		else if(iptcap->target_log == FALSE &&
			strncmp(rule->action, "LOG", 3) == 0)
		{
			(void)vrprint.warning("Warning", "output rule not "
					"created: LOG not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
		else if(iptcap->target_reject == FALSE && 
			strncmp(rule->action, "REJECT", 6) == 0)
		{
			(void)vrprint.warning("Warning", "output rule not "
					"created: REJECT not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
	}

	/* handle empty device (virtual) */
	if(rule->to_int[0] != '\0')
		snprintf(output_device, sizeof(output_device), "-o %s",
				rule->to_int);

	create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip,
			rule->from_netmask, rule->temp_src,
			sizeof(rule->temp_src));
	create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip,
			rule->to_netmask, rule->temp_dst,
			sizeof(rule->temp_dst));

	snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state NEW -j %s",
			output_device, rule->proto, rule->temp_src,
			rule->temp_src_port, rule->temp_dst,
			rule->temp_dst_port, rule->limit, /* log limit */
			rule->action);

	if(queue_rule(debuglvl, rule, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		return(-1);

	/* update rule counter */
	create->iptcount.output++;

	if (strcasecmp(rule->action, "NEWNFQUEUE") == 0)
	{
		if(debuglvl >= MEDIUM)
			(void)vrprint.debug(__FUNC__, "nfqueue_num '%u'.", create->option.nfqueue_num);

		/* check cap */
		if(conf.check_iptcaps == TRUE)
		{
			if(iptcap->target_connmark == FALSE)
			{
				(void)vrprint.warning("Warning", "connmark rules not created: CONNMARK not supported by this system.");
				return(0); /* this is not an error */
			}
		}

		/* create mangle rules for NFQUEUE using CONNMARK */

		/* new, related, established */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state NEW,RELATED -j CONNMARK --set-mark %u",
			output_device, rule->proto, rule->temp_src,
			rule->temp_src_port, rule->temp_dst, rule->temp_dst_port,
			create->option.nfqueue_num + 1);

		if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
			return(-1);

		/* REVERSE! related */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state RELATED -j CONNMARK --set-mark %u",
			reverse_output_device, rule->proto, rule->temp_src,
			temp_dst_port, rule->temp_dst, temp_src_port,
			create->option.nfqueue_num + 1);

		if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
			return(-1);

		/* helperrrr */
		if(strcmp(rule->helper, "") != 0)
		{
			/* check cap */
			if(conf.check_iptcaps == TRUE)
			{
				if(iptcap->match_helper == FALSE)
				{
					(void)vrprint.warning("Warning", "mark rules not created: helper-match not supported by this system.");
					return(0); /* this is not an error */
				}
			}

			/* RELATED */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j CONNMARK --set-mark %u",
					output_device, rule->proto, rule->temp_src,
					rule->temp_dst, rule->helper, create->option.nfqueue_num + 1);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
				return(-1);

			/* REVERSE! */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j CONNMARK --set-mark %u",
				reverse_output_device, rule->proto, rule->temp_src,
				rule->temp_dst, rule->helper, create->option.nfqueue_num + 1);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
				return(-1);
		}
	}

	/*	if the target is QUEUE we mark the traffic
	
		if nfmark is set as well, unless we handle the LOG rule
	*/
	if(	(strcasecmp(rule->action, "NEWQUEUE") == 0
			||
		(create->option.nfmark > 0 && strncasecmp(rule->action, "LOG", 3) != 0))
			&&
		(rule->portrange_ptr == NULL || rule->portrange_ptr->protocol != 1))
	{
		/* see what nfmark we use, either the option or the queue default 20000000. */
		if(create->option.nfmark > 0)
			nfmark = create->option.nfmark;
		else
			nfmark = 20000000;

		if(debuglvl >= MEDIUM)
			(void)vrprint.debug(__FUNC__, "nfmark '%lu'.", nfmark);

		/* check cap */
		if(conf.check_iptcaps == TRUE)
		{
			if(iptcap->target_mark == FALSE)
			{
				(void)vrprint.warning("Warning", "mark rules not created: MARK not supported by this system.");
				return(0); /* this is not an error */
			}
		}

		/* swap source ports and dest ports for the rules in the opposite direction */
		(void)strlcpy(temp_src_port, rule->temp_src_port, sizeof(temp_src_port));
		temp_src_port[2] = 'd';
		(void)strlcpy(temp_dst_port, rule->temp_dst_port, sizeof(temp_dst_port));
		temp_dst_port[2] = 's';

		/* swap devices, check if non empty device first */
		if(output_device[0] != '\0')
		{
			(void)strlcpy(reverse_output_device, output_device, sizeof(reverse_output_device));
			reverse_output_device[1] = 'i';
		}

		/* create mangle rules for markiptstate */
		if(create->option.markiptstate && (strcasecmp(rule->action, "NEWQUEUE") == 0))
		{
			/* new, related */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state NEW,RELATED -j MARK --set-mark 19999998",
							output_device,
							rule->proto,
							rule->temp_src,
							rule->temp_src_port,
							rule->temp_dst,
							rule->temp_dst_port);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
				return(-1);

			/* REVERSE! related */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state RELATED -j MARK --set-mark 19999998",
							reverse_output_device,
							rule->proto,
							rule->temp_src,
							temp_dst_port,
							rule->temp_dst,
							temp_src_port);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
				return(-1);
		
			/* we dont want --syn in the next rules */
			if(strcmp(rule->proto, "-p tcp -m tcp --syn") == 0)
				(void)strlcpy(stripped_proto, "-p tcp -m tcp", sizeof(stripped_proto));
			else
				(void)strlcpy(stripped_proto, rule->proto, sizeof(stripped_proto));
		
			/* established */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state ESTABLISHED -j MARK --set-mark 19999998",
							output_device,
							stripped_proto,
							rule->temp_src,
							rule->temp_src_port,
							rule->temp_dst,
							rule->temp_dst_port);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
				return(-1);

			/* REVERSE! */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state ESTABLISHED -j MARK --set-mark 19999999",
							reverse_output_device,
							stripped_proto,
							rule->temp_src,
							temp_dst_port,
							rule->temp_dst,
							temp_src_port);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
				return(-1);

			if(strcmp(rule->helper, "") != 0)
			{
				/* check cap */
				if(conf.check_iptcaps == TRUE)
				{
					if(iptcap->match_helper == FALSE)
					{
						(void)vrprint.warning("Warning", "mark rules not created: helper-match not supported by this system.");
						return(0); /* this is not an error */
					}
				}

				/* RELATED */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j MARK --set-mark 19999998",
								output_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
					return(-1);

				/* REVERSE! */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s -%s -m helper --helper \"%s\" -m state --state RELATED -j MARK --set-mark 19999998",
								reverse_output_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
					return(-1);

				/* ESTABLISHED */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED -j MARK --set-mark 19999999",
								output_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
					return(-1);

				/* REVERSE! */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED -j MARK --set-mark 19999999",
								reverse_output_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
					return(-1);

			}
		}
		/* create mangle rules for 'normal' QUEUE, or for setting nfmark */
		else
		{
			/* we dont want --syn in the next rules */
			if(strcmp(rule->proto, "-p tcp -m tcp --syn") == 0)
				(void)strlcpy(stripped_proto, "-p tcp -m tcp", sizeof(stripped_proto));
			else
				(void)strlcpy(stripped_proto, rule->proto, sizeof(stripped_proto));
		
			/* new, related, established */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state NEW,RELATED,ESTABLISHED -j MARK --set-mark %lu",
							output_device,
							stripped_proto,
							rule->temp_src,
							rule->temp_src_port,
							rule->temp_dst,
							rule->temp_dst_port,
							nfmark);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
				return(-1);

			/* REVERSE! related, established */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state RELATED,ESTABLISHED -j MARK --set-mark %lu",
							reverse_output_device,
							stripped_proto,
							rule->temp_src,
							temp_dst_port,
							rule->temp_dst,
							temp_src_port,
							nfmark);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
				return(-1);


			/* helperrrr */
			if(strcmp(rule->helper, "") != 0)
			{
				/* check cap */
				if(conf.check_iptcaps == TRUE)
				{
					if(iptcap->match_helper == FALSE)
					{
						(void)vrprint.warning("Warning", "mark rules not created: helper-match not supported by this system.");
						return(0); /* this is not an error */
					}
				}

				/* RELATED,ESTABLISHED */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED,RELATED -j MARK --set-mark %lu",
								output_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper,
								nfmark);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
					return(-1);

				/* REVERSE! */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED,RELATED -j MARK --set-mark %lu",
								reverse_output_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper,
								nfmark);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
					return(-1);
			}
		}
	}

	return(retval);
}


int
create_rule_forward(const int debuglvl, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule, struct RuleCache_ *create, IptCap *iptcap)
{
	int		retval = 0;
	char		cmd[MAX_PIPE_COMMAND] = "",
			stripped_proto[16] = "";				/* proto stripped from --syn */
	char		temp_src_port[sizeof(rule->temp_src_port)] = "",
			temp_dst_port[sizeof(rule->temp_dst_port)] = "";
	char		input_device[sizeof(rule->from_int) + 3] = "",
			output_device[sizeof(rule->to_int) + 3] = "";
	char		reverse_input_device[sizeof(rule->from_int) + 3] = "",
			reverse_output_device[sizeof(rule->to_int) + 3] = "";
	unsigned long	nfmark = 0;

	/* safety */
	if(rule == NULL || create == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check caps */
	if(conf.check_iptcaps == TRUE)
	{
		if(	iptcap->target_queue == FALSE &&
			strcmp(rule->action, "NEWQUEUE") == 0)
		{
			(void)vrprint.warning("Warning", "forward rule not "
					"created: QUEUE not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
		else if(iptcap->target_nfqueue == FALSE &&
			strcmp(rule->action, "NEWNFQUEUE") == 0)
		{
			(void)vrprint.warning("Warning", "forward rule not "
					"created: NFQUEUE not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
		else if(iptcap->target_log == FALSE && 
			strncmp(rule->action, "LOG", 3) == 0)
		{
			(void)vrprint.warning("Warning", "forward rule not "
					"created: LOG not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
		else if(iptcap->target_reject == FALSE && 
			strncmp(rule->action, "REJECT", 6) == 0)
		{
			(void)vrprint.warning("Warning", "forward rule not "
					"created: REJECT not supported by "
					"this system.");
			return(0); /* this is not an error */
		}
	}

	/* handle empty device (virtual) */
	if(rule->from_int[0] != '\0')
		snprintf(input_device, sizeof(input_device), "-i %s",
				rule->from_int);
	if(rule->to_int[0] != '\0')
		snprintf(output_device, sizeof(output_device), "-o %s",
				rule->to_int);

	create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip,
			rule->from_netmask, rule->temp_src,
			sizeof(rule->temp_src));
	create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip,
			rule->to_netmask, rule->temp_dst,
			sizeof(rule->temp_dst));

	/* create the rule */
	snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s %s %s -m state --state NEW -j %s",
			input_device, output_device, rule->proto,
			rule->temp_src, rule->temp_src_port,
			rule->temp_dst, rule->temp_dst_port,
			rule->from_mac, rule->limit, rule->action);

	if(queue_rule(debuglvl, rule, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		return(-1);

	create->iptcount.forward++;

	if (strcasecmp(rule->action, "NEWNFQUEUE") == 0)
	{
		if(debuglvl >= MEDIUM)
			(void)vrprint.debug(__FUNC__, "nfqueue_num '%u'.", create->option.nfqueue_num);

		/* check cap */
		if(conf.check_iptcaps == TRUE)
		{
			if(iptcap->target_connmark == FALSE)
			{
				(void)vrprint.warning("Warning", "connmark rules not created: CONNMARK not supported by this system.");
				return(0); /* this is not an error */
			}
		}

		/* create mangle rules for NFQUEUE using CONNMARK */

		/* new,related */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s %s -m state --state NEW,RELATED -j CONNMARK --set-mark %u",
			input_device, output_device, rule->proto,
			rule->temp_src, rule->temp_src_port, rule->temp_dst,
			rule->temp_dst_port, rule->from_mac, create->option.nfqueue_num + 1);

		if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
			return(-1);

		/* REVERSE! related */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));
			
		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state RELATED -j CONNMARK --set-mark %u",
			reverse_output_device, reverse_input_device, rule->proto,
			rule->temp_src, temp_dst_port, rule->temp_dst,
			temp_src_port, create->option.nfqueue_num + 1);

		if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
			return(-1);

		
		if(strcmp(rule->helper, "") != 0)
		{
			/* check cap */
			if(conf.check_iptcaps == TRUE)
			{
				if(iptcap->match_helper == FALSE)
				{
					(void)vrprint.warning("Warning", "mark rules not created: helper-match not supported by this system.");
					return(0); /* this is not an error */
				}
			}

			/* RELATED */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j CONNMARK --set-mark %u",
				input_device, output_device, stripped_proto,
				rule->temp_src, rule->temp_dst, rule->from_mac,
				rule->helper, create->option.nfqueue_num + 1);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
				return(-1);

			/* REVERSE! */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j CONNMARK --set-mark %u",
				reverse_output_device, reverse_input_device, stripped_proto,
				rule->temp_src, rule->temp_dst, rule->helper,
				create->option.nfqueue_num + 1);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
				return(-1);
		}
	}



	/*	if the target is QUEUE we mark the traffic
	
		if nfmark is set as well, unless we handle the LOG rule
	*/
	if(	(strcasecmp(rule->action, "NEWQUEUE") == 0
			||
		(create->option.nfmark > 0 && strncasecmp(rule->action, "LOG", 3) != 0))
			&&
		(rule->portrange_ptr == NULL || rule->portrange_ptr->protocol != 1))
	{
		/* see what nfmark we use, either the option or the queue default 20000000. */
		if(create->option.nfmark > 0)
			nfmark = create->option.nfmark;
		else
			nfmark = 20000000;

		if(debuglvl >= MEDIUM)
			(void)vrprint.debug(__FUNC__, "nfmark '%lu'.", nfmark);

		/* check cap */
		if(conf.check_iptcaps == TRUE)
		{
			if(iptcap->target_mark == FALSE)
			{
				(void)vrprint.warning("Warning", "mark rules not created: MARK not supported by this system.");
				return(0);/* this is not an error */
			}
		}

//TODO: fix for icmp
		/* swap source ports and dest ports for the rules in the opposite direction */
		(void)strlcpy(temp_src_port, rule->temp_src_port, sizeof(temp_src_port));
		temp_src_port[2] = 'd';
		(void)strlcpy(temp_dst_port, rule->temp_dst_port, sizeof(temp_dst_port));
		temp_dst_port[2] = 's';

		/* swap devices, check if non empty device first */
		if(input_device[0] != '\0')
		{
			/* swap devices */
			(void)strlcpy(reverse_input_device, input_device, sizeof(reverse_input_device));
			reverse_input_device[1] = 'o';
		}
		if(output_device[0] != '\0')
		{
			(void)strlcpy(reverse_output_device, output_device, sizeof(reverse_output_device));
			reverse_output_device[1] = 'i';
		}

		/* create mangle rules for markiptstate */
		if(create->option.markiptstate && (strcasecmp(rule->action, "NEWQUEUE") == 0))
		{
			/* new, related. from -> dst */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s %s -m state --state NEW,RELATED -j MARK --set-mark 19999998",
							input_device,
							output_device,
							rule->proto,
							rule->temp_src,
							rule->temp_src_port,
							rule->temp_dst,
							rule->temp_dst_port,
							rule->from_mac);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
				return(-1);

			/* REVERSE! related. dst -> from  */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state RELATED -j MARK --set-mark 19999998",
							reverse_output_device,
							reverse_input_device,
							rule->proto,
							rule->temp_src,
							temp_dst_port,
							rule->temp_dst,
							temp_src_port);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
				return(-1);

	
			/* we dont want --syn in the next rules */
			if(strcmp(rule->proto, "-p tcp -m tcp --syn") == 0)
				(void)strlcpy(stripped_proto, "-p tcp -m tcp", sizeof(stripped_proto));
			else
				(void)strlcpy(stripped_proto, rule->proto, sizeof(stripped_proto));

			/* established. both ways */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s %s -m state --state ESTABLISHED -j MARK --set-mark 19999999",
							input_device,
							output_device,
							stripped_proto,
							rule->temp_src,
							rule->temp_src_port,
							rule->temp_dst,
							rule->temp_dst_port,
							rule->from_mac);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
				return(-1);

			/* REVERSE! */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state ESTABLISHED -j MARK --set-mark 19999999",
							reverse_output_device,
							reverse_input_device,
							stripped_proto,
							rule->temp_src,
							temp_dst_port,
							rule->temp_dst,
							temp_src_port);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
				return(-1);

		
			if(strcmp(rule->helper, "") != 0)
			{
				/* check cap */
				if(conf.check_iptcaps == TRUE)
				{
					if(iptcap->match_helper == FALSE)
					{
						(void)vrprint.warning("Warning", "mark rules not created: helper-match not supported by this system.");
						return(0); /* this is not an error */
					}
				}

				/* RELATED */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j MARK --set-mark 19999998",
								input_device,
								output_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->from_mac,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
					return(-1);

				/* REVERSE! */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s %s -m helper --helper \"%s\" -m state --state RELATED -j MARK --set-mark 19999998",
								reverse_output_device,
								reverse_input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
					return(-1);


				/* ESTABLISHED */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED -j MARK --set-mark 19999999",
								input_device,
								output_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->from_mac,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
					return(-1);

				/* REVERSE! */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED -j MARK --set-mark 19999999",
								reverse_output_device,
								reverse_input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
					return(-1);
			}
		}
		/* create mangle rules for 'normal' QUEUE */
		else
		{
			/* we dont want --syn in the next rules */
			if(strcmp(rule->proto, "-p tcp -m tcp --syn") == 0)
				(void)strlcpy(stripped_proto, "-p tcp -m tcp", sizeof(stripped_proto));
			else
				(void)strlcpy(stripped_proto, rule->proto, sizeof(stripped_proto));

			/* new,related,established */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s %s -m state --state NEW,RELATED,ESTABLISHED -j MARK --set-mark %lu",
							input_device,
							output_device,
							stripped_proto,
							rule->temp_src,
							rule->temp_src_port,
							rule->temp_dst,
							rule->temp_dst_port,
							rule->from_mac,
							nfmark);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
				return(-1);

			/* REVERSE! related,established */
			create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
			create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));
			
			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state RELATED,ESTABLISHED -j MARK --set-mark %lu",
							reverse_output_device,
							reverse_input_device,
							stripped_proto,
							rule->temp_src,
							temp_dst_port,
							rule->temp_dst,
							temp_src_port,
							nfmark);

			if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
				return(-1);

		
			if(strcmp(rule->helper, "") != 0)
			{
				/* check cap */
				if(conf.check_iptcaps == TRUE)
				{
					if(iptcap->match_helper == FALSE)
					{
						(void)vrprint.warning("Warning", "mark rules not created: helper-match not supported by this system.");
						return(0); /* this is not an error */
					}
				}

				/* RELATED & ESTABLISHED */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED,RELATED -j MARK --set-mark %lu",
								input_device,
								output_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->from_mac,
								rule->helper,
								nfmark);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
					return(-1);

				/* REVERSE! */
				create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->to_ip, rule->to_netmask, rule->temp_src, sizeof(rule->temp_src));
				create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->from_ip, rule->from_netmask, rule->temp_dst, sizeof(rule->temp_dst));

				snprintf(cmd, sizeof(cmd), "%s %s %s %s %s -m helper --helper \"%s\" -m state --state ESTABLISHED,RELATED -j MARK --set-mark %lu",
								reverse_output_device,
								reverse_input_device,
								stripped_proto,
								rule->temp_src,
								rule->temp_dst,
								rule->helper,
								nfmark);

				if(queue_rule(debuglvl, rule, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
					return(-1);
			}
		}
	}

	return(retval);
}


int
create_rule_masq(const int debuglvl, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule, struct RuleCache_ *create, IptCap *iptcap)
{
	char	cmd[MAX_PIPE_COMMAND] = "";
	char	output_device[sizeof(rule->to_int) + 3] = "";

	/* safety */
	if(rule == NULL || create == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check cap */
	if(conf.check_iptcaps == TRUE)
	{
		if(iptcap->target_masquerade == FALSE)
		{
			(void)vrprint.warning("Warning", "masquerade rules not created: MASQUERADE-target not supported by this system.", __FUNC__, __LINE__);
			return(0); /* this is not an error */
		}
	}

	/* handle empty device (virtual) */
	if(rule->to_int[0] != '\0')
		snprintf(output_device, sizeof(output_device), "-o %s", rule->to_int);

	create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
	create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

	/* assemble the string */
	snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -j %s",
					output_device,
					rule->proto,
					rule->temp_src,
					rule->temp_src_port,
					rule->temp_dst,
					rule->temp_dst_port,
					rule->action);

	if(queue_rule(debuglvl, rule, ruleset, TB_NAT, CH_POSTROUTING, cmd, 0, 0) < 0)
		return(-1);

	/* update the chain counter */
	create->iptcount.postroute++;

	return(0);
}


/*
	TODO: maybe we want an option to use only one interface.
*/
int
create_rule_snat(const int debuglvl, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule, struct RuleCache_ *create, IptCap *iptcap)
{
	char	cmd[MAX_PIPE_COMMAND];
	char	output_device[sizeof(rule->to_int) + 3] = "";

	/* safety */
	if(rule == NULL || create == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check cap */
	if(conf.check_iptcaps == TRUE)
	{
		if(iptcap->target_snat == FALSE)
		{
			(void)vrprint.warning("Warning", "snat rules not created: SNAT-target not supported by this system.", __FUNC__, __LINE__);
			return(0); /* this is not an error */
		}
	}

	/* handle empty device (virtual) */
	if(rule->to_int[0] != '\0')
		snprintf(output_device, sizeof(output_device), "-o %s", rule->to_int);
	
	/* assemble SNAT string - we do this here because LOG can't handle --to-source */
	if(strcmp(rule->action, "SNAT") == 0)
	{
		snprintf(rule->action, sizeof(rule->action), "SNAT --to-source %s", rule->serverip);
	}

	create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
	create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

	/* assemble the string */
	snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -j %s",
					output_device,
					rule->proto,
					rule->temp_src,
					rule->temp_src_port,
					rule->temp_dst,
					rule->temp_dst_port,
					rule->action);

	if(queue_rule(debuglvl, rule, ruleset, TB_NAT, CH_POSTROUTING, cmd, 0, 0) < 0)
		return(-1);

	/* update the counter */
	create->iptcount.postroute++;

	return(0);
}


/*	create_rule_portfw

	Here we create the iptablesrules for portfw. They concist of a PREROUTING rule and a FORWARD rule.
	Both are created for PORTFW.

	For PORTFW we handle both listenport and remoteport options.
*/
int
create_rule_portfw(const int debuglvl, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule, struct RuleCache_ *create, IptCap *iptcap)
{
	int	retval = 0;
	char	cmd[MAX_PIPE_COMMAND] = "";
	char	input_device[sizeof(rule->from_int) + 3] = "";
	char	tmp_dst_prt[32] = "";

	/* safety */
	if(rule == NULL || create == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check cap */
	if(conf.check_iptcaps == TRUE)
	{
		if(iptcap->target_dnat == FALSE)
		{
			(void)vrprint.warning("Warning", "portfw rules not created: DNAT-target not supported by this system.", __FUNC__, __LINE__);
			return(0); /* this is not an error */
		}
	}

	/* see pp 278 linux firewall 2nd edition for portforwarding && 274-275 for redirect */
	
	/* assembeling rule->action, we start with rule->remoteip */

	/* for remote port use, thats easy we want to use the given remoteport as --to-destination ports */
	if(create->option.remoteport == 1 && rule->remoteport_ptr != NULL)
	{
		if(rule->remoteport_ptr->dst_high == -1)
			snprintf(rule->remoteip, sizeof(rule->remoteip), "%s:%d", create->to->ipv4.ipaddress, rule->remoteport_ptr->dst_low);
		else
			snprintf(rule->remoteip, sizeof(rule->remoteip), "%s:%d-%d", create->to->ipv4.ipaddress, rule->remoteport_ptr->dst_low, rule->remoteport_ptr->dst_high);
	}
	/* if we use listenport, we want --to-destination to be the original port(s) of the service. */
	else if(create->option.listenport == 1 && rule->portrange_ptr != NULL)
	{
		if(rule->portrange_ptr->dst_high <= 0)
			snprintf(rule->remoteip, sizeof(rule->remoteip), "%s:%d", create->to->ipv4.ipaddress, rule->portrange_ptr->dst_low);
		else
			snprintf(rule->remoteip, sizeof(rule->remoteip), "%s:%d-%d", create->to->ipv4.ipaddress, rule->portrange_ptr->dst_low, rule->portrange_ptr->dst_high);
	}
	/* if no listenport or remoteport --to-destination is just the ip. */
	else
	{
		snprintf(rule->remoteip, sizeof(rule->remoteip), "%s", create->to->ipv4.ipaddress);
	}

	/* we set this here because we need remoteip */
	if(strncmp(rule->action, "DNAT", 4) == 0)
	{
		snprintf(rule->action, sizeof(rule->action), "DNAT --to-destination %s", rule->remoteip);
	}

	/* set --dport here, but only if we need to change it. */
	if(create->option.listenport == 1 && rule->listenport_ptr != NULL)
	{
		if(rule->listenport_ptr->dst_high == -1)
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d", rule->listenport_ptr->dst_low);
		else
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d:%d", rule->listenport_ptr->dst_low, rule->listenport_ptr->dst_high);
	}

	/* handle empty device (virtual) */
	if(rule->from_int[0] != '\0')
		snprintf(input_device, sizeof(input_device), "-i %s", rule->from_int);

	/* here we pipe the rule, but only if its not a log rule, because we only log the forward rule for portfw */
	if(strncasecmp(rule->action, "LOG", 3) != 0)
	{
		/* src & dst */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->serverip, "255.255.255.255", rule->temp_dst, sizeof(rule->temp_dst));

		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state NEW -j %s",
						input_device,
						rule->proto,
						rule->temp_src,
						rule->temp_src_port,
						rule->temp_dst,
						rule->temp_dst_port,
						rule->from_mac,
						rule->action);

		if(queue_rule(debuglvl, rule, ruleset, TB_NAT, CH_PREROUTING, cmd, 0, 0) < 0)
			return(-1);

		create->iptcount.preroute++;
	}

	/* the forward rule */

	/* store temp_dst_port */
	(void)strlcpy(tmp_dst_prt, rule->temp_dst_port, sizeof(tmp_dst_prt));

	/* if we use remoteport, it will be our destination */
	if (create->option.remoteport == 1 && rule->remoteport_ptr != NULL)
	{
		if(rule->remoteport_ptr->dst_high <= 0)
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d", rule->remoteport_ptr->dst_low);
		else
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d:%d", rule->remoteport_ptr->dst_low, rule->remoteport_ptr->dst_high);
	}

	/*	if we have a listenport option temp_dst_port for the DNAT rule is different from the FORWARD rule, so we fix that here
		we only do this if remoteport == 0, otherwise we use the remoteport
	*/
	if(create->option.listenport == 1 && create->option.remoteport == 0 && rule->portrange_ptr != NULL)
	{
		if(rule->portrange_ptr->dst_high <= 0)
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d", rule->portrange_ptr->dst_low);
		else
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d:%d", rule->portrange_ptr->dst_low, rule->portrange_ptr->dst_high);
	}

	/* set the action */
	if(strncmp(rule->action, "DNAT", 4) == 0)
	{
		if(!create->option.queue)
			snprintf(rule->action, sizeof(rule->action), "NEWACCEPT");
		else
			snprintf(rule->action, sizeof(rule->action), "NEWQUEUE");
	}

	if(create_rule_forward(debuglvl, ruleset, rule, create, iptcap) < 0)
	{
		(void)vrprint.error(-1, "Error", "creating forward rule for portfw failed (in: %s).", __FUNC__);
		retval = -1;
	}

	/* restore temp_dst_port */
	(void)strlcpy(rule->temp_dst_port, tmp_dst_prt, sizeof(rule->temp_dst_port));
	
	return(retval);
}


/*	create_rule_redirect

	see pp 278 linux firewall 2nd edition 274-275 for redirect
*/
int
create_rule_redirect(const int debuglvl, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule, struct RuleCache_ *create, IptCap *iptcap)
{
	char	cmd[MAX_PIPE_COMMAND] = "";
	char	tmp_port[sizeof(rule->temp_dst_port)] = "",
		tmp_action[sizeof(rule->action)] = "",
		tmp_ipaddress[16] = "",
		tmp_netmask[16] = "";
	char	input_device[sizeof(rule->from_int) + 3] = "";

	/* safety */
	if(rule == NULL || create == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check cap */
	if(conf.check_iptcaps == TRUE)
	{
		if(iptcap->target_redirect == FALSE)
		{
			(void)vrprint.warning("Warning", "redirect rules not created: REDIRECT-target not supported by this system.", __FUNC__, __LINE__);
			return(0); /* this is not an error */
		}
	}

	/* handle empty device (virtual) */
	if(rule->from_int[0] != '\0')
		snprintf(input_device, sizeof(input_device), "-i %s", rule->from_int);

	/* here we pipe the rule, but only if its not a log rule, because we only log the forward rule for portfw */
	if(strncasecmp(rule->action, "LOG", 3) != 0)
	{
		/* src & dst */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->to_ip, rule->to_netmask, rule->temp_dst, sizeof(rule->temp_dst));

		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state NEW -j %s",
						input_device,
						rule->proto,
						rule->temp_src,
						rule->temp_src_port,
						rule->temp_dst,
						rule->temp_dst_port,
						rule->from_mac,
						rule->action);

		if(queue_rule(debuglvl, rule, ruleset, TB_NAT, CH_PREROUTING, cmd, 0, 0) < 0)
			return(-1);

		create->iptcount.preroute++;
	}

	/*
		create the corresponding input rule
	*/

	if(create->to_firewall == FALSE)
	{
		/* not to the firewall, but the input rule needs that, so get the ipaddress from the fw
		 
		 but first store the current ipaddress and netmask */
		(void)strlcpy(tmp_ipaddress, rule->to_ip, sizeof(tmp_ipaddress));
		(void)strlcpy(tmp_netmask,  rule->to_netmask, sizeof(tmp_netmask));
	}

	/* temp store the realports */
	(void)strlcpy(tmp_port, rule->temp_dst_port, sizeof(tmp_port));
	/* temp store the action */
	if(strncasecmp(rule->action, "LOG", 3) != 0)
		(void)strlcpy(tmp_action, rule->action, sizeof(tmp_action));

	/* set the redirectport to rule->temp_dst_port */
	snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d", create->option.redirectport);
	/* set the action */
	if(strncasecmp(rule->action, "LOG", 3) != 0)
	{
		if(!create->option.queue)
			snprintf(rule->action, sizeof(rule->action), "NEWACCEPT");
		else
			snprintf(rule->action, sizeof(rule->action), "NEWQUEUE");
	}
	if(create->to_firewall == FALSE && create->from_any == FALSE)
	{
		(void)strlcpy(rule->to_ip, rule->from_if_ptr->ipv4.ipaddress, sizeof(rule->to_ip));
		(void)strlcpy(rule->to_netmask, "255.255.255.255", sizeof(rule->to_netmask));
	}
	else if(create->to_firewall == FALSE && create->from_any == TRUE)
	{
		(void)strlcpy(rule->to_ip, "", sizeof(rule->to_ip));
		(void)strlcpy(rule->to_netmask, "", sizeof(rule->to_netmask));
	}

	/* now create the input rule */
	if(create_rule_input(debuglvl, ruleset, rule, create, iptcap) < 0)
	{
		(void)vrprint.error(-1, "Error", "creating input rule for redirect failed (in: %s).", __FUNC__);
		return(-1);
	}
		
	/* restore the realports */
	(void)strlcpy(rule->temp_dst_port, tmp_port, sizeof(rule->temp_dst_port));
	/* restore the chain */
//	(void)strlcpy(create->chain, tmp_chain, sizeof(create->chain));
	/* restore the action */
	if(strncasecmp(rule->action, "LOG", 3) != 0)
		(void)strlcpy(rule->action, tmp_action, sizeof(rule->action));
	if(create->to_firewall == FALSE)
	{
		(void)strlcpy(rule->to_ip, tmp_ipaddress, sizeof(rule->to_ip));
		(void)strlcpy(rule->to_netmask, tmp_netmask, sizeof(rule->to_netmask));
	}

	return(0);
}


/*	create_rule_dnat


*/
int
create_rule_dnat(	const int debuglvl, /*@null@*/RuleSet *ruleset,
			struct RuleCreateData_ *rule,
			struct RuleCache_ *create, IptCap *iptcap)
{
	int	retval = 0;
	char	cmd[MAX_PIPE_COMMAND] = "";
	char	input_device[sizeof(rule->from_int) + 3] = "";
//	char	tmp_dst_prt[32] = "";

	/* safety */
	if(rule == NULL || create == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
			"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check cap */
	if(conf.check_iptcaps == TRUE)
	{
		if(iptcap->target_dnat == FALSE)
		{
			(void)vrprint.warning("Warning", "dnat rules not "
				"created: DNAT-target not supported by this "
				"system.", __FUNC__, __LINE__);
			return(0); /* this is not an error */
		}
	}

	/* see pp 278 linux firewall 2nd edition for portforwarding  */
	
	/* assembeling rule->action, we start with rule->remoteip */

	/* for remote port use, thats easy we want to use the given remoteport as --to-destination ports */
	if(create->option.remoteport == 1 && rule->remoteport_ptr != NULL)
	{
		if(rule->remoteport_ptr->dst_high == -1)
			snprintf(rule->remoteip, sizeof(rule->remoteip), "%s:%d", create->to->ipv4.ipaddress, rule->remoteport_ptr->dst_low);
		else
			snprintf(rule->remoteip, sizeof(rule->remoteip), "%s:%d-%d", create->to->ipv4.ipaddress, rule->remoteport_ptr->dst_low, rule->remoteport_ptr->dst_high);
	}
	/* if we use listenport, we want --to-destination to be the original port(s) of the service. */
	else if(create->option.listenport == 1 && rule->portrange_ptr != NULL)
	{
		if(rule->portrange_ptr->dst_high <= 0)
			snprintf(rule->remoteip, sizeof(rule->remoteip), "%s:%d", create->to->ipv4.ipaddress, rule->portrange_ptr->dst_low);
		else
			snprintf(rule->remoteip, sizeof(rule->remoteip), "%s:%d-%d", create->to->ipv4.ipaddress, rule->portrange_ptr->dst_low, rule->portrange_ptr->dst_high);
	}
	/* if no listenport or remoteport --to-destination is just the ip. */
	else
	{
		snprintf(rule->remoteip, sizeof(rule->remoteip), "%s", create->to->ipv4.ipaddress);
	}

	/* we set this here because we need remoteip */
	if(strncmp(rule->action, "DNAT", 4) == 0)
	{
		snprintf(rule->action, sizeof(rule->action), "DNAT --to-destination %s", rule->remoteip);
	}

	/* set --dport here, but only if we need to change it. */
	if(create->option.listenport == 1 && rule->listenport_ptr != NULL)
	{
		if(rule->listenport_ptr->dst_high == -1)
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d", rule->listenport_ptr->dst_low);
		else
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d:%d", rule->listenport_ptr->dst_low, rule->listenport_ptr->dst_high);
	}

	/* handle empty device (virtual) */
	if(rule->from_int[0] != '\0')
		snprintf(input_device, sizeof(input_device), "-i %s", rule->from_int);

	/* src & dst */
	create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
	create_srcdst_string(debuglvl, SRCDST_DESTINATION, rule->serverip, "255.255.255.255", rule->temp_dst, sizeof(rule->temp_dst));

	snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state NEW -j %s",
					input_device,
					rule->proto,
					rule->temp_src,
					rule->temp_src_port,
					rule->temp_dst,
					rule->temp_dst_port,
					rule->from_mac,
					rule->action);

	if(queue_rule(debuglvl, rule, ruleset, TB_NAT, CH_PREROUTING, cmd, 0, 0) < 0)
		return(-1);

	create->iptcount.preroute++;

	return(retval);
}


/*	create_rule_bounce

*/
int
create_rule_bounce(	const int debuglvl, /*@null@*/RuleSet *ruleset,
			struct RuleCreateData_ *rule,
			struct RuleCache_ *create, IptCap *iptcap)
{
	int	retval = 0;
	char	cmd[MAX_PIPE_COMMAND] = "";
	char	input_device[sizeof(rule->from_int) + 3] = "";
	char	tmp_dst_prt[32] = "";

	/* safety */
	if(rule == NULL || create == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
			"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check cap */
	if(conf.check_iptcaps == TRUE)
	{
		if(iptcap->target_dnat == FALSE)
		{
			(void)vrprint.warning("Warning", "bounce rules not "
				"created: DNAT-target not supported by this "
				"system.", __FUNC__, __LINE__);
			return(0); /* this is not an error */
		}
		if(iptcap->target_snat == FALSE)
		{
			(void)vrprint.warning("Warning", "bounce rules not "
				"created: SNAT-target not supported by this "
				"system.", __FUNC__, __LINE__);
			return(0); /* this is not an error */
		}
	}

	/* set --dport here, but only if we need to change it. */
	if(create->option.listenport == 1 && rule->listenport_ptr != NULL)
	{
		if(rule->listenport_ptr->dst_high == -1)
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d", rule->listenport_ptr->dst_low);
		else
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d:%d", rule->listenport_ptr->dst_low, rule->listenport_ptr->dst_high);
	}

	/* handle empty device (virtual) */
	if(rule->from_int[0] != '\0')
		snprintf(input_device, sizeof(input_device), "-i %s", rule->from_int);

	/* here we pipe the rule, but only if its not a log rule, because we only log the forward rule for portfw */
	if(strncasecmp(rule->action, "LOG", 3) != 0)
	{
		/* see pp 278 linux firewall 2nd edition for portforwarding */
		snprintf(rule->remoteip, sizeof(rule->remoteip), "%s", create->to->ipv4.ipaddress);
		/* we set this here because we need remoteip */
		if(strncmp(rule->action, "DNAT", 4) == 0)
		{
			snprintf(rule->action, sizeof(rule->action), "DNAT --to-destination %s", rule->remoteip);
		}

		/* src & dst */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, create->via_int->ipv4.ipaddress, "255.255.255.255", rule->temp_dst, sizeof(rule->temp_dst));

		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s %s -m state --state NEW -j %s",
						input_device,
						rule->proto,
						rule->temp_src,
						rule->temp_src_port,
						rule->temp_dst,
						rule->temp_dst_port,
						rule->from_mac,
						rule->action);

		if(queue_rule(debuglvl, rule, ruleset, TB_NAT, CH_PREROUTING, cmd, 0, 0) < 0)
			return(-1);

		create->iptcount.preroute++;

		/* see pp 278 linux firewall 2nd edition for portforwarding */
		//snprintf(rule->remoteip, sizeof(rule->remoteip), "%s", create->to->ipv4.ipaddress);
		/* we set this here because we need remoteip */
		snprintf(rule->action, sizeof(rule->action), "SNAT --to-source %s", create->via_int->ipv4.ipaddress);

		/* src & dst */
		create_srcdst_string(debuglvl, SRCDST_SOURCE, rule->from_ip, rule->from_netmask, rule->temp_src, sizeof(rule->temp_src));
		create_srcdst_string(debuglvl, SRCDST_DESTINATION, create->to->ipv4.ipaddress, "255.255.255.255", rule->temp_dst, sizeof(rule->temp_dst));

		/* handle empty device (virtual) */
		if(rule->from_int[0] != '\0')
			snprintf(input_device, sizeof(input_device), "-o %s", rule->from_int);

		snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s -m state --state NEW -j %s",
						input_device,
						rule->proto,
						rule->temp_src,
						rule->temp_src_port,
						rule->temp_dst,
						rule->temp_dst_port,
						rule->action);

		if(queue_rule(debuglvl, rule, ruleset, TB_NAT, CH_POSTROUTING, cmd, 0, 0) < 0)
			return(-1);

		create->iptcount.postroute++;
	}

	/* the forward rule */

	/* store temp_dst_port */
	(void)strlcpy(tmp_dst_prt, rule->temp_dst_port, sizeof(tmp_dst_prt));

	/* if we use remoteport, it will be our destination */
	if (create->option.remoteport == 1 && rule->remoteport_ptr != NULL)
	{
		if(rule->remoteport_ptr->dst_high <= 0)
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d", rule->remoteport_ptr->dst_low);
		else
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d:%d", rule->remoteport_ptr->dst_low, rule->remoteport_ptr->dst_high);
	}

	/*	if we have a listenport option temp_dst_port for the DNAT rule is different from the FORWARD rule, so we fix that here
		we only do this if remoteport == 0, otherwise we use the remoteport
	*/
	if(create->option.listenport == 1 && create->option.remoteport == 0 && rule->portrange_ptr != NULL)
	{
		if(rule->portrange_ptr->dst_high <= 0)
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d", rule->portrange_ptr->dst_low);
		else
			snprintf(rule->temp_dst_port, sizeof(rule->temp_dst_port), "--dport %d:%d", rule->portrange_ptr->dst_low, rule->portrange_ptr->dst_high);
	}

	/* set the action */
	if(	strncmp(rule->action, "DNAT", 4) == 0 ||
		strncmp(rule->action, "SNAT", 4) == 0)
	{
		if(!create->option.queue)
			snprintf(rule->action, sizeof(rule->action), "NEWACCEPT");
		else
			snprintf(rule->action, sizeof(rule->action), "NEWQUEUE");
	}

	if(create_rule_forward(debuglvl, ruleset, rule, create, iptcap) < 0)
	{
		(void)vrprint.error(-1, "Error", "creating forward rule for portfw failed (in: %s).", __FUNC__);
		retval = -1;
	}

	/* restore temp_dst_port */
	(void)strlcpy(rule->temp_dst_port, tmp_dst_prt, sizeof(rule->temp_dst_port));
	
	return(retval);
}


/* pre_rules

	Cleanup
		chains
	Sets up
		default policies
		connection tracking
		portscan detection
*/
int
pre_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, Interfaces *interfaces, IptCap *iptcap)
{
	int			retval = 0,
				result = 0;
	char			cmd[MAX_PIPE_COMMAND] = "";
	d_list_node		*d_node = NULL;
	struct InterfaceData_ 	*iface_ptr = NULL;
	char			limit[] = "-m limit --limit 1/s --limit-burst 2";
	char			logprefix[64] = "";
	char			acc_chain_name[32+3] = ""; /* chain name 32 + '-A ' = 3 */

	/* safety */
	if(interfaces == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check cap */
	if(conf.check_iptcaps == TRUE)
	{
		if(iptcap->target_log == FALSE)
		{
			(void)vrprint.warning("Warning", "not creating logrules. LOG-target not supported by system.");
		}
		else
		{
			if(iptcap->match_limit == FALSE)
			{
				(void)vrprint.warning("Warning", "not setting limits on logrules. Limit-match not supported by system.");
				memset(limit, 0, sizeof(limit));
			}
		}
	}

	/*
		first flush the chains
	*/
	if(ruleset == NULL)
	{
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Flushing chains... except PRE-VRMR-CHAINS...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Flushing chains...");

		snprintf(cmd, MAX_PIPE_COMMAND, "%s --flush", conf.iptables_location);
		result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
		if(result < 0) retval = -1;
		snprintf(cmd, MAX_PIPE_COMMAND, "%s -t nat --flush", conf.iptables_location);
		result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
		if(result < 0) retval = -1;
		snprintf(cmd, MAX_PIPE_COMMAND, "%s -t mangle --flush", conf.iptables_location);
		result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
		if(result < 0) retval = -1;
	}


	/*
		BEGIN -- PRE-VUURMUUR-CHAINS feature - by(as).
		Allow to make some specials rules before the Vuurmuur rules kick in.
	*/

	/* mangle table uses {PREROUTING,INPUT,FORWARD,POSTROUTING,OUTPUT} hooks */

	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Making specials PRE-VRMR-{PREROUTING,INPUT,FORWARD,POSTROUTING,OUTPUT} CHAINS in mangle table...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Making specials PRE-VRMR-{PREROUTING,INPUT,FORWARD,POSTROUTING,OUTPUT} CHAINS in mangle table...");

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-PREROUTING 2>/dev/null", conf.iptables_location, TB_MANGLE);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-PREROUTING");
	if(process_rule(debuglvl, ruleset, TB_MANGLE, CH_PREROUTING, cmd, 0, 0) < 0)
		retval = -1;

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-INPUT 2>/dev/null", conf.iptables_location, TB_MANGLE);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-INPUT");
	if(process_rule(debuglvl, ruleset, TB_MANGLE, CH_INPUT, cmd, 0, 0) < 0)
		retval = -1;

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-FORWARD 2>/dev/null", conf.iptables_location, TB_MANGLE);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-FORWARD");
	if(process_rule(debuglvl, ruleset, TB_MANGLE, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-POSTROUTING 2>/dev/null", conf.iptables_location, TB_MANGLE);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-POSTROUTING");
	if(process_rule(debuglvl, ruleset, TB_MANGLE, CH_POSTROUTING, cmd, 0, 0) < 0)
		retval = -1;

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-OUTPUT 2>/dev/null", conf.iptables_location, TB_MANGLE);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-OUTPUT");
	if(process_rule(debuglvl, ruleset, TB_MANGLE, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;


	/* filter table uses {INPUT,FORWARD,OUTPUT} hooks */

	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Making specials PRE-VRMR-{INPUT,FORWARD,OUTPUT} CHAINS in filter table...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Making specials PRE-VRMR-{INPUT,FORWARD,OUTPUT} CHAINS in filter table...");

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-INPUT 2>/dev/null", conf.iptables_location, TB_FILTER);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-INPUT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval = -1;

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-FORWARD 2>/dev/null", conf.iptables_location, TB_FILTER);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-FORWARD");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-OUTPUT 2>/dev/null", conf.iptables_location, TB_FILTER);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-OUTPUT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;


	/* nat table uses {PREROUTING,POSTROUTING,OUTPUT} hooks */

	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Making specials PRE-VRMR-{PREROUTING,POSTROUTING,OUTPUT} CHAINS in nat table...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Making specials PRE-VRMR-{PREROUTING,POSTROUTING,OUTPUT} CHAINS in nat table...");

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-PREROUTING 2>/dev/null", conf.iptables_location, TB_NAT);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-PREROUTING");
	if(process_rule(debuglvl, ruleset, TB_NAT, CH_PREROUTING, cmd, 0, 0) < 0)
		retval = -1;

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-POSTROUTING 2>/dev/null", conf.iptables_location, TB_NAT);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-POSTROUTING");
	if(process_rule(debuglvl, ruleset, TB_NAT, CH_POSTROUTING, cmd, 0, 0) < 0)
		retval=-1;

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s %s -N PRE-VRMR-OUTPUT 2>/dev/null", conf.iptables_location, TB_NAT);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j PRE-VRMR-OUTPUT");
	if(process_rule(debuglvl, ruleset, TB_NAT, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;

	/* END -- PRE-VUURMUUR-CHAINS feature - by(as). */


	/*
		allow local loopback
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Allowing local loopback...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Allowing local loopback...");

	snprintf(cmd, sizeof(cmd), "-i lo -j ACCEPT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval = -1;

	snprintf(cmd, sizeof(cmd), "-o lo -j ACCEPT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;


	/*
		create an accounting rule in INPUT, OUTPUT and FORWARD.
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Creating interface counters...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Creating interface counters...");

	for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
	{
		if(!(iface_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}

		/* if the interface active? */
		if(iface_ptr->active == TRUE)
		{
			/* does the interface have an ipaddress? */
			if(strcmp(iface_ptr->ipv4.ipaddress, "") != 0)
			{
				/* Check for empty device string and virtual device. */
				if(strcmp(iface_ptr->device, "") != 0 && !iface_ptr->device_virtual)
				{
					/* create a chain name for use with IP Traffic Volume Logger
						WITHOUT -A !!! */
					snprintf(acc_chain_name, sizeof(acc_chain_name), "ACC-%s", iface_ptr->device);

					/* create the chain itself if not in ruleset mode */
					if(!ruleset)
					{
						snprintf(cmd, sizeof(cmd), "%s -N %s 2>/dev/null",
										conf.iptables_location,
										acc_chain_name);
						(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
					}

					/* create a chain name for use with IP Traffic Volume Logger
						WITH -A !!! */
					snprintf(acc_chain_name, sizeof(acc_chain_name), "-A ACC-%s", iface_ptr->device);

					/* create an outgoing rule for in the chain (IPTRAFVOL wants outgoing first) */
					snprintf(cmd, sizeof(cmd), "-o %s -j RETURN", iface_ptr->device);
					(void)process_rule(debuglvl, ruleset, TB_FILTER, acc_chain_name, cmd,
							iface_ptr->cnt ? iface_ptr->cnt->acc_out_packets : 0,
							iface_ptr->cnt ? iface_ptr->cnt->acc_out_bytes : 0);

					/* create an incoming rule for in the chain (IPTRAFVOL wants imcoming second) */
					snprintf(cmd, sizeof(cmd), "-i %s -j RETURN", iface_ptr->device);
					(void)process_rule(debuglvl, ruleset, TB_FILTER, acc_chain_name, cmd,
							iface_ptr->cnt ? iface_ptr->cnt->acc_in_packets : 0,
							iface_ptr->cnt ? iface_ptr->cnt->acc_in_bytes : 0);

					/* create a chain name for use with IP Traffic Volume Logger
						WITHOUT -A !!! */
					snprintf(acc_chain_name, sizeof(acc_chain_name), "ACC-%s", iface_ptr->device);

					/*
						first in the input chain
					*/
					snprintf(cmd, sizeof(cmd), "-i %s -j %s", iface_ptr->device, acc_chain_name);
					if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, iface_ptr->cnt ? iface_ptr->cnt->input_packets : 0, iface_ptr->cnt ? iface_ptr->cnt->input_bytes : 0) < 0)
						retval=-1;

					/*
						then in the output chain
					*/
					snprintf(cmd, sizeof(cmd), "-o %s -j %s", iface_ptr->device, acc_chain_name);
					if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, iface_ptr->cnt ? iface_ptr->cnt->output_packets : 0, iface_ptr->cnt ? iface_ptr->cnt->output_bytes : 0) < 0)
						retval=-1;

					/*
						then in the forward chain, in
					*/
					snprintf(cmd, sizeof(cmd), "-i %s -j %s", iface_ptr->device, acc_chain_name);
					if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, iface_ptr->cnt ? iface_ptr->cnt->forwardin_packets : 0, iface_ptr->cnt ? iface_ptr->cnt->forwardin_bytes : 0) < 0)
						retval=-1;

					/*
						then in the forward chain, out
					*/
					snprintf(cmd, sizeof(cmd), "-o %s -j %s", iface_ptr->device, acc_chain_name);
					if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, iface_ptr->cnt ? iface_ptr->cnt->forwardout_packets : 0, iface_ptr->cnt ? iface_ptr->cnt->forwardout_bytes : 0) < 0)
						retval=-1;
				}
			}
		}
	}


	if(ruleset == NULL)
	{
		/*
			set default policies to DROP
		*/
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting default policies...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting default policies...");

		snprintf(cmd, MAX_PIPE_COMMAND, "%s --policy INPUT DROP", conf.iptables_location);
		result=pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
		if(result < 0) retval=-1;
		snprintf(cmd, MAX_PIPE_COMMAND, "%s --policy OUTPUT DROP", conf.iptables_location);
		result=pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
		if(result < 0) retval=-1;
		snprintf(cmd, MAX_PIPE_COMMAND, "%s --policy FORWARD DROP", conf.iptables_location);
		result=pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
		if(result < 0) retval=-1;
	}
	else
	{
		ruleset->filter_input_policy = 1;	/* drop */
		ruleset->filter_output_policy = 1;	/* drop */
		ruleset->filter_forward_policy = 1;	/* drop */
	}


	/*
		stealthscan protection
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up stealth scan protection...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up stealth scan protection...");

	/* ALL NONE */
	if(	conf.log_probes == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_NOTSET, "DROP", "probe ALL");

		snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags ALL NONE %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags ALL NONE -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	/* SYN - FIN */
	if(	conf.log_probes == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_NOTSET, "DROP", "probe SYN-FIN");

		snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	/* SYN - RST */
	if(	conf.log_probes == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_NOTSET, "DROP", "probe SYN-RST");

		snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags SYN,RST SYN,RST %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	/* FIN - RST */
	if(	conf.log_probes == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_NOTSET, "DROP", "probe FIN-RST");

		snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags FIN,RST FIN,RST %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	/* ACK - FIN */
	if(	conf.log_probes == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_NOTSET, "DROP", "probe FIN");

		snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags ACK,FIN FIN %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	/* ACK - PSH */
	if(	conf.log_probes == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_NOTSET, "DROP", "probe PSH");

		snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags ACK,PSH PSH %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags ACK,PSH PSH -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	/* ACK - URG */
	if(	conf.log_probes == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_NOTSET, "DROP", "probe URG");

		snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags ACK,URG URG %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --tcp-flags ACK,URG URG -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	/* New tcp but no SYN */
	if(	conf.log_no_syn == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_NOTSET, "DROP", "no SYN");

		snprintf(cmd, sizeof(cmd), "-p tcp -m tcp ! --syn -m state --state NEW %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp ! --syn -m state --state NEW -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	/*
		Fragmented packets
	*/
	if(	conf.log_frag == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_NOTSET, "DROP", "FRAG");

		snprintf(cmd, sizeof(cmd), "-f %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-f -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;


	/*
		syn-flooding protection
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up SYN-limit...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up SYN-limit...");

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s -N SYNLIMIT 2>/dev/null", conf.iptables_location);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	/* create the rules */
	if(update_synlimit_rules(debuglvl, ruleset, iptcap) < 0)
		retval = -1;

	/*
		udp-flooding protection
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up UDP-limit...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up UDP-limit...");

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s -N UDPLIMIT 2>/dev/null", conf.iptables_location);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	/* create the rules */
	if(update_udplimit_rules(debuglvl, ruleset, iptcap) < 0)
		retval = -1;

	/*
		create the NEWACCEPT target
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up NEWACCEPT target...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up NEWACCEPT target...");

	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s -N NEWACCEPT 2>/dev/null", conf.iptables_location);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --syn -j SYNLIMIT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_NEWACCEPT, cmd, 0, 0) < 0)
		retval=-1;

	snprintf(cmd, sizeof(cmd), "-p udp -m state --state NEW -j UDPLIMIT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_NEWACCEPT, cmd, 0, 0) < 0)
		retval=-1;

	snprintf(cmd, sizeof(cmd), "-j ACCEPT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_NEWACCEPT, cmd, 0, 0) < 0)
		retval=-1;

	/*
		create the NEWQUEUE target
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up NEWQUEUE target...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up NEWQUEUE target...");
	if(conf.check_iptcaps == FALSE || iptcap->target_queue == TRUE)
	{
		if(ruleset == NULL)
		{
			snprintf(cmd, sizeof(cmd), "%s -N NEWQUEUE 2>/dev/null", conf.iptables_location);
			(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
		}

		snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --syn -j SYNLIMIT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_NEWQUEUE, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-p udp -m state --state NEW -j UDPLIMIT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_NEWQUEUE, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-j QUEUE");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_NEWQUEUE, cmd, 0, 0) < 0)
			retval=-1;
	} else {
		(void)vrprint.info("Info", "NEWQUEUE target not setup. QUEUE-target not supported by system.");
	}

	/*
		set up connectiontracking including mark target range

		 mark 0x0/0xff000000 means:
		 start mark:	0
		 end mark:	16777216
	*/
	if(conf.check_iptcaps == FALSE || iptcap->match_mark == TRUE)
	{
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up connection-tracking...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up connection-tracking...");

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x0/0xff000000 -m state --state ESTABLISHED -j ACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x0/0xff000000 -m state --state ESTABLISHED -j ACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x0/0xff000000 -m state --state ESTABLISHED -j ACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x0/0xff000000 -m state --state RELATED -j NEWACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x0/0xff000000 -m state --state RELATED -j NEWACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x0/0xff000000 -m state --state RELATED -j NEWACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}
	else
	{
		/* just in case we don't support mark match */
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up connection-tracking...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up connection-tracking...");

		snprintf(cmd, sizeof(cmd), "-m state --state ESTABLISHED -j ACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m state --state ESTABLISHED -j ACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m state --state ESTABLISHED -j ACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m state --state RELATED -j NEWACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m state --state RELATED -j NEWACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m state --state RELATED -j NEWACCEPT");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}


	/*
		set up connectiontracking for QUEUE:
		 
		 mark 0x1000000/0xff000000 means:
		 start mark:	16777216
		 end mark:	33554432
	*/
	if(conf.check_iptcaps == FALSE || (iptcap->target_queue == TRUE && iptcap->match_mark == TRUE))
	{
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up connection-tracking for QUEUE targets...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up connection-tracking for QUEUE targets...");

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x1000000/0xff000000 -m state --state ESTABLISHED -j QUEUE");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x1000000/0xff000000 -m state --state ESTABLISHED -j QUEUE");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x1000000/0xff000000 -m state --state ESTABLISHED -j QUEUE");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x1000000/0xff000000 -m state --state RELATED -j NEWQUEUE");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x1000000/0xff000000 -m state --state RELATED -j NEWQUEUE");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-m mark --mark 0x1000000/0xff000000 -m state --state RELATED -j NEWQUEUE");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}
	else
	{
		(void)vrprint.info("Info", "connection tracking for QUEUE not setup. QUEUE-target and/or mark-match not supported by system.");
	}

	/*
		create the NEWNFQUEUE target: the content of the chain
		is handled by create_newnfqueue_rules()
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up NEWNFQUEUE target...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up NEWNFQUEUE target...");
	if(conf.check_iptcaps == FALSE || iptcap->target_queue == TRUE)
	{
		if(ruleset == NULL)
		{
			snprintf(cmd, sizeof(cmd), "%s -N NEWNFQUEUE 2>/dev/null", conf.iptables_location);
			(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
		}
	} else {
		(void)vrprint.info("Info", "NEWNFQUEUE target not setup. NFQUEUE-target not supported by system.");
	}

	/*
		Setup NFQUEUE connection tracking
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up connection-tracking for NFQUEUE targets...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up connection-tracking for NFQUEUE targets...");

	if(conf.check_iptcaps == FALSE || (iptcap->target_nfqueue == TRUE && iptcap->match_connmark == TRUE))
	{
		if(ruleset == NULL)
		{
			/* create the chain and insert it into input, output and forward.
		
				NOTE: we ignore the returncode and want no output (although we get some
				in the errorlog) because if we start vuurmuur when a ruleset is already in
				place, the chain will exist and iptables will complain.
			*/
			snprintf(cmd, sizeof(cmd), "%s -N ESTRELNFQUEUE 2>/dev/null", conf.iptables_location);
			(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
		}

		snprintf(cmd, sizeof(cmd), "-m connmark ! --mark 0 -j ESTRELNFQUEUE");
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	/*
		invalid input
	*/
	if(	conf.log_invalid == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Drop and log invalid packets...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Drop and log invalid packets...");

		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_INPUT, "DROP", "in INVALID");

		snprintf(cmd, sizeof(cmd), "-m state --state INVALID %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-m state --state INVALID -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;

	/*
		invalid output
	*/
	if(	conf.log_invalid == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_OUTPUT, "DROP", "out INVALID");

		snprintf(cmd, sizeof(cmd), "-m state --state INVALID %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-m state --state INVALID -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;

	/*
		invalid forward
	*/
	if(	conf.log_invalid == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_FORWARD, "DROP", "fw INVALID");

		snprintf(cmd, sizeof(cmd), "-m state --state INVALID %s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-m state --state INVALID -j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;


	/*
		Setup Block lists
	*/
	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up blocklist...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up blocklist...");

	if(ruleset == NULL)
	{
		/* create the chain and insert it into input, output and forward.
	
			NOTE: we ignore the returncode and want no output (although we get some
			in the errorlog) because if we start vuurmuur when a ruleset is already in
			place, the chain will exist and iptables will complain.
		*/
		snprintf(cmd, sizeof(cmd), "%s -N BLOCKLIST 2>/dev/null", conf.iptables_location);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j BLOCKLIST");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;

	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;

	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	if(ruleset == NULL)
	{
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Setting up BLOCK target...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Setting up BLOCK target...");
		/* create the BLOCK action
	
	   	NOTE: see BLOCKLIST creation. */
		snprintf(cmd, sizeof(cmd), "%s -N BLOCK 2>/dev/null", conf.iptables_location);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	if(	conf.log_blocklist == TRUE &&
		(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE))
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_INPUT, "DROP", "BLOCKED");

		snprintf(cmd, sizeof(cmd), "%s -j LOG %s %s %s",
							limit,
							logprefix,
							loglevel,
							log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_BLOCKTARGET, cmd, 0, 0) < 0)
			retval=-1;
	}

	snprintf(cmd, sizeof(cmd), "-j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_BLOCKTARGET, cmd, 0, 0) < 0)
		retval=-1;


	if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Creating TCPRESET target...\n");
	if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Creating TCPRESET target...");

	/*
		safe TCP-RESET REJECT target
	*/
	if(ruleset == NULL)
	{
		snprintf(cmd, sizeof(cmd), "%s -N TCPRESET 2>/dev/null", conf.iptables_location);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	/* for tcp we use tcp-reset like requested */
	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp -j REJECT --reject-with tcp-reset");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_TCPRESETTARGET, cmd, 0, 0) < 0)
		retval=-1;

	/* for the rest we use normal REJECT, which means icmp-port-unreachable */
	snprintf(cmd, sizeof(cmd), "-j REJECT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_TCPRESETTARGET, cmd, 0, 0) < 0)
		retval=-1;

	/*
		anti spoof rules
	*/
	if(ruleset == NULL)
	{
		if(conf.bash_out == TRUE)
			fprintf(stdout, "\n# Setting up anti-spoofing rules...\n");

		/*	create the chain and insert it into input, output and
			forward.
	
			NOTE: we ignore the returncode and want no output
			(although we get some in the errorlog) because if we
			start vuurmuur when a ruleset is already in
			place, the chain will exist and iptables will
			complain. */
		snprintf(cmd, sizeof(cmd), "%s -N ANTISPOOF 2>/dev/null",
			conf.iptables_location);
		(void)pipe_command(debuglvl, &conf, cmd, PIPE_QUIET);
	}

	snprintf(cmd, sizeof(cmd), "-j ANTISPOOF");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
		retval=-1;

	return(retval);
}


/*	update_synlimit_rules

	Creates/updates the the rules in the SYNLIMIT chain.
	
	Note: if the limit-match is not supported, bail out of here.
*/
int
update_synlimit_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, IptCap *iptcap)
{
	int			retval = 0,
				result = 0;
	char			cmd[MAX_PIPE_COMMAND] = "";
	char			logprefix[64] = "";

	/* caps */
	if(conf.check_iptcaps == TRUE && iptcap->match_limit == FALSE)
	{
		(void)vrprint.warning("Warning", "synlimit rules not setup. Limit-match not supported by system.");
		return(0); /* no error */
	}

	if(conf.syn_limit == 0 || conf.syn_limit_burst == 0)
	{
		(void)vrprint.error(-1, "Error", "limit of 0 cannot be used (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* flush the chain if we are not in ruleset mode */
	if(ruleset == NULL)
	{
		/* first flush the chain */
		snprintf(cmd, MAX_PIPE_COMMAND, "%s --flush SYNLIMIT", conf.iptables_location);
		result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
		if(result < 0)
			retval = -1;
	}

	/* if we don't use syn_limit bail out now */
	if(conf.use_syn_limit == FALSE)
		return(0);

	/* create the return rule */
	snprintf(cmd, sizeof(cmd), "-m limit --limit %u/s --limit-burst %u -j RETURN", conf.syn_limit, conf.syn_limit_burst);
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_SYNLIMITTARGET, cmd, 0, 0) < 0)
		retval=-1;

	/* the log rule */
	if(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE)
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_INPUT, "DROP", "SYNLIMIT reach.");

		snprintf(cmd, sizeof(cmd), "-m limit --limit 1/s --limit-burst 2 -j LOG %s %s %s", 
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_SYNLIMITTARGET, cmd, 0, 0) < 0)
			retval=-1;
	}

	/* and finally the drop rule */
	snprintf(cmd, sizeof(cmd), "-j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_SYNLIMITTARGET, cmd, 0, 0) < 0)
		retval=-1;

	return(retval);
}


/*	update_udplimit_rules

	Creates/updates the the rules in the UDPLIMIT chain.
	
	Note: if the limit-match is not supported, bail out of here.
*/
int
update_udplimit_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, IptCap *iptcap)
{
	int			retval = 0,
				result = 0;
	char			cmd[MAX_PIPE_COMMAND] = "";
	char			logprefix[64] = "";

	/* caps */
	if(conf.check_iptcaps == TRUE && iptcap->match_limit == FALSE)
	{
		(void)vrprint.warning("Warning", "udplimit rules not setup. Limit-match not supported by system.");
		return(0); /* no error */
	}

	if(conf.udp_limit == 0 || conf.udp_limit_burst == 0)
	{
		(void)vrprint.error(-1, "Error", "limit of 0 cannot be used (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* flush the chain if we are not in ruleset mode */
	if(ruleset == NULL)
	{
		/* first flush the chain */
		snprintf(cmd, MAX_PIPE_COMMAND, "%s --flush UDPLIMIT", conf.iptables_location);
		result = pipe_command(debuglvl, &conf, cmd, PIPE_VERBOSE);
		if(result < 0)
			retval = -1;
	}

	/* if we don't use udp_limit bail out now */
	if(conf.use_udp_limit == FALSE)
		return(0);

	/* create the return rule */
	snprintf(cmd, sizeof(cmd), "-m limit --limit %u/s --limit-burst %u -j RETURN", conf.udp_limit, conf.udp_limit_burst);
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_UDPLIMITTARGET, cmd, 0, 0) < 0)
		retval=-1;

	/* the log rule */
	if(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE)
	{
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_INPUT, "DROP", "UDPLIMIT reach.");

		snprintf(cmd, sizeof(cmd), "-m limit --limit 1/s --limit-burst 2 -j LOG %s %s %s",
						logprefix,
						loglevel,
						log_tcp_options);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_UDPLIMITTARGET, cmd, 0, 0) < 0)
			retval=-1;
	}

	/* and finally the drop rule */
	snprintf(cmd, sizeof(cmd), "-j DROP");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_UDPLIMITTARGET, cmd, 0, 0) < 0)
		retval=-1;

	return(retval);
}


/*	post_rules

	Enables logging in the INPUT, OUTPUT and FORWARD chains.
	
	If forward_rules == 1, then /proc/sys/net/ipv4/ip_forward will be enabled. Otherwise it will be disabled.

	Returncode:
		 0: ok
		-1: error
*/
int
post_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, IptCap *iptcap, int forward_rules)
{
	int	retval=0,
		result=0;
	char	cmd[MAX_PIPE_COMMAND] = "";
	char	limit[42] = "";
	char	logprefix[64] = "";


	/* safety */
	if(!iptcap)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* do we want to log the default policy? */
	if(conf.log_policy == TRUE)
	{
		/* cap */
		if(conf.check_iptcaps == TRUE && iptcap->target_log == FALSE)
		{
			(void)vrprint.warning("Warning", "not creating logrules. LOG-target not supported by system.");
			return(0); /* no error */
		}

		/* see if we want to limit the logging of the default policy */
		if(conf.log_policy_limit > 0)
		{
			/* cap */
			if(conf.check_iptcaps == FALSE || iptcap->match_limit == TRUE)
			{
				snprintf(limit, sizeof(limit), "-m limit --limit %u/s --limit-burst %u",
										conf.log_policy_limit,
										conf.log_policy_burst);
			}
			else
			{
				(void)vrprint.warning("Warning", "not setting limits on logrules. Limit-match not supported by system.");
				return(0); /* no error */
			}
		}

		/* enable logging for all packets which don't have a rule */
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Enabling logging...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Enabling logging...");

		/* input */
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_INPUT, "DROP", "in policy");

		snprintf(cmd, sizeof(cmd), "%s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		/* output */
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_OUTPUT, "DROP", "out policy");

		snprintf(cmd, sizeof(cmd), "%s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		/* forward */
		create_logprefix_string(debuglvl, logprefix, sizeof(logprefix), RT_FORWARD, "DROP", "fw policy");

		snprintf(cmd, sizeof(cmd), "%s -j LOG %s %s %s",
						limit,
						logprefix,
						loglevel,
						log_tcp_options);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_FORWARD, cmd, 0, 0) < 0)
			retval=-1;
	}

	/* enable or disable ip-forwarding */
	if(forward_rules)
	{
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Enabling ip-forwarding...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Enabling ip-forwarding because forwarding rules were created.");

		result = set_proc_entry(debuglvl, &conf, "/proc/sys/net/ipv4/ip_forward", 1, NULL);
		if(result != 0)
		{
			/* if it fails, we dont really care, its not fatal */
			(void)vrprint.error(-1, "Error", "enabling ip-forwarding failed.");
		}
	}
	else
	{
		if(conf.bash_out == TRUE)	fprintf(stdout, "\n# Disabling ip-forwarding...\n");
		if(debuglvl >= LOW)		(void)vrprint.debug(__FUNC__, "Enabling ip-forwarding because no forwarding rules were created.");

		result = set_proc_entry(debuglvl, &conf, "/proc/sys/net/ipv4/ip_forward", 0, NULL);
		if(result != 0)
		{
			/* if it fails, we dont really care, its not fatal */
			(void)vrprint.error(-1, "Error", "enabling ip-forwarding failed.");
		}
	}

	return(retval);
}


int
create_interface_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, Interfaces *interfaces)
{
	struct RuleCache_	*create = NULL;
	d_list_node		*d_node = NULL,
				*if_d_node = NULL;
	struct RuleData_	*rule_ptr = NULL;
	struct InterfaceData_	*iface_ptr = NULL;


	/* safety */
	if(!interfaces)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	if(conf.bash_out)
		fprintf(stdout, "\n# Loading interfaces protection rules...\n");

	/* loop through the interfaces */
	for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
	{
		if(!(iface_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}
	
		/* now loop through the ruleslist */
		for(if_d_node = iface_ptr->ProtectList.top; if_d_node; if_d_node = if_d_node->next)
		{
			if(!(rule_ptr = if_d_node->data))
			{
				(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
				return(-1);
			}
			if(!(create = &rule_ptr->rulecache))
			{
				(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
				return(-1);
			}

			/* here we print the description if we are in bashmode */
			if(conf.bash_out && create->description != NULL)
			{
				fprintf(stdout, "\n# %s\n", create->description);
		
				free(create->description);
				create->description = NULL;
			}

			/*
				prot rule, proc only for interface
			*/
			if(create->danger.solution == PROT_PROC_INT)
			{
				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "protect proc (int)... ");

				if(!create->who_int)
				{
					(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
					return(-1);
				}

				/*	only set if int is active and up.
		
					NOTE: this is different from iptables rules, which are also created if the interface is
					down. However the proc entries are only available when the interface is up!
				*/
				if(create->who_int->active && create->who_int->up)
				{
					if(debuglvl >= MEDIUM)
						(void)vrprint.debug(__FUNC__, "Setting '%d' to '%s' (where * is %s)... ", create->danger.proc_set_on, create->danger.proc_entry, create->who_int->device);

					if(set_proc_entry(debuglvl, &conf, create->danger.proc_entry, create->danger.proc_set_on, create->who_int->device) != 0)
					{
						/* if it fails, we dont really care, its not fatal */
						(void)vrprint.error(-1, "Error", "setting proc entry failed (in: %s:%d).", __FUNC__, __LINE__);
					}
				}
				else
				{
					if(conf.bash_out)
					{
						fprintf(stdout, "# not created: interface is inactive or down.\n");
					}
				}
			}
			/* Whoops, this is serious. */
			else
			{
				(void)vrprint.error(-1, "Internal Error", "unknown protect danger type %d (in: %s:%d).", create->danger.solution, __FUNC__, __LINE__);
				return(-1);
			}
		}
	}

	return(0);
}


/*	two types of rules:

	normal interfaces:
	-i <dev> and -o <dev> WITHOUT the ipaddress, so they match in
	forward chain as well
	
	oldstyle virtual interfaces:
	no -i <dev> or -o <dev>, but WITH the ipaddress. So they will match in
	input and output chains

	returncodes:
		 0: ok
		-1: error
*/

static int
create_network_antispoof_rule(const int debuglvl, /*@null@*/RuleSet *ruleset,
				IptCap *iptcap, struct RuleCache_ *create,
				struct InterfaceData_ *from_if_ptr)
{
	char			input_device[16 + 3] = "";	/* 16 + '-i ' */
	char			output_device[16 + 3] = "";	/* 16 + '-i ' */
	char			limit[] = "-m limit --limit 1/s --limit-burst 5";
	char			logprefix[64] = "";
	char			cmd[MAX_PIPE_COMMAND] = "";
	int			retval = 0;

	/*	see if the interface is active */
	if(	from_if_ptr->active == FALSE ||
		(from_if_ptr->dynamic == TRUE && from_if_ptr->up == FALSE))
	{
		/* here we print the description if we are in bashmode */
		if(conf.bash_out == TRUE)
		{
			fprintf(stdout, "# anti-spoof rule for interface '%s' "
				"not created. The interface is inactive or "
				"dynamic and down.\n", from_if_ptr->name);
		}

		return(0);
	}

	/*	get the input_device

		if the device is virtual (oldstyle), we don't add it to the iptables string.
	*/
	if(from_if_ptr->device_virtual_oldstyle == FALSE)
	{
		snprintf(input_device, sizeof(input_device),
			"-i %s", from_if_ptr->device);
		snprintf(output_device, sizeof(output_device),
			"-o %s", from_if_ptr->device);
	}
	else
	{
		memset(input_device, 0, sizeof(input_device));
		memset(output_device, 0, sizeof(output_device));
	}

	/* virtual oldstyle */
	if(from_if_ptr->device_virtual_oldstyle == TRUE)
	{
		/* create the log rule */
		if(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE)
		{
			/* create the logprefix string */
			create_logprefix_string(debuglvl, logprefix,
				sizeof(logprefix), RT_NOTSET, "DROP", "%s %s",
				create->danger.type, create->danger.source);

			/* log rule string */
			snprintf(cmd, sizeof(cmd), "-s %s/%s -d %s/255.255.255.255 %s -j LOG %s %s %s",
				create->danger.source_ip.ipaddress,
				create->danger.source_ip.netmask,
				from_if_ptr->ipv4.ipaddress, limit, logprefix,
				loglevel, log_tcp_options);

			if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ANTISPOOF, cmd, 0, 0) < 0)
				retval=-1;
		}

		/* and the DROP rule */
		snprintf(cmd, sizeof(cmd), "-s %s/%s -d %s/255.255.255.255 -j DROP",
			create->danger.source_ip.ipaddress,
			create->danger.source_ip.netmask, from_if_ptr->ipv4.ipaddress);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ANTISPOOF, cmd, 0, 0) < 0)
			retval=-1;

		/* create the log rule */
		if(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE)
		{
			/* create the logprefix string */
			create_logprefix_string(debuglvl, logprefix, sizeof(logprefix),
				RT_INPUT, "DROP", "%s %s",
				create->danger.type, create->danger.source);

			/* log rule string */
			snprintf(cmd, sizeof(cmd), "-s %s/255.255.255.255 -d %s/%s %s -j LOG %s %s %s",
				from_if_ptr->ipv4.ipaddress,
				create->danger.source_ip.ipaddress,
				create->danger.source_ip.netmask, limit,
				logprefix, loglevel, log_tcp_options);

			if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ANTISPOOF, cmd, 0, 0) < 0)
				retval=-1;
		}

		/* and the DROP rule */
		snprintf(cmd, sizeof(cmd), "-s %s/255.255.255.255 -d %s/%s -j DROP",
			from_if_ptr->ipv4.ipaddress,
			create->danger.source_ip.ipaddress,
			create->danger.source_ip.netmask);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ANTISPOOF, cmd, 0, 0) < 0)
			retval=-1;
	}
	/* normal interface */
	else
	{
		/* create the log rule */
		if(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE)
		{
			/* create the logprefix string */
			create_logprefix_string(debuglvl, logprefix,
				sizeof(logprefix), RT_NOTSET, "DROP", "%s %s",
				create->danger.type, create->danger.source);

			/* log rule string */
			snprintf(cmd, sizeof(cmd), "%s -s %s/%s %s -j LOG %s %s %s",
				input_device, create->danger.source_ip.ipaddress,
				create->danger.source_ip.netmask, limit, logprefix,
				loglevel, log_tcp_options);

			if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ANTISPOOF, cmd, 0, 0) < 0)
				retval=-1;
		}

		/* and the DROP rule */
		snprintf(cmd, sizeof(cmd), "%s -s %s/%s -j DROP",
			input_device, create->danger.source_ip.ipaddress,
			create->danger.source_ip.netmask);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ANTISPOOF, cmd, 0, 0) < 0)
			retval=-1;

		/* create the log rule */
		if(conf.check_iptcaps == FALSE || iptcap->target_log == TRUE)
		{
			/* create the logprefix string */
			create_logprefix_string(debuglvl, logprefix, sizeof(logprefix),
				RT_INPUT, "DROP", "%s %s",
				create->danger.type, create->danger.source);

			/* log rule string */
			snprintf(cmd, sizeof(cmd), "%s -d %s/%s %s -j LOG %s %s %s",
				output_device, create->danger.source_ip.ipaddress,
				create->danger.source_ip.netmask, limit,
				logprefix, loglevel, log_tcp_options);

			if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ANTISPOOF, cmd, 0, 0) < 0)
				retval=-1;
		}

		/* and the DROP rule */
		snprintf(cmd, sizeof(cmd), "%s -d %s/%s -j DROP",
			output_device, create->danger.source_ip.ipaddress,
			create->danger.source_ip.netmask);

		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ANTISPOOF, cmd, 0, 0) < 0)
			retval=-1;
	}
	return(0);
}


/*
	TODO: add some descriptions to each rule. What they do, etc.
*/
int
create_network_protect_rules_dhcp_server(	const int debuglvl,
						/*@null@*/RuleSet *ruleset,
						Zones *zones, IptCap *iptcap,
						struct RuleCache_ *create,
						struct InterfaceData_ *if_ptr)
{
	int		retval = 0;
	char		cmd[MAX_PIPE_COMMAND] = "";

	if(if_ptr->device_virtual_oldstyle == TRUE)
	{
		if(conf.bash_out == TRUE)
			fprintf(stdout, "# dhcp-server rules for interface '%s' not created. The interface is an oldstyle virtual interface.\n", if_ptr->name);
		return(0);
	}
	else if(if_ptr->device[0] == '\0')
	{
		if(conf.bash_out == TRUE)
			fprintf(stdout, "# dhcp-server rules for interface '%s' not created. The DEVICE is not set.\n", if_ptr->name);
		return(0);
	}

	/*	external DHCP client request to server
		DHCPDISCOVER; DHCPREQUEST */
	snprintf(cmd, sizeof(cmd), "-i %s -p udp -m udp -s 0.0.0.0 --sport 68 -d 255.255.255.255 --dport 67 -j ACCEPT",
			if_ptr->device);
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;

	/* DHCPOFFER */
	snprintf(cmd, sizeof(cmd), "-o %s -p udp -m udp -s 0.0.0.0 --sport 67 -d 255.255.255.255 --dport 68 -j ACCEPT",
			if_ptr->device);
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;

	/* make sure we have everything set */
	if(	create->who->ipv4.network[0] != '\0' &&
		create->who->ipv4.netmask[0] != '\0' &&
		if_ptr->ipv4.ipaddress[0] != '\0')
	{
		/* DHCPOFFER and negative response to external DHCP client */
		snprintf(cmd, sizeof(cmd), "-o %s -p udp -m udp -s %s/255.255.255.255 --sport 67 -d %s/%s --dport 68 -j ACCEPT",
				if_ptr->device, if_ptr->ipv4.ipaddress, create->who->ipv4.network, create->who->ipv4.netmask);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		/* DHCPREQUEST; DHCPRELEASE */
		snprintf(cmd, sizeof(cmd), "-i %s -p udp -m udp -s %s/%s --sport 68 -d %s/255.255.255.255 --dport 67 -j ACCEPT",
				if_ptr->device, create->who->ipv4.network, create->who->ipv4.netmask, if_ptr->ipv4.ipaddress);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;
	}

	/* make sure we have everything set */
	if(if_ptr->ipv4.ipaddress[0] != '\0')
	{
		/* DHCPREQUEST; DHCPDECLINE */
		snprintf(cmd, sizeof(cmd), "-i %s -p udp -m udp -s 0.0.0.0 --sport 68 -d %s/255.255.255.255 --dport 67 -j ACCEPT",
				if_ptr->device, if_ptr->ipv4.ipaddress);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		/* DHCPACK; DHCPNAK */
		snprintf(cmd, sizeof(cmd), "-o %s -p udp -m udp -s %s/255.255.255.255 --sport 67 -d 255.255.255.255 --dport 68 -j ACCEPT",
				if_ptr->device, if_ptr->ipv4.ipaddress);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

	}

	return(retval);
}

/*
	TODO: add some descriptions to each rule. What they do, etc.
*/
int
create_network_protect_rules_dhcp_client(	const int debuglvl,
						/*@null@*/RuleSet *ruleset,
						Zones *zones, IptCap *iptcap,
						struct RuleCache_ *create,
						struct InterfaceData_ *if_ptr)
{
	int		retval = 0;
	char		cmd[MAX_PIPE_COMMAND] = "";

	if(if_ptr->dynamic == FALSE)
	{
		if(conf.bash_out == TRUE)
			fprintf(stdout, "# dhcp-client rules for interface '%s' not created. The interface is not dynamic.\n", if_ptr->name);
		return(0);
	}
	else if(if_ptr->device_virtual_oldstyle == TRUE)
	{
		if(conf.bash_out == TRUE)
			fprintf(stdout, "# dhcp-client rules for interface '%s' not created. The interface is an oldstyle virtual interface.\n", if_ptr->name);
		return(0);
	}
	else if(if_ptr->device[0] == '\0')
	{
		if(conf.bash_out == TRUE)
			fprintf(stdout, "# dhcp-client rules for interface '%s' not created. The DEVICE is not set.\n", if_ptr->name);
		return(0);
	}

	snprintf(cmd, sizeof(cmd), "-o %s -p udp -m udp -s 0.0.0.0 --sport 68 -d 255.255.255.255 --dport 67 -j ACCEPT",
			if_ptr->device);
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
		retval=-1;

	snprintf(cmd, sizeof(cmd), "-i %s -p udp -m udp -s 0.0.0.0 --sport 67 -d 255.255.255.255 --dport 68 -j ACCEPT",
			if_ptr->device);
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
		retval=-1;

	if(	create->who->ipv4.network[0] != '\0' &&
		create->who->ipv4.netmask[0] != '\0')
	{
		snprintf(cmd, sizeof(cmd), "-i %s -p udp -m udp -s %s/%s --sport 67 -d 255.255.255.255 --dport 68 -j ACCEPT",
				if_ptr->device, create->who->ipv4.network, create->who->ipv4.netmask);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-o %s -p udp -m udp -s 0.0.0.0 --sport 68 -d %s/%s --dport 67 -j ACCEPT",
				if_ptr->device, create->who->ipv4.network, create->who->ipv4.netmask);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-i %s -p udp -m udp -s %s/%s --sport 67 -d %s/%s --dport 68 -j ACCEPT",
				if_ptr->device,
				create->who->ipv4.network, create->who->ipv4.netmask,
				create->who->ipv4.network, create->who->ipv4.netmask);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_INPUT, cmd, 0, 0) < 0)
			retval=-1;

		snprintf(cmd, sizeof(cmd), "-o %s -p udp -m udp -s %s/%s --sport 68 -d %s/%s --dport 67 -j ACCEPT",
				if_ptr->device,
				create->who->ipv4.network, create->who->ipv4.netmask,
				create->who->ipv4.network, create->who->ipv4.netmask);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_OUTPUT, cmd, 0, 0) < 0)
			retval=-1;
	}

	return(retval);
}


/*
	we don't care if the network is active or not
*/
int
create_network_protect_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, Zones *zones, IptCap *iptcap)
{
	struct RuleCache_	*create = NULL;
	d_list_node		*d_node = NULL,
				*net_d_node = NULL,
				*from_if_node = NULL;
	struct ZoneData_	*zone_ptr = NULL;
	struct RuleData_	*rule_ptr = NULL;
	int			retval = 0;
	struct InterfaceData_	*from_if_ptr = NULL;
//	char			cmd[MAX_PIPE_COMMAND] = "";
	char			limit[] = "-m limit --limit 1/s --limit-burst 5";


	/* safety */
	if(zones == NULL || iptcap == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
			"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* check capability */
	if(conf.check_iptcaps == TRUE && iptcap->match_limit == FALSE)
	{
		(void)vrprint.warning("Warning", "not setting limits on "
			"logrules. Limit-match not supported by system.");
		memset(limit, 0, sizeof(limit));
	}

	if(conf.bash_out == TRUE)
		fprintf(stdout, "\n# Loading anti-spoofing rules...\n");

	/* loop through the zones to look for networks */
	for(d_node = zones->list.top; d_node; d_node = d_node->next)
	{
		if(!(zone_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL "
				"pointer (in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}
	
		if(zone_ptr->type == TYPE_NETWORK)
		{
			/* now loop through the ruleslist */
			for(	net_d_node = zone_ptr->ProtectList.top;
				net_d_node; net_d_node = net_d_node->next)
			{
				if(!(rule_ptr = net_d_node->data))
				{
					(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
					return(-1);
				}
				if(!(create = &rule_ptr->rulecache))
				{
					(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
					return(-1);
				}
				if(create->who == NULL)
				{
					(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
					return(-1);
				}


				/* here we print the description if we are in bashmode */
				if(conf.bash_out == TRUE && create->description != NULL)
				{
					fprintf(stdout, "\n# %s\n", create->description);
		
					free(create->description);
					create->description = NULL;
				}

				/* iptables protect */
				if(create->danger.solution == PROT_IPTABLES)
				{
					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "protect iptables.");

					/* check if all is filled in right */
					if(	strcmp(create->danger.source_ip.ipaddress, "") != 0 &&
						strcmp(create->danger.source_ip.netmask, "") != 0 &&
						strcmp(create->danger.type, "") != 0 &&
						strcmp(create->danger.source, "") != 0)
					{
						for(from_if_node = create->who->InterfaceList.top; from_if_node; from_if_node = from_if_node->next)
						{
							if(!(from_if_ptr = from_if_node->data))
							{
								(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
															__FUNC__, __LINE__);
								return(-1);
							}

							if(create_network_antispoof_rule(debuglvl, ruleset,
								iptcap, create, from_if_ptr) < 0)
							{
								(void)vrprint.error(-1, "Error", "creating anti-spoofing rule failed.");
								return(-1);
							}
						}
					}
					else if(strcasecmp(rule_ptr->service,"dhcp-client") == 0)
					{
						for(from_if_node = create->who->InterfaceList.top; from_if_node; from_if_node = from_if_node->next)
						{
							if(!(from_if_ptr = from_if_node->data))
							{
								(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
															__FUNC__, __LINE__);
								return(-1);
							}

							if(create_network_protect_rules_dhcp_client(debuglvl, ruleset, zones, iptcap, create, from_if_ptr) < 0)
								retval = -1;
}					}
					else if(strcasecmp(rule_ptr->service,"dhcp-server") == 0)
					{
						for(from_if_node = create->who->InterfaceList.top; from_if_node; from_if_node = from_if_node->next)
						{
							if(!(from_if_ptr = from_if_node->data))
							{
								(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
															__FUNC__, __LINE__);
								return(-1);
							}

							if(create_network_protect_rules_dhcp_server(debuglvl, ruleset, zones, iptcap, create, from_if_ptr) < 0)
								retval = -1;
						}
					}
				}
				/* Whoops, this is serious. */
				else
				{
					(void)vrprint.error(-1, "Internal Error", "unknown protect danger type %d (in: %s).", create->danger.solution, __FUNC__);
					return(-1);
				}
			}
		}
	}

	return(0);
}


int
create_block_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, BlockList *blocklist)
{
	char		cmd[MAX_PIPE_COMMAND] = "",
			*ipaddress = NULL;
	d_list_node	*d_node = NULL;
	int		retval = 0;


	/* safety */
	if(!blocklist)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	if(conf.bash_out == TRUE)
		fprintf(stdout, "\n# Loading Blocklist...\n");

	if(blocklist->list.len == 0)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "no items in blocklist.");

		return(0);
	}

	/* create two rules for each ipaddress */
	for(d_node = blocklist->list.top; d_node; d_node = d_node->next)
	{
		if(!(ipaddress = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}

		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "ipaddress to add: '%s'.", ipaddress);

		/* ip is source */
		snprintf(cmd, sizeof(cmd), "-s %s/255.255.255.255 -j BLOCK", ipaddress);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_BLOCKLIST, cmd, 0, 0) < 0)
			retval=-1;

		/* ip is dst */
		snprintf(cmd, sizeof(cmd), "-d %s/255.255.255.255 -j BLOCK", ipaddress);
		if(process_rule(debuglvl, ruleset, TB_FILTER, CH_BLOCKLIST, cmd, 0, 0) < 0)
			retval=-1;
	}

	return(retval);
}

/* create_estrelnfqueue_rules
 *
 * Create the rules for RELATED and ESTABLISHED traffic for nfqueue.
 *
 * Return:	 0: ok
 * 		-1: error
 */
int
create_estrelnfqueue_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, Rules *rules)
{
	char		cmd[MAX_PIPE_COMMAND] = "";
	d_list_node	*d_node = NULL;
	int		retval = 0;
	struct RuleData_ *rule_ptr = NULL;

	/* safety */
	if(rules == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
			"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	if(conf.bash_out == TRUE)
		fprintf(stdout, "\n# Setting up NFQueue state rules...\n");

	if(rules->list.len == 0)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "no items in ruleslist.");

		return(0);
	}

	/* create two rules for each ipaddress */
	for(d_node = rules->list.top; d_node; d_node = d_node->next)
	{
		if(!(rule_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer "
				"(in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}

		if (rule_ptr->action == AT_NFQUEUE)
		{
			/* ESTABLISHED */
			snprintf(cmd, sizeof(cmd), "-m connmark --mark %u "
				"-m state --state ESTABLISHED -j NFQUEUE --queue-num %u",
				rule_ptr->opt->nfqueue_num + 1, rule_ptr->opt->nfqueue_num);
			if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ESTRELNFQUEUE, cmd, 0, 0) < 0)
				retval=-1;

			/* RELATED */
			snprintf(cmd, sizeof(cmd), "-m connmark --mark %u "
				"-m state --state RELATED -j NEWNFQUEUE",
				rule_ptr->opt->nfqueue_num + 1);
			if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ESTRELNFQUEUE, cmd, 0, 0) < 0)
				retval=-1;
		}
	}

	return(retval);
}

/* create_newnfqueue_rules
 *
 * Create the rules for the NEWQUEUE target.
 *
 * Return:	 0: ok
 * 		-1: error
 */
int
create_newnfqueue_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, Rules *rules)
{
	char		cmd[MAX_PIPE_COMMAND] = "";
	d_list_node	*d_node = NULL;
	int		retval = 0;
	struct RuleData_ *rule_ptr = NULL;


	/* safety */
	if(rules == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
			"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	if(conf.bash_out == TRUE)
		fprintf(stdout, "\n# Setting up NFQueue NEWNFQUEUE target rules...\n");

	/* TCP and UDP limits */
	snprintf(cmd, sizeof(cmd), "-p tcp -m tcp --syn -j SYNLIMIT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_NEWNFQUEUE, cmd, 0, 0) < 0)
		retval=-1;

	snprintf(cmd, sizeof(cmd), "-p udp -m state --state NEW -j UDPLIMIT");
	if(process_rule(debuglvl, ruleset, TB_FILTER, CH_NEWNFQUEUE, cmd, 0, 0) < 0)
		retval=-1;

	if(rules->list.len == 0)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "no items in ruleslist.");

		return(0);
	}

	/* create two rules for each ipaddress */
	for(d_node = rules->list.top; d_node; d_node = d_node->next)
	{
		if(!(rule_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer "
				"(in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}

		if (rule_ptr->action == AT_NFQUEUE)
		{
			/* NEW */
			snprintf(cmd, sizeof(cmd), "-m connmark --mark %u "
				"-m state --state NEW -j NFQUEUE --queue-num %u",
				rule_ptr->opt->nfqueue_num + 1, rule_ptr->opt->nfqueue_num);
			if(process_rule(debuglvl, ruleset, TB_FILTER, CH_ESTRELNFQUEUE, cmd, 0, 0) < 0)
				retval=-1;
		}
	}

	return(retval);
}


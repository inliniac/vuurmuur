/***************************************************************************
 *   Copyright (C) 2002-2006 by Victor Julien                              *
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
 
#include "vuurmuur_log.h"

/*@null@*/
struct SHM_TABLE *shm_table = 0;

/*
	we put this here, because we only use it here in main.
*/
static int sigint_count = 0;
static int sighup_count = 0;
static int sigterm_count = 0;


void
handle_sigint(int sig)
{
	sigint_count = 1;
}


void
handle_sigterm(int sig)
{
	sigterm_count = 1;
}


void
handle_sighup(int sig)
{
	sighup_count = 1;
}


static void
setup_signal_handler(int sig, void (*handler)())
{
	struct sigaction action;

	action.sa_handler = handler;
	sigemptyset(&(action.sa_mask));
	sigaddset(&(action.sa_mask),sig);
	action.sa_flags = 0;
	sigaction(sig, &action, 0);
}


static char *
assemble_logline_sscanf_string(const int debuglvl, struct log_rule *logrule_ptr)
{
	char		*string,
			temp_buf[256] = "";
	size_t		str_len = 0;

	//"%s %2d %2d:%2d:%2d %s";
	snprintf(temp_buf, sizeof(temp_buf), "%%%ds %%2d %%2d:%%2d:%%2d %%%ds",
			(int)sizeof(logrule_ptr->month)-1,
			(int)sizeof(logrule_ptr->hostname)-1);

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "assemble_logline_sscanf_string: string: '%s'. (len: %d)", temp_buf, strlen(temp_buf));

	str_len = strlen(temp_buf) + 1;
	if(str_len > sizeof(temp_buf))
	{
		(void)vrprint.error(-1, "Internal Error", "string overflow (in: %s:%d).", __FUNC__, __LINE__);
		return(NULL);
	}

	if(!(string = malloc(str_len)))
	{
		(void)vrprint.error(-1, "Error", "malloc failed: %s.", strerror(errno));
		return(NULL);
	}

	if(strlcpy(string, temp_buf, str_len) > str_len)
	{
		(void)vrprint.error(-1, "Internal Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
		return(NULL);
	}

	return(string);
}


/*	search_in_ipt_line

	Arguments:
		line:		line string
		search_start:	position in the line to start searching. Useful for
				ommitting matching on the logprefix.
		keyword:	the keyword in the line we look for
		startpos:	pointer to the beginning of the value
		endpos:		idem, but the end

	Returncodes:
		-1: error
		 0: ok
*/
static int
search_in_ipt_line(char *line, size_t search_start, char *keyword, size_t *startpos, size_t *endpos)
{
	size_t	keyword_len = 0,
		line_len = 0,
		x = 0,
		k = 0,
		startp = 0;

	if(!keyword || !line)
		return(-1);

	*startpos = 0;
	*endpos = 0;

	keyword_len = strlen(keyword);
	if(keyword_len <= 0)
		return(-1);

	line_len = strlen(line);
	if(line_len <= 0)
		return(-1);

	for(x = search_start, k = 0; x < line_len; x++)
	{

		// if keyword[k] is not what we expect, reset k
		if(k > 0 && k < keyword_len)
		{
			if(line[x] != keyword[k])
			{
				k = 0;
				//fprintf(stdout, "reset\n");
			}
		}

		// if we match add to k
		if(line[x] == keyword[k])
		{
			if(k == 0)
				startp = x;

			k++;
		}
	}

	if(keyword_len == k)
	{
		*startpos = startp;
		*endpos = startp;

		for(x = startp; line[x] != ' '; x++)
			*endpos=*endpos+1;

	}
	//fprintf(stdout, "k: %d, keyword_len: %d, startp: %d\n", k, keyword_len, startp);

	return(0);
}


/*	check_ipt_line

	checks if the rule is a iptables rule.
	returns 1 if yes 0 if no
	we only accept rules which contain our own 'vrmr:' prefix

	TODO: we could use a regex?
*/
static int
check_ipt_line(char *line)
{
	size_t	start = 0,
		end = 0;

	search_in_ipt_line(line, LINE_START, "vrmr:", &start, &end);
	if(start == end)
		return(0);

	return(1);
}


/* Input is packet and an zeven-byte (including NULL) character array.  Results
 * are put into the character array.
 *
 * Shamelessly ripped from snort_inline 2.2.0 (c) Martin Roesch
 */
static void
CreateTCPFlagString(struct log_rule *logrule_ptr, char *flagBuffer)
{
    /* parse TCP flags */
    *flagBuffer++ = (char) (logrule_ptr->urg ? 'U' : '*');
    *flagBuffer++ = (char) (logrule_ptr->ack ? 'A' : '*');
    *flagBuffer++ = (char) (logrule_ptr->psh ? 'P' : '*');
    *flagBuffer++ = (char) (logrule_ptr->rst ? 'R' : '*');
    *flagBuffer++ = (char) (logrule_ptr->syn ? 'S' : '*');
    *flagBuffer++ = (char) (logrule_ptr->fin ? 'F' : '*');
    *flagBuffer = '\0';
}


/*	parse the logline to the logrule_ptr

	Returncodes:
		 1: ok
		 0: invalid logline
		-1: error
*/
static int
parse_ipt_logline(	const int debuglvl,
			char *logline,
			size_t logline_len,
			char *sscanf_str,
			struct log_rule *logrule_ptr,
			struct draw_rule_format_ *rulefmt_ptr,
			struct Counters_ *counter_ptr)
{
	int		result = 0;
	size_t		hostname_len = 0,
			pre_prefix_len = 0,
			str_begin = 0,
			str_end = 0,
			vrmr_start = 0;
	char		from_mac[18] = "",
			to_mac[18] = "";
	char		packet_len[6] = "";
	char		protocol[5] = "";
	char		port[6] = "";

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "parse_ipt_logline: start");


	/* safety first */
	if(	logline == NULL || logrule_ptr == NULL || rulefmt_ptr == NULL ||
		sscanf_str == NULL || counter_ptr == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
			"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}


	memset(logrule_ptr, 0, sizeof(struct log_rule));
	memset(rulefmt_ptr, 0, sizeof(struct draw_rule_format_));

	/* get date, time, hostname */
	result = sscanf(logline, sscanf_str,	logrule_ptr->month,
						&logrule_ptr->day,
						&logrule_ptr->hour,
						&logrule_ptr->minute,
						&logrule_ptr->second,
						logrule_ptr->hostname);
	if(result < 6)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "logline is invalid because sscanf reported an error.");

		return(0);
	}

	/*	this will get us past 'kernel:' and all other stuff that might
		be in the line */
	result = search_in_ipt_line(logline, LINE_START, "vrmr:", &str_begin, &str_end);
	if(result == 0)
	{
		/*	start copying after 'vrmr:' keyword */
		str_begin = str_end = str_end + 1;
		/*	search for the end of the action (the action is a
			string with no spaces in it */
		while(	str_end < logline_len &&
			logline[str_end] != ' ')
			str_end++;
	
		if(range_strcpy(logrule_ptr->action, logline, str_begin,
			str_end, sizeof(logrule_ptr->action)) < 0)
			return(0);
			
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "action '%s', "
				"str_begin %u, str_end %u",
				logrule_ptr->action, str_begin, str_end);
		
		/* the start of the prefix is the end of the action + 1 */
		pre_prefix_len = str_end + 1;
	}
	else
	{
		(void)vrprint.error(-1, "Error", "Searching 'vrmr:' in iptables logline failed.");
		return(0);
	}

	/* ACTION counters */
	if(strcmp(logrule_ptr->action, "DROP") == 0)
		counter_ptr->drop++;
	else if(strcmp(logrule_ptr->action, "ACCEPT") == 0)
		counter_ptr->accept++;
	else if(strcmp(logrule_ptr->action, "REJECT") == 0)
		counter_ptr->reject++;
	else if(strcmp(logrule_ptr->action, "QUEUE") == 0)
		counter_ptr->queue++;
	else
		counter_ptr->other_match++;
        
	hostname_len = strlen(logrule_ptr->hostname);
	if(hostname_len <= 0)
		return(-1);

	/*	get the input inferface (if any),
		we do this before the prefix because IN= should always be in
		the line and marks the end of the prefix
	*/
	result = search_in_ipt_line(logline, pre_prefix_len, "IN=", &str_begin, &str_end);
	if(result == 0)
	{
		if(str_begin == str_end - strlen("IN="))
		{
			memset(logrule_ptr->interface_in, 0, sizeof(logrule_ptr->interface_in));
			memset(rulefmt_ptr->from_int, 0, sizeof(rulefmt_ptr->from_int));
		}
		else if(str_begin == str_end)
		{
			//(void)vrprint.error(-1, "Error", "Not a valid iptables line: No IN= keyword: %s", line);
			return(0);
		}
		else
		{
			if(range_strcpy(logrule_ptr->interface_in, logline, str_begin + strlen("IN="), str_end, sizeof(logrule_ptr->interface_in)) < 0)
				return(0);
			else
				snprintf(rulefmt_ptr->from_int, sizeof(rulefmt_ptr->from_int), "in: %s", logrule_ptr->interface_in);
		}
	}
	else
	{
		(void)vrprint.error(-1, "Error", "Searching IN= in iptables logline failed.");
		return(0);
	}


	/* here we handle the user prefix */
	if(str_begin > pre_prefix_len + 1)
	{
		if(range_strcpy(logrule_ptr->logprefix, logline, pre_prefix_len, str_begin - 1, sizeof(logrule_ptr->logprefix)) < 0)
			return(0);
	}
	else
	{
		strlcpy(logrule_ptr->logprefix, "none", sizeof(logrule_ptr->logprefix));
	}


	/* from now on, we only search after vrmr_start */
	vrmr_start = str_begin;


	/* get the output inferface (in any) */
	result = search_in_ipt_line(logline, vrmr_start, "OUT=", &str_begin, &str_end);
	if(result == 0)
	{
		if(str_begin == str_end - strlen("OUT="))
		{
			memset(logrule_ptr->interface_out, 0, sizeof(logrule_ptr->interface_out));
			memset(rulefmt_ptr->to_int, 0, sizeof(rulefmt_ptr->to_int));
		}
		else if(str_begin == str_end)
		{
			//(void)vrprint.error(-1, "Error", "Not a valid iptables line: No OUT= keyword: %s", line);
			return(0);
		}
		else
		{
			if(range_strcpy(logrule_ptr->interface_out, logline, str_begin + strlen("OUT="), str_end, sizeof(logrule_ptr->interface_out)) < 0)
				return(0);
			else
			{
				snprintf(rulefmt_ptr->to_int, sizeof(rulefmt_ptr->to_int), "out: %s", logrule_ptr->interface_out);

				/* append a space to the from_int */
				if(strcmp(rulefmt_ptr->from_int, "") != 0)
					(void)strlcat(rulefmt_ptr->from_int, " ", sizeof(rulefmt_ptr->from_int));
			}
		}
	}
	else
	{
		(void)vrprint.error(-1, "Error", "Searching OUT= in iptables logline failed.");
		return(0);
	}


	/* get the source ip of the line */
	result = search_in_ipt_line(logline, vrmr_start, "SRC=", &str_begin, &str_end);
	if(result == 0)
	{
		if(str_begin == str_end - strlen("SRC="))
		{
			memset(logrule_ptr->interface_in, 0, sizeof(logrule_ptr->interface_in));
		}
		else if(str_begin == str_end)
		{
			//(void)vrprint.error(-1, "Error", "Not a valid iptables line: No SRC= keyword: %s", line);
			return(0);
		}
		else
		{
			if(range_strcpy(logrule_ptr->src_ip, logline, str_begin + strlen("SRC="), str_end, sizeof(logrule_ptr->src_ip)) < 0)
				return(0);
		}
	}
	else
	{
		(void)vrprint.error(-1, "Error", "Searching SRC= in iptables logline failed.");
		return(0);
	}

	/* get the destination ip */
	result = search_in_ipt_line(logline, vrmr_start, "DST=", &str_begin, &str_end);
	if(result == 0)
	{
		if(str_begin == str_end - strlen("DST="))
		{
			memset(logrule_ptr->interface_out, 0, sizeof(logrule_ptr->interface_out));
		}
		else if(str_begin == str_end)
		{
			//(void)vrprint.error(-1, "Error", "Not a valid iptables line: No DST= keyword: %s", line);
			return(0);
		}
		else
		{
			if(range_strcpy(logrule_ptr->dst_ip, logline, str_begin + strlen("DST="), str_end, sizeof(logrule_ptr->dst_ip)) < 0)
				return(0);
		}
	}
	else
	{
		(void)vrprint.error(-1, "Error", "Searching SRC= in iptables logline failed.");
		return(0);
	}


	/* get the mac (src & dst) if it exists */
	result = search_in_ipt_line(logline, vrmr_start, "MAC=", &str_begin, &str_end);
	if(result == 0)
	{
		if(str_begin == str_end - strlen("MAC="))
		{
			/* keyword exists, but no data */
			memset(logrule_ptr->src_mac, 0, sizeof(logrule_ptr->src_mac));
			memset(logrule_ptr->dst_mac, 0, sizeof(logrule_ptr->dst_mac));
		}
		else if(str_begin == str_end)
		{
			/* keyword not found - not an error for MAC */
			memset(logrule_ptr->src_mac, 0, sizeof(logrule_ptr->src_mac));
			memset(logrule_ptr->dst_mac, 0, sizeof(logrule_ptr->dst_mac));
		}
		else
		{
			if(range_strcpy(to_mac, logline, str_begin + strlen("MAC="), str_begin + strlen("MAC=") + 17, sizeof(to_mac)) < 0)
				return(0);
			else
			{
				if(range_strcpy(from_mac, logline, str_begin + strlen("MAC=") + 18, str_begin + strlen("MAC=") + 35, sizeof(from_mac)) < 0)
					return(0);
			}

			if(snprintf(logrule_ptr->src_mac, sizeof(logrule_ptr->src_mac), "(%s)", from_mac) >= (int)sizeof(logrule_ptr->src_mac))
			{
				(void)vrprint.error(-1, "Error", "overflow in src_mac string (in: %s).", __FUNC__);
				return(0);
			}

			if(snprintf(logrule_ptr->dst_mac, sizeof(logrule_ptr->dst_mac), "(%s)", to_mac) >= (int)sizeof(logrule_ptr->dst_mac))
			{
				(void)vrprint.error(-1, "Error", "overflow in dst_mac string (in: %s).", __FUNC__);
				return(0);
			}
		}
	}
	else
	{
		(void)vrprint.error(-1, "Error", "Searching MAC= in iptables logline failed.");
		return(0);
	}

	/*
		get the packet length
	*/
	result = search_in_ipt_line(logline, vrmr_start, "LEN=", &str_begin, &str_end);
	if(result == 0)
	{
		if(str_begin == str_end-strlen("LEN="))
		{
			/* no length */
			logrule_ptr->packet_len = 0;
		}
		/* no len keyword */
		else if(str_begin == str_end)
		{
			if(debuglvl >= HIGH)
				(void)vrprint.debug(__FUNC__, "No LEN keyword: no valid logline.");

			return(0);
		}
		/* if len is too long (4: LEN=, 5: 12345 max */
		else if(str_end > str_begin + (4 + 5))
		{
			if(debuglvl >= HIGH)
				(void)vrprint.debug(__FUNC__, "LEN too long: no valid logline.");

			return(0);
		}
		else
		{
			if(range_strcpy(packet_len, logline, str_begin + strlen("LEN="), str_end, sizeof(packet_len)) < 0)
			{
				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "LEN: lenght copy failed: no valid logline.");

				return(0);
			}
			else
			{
				logrule_ptr->packet_len = (unsigned int)atoi(packet_len);
			}
		}
	}
	else
	{
		(void)vrprint.error(-1, "Error", "Searching LEN= in iptables logline failed.");
		return(0);
	}


	/*
		get the packet ttl
	*/
	result = search_in_ipt_line(logline, vrmr_start, "TTL=", &str_begin, &str_end);
	if(result == 0)
	{
		if(str_begin == str_end-strlen("TTL="))
		{
			/* no length */
			logrule_ptr->ttl = 0;
		}
		/* no ttl keyword */
		else if(str_begin == str_end)
		{
			if(debuglvl >= HIGH)
				(void)vrprint.debug(__FUNC__, "No TTL keyword: no valid logline.");

			return(0);
		}
		/* if len is too long (4: TTL=, 5: 12345 max */
		else if(str_end > str_begin + (4 + 5))
		{
			if(debuglvl >= HIGH)
				(void)vrprint.debug(__FUNC__, "TTL too long: no valid logline.");

			return(0);
		}
		else
		{
			if(range_strcpy(packet_len, logline, str_begin + strlen("TTL="), str_end, sizeof(packet_len)) < 0)
			{
				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "TTL: lenght copy failed: no valid logline.");

				return(0);
			}
			else
			{
				logrule_ptr->ttl = (unsigned int)atoi(packet_len);
			}
		}
	}
	else
	{
		(void)vrprint.error(-1, "Error", "Searching TTL= in iptables logline failed.");
		return(0);
	}


	/*
		get the protocol
	*/
	result = search_in_ipt_line(logline, vrmr_start, "PROTO=", &str_begin, &str_end);
	if(result == 0)
	{
		if(str_begin == str_end-strlen("PROTO="))
		{
			/* no proto */
			logrule_ptr->protocol = -1;
		}
		/* no proto keyword */
		else if(str_begin == str_end)
		{
			//(void)vrprint.error(-1, "Error", "Not a valid iptables line: No PROTO= keyword: %s", line);
			return(0);
		}
		/* if proto is too long (6: PROTO=, 4: ICMP max) */
		else if(str_end > str_begin + 6 + 4)
		{
			//(void)vrprint.error(-1, "Error", "Not a valid iptables line: PROTO= value is too long: %s", line);
			return(0);
		}
		else
		{
			/*	in the log for the following protocol netfilter uses the names:
				tcp,udp,icmp,ah,esp, for the rest numbers
			*/
			if(range_strcpy(protocol, logline, str_begin + strlen("PROTO="), str_end, sizeof(protocol)) < 0)
			{
				return(0);
			}
			else
			{
				if(strcasecmp(protocol, "tcp") == 0)
				{
					logrule_ptr->protocol = 6;
					counter_ptr->tcp++;
				}
				else if(strcasecmp(protocol, "udp") == 0)
				{
					logrule_ptr->protocol = 17;
					counter_ptr->udp++;
				}
				else if(strcasecmp(protocol, "icmp") == 0)
				{
					logrule_ptr->protocol = 1;
					counter_ptr->icmp++;
				}
				else if(strcasecmp(protocol, "ah") == 0)
				{
					logrule_ptr->protocol = 51;
					counter_ptr->other_proto++;
				}
				else if(strcasecmp(protocol, "esp") == 0)
				{
					logrule_ptr->protocol = 50;
					counter_ptr->other_proto++;
				}
				else
				{
					logrule_ptr->protocol = atoi(protocol);
					counter_ptr->other_proto++;
				}
			}

			/* protocol numbers bigger than 255 are not allowed */
			if(logrule_ptr->protocol < 1 || logrule_ptr->protocol > 255)
			{
				return(0);
			}
		}
	}
	else
	{
		(void)vrprint.error(-1, "Error", "Searching PROTO= in iptables logline failed.");
		return(0);
	}

	/*
		ports TODO: all protocols except tcp,udp,icmp
	*/
	
	/* tcp & udp */
	if(logrule_ptr->protocol == 6 || logrule_ptr->protocol == 17)
	{
		// set icmp to unused
		logrule_ptr->icmp_type = -1;
		logrule_ptr->icmp_code = -1;

		/*
			get the source port
		*/
		result = search_in_ipt_line(logline, vrmr_start, "SPT=", &str_begin, &str_end);
		if(result == 0)
		{
			/* if the SPT= part is the only part */
			if(str_begin == str_end - strlen("SPT="))
			{
				/* do ehhh, basicly nothing ;-) */
			}
			/* if the length of SPT=xxxxx is longer than expected */
			else if(str_end > str_begin + 4 + 5)
			{
				return(0);
			}
			else
			{
				if(range_strcpy(port, logline, str_begin + strlen("SPT="), str_end, sizeof(port)) < 0)
				{
					return(0);
				}
				else
				{
					logrule_ptr->src_port = atoi(port);

					if(!valid_tcpudp_port(debuglvl, logrule_ptr->src_port))
					{
						return(0);
					}
				}
			}
		}
		else
		{
			(void)vrprint.error(-1, "Error", "Searching SPT= in iptables logline failed.");
			return(0);
		}

		/*
			now the dst port
		*/							
		result = search_in_ipt_line(logline, vrmr_start, "DPT=", &str_begin, &str_end);
		if(result == 0)
		{
			/* if the DPT= part is the only part */
			if(str_begin == str_end-strlen("DPT="))
			{
				/* do ehhh, basicly nothing ;-) */
			}
			/* if the length of DPT=xxxxx is longer than expected */
			else if(str_end > str_begin + 4 + 5)
			{
				return(0);
			}
			else
			{
				memset(port, 0, sizeof(port));

				if(range_strcpy(port, logline, str_begin + strlen("DPT="), str_end, sizeof(port)) < 0)
				{
					return(0);
				}
				else
				{
					logrule_ptr->dst_port = atoi(port);

					if(!valid_tcpudp_port(debuglvl, logrule_ptr->dst_port))
					{
						return(0);
					}
				}
			}
		}
		else
		{
			(void)vrprint.error(-1, "Error", "Searching DPT= in iptables logline failed.");
			return(0);
		}

		/* now look for tcp-options */
		if(logrule_ptr->protocol == 6)
		{
			/*
				get the SYN flag
			*/
			result = search_in_ipt_line(logline, vrmr_start, "SYN", &str_begin, &str_end);
			if(result == 0)
			{
				/* if the SYN part is the only part we are cool */
				if(str_begin == str_end - strlen("SYN"))
				{
					logrule_ptr->syn = 1;
				}
				/* if the length of SYN is longer than expected */
				else if(str_end > str_begin + strlen("SYN"))
				{
					return(0);
				}
				else
				{
					logrule_ptr->syn = 0;
				}
			}
			else
			{
				(void)vrprint.error(-1, "Error", "Searching SYN in iptables logline failed.");
				return(0);
			}
			/*
				get the FIN flag
			*/
			result = search_in_ipt_line(logline, vrmr_start, "FIN", &str_begin, &str_end);
			if(result == 0)
			{
				/* if the FIN part is the only part we are cool */
				if(str_begin == str_end - strlen("FIN"))
				{
					logrule_ptr->fin = 1;
				}
				/* if the length of FIN is longer than expected */
				else if(str_end > str_begin + strlen("FIN"))
				{
					return(0);
				}
				else
				{
					logrule_ptr->fin = 0;
				}
			}
			else
			{
				(void)vrprint.error(-1, "Error", "Searching FIN in iptables logline failed.");
				return(0);
			}
			/*
				get the RST flag
			*/
			result = search_in_ipt_line(logline, vrmr_start, "RST", &str_begin, &str_end);
			if(result == 0)
			{
				/* if the RST part is the only part we are cool */
				if(str_begin == str_end - strlen("RST"))
				{
					logrule_ptr->rst = 1;
				}
				/* if the length of RST is longer than expected */
				else if(str_end > str_begin + strlen("RST"))
				{
					return(0);
				}
				else
				{
					logrule_ptr->rst = 0;
				}
			}
			else
			{
				(void)vrprint.error(-1, "Error", "Searching RST in iptables logline failed.");
				return(0);
			}
			/*
				get the ACK flag
			*/
			result = search_in_ipt_line(logline, vrmr_start, "ACK", &str_begin, &str_end);
			if(result == 0)
			{
				/* if the ACK part is the only part we are cool */
				if(str_begin == str_end - strlen("ACK"))
				{
					logrule_ptr->ack = 1;
				}
				/* if the length of ACK is longer than expected */
				else if(str_end > str_begin + strlen("ACK"))
				{
					return(0);
				}
				else
				{
					logrule_ptr->ack = 0;
				}
			}
			else
			{
				(void)vrprint.error(-1, "Error", "Searching ACK in iptables logline failed.");
				return(0);
			}
			/*
				get the PSH flag
			*/
			result = search_in_ipt_line(logline, vrmr_start, "PSH", &str_begin, &str_end);
			if(result == 0)
			{
				/* if the PSH part is the only part we are cool */
				if(str_begin == str_end - strlen("PSH"))
				{
					logrule_ptr->psh = 1;
				}
				/* if the length of PSH is longer than expected */
				else if(str_end > str_begin + strlen("PSH"))
				{
					return(0);
				}
				else
				{
					logrule_ptr->psh = 0;
				}
			}
			else
			{
				(void)vrprint.error(-1, "Error", "Searching PSH in iptables logline failed.");
				return(0);
			}
			/*
				get the URG flag
				
				Please note that we look for 'URG ' (inlcuding space) so we don't
				get confused with URGP.
			*/
			result = search_in_ipt_line(logline, vrmr_start, "URG ", &str_begin, &str_end);
			if(result == 0)
			{
				/* if the URG part is the only part we are cool */
				if(str_begin == str_end - strlen("URG "))
				{
					logrule_ptr->urg = 1;
				}
				/* if the length of URG is longer than expected */
				else if(str_end > str_begin + strlen("URG "))
				{
					return(0);
				}
				else
				{
					logrule_ptr->urg = 0;
				}
			}
			else
			{
				(void)vrprint.error(-1, "Error", "Searching URG in iptables logline failed.");
				return(0);
			}

		}
	}

	/* icmp */
	else if(logrule_ptr->protocol == 1)
	{
		/* no 'normal' ports, set to unused */
		logrule_ptr->src_port = -1;
		logrule_ptr->dst_port = -1;

		/*
			get the ICMP TYPE
		*/
		result = search_in_ipt_line(logline, vrmr_start, "TYPE=", &str_begin, &str_end);
		if(result == 0)
		{
			if(str_begin == str_end - strlen("TYPE="))
			{
//TODO: is this true?
				/* we dont NEED the type */
			}
			else
			{
				memset(port, 0, sizeof(port));

				if(range_strcpy(port, logline, str_begin + strlen("TYPE="), str_end, sizeof(port)) < 0)
				{
					return(0);
				}
				else
				{
// TODO: check number
					logrule_ptr->icmp_type = atoi(port);
					logrule_ptr->src_port = logrule_ptr->icmp_type;
				}
			}
		}
		else
		{
			(void)vrprint.error(-1, "Error", "Searching TYPE= in iptables logline failed.");
			return(0);
		}

		/*
			get the ICMP CODE
		*/
		result = search_in_ipt_line(logline, vrmr_start, "CODE=", &str_begin, &str_end);
		if(result == 0)
		{
			if(str_begin == str_end - strlen("CODE="))
			{
				/* we dont _need_ the code */
			}
			else
			{
				memset(port, 0, sizeof(port));

				if(range_strcpy(port, logline, str_begin + strlen("CODE="), str_end, sizeof(port)) < 0)
				{
					return(0);
				}
				else
				{
//TODO: check code
					logrule_ptr->icmp_code = atoi(port);
					logrule_ptr->dst_port = logrule_ptr->icmp_code;
				}
			}
		}
		else
		{
			(void)vrprint.error(-1, "Error", "Searching CODE= in iptables logline failed.");
			return(0);
		}
	}
	else if(logrule_ptr->protocol == 0)
	{
		return(0);
	} /* end ports */

	/* if we reach this, it's a valid logline */
	return(1);
};


/*
	get the vuurmuurnames with the ips and ports
	
	Returncodes:
		 1: ok
		 0: logline not ok
		-1: internal error
		
	NOTE: if the function returns -1 the memory is not cleaned up: the program is supposed to exit
*/
static int
get_vuurmuur_names(const int debuglvl, struct log_rule *logrule_ptr, struct draw_rule_format_ *rulefmt_ptr, Hash *ZoneHash, Hash *ServiceHash)
{
	struct ZoneData_	*search_ptr = NULL;
	struct ServicesData_	*ser_search_ptr = NULL;

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "start");


	/* safety */
	if(!logrule_ptr || !rulefmt_ptr || !ZoneHash || !ServiceHash)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}


	/* search in the hash with the ipaddress */
	if(!(search_ptr = search_zone_in_hash_with_ipv4(debuglvl, logrule_ptr->src_ip, ZoneHash)))
	{
		/* not found in hash */
		if(strlcpy(rulefmt_ptr->from_name, logrule_ptr->src_ip, sizeof(rulefmt_ptr->from_name)) >= sizeof(rulefmt_ptr->from_name))
			(void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
	}
	else
	{
		/* found in the hash */
		if(strlcpy(rulefmt_ptr->from_name, search_ptr->name, sizeof(rulefmt_ptr->from_name)) >= sizeof(rulefmt_ptr->from_name))
			(void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);

		if(search_ptr->type == TYPE_NETWORK)
			strlcpy(rulefmt_ptr->from_name, "firewall", sizeof(rulefmt_ptr->from_name));
	}
	search_ptr = NULL;


	/*	do it all again for TO */
	if(!(search_ptr = search_zone_in_hash_with_ipv4(debuglvl, logrule_ptr->dst_ip, ZoneHash)))
	{
		/* not found in hash */
		if(strlcpy(rulefmt_ptr->to_name, logrule_ptr->dst_ip, sizeof(rulefmt_ptr->to_name)) >= sizeof(rulefmt_ptr->to_name))
			(void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
	}
	else
	{
		/* found in the hash */
		if(strlcpy(rulefmt_ptr->to_name, search_ptr->name, sizeof(rulefmt_ptr->to_name)) >= sizeof(rulefmt_ptr->to_name))
			(void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);

		if(search_ptr->type == TYPE_NETWORK)
			strlcpy(rulefmt_ptr->to_name, "firewall", sizeof(rulefmt_ptr->to_name));
	}
	search_ptr = NULL;


	/*
		THE SERVICE
	*/

	/*	icmp is treated different because of the type and code
		and we can call get_icmp_name_short.
	*/
	if(logrule_ptr->protocol == 1)
	{
		if(!(ser_search_ptr = search_service_in_hash(debuglvl, logrule_ptr->icmp_type, logrule_ptr->icmp_code, logrule_ptr->protocol, ServiceHash)))
		{
			/* not found in hash */
			snprintf(rulefmt_ptr->ser_name, sizeof(rulefmt_ptr->ser_name), "%d.%d(icmp)", logrule_ptr->icmp_type, logrule_ptr->icmp_code);

			/* try to get the icmp-names */
			if(get_icmp_name_short(logrule_ptr->icmp_type, logrule_ptr->icmp_code, rulefmt_ptr->ser_name, sizeof(rulefmt_ptr->ser_name), 0) < 0)
			{
				(void)vrprint.error(-1, "Internal Error", "get_icmp_name_short failed (in: %s:%d).", __FUNC__, __LINE__);
				return(-1);
			}
		}
		else
		{
			/* found in the hash, now copy the name */
			if(strlcpy(rulefmt_ptr->ser_name, ser_search_ptr->name, sizeof(rulefmt_ptr->ser_name)) >= sizeof(rulefmt_ptr->ser_name))
				(void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
		}
	}

	/*	here we handle the rest
	*/
	else if(	logrule_ptr->protocol == 6  ||
			logrule_ptr->protocol == 17 ||
			logrule_ptr->protocol == 41 ||
			logrule_ptr->protocol == 47 ||
			logrule_ptr->protocol == 50 ||
			logrule_ptr->protocol == 51)
	{
		/* first a normal search */
		if(!(ser_search_ptr = search_service_in_hash(debuglvl, logrule_ptr->src_port, logrule_ptr->dst_port, logrule_ptr->protocol, ServiceHash)))
		{
			/* only do the reverse check for tcp and udp */
			if(logrule_ptr->protocol == 6 || logrule_ptr->protocol == 17)
			{
				/* not found, do a reverse search */
				if(!(ser_search_ptr = search_service_in_hash(debuglvl, logrule_ptr->dst_port, logrule_ptr->src_port, logrule_ptr->protocol, ServiceHash)))
				{
					/* not found in the hash */
					if(logrule_ptr->protocol == 6) /* tcp */
					{
						snprintf(rulefmt_ptr->ser_name, sizeof(rulefmt_ptr->ser_name), "%d->%d(tcp)", logrule_ptr->src_port, logrule_ptr->dst_port);
					}
					else if(logrule_ptr->protocol == 17) /* udp */
					{
						snprintf(rulefmt_ptr->ser_name, sizeof(rulefmt_ptr->ser_name), "%d->%d(udp)", logrule_ptr->src_port, logrule_ptr->dst_port);
					}
				}
				else
				{
					/* found in the hash! (reverse) */
					if(strlcpy(rulefmt_ptr->ser_name, ser_search_ptr->name, sizeof(rulefmt_ptr->ser_name)) >= sizeof(rulefmt_ptr->ser_name))
						(void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
				}
			}
			else
			{
				if(logrule_ptr->dst_port == 0 && logrule_ptr->src_port == 0)
					snprintf(rulefmt_ptr->ser_name, sizeof(rulefmt_ptr->ser_name), "proto-%d", logrule_ptr->protocol);
				else
					snprintf(rulefmt_ptr->ser_name, sizeof(rulefmt_ptr->ser_name), "%d*%d(%d)", logrule_ptr->src_port, logrule_ptr->dst_port, logrule_ptr->protocol);
	
			}
		}
		else
		{
			/* found in the hash! */
			if(strlcpy(rulefmt_ptr->ser_name, ser_search_ptr->name, sizeof(rulefmt_ptr->ser_name)) >= sizeof(rulefmt_ptr->ser_name))
				(void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
		}
	}
	else
	{
		snprintf(rulefmt_ptr->ser_name, sizeof(rulefmt_ptr->ser_name), "proto-%d", logrule_ptr->protocol);
	}

	return(1);
}


static void
print_help(void)
{
	fprintf(stdout, "Usage: vuurmuur_log [OPTIONS]\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout, " -h, --help\t\t\tgives this help\n");
	fprintf(stdout, " -v, --verbose\t\t\tverbose mode\n");
	fprintf(stdout, " -n, --nodaemon\t\t\tdo NOT start as a daemon\n");
	fprintf(stdout, " -c, --configfile\t\tuse the given configfile\n");
	fprintf(stdout, " -d, --debug\t\t\tenable debugging (1 = low, 3 = high)\n");
	fprintf(stdout, " -V, --version\t\t\tgives the version\n");
	fprintf(stdout, "\n");
	exit(EXIT_SUCCESS);
}


int
main(int argc, char *argv[])
{
	Interfaces			interfaces;
	Services			services;
	Zones				zones;
	
	Hash				zone_htbl,
					service_htbl;
	FILE				*system_log = NULL,
					*vuurmuur_log = NULL;
	char				line[1024] = "";
	size_t				linelen = 0;
	
	int				result,

					/*	variable for counting how long we are waiting
						for the next line in 1/10th of a second.
					*/
					waiting = 0;
	
	int				optch;
	static char			optstring[] = "hc:vnd:V";
	int				verbose = 0,
					nodaemon = 0;
	struct option prog_opts[] =
	{
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, &verbose, 1 },
		{ "nodaemon", no_argument, &nodaemon, 1 },
		{ "configfile", required_argument, NULL, 'c' },
		{ "debug", required_argument, NULL, 'd' },
		{ "version", no_argument, NULL, 'V' },
		{ 0, 0, 0, 0 },
	};
	int 			option_index = 0;
	char				*sscanf_str = NULL;
	
	struct log_rule			logrule;
	struct draw_rule_format_	rulefmt;
	int				debuglvl = 0;

	/* shm, sem stuff */
	int				shm_id;
	char				*shmp;
	union semun			semarg;
	ushort				seminit[] = { 1,0 };

	char				reload = 0;
	int				wait_time = 0;

	struct Counters_ Counters =
	{
		0, 0, 0, 0, 0,
		0, 0, 0, 0,

		0, 0, 0, 0,
	};
  
	struct rgx_			reg;
	char				quit = 0;
 
	/* get the current user */
	get_user_info(debuglvl, &user_data);

	if(VUURMUUR_PRERELEASE_VERSION == 0)
		snprintf(version_string, sizeof(version_string), "%d.%d.%d", 	VUURMUUR_VERSION_MAJOR,
										VUURMUUR_VERSION_MINOR,
										VUURMUUR_VERSION_SUB);
	else
		snprintf(version_string, sizeof(version_string), "%d.%d.%da%d",	VUURMUUR_VERSION_MAJOR,
										VUURMUUR_VERSION_MINOR,
										VUURMUUR_VERSION_SUB,
										VUURMUUR_PRERELEASE_VERSION);

	/* init signals */
	setup_signal_handler(SIGINT, handle_sigint);
	setup_signal_handler(SIGTERM, handle_sigterm);
	setup_signal_handler(SIGHUP, handle_sighup);

	/* initialize the print functions */
	vrprint.logger = "vuurmuur_log";
	vrprint.error = libvuurmuur_stdoutprint_error;
	vrprint.warning = libvuurmuur_stdoutprint_warning;
	vrprint.info = libvuurmuur_stdoutprint_info;
	vrprint.debug = libvuurmuur_stdoutprint_debug;
	vrprint.username = user_data.realusername;
	vrprint.audit = libvuurmuur_stdoutprint_audit;

	/* set default configfile location */
	if(pre_init_config(&conf) < 0)
		exit(EXIT_FAILURE);

	/* process the options */
	while((optch = getopt_long(argc, argv, optstring, prog_opts,
					&option_index)) != -1 )
	{
		switch(optch)
		{
			case 0 :
				/* This is used for the flags long options */
				break;

			case 'h' :
				print_help();
				break;

			case 'v' :
				verbose = 1;
				break;

			case 'n' :
				nodaemon = 1;
				break;

			case 'c' :
				/* config file */
				if(conf.verbose_out == TRUE)
					fprintf(stdout, "Using this configfile: %s\n", optarg);

				if(strlcpy(conf.configfile, optarg, sizeof(conf.configfile)) >= sizeof(conf.configfile))
				{
					fprintf(stderr, "Error: configfile (-c): argument too long (max: %d).\n", (int)sizeof(conf.configfile)-1);
					exit(EXIT_FAILURE);
				}
				break;

			case 'd' :
				/* debugging */
				fprintf(stdout, "vuurmuur: debugging enabled.\n");

				/* convert the debug string and check the result */
				debuglvl = atoi(optarg);
				if(debuglvl < 0 || debuglvl > HIGH)
				{
					fprintf(stdout, "Error: illegal debug level: %d (max: %d).\n", debuglvl, HIGH);
					exit(EXIT_FAILURE);
				}

				fprintf(stdout, "vuurmuur-log: debug level: %d\n", debuglvl);
				break;

			case 'V' :
				/* print version */
				fprintf(stdout, "Vuurmuur_log %s\n", version_string);
				fprintf(stdout, "Copyright (C) 2002-2006 by Victor Julien\n");

				exit(EXIT_SUCCESS);
		}
	}

	/* check if the pidfile already exists */
	if(check_pidfile(PIDFILE) == -1)
		exit(EXIT_FAILURE);

	/* set up the sscanf parser string */
	if(!(sscanf_str = assemble_logline_sscanf_string(debuglvl, &logrule)))
	{
		(void)vrprint.error(-1, "Error", "could not set up parse string.");
		exit(EXIT_FAILURE);
	}

	/* init the config file */
	if(init_config(debuglvl, &conf) < VR_CNF_OK)
	{
		(void)vrprint.error(-1, "Error", "initializing the config failed.");
		exit(EXIT_FAILURE);
	}

	if(verbose)
		(void)vrprint.info("Info", "Vuurmuur_log %s", version_string);

	/* now setup the print function */
	if(verbose)
		vrprint.error = libvuurmuur_stdoutprint_error;
	else
		vrprint.error = libvuurmuur_logprint_error;

	vrprint.warning = libvuurmuur_logprint_warning;
	vrprint.info = libvuurmuur_logprint_info;
	vrprint.debug = libvuurmuur_logprint_debug;
	vrprint.audit = libvuurmuur_logprint_audit;

	(void)vrprint.audit("Vuurmuur_log %s started by user %s.", version_string, user_data.realusername);

	/* setup regexes */
	if(setup_rgx(1, &reg) < 0)
	{
		(void)vrprint.error(-1, "Internal Error", "setting up regular expressions failed.");
		exit(EXIT_FAILURE);
	}

	if(load_backends(debuglvl, &PluginList) < 0)
	{
		(void)vrprint.error(-1, "Error", "loading plugins failed, bailing out.");
		exit(EXIT_FAILURE);
	}
	else
	{
		if(verbose)
			(void)vrprint.info("Info", "Loading plugins succesfull.");
	}

	/* open the logs */
	if(open_logfiles(debuglvl, &system_log, &vuurmuur_log) < 0)
	{
		(void)vrprint.error(-1, "Error", "opening logfiles failed.");
		exit(EXIT_FAILURE);
	}

	/* load the services into memory */
	result = load_services(debuglvl, &services, &reg);
	if(result == -1)
		exit(EXIT_FAILURE);

	/* load the interfaces into memory */
	result = load_interfaces(debuglvl, &interfaces);
	if(result == -1)
		exit(EXIT_FAILURE);

	/* load the zonedata into memory */
	result = load_zones(debuglvl, &zones, &interfaces, &reg);
	if(result == -1)
		exit(EXIT_FAILURE);


	/* insert the interfaces as TYPE_FIREWALL's into the zonelist as 'firewall', so this appears in to log as 'firewall(interface)' */
	if(ins_iface_into_zonelist(debuglvl, &interfaces.list, &zones.list) < 0)
	{
		(void)vrprint.error(-1, "Error", "iface_into_zonelist failed (in: main).");
		exit(EXIT_FAILURE);
	}
	
	/* these are removed by: rem_iface_from_zonelist() (see below) */
	if(add_broadcasts_zonelist(debuglvl, &zones) < 0)
	{
		(void)vrprint.error(-1, "Error", "unable to add broadcasts to list.");
		exit(EXIT_FAILURE);
	}

	(void)vrprint.info("Info", "Creating hash-table for the zones...");
	if(init_zonedata_hashtable(debuglvl, zones.list.len * 3, &zones.list, hash_ipaddress, compare_ipaddress, &zone_htbl) < 0)
	{
		(void)vrprint.error(-1, "Error", "init_zonedata_hashtable failed.");
		exit(EXIT_FAILURE);
	}

	(void)vrprint.info("Info", "Creating hash-table for the services...");
	if(init_services_hashtable(debuglvl, services.list.len * 500, &services.list, hash_port, compare_ports, &service_htbl) < 0)
	{
		(void)vrprint.error(-1, "Error", "init_services_hashtable failed.");
		exit(EXIT_FAILURE);
	}

	/* enter daemon mode */
	if(nodaemon == 0)
		daemon(1,1);

	/* create shared memory segment */
	shm_id = shmget(IPC_PRIVATE, sizeof(*shm_table), 0600);
	if(shm_id < 0)
	{
		(void)vrprint.error(-1, "Error", "unable to create shared memory: %s.", strerror(errno));
		exit(EXIT_FAILURE);
	}
	/* for some reason on my machine the shm_id is zero when vuurmuur is started at boot
	   if we sleep for some time and retry it works */
	else if(shm_id == 0)
	{
		/* sleep 3 seconds before trying again */
		(void)sleep(3);

		shm_id = shmget(IPC_PRIVATE, sizeof(*shm_table), 0600);
		if(shm_id < 0)
		{
			(void)vrprint.error(-1, "Error", "Unable to create shared memory: %s (retry).", strerror(errno));
			exit(EXIT_FAILURE);
		}
		else if(shm_id == 0)
		{
			(void)vrprint.info("Info", "Still no valid shm_id. Giving up.");
		}
		else
		{
			(void)vrprint.info("Info", "Creating shared memory successfull: shm_id: %d (retry).", shm_id);
		}
	}
	else
	{
		(void)vrprint.info("Info", "Creating shared memory successfull: shm_id: %d.", shm_id);
	}

	/* now attach to the shared mem */
	if(shm_id > 0)
	{
		shmp = shmat(shm_id, 0, 0);
		if(shmp == (char *)(-1))
		{
			(void)vrprint.error(-1, "Error", "unable to attach to shared memory: %s.", strerror(errno));
			exit(EXIT_FAILURE);
		}
		else
		{
			shm_table = (struct SHM_TABLE *)shmp;
			(void)vrprint.info("Info", "Attaching to shared memory successfull.");
		}

		/* if all went well we create a semaphore */
		if(shm_table)
		{
			sem_id = semget(IPC_PRIVATE, 2, 0600);
			if(sem_id == -1)
			{
				(void)vrprint.error(-1, "Error", "Unable to create semaphore: %s.", strerror(errno));
				exit(EXIT_FAILURE);
			}
			else
			{
				(void)vrprint.info("Info", "Creating a semaphore success: %d", sem_id);
			}

			semarg.array = seminit;
			if(semctl(sem_id, 0, SETALL, semarg) == -1)
			{
				(void)vrprint.error(-1, "Error", "Unable to initialize semaphore: %s.", strerror(errno));
				exit(EXIT_FAILURE);
			}
			else
			{
				(void)vrprint.info("Info", "Initializeing the semaphore successfull.");
			}

			/* now initialize the shared mem */
			if(LOCK)
			{
				shm_table->sem_id = sem_id;
				shm_table->backend_changed = 0;
				shm_table->reload_result = VR_RR_READY;

				UNLOCK;
			}
		}
	}

	/* Create a pidfile. */
	result = create_pidfile(PIDFILE, shm_id);
	if(result < 0)
		exit(EXIT_FAILURE);


	if(sigint_count || sigterm_count)
		quit = 1;

	/* enter the main loop */
	while(quit == 0)
	{
		/* check the shm for changes */
		if(LOCK)
		{
			if(shm_table->configtool.connected == 1)
			{
				(void)vrprint.info("Info", "Configtool connected: %s.", shm_table->configtool.name);
				shm_table->configtool.connected = 2;
			}
			else if(shm_table->configtool.connected == 3)
			{
				(void)vrprint.info("Info", "Configtool disconnected: %s.", shm_table->configtool.name);
				shm_table->configtool.connected = 0;
			}

			if(shm_table->backend_changed == 1)
			{
				(void)vrprint.audit("IPC-SHM: backend changed: reload (user: %s).", shm_table->configtool.username);
				reload = 1;
				shm_table->backend_changed = 0;

				/* start at 0% */
				shm_table->reload_progress = 0;
			}

			UNLOCK;
		}

		if(reload == 0)
		{
			if(fgets(line, (int)sizeof(line), system_log) != NULL)
			{
				linelen = strlen(line);

				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "got a logline (len = %u, max = %u).", linelen, sizeof(line));

				/* if we got a line, we reset waiting */
				waiting = 0;

				/*	if the line does not end with a
					newline it is incomplete, so we
					rewind.
					
					we first check if the line isn't
					longer than our buffer, so the newline
					char might just be past the buffer.
					Fixes a race condition reported by
					Adi. */
				if(	(linelen < sizeof(line)-1) &&
					line[linelen - 1] != '\n')
				{
					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "logline (len = %u) is incomplete: no trailing newline char. Rewinding(using fseek).", linelen);

					fseek(system_log, (int)linelen*-1, SEEK_CUR);
				}
				else
				{
					/*
						first check if this is a vuurmuur line
					*/
					if(check_ipt_line(line))
					{
						if(debuglvl >= LOW)
							(void)vrprint.debug(__FUNC__, "the line is a vuurmuur line.");

						/* now parse it */
						result = parse_ipt_logline(debuglvl, line, linelen, sscanf_str, &logrule, &rulefmt, &Counters);
						if(result == -1)
						{
							exit(EXIT_FAILURE);
						}
						else if(result == 0)
						{
							/* invalid line */
							if(debuglvl >= LOW)
								(void)vrprint.debug(__FUNC__, "the line is invalid after parsing.");

							Counters.invalid_loglines++;
						}
						else
						{
							if(debuglvl >= LOW)
								(void)vrprint.debug(__FUNC__, "the line was successfully parsed.");

							/*
								now try to get our vuurmuur names into it
							*/
							result = get_vuurmuur_names(debuglvl, &logrule, &rulefmt, &zone_htbl, &service_htbl);
							if(result == -1)
							{
								exit(EXIT_FAILURE);
							}
							else if(result == 0)
							{
								/* some minor error */
								if(debuglvl >= LOW)
									(void)vrprint.debug(__FUNC__, "the line is invalid after trying to insert the vuurmuur names.");

								Counters.invalid_loglines++;
							}
							else
							{
								if(debuglvl >= LOW)
									(void)vrprint.debug(__FUNC__, "the line was successfully named.");

								/* TCP */
								if(logrule.protocol == 6)
								{
									CreateTCPFlagString(&logrule, rulefmt.tcpflags);

									fprintf(vuurmuur_log, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s %s%s:%d -> %s%s:%d TCP flags: %s len:%u ttl:%u)\n",
													logrule.month,
													logrule.day,
													logrule.hour,
													logrule.minute,
													logrule.second,
													logrule.action,
													rulefmt.ser_name,
													rulefmt.from_name,
													rulefmt.to_name,
													logrule.logprefix,
													rulefmt.from_int,
													rulefmt.to_int,
													logrule.src_ip,
													logrule.src_mac,
													logrule.src_port,
													logrule.dst_ip,
													logrule.dst_mac,
													logrule.dst_port,
													rulefmt.tcpflags,
													logrule.packet_len,
													logrule.ttl);
								}
								/* UDP */
								else if(logrule.protocol == 17)
								{
									fprintf(vuurmuur_log, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s %s%s:%d -> %s%s:%d UDP len:%u ttl:%u)\n",
													logrule.month,
													logrule.day,
													logrule.hour,
													logrule.minute,
													logrule.second,
													logrule.action,
													rulefmt.ser_name,
													rulefmt.from_name,
													rulefmt.to_name,
													logrule.logprefix,
													rulefmt.from_int,
													rulefmt.to_int,
													logrule.src_ip,
													logrule.src_mac,
													logrule.src_port,
													logrule.dst_ip,
													logrule.dst_mac,
													logrule.dst_port,
													logrule.packet_len,
													logrule.ttl);
								}
								/* ICMP */
								else if(logrule.protocol == 1)
								{
									fprintf(vuurmuur_log, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s %s%s -> %s%s ICMP type %d code %d len:%u ttl:%u)\n",
													logrule.month,
													logrule.day,
													logrule.hour,
													logrule.minute,
													logrule.second,
													logrule.action,
													rulefmt.ser_name,
													rulefmt.from_name,
													rulefmt.to_name,
													logrule.logprefix,
													rulefmt.from_int,
													rulefmt.to_int,
													logrule.src_ip,
													logrule.src_mac,
													logrule.dst_ip,
													logrule.dst_mac,
													logrule.icmp_type,
													logrule.icmp_code,
													logrule.packet_len,
													logrule.ttl);
								}
								/* GRE */
								else if(logrule.protocol == 47)
								{
									fprintf(vuurmuur_log, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s %s%s -> %s%s GRE len:%u ttl:%u)\n",
													logrule.month,
													logrule.day,
													logrule.hour,
													logrule.minute,
													logrule.second,
													logrule.action,
													rulefmt.ser_name,
													rulefmt.from_name,
													rulefmt.to_name,
													logrule.logprefix,
													rulefmt.from_int,
													rulefmt.to_int,
													logrule.src_ip,
													logrule.src_mac,
													logrule.dst_ip,
													logrule.dst_mac,
													logrule.packet_len,
													logrule.ttl);
								}
								/* ESP */
								else if(logrule.protocol == 50)
								{
									fprintf(vuurmuur_log, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s %s%s -> %s%s ESP len:%u ttl:%u)\n",
													logrule.month,
													logrule.day,
													logrule.hour,
													logrule.minute,
													logrule.second,
													logrule.action,
													rulefmt.ser_name,
													rulefmt.from_name,
													rulefmt.to_name,
													logrule.logprefix,
													rulefmt.from_int,
													rulefmt.to_int,
													logrule.src_ip,
													logrule.src_mac,
													logrule.dst_ip,
													logrule.dst_mac,
													logrule.packet_len,
													logrule.ttl);
								}
								/* AH */
								else if(logrule.protocol == 51)
								{
									fprintf(vuurmuur_log, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s %s%s -> %s%s AH len:%u ttl:%u)\n",
													logrule.month,
													logrule.day,
													logrule.hour,
													logrule.minute,
													logrule.second,
													logrule.action,
													rulefmt.ser_name,
													rulefmt.from_name,
													rulefmt.to_name,
													logrule.logprefix,
													rulefmt.from_int,
													rulefmt.to_int,
													logrule.src_ip,
													logrule.src_mac,
													logrule.dst_ip,
													logrule.dst_mac,
													logrule.packet_len,
													logrule.ttl);
								}
								/* other */
								else
								{
									fprintf(vuurmuur_log, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s %s%s -> %s%s (%d) len:%u ttl:%u)\n",
													logrule.month,
													logrule.day,
													logrule.hour,
													logrule.minute,
													logrule.second,
													logrule.action,
													rulefmt.ser_name,
													rulefmt.from_name,
													rulefmt.to_name,
													logrule.logprefix,
													rulefmt.from_int,
													rulefmt.to_int,
													logrule.src_ip,
													logrule.src_mac,
													logrule.dst_ip,
													logrule.dst_mac,
													logrule.protocol,
													logrule.packet_len,
													logrule.ttl);
								}

								fflush(vuurmuur_log);
							}
						}

						Counters.totalvuurmuur++;
					}
					else
					{
						Counters.noipt++;
					}

					Counters.total++;
				}
			}

			/* no line received */
			else
			{
				/* increase the waiter */
				waiting++;

				/* see the definition of MAX_WAIT_TIME for details. */
				if(waiting >= MAX_WAIT_TIME)
				{
					if(debuglvl >= MEDIUM)
						(void)vrprint.debug(__FUNC__, "didn't get a logline for %d seconds, closing and reopening the logfiles.", waiting / 10);

					/* re-open the logs */
					if(reopen_logfiles(debuglvl, &system_log, &vuurmuur_log) < 0)
					{
						(void)vrprint.error(-1, "Error", "re-opening logfiles failed.");
						exit(EXIT_FAILURE);
					}
					else
					{
						if(debuglvl >= MEDIUM)
							(void)vrprint.debug(__FUNC__, "re-opening the logfiles was successfull.");
					}

					/* reset waiting */
					waiting = 0;
				}
				else
				{
					/* sleep so we don't use all system resources */
					usleep(100000);  /* this should be 1/10th of a second */
				}
			}
		} /* if reload == 0 */

		/*
			hey! we received a sighup. We will reload the data.
		*/
		if(sighup_count || reload)
		{
			if(debuglvl >= LOW)
				(void)vrprint.debug(__FUNC__, "received sig_hup or shm-reload.");

			sighup_count = 0;

			/*
				clean up data
			*/

			/* destroy hashtables */
			hash_cleanup(debuglvl, &zone_htbl);
			hash_cleanup(debuglvl, &service_htbl);
  
			/* destroy the ServicesList */
			destroy_serviceslist(debuglvl, &services);
			/* destroy the ZonedataList */
			destroy_zonedatalist(debuglvl, &zones);
			/* destroy the InterfacesList */
			destroy_interfaceslist(debuglvl, &interfaces);

			/* close backend */
			result = unload_backends(debuglvl, &PluginList);
			if(result < 0)
			{
				(void)vrprint.error(-1, "Error", "unloading backends failed.");
				exit(EXIT_FAILURE);
			}

			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 10);

			/* reload the config

			   if it fails it's no big deal, we just keep using the old config.
			*/
			if(reload_config(debuglvl, &conf) < VR_CNF_OK)
			{
				(void)vrprint.warning("Warning", "reloading config failed, using old config.");
			}

			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 20);

			/* open backends */
			result = load_backends(debuglvl, &PluginList);
			if(result < 0)
			{
				(void)vrprint.error(-1, "Error", "re-opening backends failed.");
				exit(EXIT_FAILURE);
			}

			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 30);

			/* re-initialize the data */
			(void)vrprint.info("Info", "Initializing interfaces...");
			if(init_interfaces(debuglvl, &interfaces) < 0)
			{
				(void)vrprint.error(-1, "Error", "initializing interfaces failed.");
				exit(EXIT_FAILURE);
			}

			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 40);

			(void)vrprint.info("Info", "Initializing zones...");
			if(init_zonedata(debuglvl, &zones, &interfaces, &reg) < 0)
			{
				(void)vrprint.error(-1, "Error", "initializing zones failed.");
				exit(EXIT_FAILURE);
			}

			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 50);

			(void)vrprint.info("Info", "Initializing services...");
			if(init_services(debuglvl, &services, &reg) < 0)
			{
				(void)vrprint.error(-1, "Error", "initializing services failed.");
				exit(EXIT_FAILURE);
			}

			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 60);

			/* insert the interfaces as TYPE_FIREWALL's into the zonelist as 'firewall', so this appears in to log as 'firewall(interface)' */
			if(ins_iface_into_zonelist(debuglvl, &interfaces.list, &zones.list) < 0)
			{
				(void)vrprint.error(-1, "Error", "iface_into_zonelist failed (in: main).");
				exit(EXIT_FAILURE);
			}

			/* these are removed by: rem_iface_from_zonelist() (see below) */
			if(add_broadcasts_zonelist(debuglvl, &zones) < 0)
			{
				(void)vrprint.error(-1, "Error", "unable to add broadcasts to list.");
				return(-1);
			}
			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 70);

			(void)vrprint.info("Info", "Creating hash-table for the zones...");
			if(init_zonedata_hashtable(debuglvl, zones.list.len * 3, &zones.list, hash_ipaddress, compare_ipaddress, &zone_htbl) < 0)
			{
				(void)vrprint.error(result, "Error", "init_zonedata_hashtable failed.");
				exit(EXIT_FAILURE);
			}
			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 80);

			(void)vrprint.info("Info", "Creating hash-table for the services...");
			if(init_services_hashtable(debuglvl, services.list.len * 500, &services.list, hash_port, compare_ports, &service_htbl) < 0)
			{
				(void)vrprint.error(result, "Error", "init_services_hashtable failed.");
				exit(EXIT_FAILURE);
			}
			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 90);

			/* re-open the logs */
			if(reopen_logfiles(debuglvl, &system_log, &vuurmuur_log) < 0)
			{
				(void)vrprint.error(-1, "Error", "re-opening logfiles failed.");
				exit(EXIT_FAILURE);
			}
			shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 95);

			/* only ok now */
			result = 0;

			/* if we are reloading because of an IPC command, we need to communicate with the caller */
			if(reload == 1)
			{
				if(LOCK)
				{
					/* finished so 100% */
					shm_table->reload_progress = 100;

					/* tell the caller about the reload result */
					if(result < 0)
					{
						shm_table->reload_result = VR_RR_ERROR;
					}
					else if(result == 0)
					{
						shm_table->reload_result = VR_RR_SUCCES;
					}
					else
					{
						shm_table->reload_result = VR_RR_NOCHANGES;
					}
					UNLOCK;
				}
				reload = 0;

				(void)vrprint.info("Info", "Waiting for an VR_RR_RESULT_ACK");

				result = 0;
				wait_time = 0;

				/* now wait max 30 seconds for an ACK from the caller */
				while(result == 0 && wait_time < 30)
				{
					if(LOCK)
					{
						/* ah, we got one */
						if(shm_table->reload_result == VR_RR_RESULT_ACK)
						{
							shm_table->reload_result = VR_RR_READY;
							shm_table->reload_progress = 0;
							result = 1;

							(void)vrprint.info("Info", "We got an VR_RR_RESULT_ACK!");
						}
						UNLOCK;
					}

					wait_time++;
					sleep(1);
				}

				/* damn, we didn't get one */
				if(result == 0)
				{
					(void)vrprint.info("Info", "We've waited for %d seconds for an VR_RR_RESULT_ACK, but got none. Setting to VR_RR_READY", wait_time);
					if(LOCK)
					{
						shm_table->reload_result = VR_RR_READY;
						shm_table->reload_progress = 0;
						UNLOCK;
					}
					else
					{
						(void)vrprint.info("Info", "Hmmmm, failed to set to ready. Did the client crash?");
					}
				}
				result = 0;
			}
		}

		/* check for a signal */
		if(sigint_count || sigterm_count)
			quit = 1;

	}


	/*
		cleanup
	*/

	/* destroy shm */
	(void)vrprint.info("Info", "Destroying shared memory...");
	if(shmctl(shm_id, IPC_RMID, NULL) < 0)
	{
		(void)vrprint.error(-1, "Error", "destroying shared memory failed: %s.", strerror(errno));
	}
	else
	{
		if(debuglvl >= LOW)
			(void)vrprint.debug(__FUNC__, "shared memory destroyed.");
	}

	/* destroy semaphore */
	if(semctl(sem_id, 0, IPC_RMID, semarg) == -1)
	{
		(void)vrprint.error(-1, "Error", "failed to remove semaphore.");
	}

	/* free the sscanf parser string */
	free(sscanf_str);
	
	/* close the logfiles */
	fclose(vuurmuur_log);
	fclose(system_log);

	/* destroy hashtables */
	hash_cleanup(debuglvl, &zone_htbl);
	hash_cleanup(debuglvl, &service_htbl);

	/* destroy the ServicesList */
	destroy_serviceslist(debuglvl, &services);
	/* destroy the ZonedataList */
	destroy_zonedatalist(debuglvl, &zones);
	/* destroy the InterfacesList */
	destroy_interfaceslist(debuglvl, &interfaces);
  
	if(nodaemon)
	{
		fprintf(stdout, "\nStatistics:\n");

		fprintf(stdout, "Total logrules: %u (vuurmuur: %u, other: %u, invalid: %u)\n", Counters.total, Counters.totalvuurmuur, Counters.noipt, Counters.invalid_loglines);

		fprintf(stdout, "\nMatches:\n");
		fprintf(stdout, "Accepted    : %u\n", Counters.accept);
		fprintf(stdout, "Queued      : %u\n", Counters.queue);
		fprintf(stdout, "Rejected    : %u\n", Counters.reject);
		fprintf(stdout, "Dropped     : %u\n", Counters.drop);
		fprintf(stdout, "Other       : %u\n", Counters.other_match);

		fprintf(stdout, "\nProtocols:\n");
		fprintf(stdout, "TCP         : %u\n", Counters.tcp);
		fprintf(stdout, "UDP         : %u\n", Counters.udp);
		fprintf(stdout, "ICMP        : %u\n", Counters.icmp);
		fprintf(stdout, "Other       : %u\n", Counters.other_proto);
	}

	if(unload_backends(debuglvl, &PluginList) < 0)
	{
		(void)vrprint.error(-1, "Error", "unloading backends failed.");
	}

	/* cleanup regexes */
	(void)setup_rgx(0, &reg);

	/* remove the pidfile */
	if(remove_pidfile(PIDFILE) < 0)
	{
		(void)vrprint.error(-1, "Error", "unable to remove pidfile: %s.", strerror(errno));
	}

	exit(EXIT_SUCCESS);
}

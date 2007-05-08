/***************************************************************************
 *   Copyright (C) 2003-2006 by Victor Julien                              *
 *   victor@nk.nl                                                          *
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

#include "conntrack.h"
#include "vuurmuur.h"

struct ConntrackLine
{
	int			protocol;
	int			ttl;
	int			state;
	char			src_ip[16];
	char			dst_ip[16];
	char			alt_src_ip[16];
	char			alt_dst_ip[16];
	int			src_port;
	int			dst_port;
	int			alt_src_port;
	int			alt_dst_port;

	char			use_acc;
	unsigned long long	to_src_packets;
	unsigned long long	to_src_bytes;
	unsigned long long	to_dst_packets;
	unsigned long long	to_dst_bytes;

	char			to_src_packets_str[16];
	char			to_src_bytes_str[16];
	char			to_dst_packets_str[16];
	char			to_dst_bytes_str[16];

	char			status[16];
};


/*

	Returncodes:
		0: not filtered
		1: filtered
		
		In case of error we return 0.
*/
static int
filtered_connection(const int debuglvl, struct ConntrackData *cd_ptr, VR_filter *filter)
{
	char	line[512] = "";

	if(cd_ptr == NULL || filter == NULL)
		return(0);

	snprintf(line, sizeof(line), "%d %s %s %s %d %d %d %s %s",
					cd_ptr->cnt,
					cd_ptr->sername,
					cd_ptr->fromname,
					cd_ptr->toname,
					cd_ptr->src_port,
					cd_ptr->dst_port,
					cd_ptr->protocol,
					cd_ptr->src_ip,
					cd_ptr->dst_ip);

	/*	check the regex
		
		If the regex matches, the line is not filtered, so we return 0.
	*/
	if(regexec(&filter->reg, line, 0, NULL, 0) == 0)
	{
		if(filter->neg == FALSE)
			return(0);
		else
			return(1);
	}
	else
	{
		if(filter->neg == FALSE)
			return(1);
		else
			return(0);
	}
}


//- print_dlist
void
conn_print_dlist(const d_list *dlist)
{
	d_list_node		*d_node = NULL;
	struct ConntrackData	*cd_ptr = NULL;
	char			status[16] = "";
	char			direction[16] = "";

	if(!dlist)
		return;

	for(d_node = dlist->top; d_node; d_node = d_node->next)
	{
		cd_ptr = d_node->data;

		if(cd_ptr->connect_status == CONN_UNUSED)
			strcpy(status, "");
		else if(cd_ptr->connect_status == CONN_CONNECTING)
			strcpy(status, "CONNECTING");
		else if(cd_ptr->connect_status == CONN_CONNECTED)
			strcpy(status, "CONNECTED");
		else if(cd_ptr->connect_status == CONN_DISCONNECTING)
			strcpy(status, "DISCONNECTING");
		else
			strcpy(status, "UNKNOWN");

		if(cd_ptr->direction_status == CONN_UNUSED)
			strcpy(direction, "");
		else if(cd_ptr->direction_status == CONN_IN)
			strcpy(direction, "INCOMING");
		else if(cd_ptr->direction_status == CONN_OUT)
			strcpy(direction, "OUTGOING");
		else if(cd_ptr->direction_status == CONN_FW)
			strcpy(direction, "FORWARDING");

		fprintf(stdout, "%4d: service %s from %s to %s %s %s\n", cd_ptr->cnt, cd_ptr->sername, cd_ptr->fromname, cd_ptr->toname, status, direction);
	}

	return;
}


/*	conntrack_line_to_data

	This function analyzes the line supplied through the connline_ptr.
	It should never fail, unless we have a serious problem: malloc failure
	or parameter problems.

	Returncodes:
		 0: ok
		-1: (serious) error
*/
int
conn_line_to_data(	const int debuglvl,
			struct ConntrackLine *connline_ptr,
			struct ConntrackData *conndata_ptr,
			Hash *serhash,
			Hash *zonehash,
			d_list *zonelist,
			VR_ConntrackRequest *req
		)
{
	char		service_name[MAX_SERVICE] = "",
			zone_name[MAX_HOST_NET_ZONE] = "",
			*zone_name_ptr = NULL;
	size_t		size = 0;

	/* safety */
	if(	connline_ptr == NULL || conndata_ptr == NULL ||
		serhash == NULL || zonehash == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}
	if(req->unknown_ip_as_net && zonelist == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* first the service name */
	conndata_ptr->service = search_service_in_hash(debuglvl,
					connline_ptr->src_port,
					connline_ptr->dst_port,
					connline_ptr->protocol, serhash);
	if(conndata_ptr->service == NULL)
	{
		/* do a reverse lookup. This will prevent connections that
		 * have been picked up by conntrack midstream to look
		 * unrecognized  */
		if((conndata_ptr->service = search_service_in_hash(debuglvl,
			connline_ptr->dst_port, connline_ptr->src_port,
			connline_ptr->protocol, serhash)) == NULL)
		{
			snprintf(service_name, sizeof(service_name), "%d -> %d",
				connline_ptr->src_port, connline_ptr->dst_port);

			size = strlen(service_name) + 1;

			if(!(conndata_ptr->sername = malloc(size)))
			{
				(void)vrprint.error(-1, "Error", "malloc() failed: %s "
						"(in: %s:%d).", strerror(errno),
						__FUNC__, __LINE__);
				return(-1);
			}

			if(strlcpy(conndata_ptr->sername, service_name, size) >= size)
			{
				(void)vrprint.error(-1, "Internal Error",
					"string overflow (in: %s:%d).",
					__FUNC__, __LINE__);
				return(-1);
			}
		}
	}

	if(conndata_ptr->service != NULL)
	{
		conndata_ptr->sername = conndata_ptr->service->name;
	}

	/* for hashing and display */

	/* if the dst port and alt_dst_port don't match, it is
		a portfw rule with the remoteport option set. */
	if(connline_ptr->dst_port == connline_ptr->alt_src_port)
		conndata_ptr->dst_port = connline_ptr->dst_port;
	else
		conndata_ptr->dst_port = connline_ptr->alt_src_port;

	conndata_ptr->protocol = connline_ptr->protocol;
	conndata_ptr->src_port = connline_ptr->src_port;

	/* src ip */
	if(strlcpy(conndata_ptr->src_ip, connline_ptr->src_ip,
			sizeof(conndata_ptr->src_ip)) >= sizeof(conndata_ptr->src_ip))
	{
		(void)vrprint.error(-1, "Internal Error", "string overflow "
			"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* then the from name */
	conndata_ptr->from = search_zone_in_hash_with_ipv4(debuglvl,
				connline_ptr->src_ip, zonehash);
	if(conndata_ptr->from == NULL)
	{
		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "unknown ip: '%s'.",
					connline_ptr->src_ip);

		if(req->unknown_ip_as_net == FALSE)
		{
			snprintf(zone_name, sizeof(zone_name), "%s",
							connline_ptr->src_ip);

			size = strlen(zone_name) + 1;

			if(!(conndata_ptr->fromname = malloc(size)))
			{
				(void)vrprint.error(-1, "Error", "malloc() "
					"failed: %s (in: %s:%d).",
					strerror(errno), __FUNC__, __LINE__);
				return(-1);
			}
			else
			{
				if(strlcpy(conndata_ptr->fromname, zone_name, size) >= size)
				{
					(void)vrprint.error(-1, "Internal Error",
						"string overflow (in: %s:%d).",
						__FUNC__, __LINE__);
					return(-1);
				}
			}
		}
		else
		{
 			if(!(zone_name_ptr = get_network_for_ipv4(debuglvl, connline_ptr->src_ip, zonelist)))
			{
				size = strlen(connline_ptr->src_ip) + 1;

				if(!(conndata_ptr->fromname = malloc(size)))
				{
					(void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: conntrack_line_to_data).", strerror(errno));
					return(-1);
				}
				else
				{
					if(strlcpy(conndata_ptr->fromname, connline_ptr->src_ip, size) >= size)
					{
						(void)vrprint.error(-1, "Internal Error",
							"string overflow (in: %s:%d).",
							__FUNC__, __LINE__);
						return(-1);
					}
				}
			}
			else
			{
				size = strlen(zone_name_ptr) + 1;

				if(!(conndata_ptr->fromname = malloc(size)))
				{
					(void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: conntrack_line_to_data).", strerror(errno));
					return(-1);
				}
				else
				{
					if(strlcpy(conndata_ptr->fromname, zone_name_ptr, size) >= size)
					{
						(void)vrprint.error(-1, "Internal Error",
							"string overflow (in: %s:%d).",
							__FUNC__, __LINE__);
						free(zone_name_ptr);
						return(-1);
					}
				}

				free(zone_name_ptr);
			}
		}
	}
	else
	{
		conndata_ptr->fromname = conndata_ptr->from->name;
	}

	/* dst ip */
	if(strlcpy(conndata_ptr->dst_ip, connline_ptr->dst_ip, sizeof(conndata_ptr->dst_ip)) >= sizeof(conndata_ptr->dst_ip))
	{
		(void)vrprint.error(-1, "Internal Error", "string overflow "
			"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}
	/* then the to name */
	conndata_ptr->to = search_zone_in_hash_with_ipv4(debuglvl, connline_ptr->dst_ip, zonehash);
	if(conndata_ptr->to == NULL)
	{
		if(req->unknown_ip_as_net == FALSE)
		{
			snprintf(zone_name, sizeof(zone_name), "%s", connline_ptr->dst_ip);

			size = strlen(zone_name) + 1;

			if(!(conndata_ptr->toname = malloc(size)))
			{
				(void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: conntrack_line_to_data).", strerror(errno));
				return(-1);
			}
			else
			{
				if(strlcpy(conndata_ptr->toname, zone_name, size) >= size)
				{
					(void)vrprint.error(-1, "Internal Error",
						"string overflow (in: %s:%d).",
						__FUNC__, __LINE__);
					return(-1);
				}
			}
		}
		else
		{
			if(!(zone_name_ptr = get_network_for_ipv4(debuglvl, connline_ptr->dst_ip, zonelist)))
			{
				size = strlen(connline_ptr->dst_ip) + 1;

				if(!(conndata_ptr->toname = malloc(size)))
				{
					(void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: conntrack_line_to_data).", strerror(errno));
					return(-1);
				}
				else
				{
					if(strlcpy(conndata_ptr->toname, connline_ptr->dst_ip, size) >= size)
					{
						(void)vrprint.error(-1, "Internal Error",
							"string overflow (in: %s:%d).",
							__FUNC__, __LINE__);
						return(-1);
					}
				}
			}
			else
			{
				size = strlen(zone_name_ptr) + 1;

				if(!(conndata_ptr->toname = malloc(size)))
				{
					(void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: conntrack_line_to_data).", strerror(errno));
					return(-1);
				}
				else
				{
					if(strlcpy(conndata_ptr->toname, zone_name_ptr, size) >= size)
					{
						(void)vrprint.error(-1, "Internal Error",
							"string overflow (in: %s:%d).",
							__FUNC__, __LINE__);
						return(-1);
					}
				}

				free(zone_name_ptr);
			}
		}
	}
	else
	{
		conndata_ptr->toname = conndata_ptr->to->name;
	}

	if(connline_ptr->state == SYN_SENT || connline_ptr->state == SYN_RECV || connline_ptr->state == UNREPLIED)
		conndata_ptr->connect_status = CONN_CONNECTING;
	else if(connline_ptr->state == TCP_ESTABLISHED || connline_ptr->state == UDP_ESTABLISHED)
		conndata_ptr->connect_status = CONN_CONNECTED;
	else if(connline_ptr->state == FIN_WAIT || connline_ptr->state == TIME_WAIT || connline_ptr->state == CLOSE || connline_ptr->state == CLOSE_WAIT)
		conndata_ptr->connect_status = CONN_DISCONNECTING;
	else
		conndata_ptr->connect_status = CONN_UNUSED;

	if(conndata_ptr->from != NULL && conndata_ptr->from->type == TYPE_FIREWALL)
		conndata_ptr->direction_status = CONN_OUT;
	else if(conndata_ptr->to != NULL && conndata_ptr->to->type == TYPE_FIREWALL)
		conndata_ptr->direction_status = CONN_IN;
	else
		conndata_ptr->direction_status = CONN_FW;

	/* transfer the acc data */
	conndata_ptr->use_acc = connline_ptr->use_acc;
	conndata_ptr->to_src_packets = connline_ptr->to_src_packets;
	conndata_ptr->to_src_bytes = connline_ptr->to_src_bytes;
	conndata_ptr->to_dst_packets = connline_ptr->to_dst_packets;
	conndata_ptr->to_dst_bytes = connline_ptr->to_dst_bytes;

	return(0);
}


/* tcp      6 431999 ESTABLISHED src=192.168.1.2 dst=192.168.1.16 sport=51359 dport=22 packets=80969 bytes=7950474 src=192.168.1.16 dst=192.168.1.2 sport=22 dport=51359 packets=117783 bytes=123061993 [ASSURED] mark=0 use=1*/
static void
parse_tcp_line(const int debuglvl, const char *line,
		struct ConntrackLine *connline_ptr)
{
	int	result = 0;
	char	source_port[16] = "",
		dest_port[16] = "",
		alt_source_port[16] = "",
		alt_dest_port[16] = "",
		tmp[16] = "";

	if(connline_ptr->use_acc == TRUE)
	{
		result = sscanf(line,	"%16s %d %d %s src=%s dst=%s "
					"sport=%s dport=%s packets=%s "
					"bytes=%s src=%s dst=%s "
					"sport=%s dport=%s packets=%s "
					"bytes=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->status,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port,
				connline_ptr->to_dst_packets_str,
				connline_ptr->to_dst_bytes_str,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				alt_source_port,
				alt_dest_port,
				connline_ptr->to_src_packets_str,
				connline_ptr->to_src_bytes_str);
		if(result != 16)
		{
			/* unreplied */
			result = sscanf(line,	"%16s %d %d %s src=%s dst=%s "
						"sport=%s dport=%s packets=%s "
						"bytes=%s %s src=%s dst=%s "
						"sport=%s dport=%s packets=%s "
						"bytes=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->status,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port,
				tmp,
				connline_ptr->to_dst_packets_str,
				connline_ptr->to_dst_bytes_str,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				alt_source_port,
				alt_dest_port,
				connline_ptr->to_src_packets_str,
				connline_ptr->to_src_bytes_str);
			if(result != 17)
			{
				(void)vrprint.debug(__FUNC__, "parse error: '%s'", line);
			}
		}

		if(debuglvl >= LOW)
			(void)vrprint.debug(__FUNC__, "to dst: %sP %sB to src: %sP %sB",
					connline_ptr->to_dst_packets_str,
					connline_ptr->to_dst_bytes_str,
					connline_ptr->to_src_packets_str,
					connline_ptr->to_src_bytes_str);
	}
	else
	{
		result = sscanf(line,	"%16s %d %d %s src=%s dst=%s "
					"sport=%s dport=%s src=%s "
					"dst=%s sport=%s dport=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->status,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				alt_source_port,
				alt_dest_port);
		if(result != 12)
		{
			result = sscanf(line,	"%16s %d %d %s src=%s dst=%s "
						"sport=%s dport=%s %s src=%s "
						"dst=%s sport=%s dport=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->status,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port,
				tmp,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				alt_source_port,
				alt_dest_port);
			if(result != 13)
			{
				(void)vrprint.debug(__FUNC__, "parse error: '%s'", line);
			}
		}
	}

	connline_ptr->src_port = atoi(source_port);
	if(connline_ptr->src_port <= 0 || connline_ptr->src_port > 65535)
		connline_ptr->src_port = 0;

	connline_ptr->dst_port = atoi(dest_port);
	if(connline_ptr->dst_port <= 0 || connline_ptr->dst_port > 65535)
		connline_ptr->dst_port = 0;

	connline_ptr->alt_src_port = atoi(alt_source_port);
	if(connline_ptr->alt_src_port <= 0 || connline_ptr->alt_src_port > 65535)
		connline_ptr->alt_src_port = 0;

	connline_ptr->alt_dst_port = atoi(alt_dest_port);
	if(connline_ptr->alt_dst_port <= 0 || connline_ptr->alt_dst_port > 65535)
		connline_ptr->alt_dst_port = 0;
}


/* udp      17 23 src=192.168.1.2 dst=192.168.1.1 sport=38009 dport=53 packets=20 bytes=1329 src=192.168.1.1 dst=192.168.1.2 sport=53 dport=38009 packets=20 bytes=3987 [ASSURED] mark=0 use=1 */
/* udp      17 12 src=192.168.1.2 dst=192.168.1.255 sport=137 dport=137 [UNREPLIED] src=192.168.1.255 dst=192.168.1.2 sport=137 dport=137 use=1*/
static void
parse_udp_line(const int debuglvl, const char *line,
		struct ConntrackLine *connline_ptr)
{
	int	result = 0;
	char	source_port[16] = "",
		dest_port[16] = "",
		alt_source_port[16] = "",
		alt_dest_port[16] = "",
		tmp[16] = "";

	if(connline_ptr->use_acc == TRUE)
	{
		result = sscanf(line,	"%16s %d %d src=%s dst=%s "
					"sport=%s dport=%s packets=%s "
					"bytes=%s src=%s dst=%s "
					"sport=%s dport=%s packets=%s "
					"bytes=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port,
				connline_ptr->to_dst_packets_str,
				connline_ptr->to_dst_bytes_str,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				alt_source_port,
				alt_dest_port,
				connline_ptr->to_src_packets_str,
				connline_ptr->to_src_bytes_str);
		if(result != 15)
		{
			result = sscanf(line,	"%16s %d %d src=%s dst=%s "
						"sport=%s dport=%s packets=%s "
						"bytes=%s %s src=%s dst=%s "
						"sport=%s dport=%s packets=%s "
						"bytes=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port,
				connline_ptr->to_dst_packets_str,
				connline_ptr->to_dst_bytes_str,
				connline_ptr->status,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				alt_source_port,
				alt_dest_port,
				connline_ptr->to_src_packets_str,
				connline_ptr->to_src_bytes_str);
			if(result != 16)
			{
				(void)vrprint.debug(__FUNC__, "parse error: '%s'", line);
			}
		}
		else
		{
			strcpy(connline_ptr->status, "UDP_ESTABLISHED");
		}

		if(debuglvl >= LOW)
			(void)vrprint.debug(__FUNC__, "to dst: %sP %sB to src: %sP %sB",
					connline_ptr->to_dst_packets_str,
					connline_ptr->to_dst_bytes_str,
					connline_ptr->to_src_packets_str,
					connline_ptr->to_src_bytes_str);
	}
	else
	{
		result = sscanf(line,	"%16s %d %d src=%s dst=%s "
					"sport=%s dport=%s src=%s "
					"dst=%s sport=%s dport=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port, 
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				alt_source_port,
				alt_dest_port);
		if(result != 11)
		{
			result = sscanf(line,	"%16s %d %d src=%s dst=%s "
						"sport=%s dport=%s %s "
						"src=%s dst=%s "
						"sport=%s dport=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port,
				connline_ptr->status,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				alt_source_port,
				alt_dest_port);
			if(result != 12)
			{
				(void)vrprint.debug(__FUNC__, "parse error: '%s'", line);
			}
		}
		else
		{
			strcpy(connline_ptr->status, "UDP_ESTABLISHED");
		}
	}

	connline_ptr->src_port = atoi(source_port);
	if(connline_ptr->src_port <= 0 || connline_ptr->src_port > 65535)
		connline_ptr->src_port = 0;

	connline_ptr->dst_port = atoi(dest_port);
	if(connline_ptr->dst_port <= 0 || connline_ptr->dst_port > 65535)
		connline_ptr->dst_port = 0;

	connline_ptr->alt_src_port = atoi(alt_source_port);
	if(connline_ptr->alt_src_port <= 0 || connline_ptr->alt_src_port > 65535)
		connline_ptr->alt_src_port = 0;

	connline_ptr->alt_dst_port = atoi(alt_dest_port);
	if(connline_ptr->alt_dst_port <= 0 || connline_ptr->alt_dst_port > 65535)
		connline_ptr->alt_dst_port = 0;
}


//icmp     1 29 src=192.168.0.2 dst=194.109.6.11 type=8 code=0 id=57376 [UNREPLIED] src=194.109.6.11 dst=192.168.0.2 type=0 code=0 id=57376 use=1
//icmp     1 30 src=192.168.1.2 dst=192.168.1.64 type=8 code=0 id=64811 packets=1 bytes=84 [UNREPLIED] src=192.168.1.64 dst=192.168.1.2 type=0 code=0 id=64811 packets=0 bytes=0 mark=0 use=1
static void
parse_icmp_line(const int debuglvl, const char *line,
		struct ConntrackLine *connline_ptr)
{
	int	result = 0;
	char	source_port[16] = "",
		dest_port[16] = "",
		tmp[16] = "";

	if(connline_ptr->use_acc == TRUE)
	{
		result = sscanf(line,	"%16s %d %d src=%s dst=%s "
					"type=%s code=%s id=%s "
					"packets=%s bytes=%s %s src=%s "
					"dst=%s type=%s code=%s id=%s "
					"packets=%s bytes=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port,
				tmp,
				connline_ptr->to_dst_packets_str,
				connline_ptr->to_dst_bytes_str,
				connline_ptr->status,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				tmp,
				tmp,
				tmp,
				connline_ptr->to_src_packets_str,
				connline_ptr->to_src_bytes_str);
		if(result != 18)
		{
			(void)vrprint.debug(__FUNC__, "parse error: '%s'", line);
		}

		(void)vrprint.debug(__FUNC__, "to dst: %sP %sB to src: %sP %sB",
				connline_ptr->to_dst_packets_str,
				connline_ptr->to_dst_bytes_str,
				connline_ptr->to_src_packets_str,
				connline_ptr->to_src_bytes_str);
	}
	else
	{
		result = sscanf(line,	"%16s %d %d src=%s dst=%s "
					"type=%s code=%s id=%s %s "
					"src=%s dst=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				source_port,
				dest_port,
				tmp,
				connline_ptr->status,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip);
		if(result != 11)
		{
			(void)vrprint.debug(__FUNC__, "parse error: '%s'", line);
		}
	}

	connline_ptr->src_port = atoi(source_port);
	if(connline_ptr->src_port <= 0 || connline_ptr->src_port > 65535)
		connline_ptr->src_port = 0;

	connline_ptr->dst_port = atoi(dest_port);
	if(connline_ptr->dst_port <= 0 || connline_ptr->dst_port > 65535)
		connline_ptr->dst_port = 0;
}


/*
	unknown  41 585 src=<ip> dst=<ip> src=<ip> dst=<ip> use=1
	unknown  47 599 src=<ip> dst=<ip> src=<ip> dst=<ip> use=1
*/
static void
parse_unknown_line(const int debuglvl, const char *line,
		struct ConntrackLine *connline_ptr)
{
	int	result = 0;
	char	tmp[16] = "";

	if(connline_ptr->use_acc == TRUE)
	{
		result = sscanf(line,	"%16s %d %d src=%s dst=%s "
					"packets=%s bytes=%s src=%s "
					"dst=%s packets=%s bytes=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				connline_ptr->to_dst_packets_str,
				connline_ptr->to_dst_bytes_str,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip,
				connline_ptr->to_src_packets_str,
				connline_ptr->to_src_bytes_str);
		if(result != 11)
		{
			(void)vrprint.debug(__FUNC__, "parse error: '%s'", line);
		}

		if(debuglvl >= LOW)
			(void)vrprint.debug(__FUNC__, "to dst: %sP %sB to src: %sP %sB",
					connline_ptr->to_dst_packets_str,
					connline_ptr->to_dst_bytes_str,
					connline_ptr->to_src_packets_str,
					connline_ptr->to_src_bytes_str);
	}
	else
	{
		result = sscanf(line,	"%16s %d %d src=%s dst=%s "
					"src=%s dst=%s",
				tmp,
				&connline_ptr->protocol,
				&connline_ptr->ttl,
				connline_ptr->src_ip,
				connline_ptr->dst_ip,
				connline_ptr->alt_src_ip,
				connline_ptr->alt_dst_ip);
		if(result != 7)
		{
			(void)vrprint.debug(__FUNC__, "parse error: '%s'", line);
		}
	}

	strcpy(connline_ptr->status, "none");
	connline_ptr->src_port = 0;
	connline_ptr->dst_port = 0;
}


/*	process one line from the conntrack file */
int
conn_process_one_conntrack_line(const int debuglvl, const char *line,
					struct ConntrackLine *connline_ptr)
{
	char	protocol[16] = "";

	/* check if we need to read packets as well */
	if(strstr(line,"packets"))
		connline_ptr->use_acc = TRUE;
	else
		connline_ptr->use_acc = FALSE;

	/* first determine protocol */
	sscanf(line, "%s", protocol);

	if(strcmp(protocol, "tcp") == 0)
	{
		parse_tcp_line(debuglvl, line, connline_ptr);
	}
	else if(strcmp(protocol, "udp") == 0)
	{
		parse_udp_line(debuglvl, line, connline_ptr);
	}
	else if(strcmp(protocol, "icmp") == 0)
	{
		parse_icmp_line(debuglvl, line, connline_ptr);
	}
	else if(strcmp(protocol, "unknown") == 0)
	{
		parse_unknown_line(debuglvl, line, connline_ptr);
	}
	else
	{
		strcpy(connline_ptr->status, "none");
		connline_ptr->protocol = 0;
		strcpy(connline_ptr->src_ip, "PARSE-ERROR");
		strcpy(connline_ptr->dst_ip, "PARSE-ERROR");
		connline_ptr->src_port = 0;
		connline_ptr->dst_port = 0;
	}

	/* now, for snat and dnat some magic is required */
	if(	strcmp(connline_ptr->src_ip,connline_ptr->alt_dst_ip) == 0 &&
		strcmp(connline_ptr->dst_ip,connline_ptr->alt_src_ip) == 0)
	{
		/* normal line */
	}
	else if(strcmp(connline_ptr->src_ip,connline_ptr->alt_dst_ip) == 0)
	{
		/* DNAT, we use alt_source_ip as dest */
		if(strlcpy(connline_ptr->dst_ip, connline_ptr->alt_src_ip,
				sizeof(connline_ptr->dst_ip)) >= sizeof(connline_ptr->dst_ip))
		{
			(void)vrprint.error(-1, "Internal Error",
				"string overflow (in: %s:%d).",
				__FUNC__, __LINE__);
			return(-1);
		}
	}
	else if(strcmp(connline_ptr->src_ip,connline_ptr->alt_src_ip) != 0 &&
		strcmp(connline_ptr->dst_ip,connline_ptr->alt_dst_ip) != 0)
	{
		/* DNAT, we use alt_source_ip as dest */
		if(strlcpy(connline_ptr->dst_ip, connline_ptr->alt_src_ip,
				sizeof(connline_ptr->dst_ip)) >= sizeof(connline_ptr->dst_ip))
		{
			(void)vrprint.error(-1, "Internal Error",
				"string overflow (in: %s:%d).",
				__FUNC__, __LINE__);
			return(-1);
		}
	}
	/*
		portfw rule

		tcp      6 431950 ESTABLISHED
			src=192.168.166.2 dst=192.168.166.10
				sport=1241 dport=80 packets=3 bytes=128
			src=192.168.166.9 dst=192.168.166.10
				sport=22 dport=1241 packets=2 bytes=123
					[ASSURED] mark=0 use=1
					
		firewall	192.168.166.10
		target		192.168.166.9
		source		192.168.166.2

		We see that dst = alt_dst and src != alt_src.
	*/
	else if(strcmp(connline_ptr->src_ip,connline_ptr->alt_src_ip) != 0 &&
		strcmp(connline_ptr->dst_ip,connline_ptr->alt_dst_ip) == 0)
	{
		/* DNAT, we use alt_source_ip as dest */
		if(strlcpy(connline_ptr->dst_ip, connline_ptr->alt_src_ip,
				sizeof(connline_ptr->dst_ip)) >= sizeof(connline_ptr->dst_ip))
		{
			(void)vrprint.error(-1, "Internal Error",
				"string overflow (in: %s:%d).",
				__FUNC__, __LINE__);
			return(-1);
		}
	}

	/* process status */
	if(strcmp(connline_ptr->status, "none") == 0)
		connline_ptr->state = NONE;
	else if(strcmp(connline_ptr->status, "ESTABLISHED") == 0)
		connline_ptr->state = TCP_ESTABLISHED;
	else if(strcmp(connline_ptr->status, "UDP_ESTABLISHED") == 0)
		connline_ptr->state = UDP_ESTABLISHED;
	else if(strcmp(connline_ptr->status, "SYN_SENT") == 0)
		connline_ptr->state = SYN_SENT;
	else if(strcmp(connline_ptr->status, "SYN_RECV") == 0)
		connline_ptr->state = SYN_RECV;
	else if(strcmp(connline_ptr->status, "FIN_WAIT") == 0)
		connline_ptr->state = FIN_WAIT;
	else if(strcmp(connline_ptr->status, "TIME_WAIT") == 0)
		connline_ptr->state = TIME_WAIT;
	else if(strcmp(connline_ptr->status, "CLOSE") == 0)
		connline_ptr->state = CLOSE;
	else if(strcmp(connline_ptr->status, "CLOSE_WAIT") == 0)
		connline_ptr->state = CLOSE_WAIT;
	else if(strcmp(connline_ptr->status, "[UNREPLIED]") == 0)
		connline_ptr->state = UNREPLIED;
	else
		connline_ptr->state = UNDEFINED;

	if(connline_ptr->use_acc == TRUE)
	{
		connline_ptr->to_src_packets = strtoull(connline_ptr->to_src_packets_str, NULL, 10);
		connline_ptr->to_src_bytes = strtoull(connline_ptr->to_src_bytes_str, NULL, 10);
		connline_ptr->to_dst_packets = strtoull(connline_ptr->to_dst_packets_str, NULL, 10);
		connline_ptr->to_dst_bytes = strtoull(connline_ptr->to_dst_bytes_str, NULL, 10);
	}

	return(0);
}


/*	conn_hash_name

	Very simple string hashing function. It just adds up
	all chars.
*/
unsigned int
conn_hash_name(const void *key)
{
	size_t		len = 0;
	unsigned int	hash = 0;
	char		*name = NULL;

	if(!key)
		return(1);

	name = (char *)key;

	len = strlen(name);
	while(len)
	{
		hash = hash + name[len];
		len--;
	}

	return(hash);
}


//TODO silly names
int
conn_match_name(const void *ser1, const void *ser2)
{
	if(!ser1 || !ser2)
		return(0);

	if(strcmp((char *)ser1, (char *)ser2) == 0)
		return 1;
	else
		return 0;
}

//- print_list -
void
conn_list_print(const d_list *conn_list)
{
	d_list_node		*d_node = NULL;
	struct ConntrackData	*item_ptr = NULL;

	// Display the linked list.
	fprintf(stdout, "List len is %u\n", conn_list->len);

	for(d_node = conn_list->top; d_node ; d_node = d_node->next)
	{
		item_ptr = d_node->data;

		fprintf(stdout, "sername: %s, fromname: %s, toname: %s\n", item_ptr->sername, item_ptr->fromname, item_ptr->toname);
	}

	return;
}


unsigned int
conn_hash_string(const void *key)
{
	const char	*ptr = NULL;
	unsigned int	val = 0;
	unsigned int	tmp = 0;

	ptr = key;

	while(*ptr != '\0')
	{

		val = (val << 4) + (*ptr);

		if((tmp = (val & 0xf0000000)))
		{
			val = val ^ (tmp >> 24);
			val = val ^ tmp;
		}
		ptr++;
	}

	return(val);
}


/*	hash_conntrackdata

	Hashes conntrackdata. It does this by creating seperate
	hashes for sername, fromname and toname.

	Returns the hash.
*/
unsigned int
conn_hash_conntrackdata(const void *key)
{
	unsigned int		retval = 0;
	struct ConntrackData	*cd_ptr = NULL;

	if(!key)
		return(1);

	cd_ptr = (struct ConntrackData *)key;

	/*	from and to have different weight, so firewall -> internet
		is not the same as internet -> firewall
	*/
	retval = retval + conn_hash_name(cd_ptr->sername);
	retval = retval + conn_hash_name(cd_ptr->fromname) / 2;
	retval = retval + conn_hash_name(cd_ptr->toname) / 3;

	return(retval);
}


/*	match_conntrackdata

*/
int
conn_match_conntrackdata(const void *check, const void *hash)
{
	struct ConntrackData	*check_cd = NULL,
				*hash_cd = NULL;

	/* safety */
	if(!check || !hash)
		return(0);

	check_cd = (struct ConntrackData *)check;
	hash_cd  = (struct ConntrackData *)hash;
	if(!check_cd || !hash_cd)
	{
		(void)vrprint.error(0, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
		return(0);
	}

	if(strncmp(check_cd->sername, hash_cd->sername, MAX_SERVICE) == 0)
	{
		// service matches
		if(strncmp(check_cd->fromname, hash_cd->fromname, MAX_HOST_NET_ZONE) == 0)
		{
			// from host also matches
			if(strncmp(check_cd->toname, hash_cd->toname, MAX_HOST_NET_ZONE) == 0)
			{
				if(check_cd->connect_status == hash_cd->connect_status)
				{
					// they all match-> return 1
					return(1);
				}
			}
		}
	}

	// sorry, no match
	return(0);
}


/*	conn_dlist_destroy

	Destroys the list.
*/
void
conn_list_cleanup(int debuglvl, d_list *conn_dlist)
{
	d_list_node		*d_node = NULL;
	struct ConntrackData	*cd_ptr = NULL;

	for(d_node = conn_dlist->top; d_node; d_node = d_node->next)
	{
		cd_ptr = d_node->data;

		if(cd_ptr->from == NULL)
			free(cd_ptr->fromname);
		if(cd_ptr->to == NULL)
			free(cd_ptr->toname);
		if(cd_ptr->service == NULL)
			free(cd_ptr->sername);

		free(cd_ptr);
	}

	d_list_cleanup(debuglvl, conn_dlist);
}


/*	conn_get_connections

	Assembles all conntrack connections in one list, and counts all items.

	prev_conn_cnt is used to determine the size of the hashtable which is
	used. It is based on the size of the list of the last time we ran this
	function. If it is zero, we use a default.

	TODO:	intergrate with get stats
		group results on:	network when unknown host - done
					fw, in, out
					connected, connecting, disconnecting

		make sorting better by check if current cd is bigger than
		the top 3

	Do this by the way we create a hash, so set the options into the
	cd struct
*/
int
conn_get_connections(	const int debuglvl,
			const unsigned int prev_conn_cnt,
			Hash *serv_hash,
			Hash *zone_hash,
			d_list *conn_dlist,
			d_list *zone_list,
			VR_ConntrackRequest *req,
			struct ConntrackStats_ *connstat_ptr
		)
{
	int			retval = 0;

	char			line[256] = "";
	FILE			*fp = NULL;
	struct ConntrackLine	cl;
	struct ConntrackData	*cd_ptr = NULL,
				*old_cd_ptr = NULL,
				*prev_cd_ptr = NULL,
				*next_cd_ptr = NULL;

	/* default hashtable size */
	unsigned int		hashtbl_size = 256;
	Hash			conn_hash;
	d_list_node		*d_node = NULL;


	/* safety */
	if(!serv_hash || !zone_hash || prev_conn_cnt < 0)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
					"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* if the prev_conn_cnt supplied by the user is bigger than 0,
	   use it. */
	if(prev_conn_cnt > 0)
		hashtbl_size = prev_conn_cnt;

	/* initialize the hash */
	if(hash_setup(debuglvl, &conn_hash, hashtbl_size,
			conn_hash_conntrackdata, conn_match_conntrackdata) != 0)
	{
		(void)vrprint.error(-1, "Internal Error", "hash_setup() failed "
					"(in: %s:%d).", __FUNC__, __LINE__);
		return(-1);
	}

	/* open conntrack file (fopen) */
	if(!(fp = fopen(PROC_IPCONNTRACK, "r")))
	{
		(void)vrprint.error(-1, "Error", "unable to open %s: %s "
					"(in: %s:%d).", PROC_IPCONNTRACK,
					strerror(errno), __FUNC__, __LINE__);
		return(-1);
	}

	/* set stat counters to zero */
	connstat_ptr->conn_total = 0,
	connstat_ptr->conn_in = 0,
	connstat_ptr->conn_out = 0,
	connstat_ptr->conn_fw = 0;

	connstat_ptr->stat_connect = 0,
	connstat_ptr->stat_estab = 0,
	connstat_ptr->stat_closing = 0,
	connstat_ptr->stat_other = 0;


	/*	now read the file, interpret the line and trough hash_look up
		if the line is already in the list

		if it is do 2 things:
			1. increment the counter
			2. check if the count is bigger than the line
			   above (in the list)
				if so, move line up one

		else insert the line into the list, and hash

		The result will be reasonably good sorted list, at almost
		no speed penalty.
	*/
	while((fgets(line, (int)sizeof(line), fp) != NULL))
	{
		/* start with a clean slate */
		memset(&cl, 0, sizeof(cl));

		/* parse the line */
		if(conn_process_one_conntrack_line(debuglvl, line, &cl) < 0)
		{
			(void)vrprint.error(-1, "Internal Error",
						"conn_process_one_conntrack_line() failed "
						"(in: %s:%d).", __FUNC__, __LINE__);
			return(-1);
		}

		/* allocate memory for the data */
		if(!(cd_ptr = (struct ConntrackData *)malloc(sizeof(struct ConntrackData))))
		{
			(void)vrprint.error(-1, "Error", "malloc() failed: %s "
						"(in: %s:%d).", strerror(errno),
						__FUNC__, __LINE__);
			return(-1);
		}
		/* init to 0 */
		memset(cd_ptr, 0, sizeof(struct ConntrackData));

		/* analyse it */
		if(conn_line_to_data(debuglvl, &cl, cd_ptr, serv_hash,
				zone_hash, zone_list, req) < 0)
		{
			(void)vrprint.error(-1, "Error", "conn_line_to_data() "
						"failed: (in: %s:%d).",
						__FUNC__, __LINE__);
			free(cd_ptr);
			return(-1);
		}

		/*	if the hashlookup is succesfull, cd_ptr is overwritten,
			so we store it here */
		old_cd_ptr = cd_ptr;

		/*
			we ignore the local loopback connections
			and connections that are filtered
		 */
		if((	strncmp(cd_ptr->fromname, "127.", 4) == 0 ||
			strncmp(cd_ptr->toname,   "127.", 4) == 0 ||
			(req->use_filter == TRUE &&
			filtered_connection(debuglvl, cd_ptr, &req->filter) == 1)))
		{
			if(cd_ptr->from == NULL)
				free(cd_ptr->fromname);
			if(cd_ptr->to == NULL)
				free(cd_ptr->toname);
			if(cd_ptr->service == NULL)
				free(cd_ptr->sername);

			free(cd_ptr);
			cd_ptr = NULL;
			old_cd_ptr = NULL;
		}
		else
		{
			/* update counters */
			connstat_ptr->conn_total++;

			if(cd_ptr->from != NULL && cd_ptr->from->type == TYPE_FIREWALL)
				connstat_ptr->conn_out++;
			else if(cd_ptr->to != NULL && cd_ptr->to->type == TYPE_FIREWALL)
				connstat_ptr->conn_in++;
			else
				connstat_ptr->conn_fw++;

			if(cd_ptr->connect_status == CONN_CONNECTING)
				connstat_ptr->stat_connect++;
			else if(cd_ptr->connect_status == CONN_DISCONNECTING)
				connstat_ptr->stat_closing++;
			else if(cd_ptr->connect_status == CONN_CONNECTED)
				connstat_ptr->stat_estab++;
			else
				connstat_ptr->stat_other++;

			/* now check if the cd is already in the list */
			if(req->group_conns == TRUE &&
				(cd_ptr = hash_search(debuglvl, &conn_hash, (void *)cd_ptr)) != NULL)
			{
				/*	FOUND in the hash

					transfer the acc data */
				cd_ptr->to_src_packets = cd_ptr->to_src_packets + old_cd_ptr->to_src_packets;
				cd_ptr->to_src_bytes = cd_ptr->to_src_bytes + old_cd_ptr->to_src_bytes;
				cd_ptr->to_dst_packets = cd_ptr->to_dst_packets + old_cd_ptr->to_dst_packets;
				cd_ptr->to_dst_bytes = cd_ptr->to_dst_bytes + old_cd_ptr->to_dst_bytes;

				/*	free the memory in the old_cd_ptr,
					we dont need it no more */
				if(old_cd_ptr->from == NULL)
					free(old_cd_ptr->fromname);
				if(old_cd_ptr->to == NULL)
					free(old_cd_ptr->toname);
				if(old_cd_ptr->service == NULL)
					free(old_cd_ptr->sername);

				free(old_cd_ptr);
				old_cd_ptr = NULL;

				/* now increment the counter */
				cd_ptr->cnt++;

				/* check if the above cd in the list is smaller than we are */
				if((d_node = cd_ptr->d_node->prev))
				{
					prev_cd_ptr = d_node->data;

					if(cd_ptr->cnt > prev_cd_ptr->cnt)
					{
						/* yes, so now we move one up */
						if(d_list_remove_node(debuglvl, conn_dlist, cd_ptr->d_node) < 0)
						{
							(void)vrprint.error(-1, "Internal Error", "removing from list failed (in: conn_get_connections).");
							return(-1);
						}

						/* now reinsert */
						if(!(cd_ptr->d_node = d_list_insert_before(debuglvl, conn_dlist, d_node, cd_ptr)))
						{
							(void)vrprint.error(-1, "Internal Error", "unable to insert into list (in: conn_get_connections).");
							return(-1);
						}
					}
					/*	check if the beneath cd in the list is bigger than we are,
						 we only do this if the above wasn't smaller
					*/
					else if((d_node = cd_ptr->d_node->next))
					{
						next_cd_ptr = d_node->data;

						if(cd_ptr->cnt < next_cd_ptr->cnt)
						{
							/* yes, so now we move one down */
							if(d_list_remove_node(debuglvl, conn_dlist, cd_ptr->d_node) < 0)
							{
								(void)vrprint.error(-1, "Internal Error", "removing from list failed (in: conn_get_connections).");
								return(-1);
							}

							/* now reinsert */
							if(!(cd_ptr->d_node = d_list_insert_after(debuglvl, conn_dlist, d_node, cd_ptr)))
							{
								(void)vrprint.error(-1, "Internal Error", "unable to insert into list (in: conn_get_connections).");
								return(-1);
							}
						}
					}
				}

				/*
					now we do one last check
				*/

				/* check if the one above us is 1, if so, move to bottom of the list */
				if((d_node = cd_ptr->d_node->prev))
				{
					prev_cd_ptr = d_node->data;

					/*	is the one beneath us is 1 and not the bottom of the list,
						move it to the bottom of the list */
					if(prev_cd_ptr->cnt == 1 && d_node->prev != NULL)
					{
						/* yes, so now we first remove */
						if(d_list_remove_node(debuglvl, conn_dlist, d_node) < 0)
						{
							(void)vrprint.error(-1, "Internal Error", "removing from list failed (in: conn_get_connections).");
							return(-1);
						}

						/* and then re-insert */
						if(!(prev_cd_ptr->d_node = d_list_append(debuglvl, conn_dlist, prev_cd_ptr)))
						{
							(void)vrprint.error(-1, "Internal Error", "unable to insert into list (in: conn_get_connections).");
							return(-1);
						}
					}
				}

				/* do the same for the one below us */
				if((d_node = cd_ptr->d_node->next))
				{
					next_cd_ptr = d_node->data;

					/* is the one beneath us is 1 and not the bottom of the list, 
					   move it to the bottom */
					if(next_cd_ptr->cnt == 1 && d_node->next != NULL)
					{
						/* yes, so now remove */
						if(d_list_remove_node(debuglvl, conn_dlist, d_node) < 0)
						{
							(void)vrprint.error(-1, "Internal Error", "removing from list failed (in: conn_get_connections).");
							return(-1);
						}

						/* now reinsert */
						if(!(next_cd_ptr->d_node = d_list_append(debuglvl, conn_dlist, next_cd_ptr)))
						{
							(void)vrprint.error(-1, "Internal Error", "unable to insert into list (in: conn_get_connections).");
							return(-1);
						}
					}
				}
			}
			else
			{
				/*	NOT found in the hash

					set cd_ptr to old_cd_ptr because cd_ptr is NULL after the failed hash search
				*/
				cd_ptr = old_cd_ptr;

				/* append the new cd to the list */
				cd_ptr->d_node = d_list_append(debuglvl, conn_dlist, cd_ptr);
				if(!cd_ptr->d_node)
				{
					(void)vrprint.error(-1, "Internal Error", "unable to append into list (in: conn_get_connections).");
					return(-1);
				}

				/* and insert it into the hash */
				if(hash_insert(debuglvl, &conn_hash, cd_ptr) != 0)
				{
					(void)vrprint.error(-1, "Internal Error", "unable to insert into hash (in: conn_get_connections).");
					return(-1);
				}

				/* set cnt to 1 */
				cd_ptr->cnt = 1;
			}
		}
	}

	/* close the file */
	if(fclose(fp) < 0)
		retval = -1;

	/* cleanup */
	hash_cleanup(debuglvl, &conn_hash);

	return(retval);
}

void
VR_connreq_setup(const int debuglvl, VR_ConntrackRequest *connreq)
{
	/* safety */
	if(connreq == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return;
	}

	VR_filter_setup(debuglvl, &connreq->filter);

	memset(connreq, 0, sizeof(VR_ConntrackRequest));
}


void
VR_connreq_cleanup(const int debuglvl, VR_ConntrackRequest *connreq)
{
	/* safety */
	if(connreq == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem "
				"(in: %s:%d).", __FUNC__, __LINE__);
		return;
	}

	VR_filter_cleanup(debuglvl, &connreq->filter);

	memset(connreq, 0, sizeof(VR_ConntrackRequest));
}

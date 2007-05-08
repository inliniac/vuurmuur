/***************************************************************************
 *   Copyright (C) 2005-2006 by Victor Julien                              *
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

#ifndef __BACKENDCHECK_H__
#define __BACKENDCHECK_H__

int backend_check_active(const int, char *, struct rgx_ *);
int backend_check_comment(const int, char *, struct rgx_ *);

int backend_check_host_ipaddress(const int, char *, struct rgx_ *);
int backend_check_host_macaddress(const int, char *, struct rgx_ *);

int backend_check_group_member(const int, char *, struct rgx_ *);

int backend_check_network_network(const int, char *, struct rgx_ *);
int backend_check_network_netmask(const int, char *, struct rgx_ *);
int backend_check_network_interface(const int, char *, struct rgx_ *);
int backend_check_network_rule(const int, char *, struct rgx_ *);

int backend_check_interface_ipaddress(const int, char *, struct rgx_ *);
int backend_check_interface_device(const int, char *, struct rgx_ *);
int backend_check_interface_virtual(const int, char *, struct rgx_ *);
int backend_check_interface_rule(const int, char *, struct rgx_ *);

int backend_check_service_broadcast(const int, char *, struct rgx_ *);
int backend_check_service_helper(const int, char *, struct rgx_ *);
int backend_check_service_tcp(const int, char *, struct rgx_ *);
int backend_check_service_udp(const int, char *, struct rgx_ *);
int backend_check_service_icmp(const int, char *, struct rgx_ *);
int backend_check_service_gre(const int, char *, struct rgx_ *);
int backend_check_service_esp(const int, char *, struct rgx_ *);
int backend_check_service_ah(const int, char *, struct rgx_ *) ;
int backend_check_service_proto41(const int, char *, struct rgx_ *);

int backend_check_rule_rule(const int, char *, struct rgx_ *);


struct backend_vars_
{
	int	type;
	char	var[32];
	char	multi;
	int	(*chk)(const int debuglvl, char *value, struct rgx_ *reg);
}
backend_vars[] =
{
	/* host specific */
	{TYPE_HOST,	"ACTIVE",	0, backend_check_active},
	{TYPE_HOST,	"IPADDRESS",	0, backend_check_host_ipaddress},
	{TYPE_HOST,	"MAC",		0, backend_check_host_macaddress},
	{TYPE_HOST,	"COMMENT",	0, backend_check_comment},

	/* group specific */
	{TYPE_GROUP,	"ACTIVE",	0, backend_check_active},
	{TYPE_GROUP,	"MEMBER",	1, backend_check_group_member},
	{TYPE_GROUP,	"COMMENT",	0, backend_check_comment},

	/* network specific */
	{TYPE_NETWORK,	"ACTIVE",	0, backend_check_active},
	{TYPE_NETWORK,	"NETWORK",	0, backend_check_network_network},
	{TYPE_NETWORK,	"NETMASK",	0, backend_check_network_netmask},
	{TYPE_NETWORK,	"INTERFACE",	1, backend_check_network_interface},
	{TYPE_NETWORK,	"RULE",		1, backend_check_network_rule},
	{TYPE_NETWORK,	"COMMENT",	0, backend_check_comment},

	/* zone specific */
	{TYPE_ZONE,	"ACTIVE",	0, backend_check_active},
	{TYPE_ZONE,	"COMMENT",	0, backend_check_comment},

	/* interface specific */
	{TYPE_INTERFACE,"ACTIVE",	0, backend_check_active},
	{TYPE_INTERFACE,"IPADDRESS",	0, backend_check_interface_ipaddress},
	{TYPE_INTERFACE,"DEVICE",	0, backend_check_interface_device},
	{TYPE_INTERFACE,"VIRTUAL",	0, backend_check_interface_virtual},
	{TYPE_INTERFACE,"RULE",		1, backend_check_interface_rule},
	{TYPE_INTERFACE,"COMMENT",	0, backend_check_comment},

	/* service specific */
	{TYPE_SERVICE,	"ACTIVE",	0, backend_check_active},
	{TYPE_SERVICE,	"BROADCAST",	0, backend_check_service_broadcast},
	{TYPE_SERVICE,	"HELPER",	0, backend_check_service_helper},
	{TYPE_SERVICE,	"TCP",		1, backend_check_service_tcp},
	{TYPE_SERVICE,	"UDP",		1, backend_check_service_udp},
	{TYPE_SERVICE,	"ICMP",		1, backend_check_service_icmp},
	{TYPE_SERVICE,	"GRE",		1, backend_check_service_gre},
	{TYPE_SERVICE,	"ESP",		1, backend_check_service_esp},
	{TYPE_SERVICE,	"AH",		1, backend_check_service_ah},
	{TYPE_SERVICE,	"PROTO_41",	1, backend_check_service_proto41},
	{TYPE_SERVICE,	"COMMENT",	0, backend_check_comment},

	/* rule specific */
	{TYPE_RULE,	"RULE",		1, backend_check_rule_rule},

	/* last */
	{-1, "", 0, NULL},
};


#endif

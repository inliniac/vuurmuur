/***************************************************************************
 *   Copyright (C) 2005-2017 by Victor Julien                              *
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

#ifndef __BACKENDCHECK_H__
#define __BACKENDCHECK_H__

int backend_vrmr_check_active(char *, struct vrmr_regex *);
int backend_check_comment(char *, struct vrmr_regex *);

int backend_check_host_ipaddress(char *, struct vrmr_regex *);
int backend_check_host_macaddress(char *, struct vrmr_regex *);

int backend_check_group_member(char *, struct vrmr_regex *);

int backend_check_network_network(char *, struct vrmr_regex *);
int backend_check_network_netmask(char *, struct vrmr_regex *);
int backend_check_network_interface(char *, struct vrmr_regex *);
int backend_check_network_rule(char *, struct vrmr_regex *);

int backend_check_interface_ipaddress(char *, struct vrmr_regex *);
int backend_check_interface_device(char *, struct vrmr_regex *);
int backend_check_interface_virtual(char *, struct vrmr_regex *);
int backend_check_interface_shape(char *, struct vrmr_regex *);
int backend_check_interface_bw(char *, struct vrmr_regex *);
int backend_check_interface_bw_unit(char *, struct vrmr_regex *);
int backend_check_interface_rule(char *, struct vrmr_regex *);
int backend_check_interface_tcpmss(char *, struct vrmr_regex *);

int backend_check_service_broadcast(char *, struct vrmr_regex *);
int backend_check_service_helper(char *, struct vrmr_regex *);
int backend_check_service_tcp(char *, struct vrmr_regex *);
int backend_check_service_udp(char *, struct vrmr_regex *);
int backend_check_service_icmp(char *, struct vrmr_regex *);
int backend_check_service_gre(char *, struct vrmr_regex *);
int backend_check_service_esp(char *, struct vrmr_regex *);
int backend_check_service_ah(char *, struct vrmr_regex *);
int backend_check_service_proto41(char *, struct vrmr_regex *);

int backend_check_rule_rule(char *, struct vrmr_regex *);

struct backend_vars_ {
    int type;
    char var[32];
    char multi;
    int (*chk)(char *value, struct vrmr_regex *reg);
} backend_vars[] = {
        /* host specific */
        {VRMR_TYPE_HOST, "ACTIVE", 0, backend_vrmr_check_active},
        {VRMR_TYPE_HOST, "IPADDRESS", 0, backend_check_host_ipaddress},
        {VRMR_TYPE_HOST, "MAC", 0, backend_check_host_macaddress},
        {VRMR_TYPE_HOST, "COMMENT", 0, backend_check_comment},

        /* group specific */
        {VRMR_TYPE_GROUP, "ACTIVE", 0, backend_vrmr_check_active},
        {VRMR_TYPE_GROUP, "MEMBER", 1, backend_check_group_member},
        {VRMR_TYPE_GROUP, "COMMENT", 0, backend_check_comment},

        /* network specific */
        {VRMR_TYPE_NETWORK, "ACTIVE", 0, backend_vrmr_check_active},
        {VRMR_TYPE_NETWORK, "NETWORK", 0, backend_check_network_network},
        {VRMR_TYPE_NETWORK, "NETMASK", 0, backend_check_network_netmask},
        {VRMR_TYPE_NETWORK, "INTERFACE", 1, backend_check_network_interface},
        {VRMR_TYPE_NETWORK, "RULE", 1, backend_check_network_rule},
        {VRMR_TYPE_NETWORK, "COMMENT", 0, backend_check_comment},

        /* zone specific */
        {VRMR_TYPE_ZONE, "ACTIVE", 0, backend_vrmr_check_active},
        {VRMR_TYPE_ZONE, "COMMENT", 0, backend_check_comment},

        /* interface specific */
        {VRMR_TYPE_INTERFACE, "ACTIVE", 0, backend_vrmr_check_active},
        {VRMR_TYPE_INTERFACE, "IPADDRESS", 0,
                backend_check_interface_ipaddress},
        {VRMR_TYPE_INTERFACE, "DEVICE", 0, backend_check_interface_device},
        {VRMR_TYPE_INTERFACE, "VIRTUAL", 0, backend_check_interface_virtual},
        {VRMR_TYPE_INTERFACE, "RULE", 1, backend_check_interface_rule},
        {VRMR_TYPE_INTERFACE, "COMMENT", 0, backend_check_comment},
        {VRMR_TYPE_INTERFACE, "SHAPE", 0, backend_check_interface_shape},
        {VRMR_TYPE_INTERFACE, "TCPMSS", 0, backend_check_interface_tcpmss},
        {VRMR_TYPE_INTERFACE, "BW_IN", 0, backend_check_interface_bw},
        {VRMR_TYPE_INTERFACE, "BW_OUT", 0, backend_check_interface_bw},
        {VRMR_TYPE_INTERFACE, "BW_IN_UNIT", 0, backend_check_interface_bw_unit},
        {VRMR_TYPE_INTERFACE, "BW_OUT_UNIT", 0,
                backend_check_interface_bw_unit},

        /* service specific */
        {VRMR_TYPE_SERVICE, "ACTIVE", 0, backend_vrmr_check_active},
        {VRMR_TYPE_SERVICE, "BROADCAST", 0, backend_check_service_broadcast},
        {VRMR_TYPE_SERVICE, "HELPER", 0, backend_check_service_helper},
        {VRMR_TYPE_SERVICE, "TCP", 1, backend_check_service_tcp},
        {VRMR_TYPE_SERVICE, "UDP", 1, backend_check_service_udp},
        {VRMR_TYPE_SERVICE, "ICMP", 1, backend_check_service_icmp},
        {VRMR_TYPE_SERVICE, "GRE", 1, backend_check_service_gre},
        {VRMR_TYPE_SERVICE, "ESP", 1, backend_check_service_esp},
        {VRMR_TYPE_SERVICE, "AH", 1, backend_check_service_ah},
        {VRMR_TYPE_SERVICE, "PROTO_41", 1, backend_check_service_proto41},
        {VRMR_TYPE_SERVICE, "COMMENT", 0, backend_check_comment},

        /* rule specific */
        {VRMR_TYPE_RULE, "RULE", 1, backend_check_rule_rule},

        /* last */
        {-1, "", 0, NULL},
};

#endif

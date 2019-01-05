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

#include "vuurmuur_script.h"
#include "backendcheck.h"

/*  ACTIVE

*/
int backend_vrmr_check_active(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* check */
    if (strcasecmp(value, "yes") == 0 || strcasecmp(value, "no") == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'ACTIVE'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  COMMENT

*/
int backend_check_comment(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* TODO check */
    if (1)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'COMMENT'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  IPADDRESS (host)

*/
int backend_check_host_ipaddress(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* check */
    if (vrmr_check_ipv4address(NULL, NULL, value, 0) == 1)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'IPADDRESS'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  MAC

*/
int backend_check_host_macaddress(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* test against the regex */
    if (regexec(reg->macaddr, value, 0, NULL, 0) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'MAC'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  MEMBER

*/
int backend_check_group_member(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* test against the regex */
    if (regexec(reg->host_part, value, 0, NULL, 0) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'MEMBER'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  NETWORK

*/
int backend_check_network_network(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* check */
    if (vrmr_check_ipv4address(NULL, NULL, value, 0) == 1)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'NETWORK'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  NETMASK

*/
int backend_check_network_netmask(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* check */
    if (vrmr_check_ipv4address(NULL, NULL, value, 0) == 1)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'NETMASK'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  INTERFACE

*/
int backend_check_network_interface(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* test against the regex */
    if (regexec(reg->interfacename, value, 0, NULL, 0) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'INTERFACE'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  RULE

*/
int backend_check_network_rule(char *value, struct vrmr_regex *reg)
{
    char line[1024] = "";
    struct vrmr_rule rule;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (strlcpy(line, value, sizeof(line)) >= sizeof(line)) {
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                "value for variable 'RULE' to long");
        return (VRS_ERR_COMMANDLINE);
    }

    if (vrmr_rules_decode_rule(line, sizeof(line)) < 0) {
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR, "decoding 'RULE' failed");
        return (VRS_ERR_COMMANDLINE);
    }

    if (vrmr_zones_network_rule_parse_line(line, &rule) < 0) {
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR, "parsing rule failed");
        return (VRS_ERR_COMMANDLINE);
    }

    return (0);
}

/*  IPADDRESS

*/
int backend_check_interface_ipaddress(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* check */
    if (strcasecmp(value, "dynamic") == 0)
        return (0);
    else if (vrmr_check_ipv4address(NULL, NULL, value, 0) == 1)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'IPADDRESS'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  DEVICE

*/
int backend_check_interface_device(char *value, struct vrmr_regex *reg)
{
    struct vrmr_interface interface;

    assert(value && reg);

    /* check */
    if (strlen(value) < sizeof(interface.device))
        return (0);

    /* TODO check */
    if (1)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'DEVICE'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  VIRTUAL

*/
int backend_check_interface_virtual(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* check */
    if (strcasecmp(value, "yes") == 0 || strcasecmp(value, "no") == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'VIRTUAL'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  RULE

*/
int backend_check_interface_rule(char *value, struct vrmr_regex *reg)
{
    char line[1024] = "";
    struct vrmr_rule rule;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (strlcpy(line, value, sizeof(line)) >= sizeof(line)) {
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                "value for variable 'RULE' to long");
        return (VRS_ERR_COMMANDLINE);
    }

    if (vrmr_rules_decode_rule(line, sizeof(line)) < 0) {
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR, "decoding 'RULE' failed");
        return (VRS_ERR_COMMANDLINE);
    }

    if (vrmr_interfaces_rule_parse_line(line, &rule) < 0) {
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR, "parsing rule failed");
        return (VRS_ERR_COMMANDLINE);
    }

    return (0);
}

/*  SHAPE

*/
int backend_check_interface_shape(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (strcasecmp(value, "yes") == 0 || strcasecmp(value, "no") == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'SHAPE'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  BW_IN/BW_OUT

*/
int backend_check_interface_bw(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    for (size_t i = 0; i < strlen(value); i++) {
        if (!isdigit(value[i])) {
            vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                    "'%s' is not a valid value for variable 'BW_IN' or "
                    "'BW_OUT' ",
                    value);
            return (VRS_ERR_COMMANDLINE);
        }
    }

    /* check */
    if (strlen(value) >= 11) { /* max len of 32 bit int */
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                "'%s' is not a valid value for variable 'BW_IN' or 'BW_OUT'",
                value);
        return (VRS_ERR_COMMANDLINE);
    }

    return (0);
}

/*  BW_IN_UNIT/BW_OUT_UNIT

*/
int backend_check_interface_bw_unit(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (strcasecmp(value, "kbit") == 0 || strcasecmp(value, "mbit") == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'BW_IN_OUT' or "
            "'BW_OUT_OUT'",
            value);
    return (VRS_ERR_COMMANDLINE);
}

/*  TCPMSS

*/
int backend_check_interface_tcpmss(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (strcasecmp(value, "yes") == 0 || strcasecmp(value, "no") == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'TCPMSS'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  BROADCAST

*/
int backend_check_service_broadcast(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* check */
    if (strcasecmp(value, "yes") == 0 || strcasecmp(value, "no") == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'BROADCAST'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  HELPER

*/
int backend_check_service_helper(char *value, struct vrmr_regex *reg)
{
    struct vrmr_service service;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (strlen(value) < sizeof(service.helper))
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'HELPER'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  TCP

*/
int backend_check_service_tcp(char *value, struct vrmr_regex *reg)
{
    struct vrmr_service service;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (vrmr_process_portrange("TCP", value, &service) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'TCP'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  UDP

*/
int backend_check_service_udp(char *value, struct vrmr_regex *reg)
{
    struct vrmr_service service;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (vrmr_process_portrange("UDP", value, &service) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'UDP'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  ICMP

*/
int backend_check_service_icmp(char *value, struct vrmr_regex *reg)
{
    struct vrmr_service service;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (vrmr_process_portrange("ICMP", value, &service) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'ICMP'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  GRE

*/
int backend_check_service_gre(char *value, struct vrmr_regex *reg)
{
    struct vrmr_service service;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (vrmr_process_portrange("GRE", value, &service) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'GRE'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  AH

*/
int backend_check_service_ah(char *value, struct vrmr_regex *reg)
{
    struct vrmr_service service;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (vrmr_process_portrange("AH", value, &service) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'AH'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  ESP

*/
int backend_check_service_esp(char *value, struct vrmr_regex *reg)
{
    struct vrmr_service service;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (vrmr_process_portrange("ESP", value, &service) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'ESP'", value);
    return (VRS_ERR_COMMANDLINE);
}

/*  PROTO_41

*/
int backend_check_service_proto41(char *value, struct vrmr_regex *reg)
{
    struct vrmr_service service;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (vrmr_process_portrange("PROTO_41", value, &service) == 0)
        return (0);

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'PROTO_41'", value);
    return (VRS_ERR_COMMANDLINE);
}

static int backend_check_blocklist_rule(char *value, struct vrmr_regex *reg)
{
    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    return (0);
}

/*  RULE

*/
int backend_check_rule_rule(char *value, struct vrmr_regex *reg)
{
    char line[1024] = "";
    char action[32] = "";
    struct vrmr_rule rule;

    assert(value && reg);

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return (0);

    /* check */
    if (strlcpy(line, value, sizeof(line)) >= sizeof(line)) {
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                "value for variable 'RULE' to long");
        return (VRS_ERR_COMMANDLINE);
    }

    if (vrmr_rules_decode_rule(line, sizeof(line)) < 0) {
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR, "decoding 'RULE' failed");
        return (VRS_ERR_COMMANDLINE);
    }

    sscanf(line, "%s", action);
    if (strcasecmp(action, "block") == 0) {
        return (backend_check_blocklist_rule(value, reg));
    } else {
        if (vrmr_rules_parse_line(line, &rule, reg) < 0) {
            vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR, "parsing rule failed");
            return (VRS_ERR_COMMANDLINE);
        }
    }

    return (0);
}

int backend_check(
        int type, char *var, char *val, char overwrite, struct vrmr_regex *reg)
{
    for (int i = 0;; i++) {
        if (backend_vars[i].type == -1)
            break;

        if ((backend_vars[i].type == type ||
                    backend_vars[i].type == VRMR_TYPE_UNSET) &&
                strcmp(backend_vars[i].var, var) == 0) {
            if (overwrite == 0 && backend_vars[i].multi == 0) {
                vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                        "%s does not support appending", var);
                return (VRS_ERR_COMMANDLINE);
            }

            if (backend_vars[i].chk == NULL) {
                vrmr_error(VRS_ERR_INTERNAL, VR_INTERR,
                        "could not check: no check function defined");
                return (VRS_ERR_INTERNAL);
            }

            return (backend_vars[i].chk(val, reg));
        }
    }

    vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR, "%s is not a valid variable name",
            var);
    return (VRS_ERR_COMMANDLINE);
}

/***************************************************************************
 *   Copyright (C) 2005-2007 by Victor Julien                              *
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
int
backend_check_active(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* check */
    if(strcasecmp(value,"yes") == 0 || strcasecmp(value,"no") == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'ACTIVE' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  COMMENT

*/
int
backend_check_comment(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* check */
    if(1)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'COMMENT' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  IPADDRESS (host)

*/
int
backend_check_host_ipaddress(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* check */
    if(check_ipv4address(debuglvl, NULL, NULL, value, 0) == 1)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'IPADDRESS' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  MAC

*/
int
backend_check_host_macaddress(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* test against the regex */
    if(regexec(reg->macaddr, value, 0, NULL, 0) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'MAC' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  MEMBER

*/
int
backend_check_group_member(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* test against the regex */
    if(regexec(reg->host_part, value, 0, NULL, 0) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'MEMBER' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  NETWORK

*/
int
backend_check_network_network(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* check */
    if(check_ipv4address(debuglvl, NULL, NULL, value, 0) == 1)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'NETWORK' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  NETMASK

*/
int
backend_check_network_netmask(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* check */
    if(check_ipv4address(debuglvl, NULL, NULL, value, 0) == 1)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'NETMASK' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  INTERFACE

*/
int
backend_check_network_interface(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* test against the regex */
    if(regexec(reg->interfacename, value, 0, NULL, 0) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'INTERFACE' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  RULE

*/
int
backend_check_network_rule(const int debuglvl, char *value, struct rgx_ *reg)
{
    char                line[1024] = "";
    struct RuleData_    rule;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(strlcpy(line, value, sizeof(line)) >= sizeof(line))
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "value for variable 'RULE' to long (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_COMMANDLINE);
    }

    if(rules_decode_rule(debuglvl, line, sizeof(line)) < 0)
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "decoding 'RULE' failed (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_COMMANDLINE);
    }

    if(zones_network_rule_parse_line(debuglvl, line, &rule) < 0)
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "parsing rule failed (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_COMMANDLINE);
    }

    return(0);
}


/*  IPADDRESS

*/
int
backend_check_interface_ipaddress(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* check */
    if(strcasecmp(value, "dynamic") == 0)
        return(0);
    else if(check_ipv4address(debuglvl, NULL, NULL, value, 0) == 1)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'IPADDRESS' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  DEVICE

*/
int
backend_check_interface_device(const int debuglvl, char *value, struct rgx_ *reg)
{
    struct InterfaceData_   interface;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* check */
    if(strlen(value) < sizeof(interface.device))
        return(0);

    /* check */
    if(1)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'DEVICE' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  VIRTUAL

*/
int
backend_check_interface_virtual(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* check */
    if(strcasecmp(value,"yes") == 0 || strcasecmp(value,"no") == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'VIRTUAL' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  RULE

*/
int
backend_check_interface_rule(const int debuglvl, char *value, struct rgx_ *reg)
{
    char                line[1024] = "";
    struct RuleData_    rule;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(strlcpy(line, value, sizeof(line)) >= sizeof(line))
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "value for variable 'RULE' to long (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_COMMANDLINE);
    }

    if(rules_decode_rule(debuglvl, line, sizeof(line)) < 0)
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "decoding 'RULE' failed (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_COMMANDLINE);
    }

    if(interfaces_rule_parse_line(debuglvl, line, &rule) < 0)
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "parsing rule failed (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_COMMANDLINE);
    }

    return(0);
}

/*  SHAPE

*/
int
backend_check_interface_shape(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(strcasecmp(value,"yes") == 0 || strcasecmp(value,"no") == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'SHAPE' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}



/*  BW_IN/BW_OUT

*/
int
backend_check_interface_bw(const int debuglvl, char *value, struct rgx_ *reg)
{
    int i = 0;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    for (i = 0; i < strlen(value); i++) {
        if (!isdigit(value[i])) {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR,
                "'%s' is not a valid value for variable 'BW_IN' or 'BW_OUT' "
                " (in: %s:%d).", value, __FUNC__, __LINE__);
            return(VRS_ERR_COMMANDLINE);
        }
    }

    /* check */
    if(strlen(value) >= 11) { /* max len of 32 bit int */
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR,
            "'%s' is not a valid value for variable 'BW_IN' or 'BW_OUT' "
            " (in: %s:%d).", value, __FUNC__, __LINE__);
        return(VRS_ERR_COMMANDLINE);
    }

    return(0);
}

/*  BW_IN_UNIT/BW_OUT_UNIT

*/
int
backend_check_interface_bw_unit(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if (strcasecmp(value, "kbit") == 0 || strcasecmp(value, "mbit") == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR,
        "'%s' is not a valid value for variable 'BW_IN_OUT' or 'BW_OUT_OUT' "
        " (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  BROADCAST

*/
int
backend_check_service_broadcast(const int debuglvl, char *value, struct rgx_ *reg)
{
    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* check */
    if(strcasecmp(value,"yes") == 0 || strcasecmp(value,"no") == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'BROADCAST' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  HELPER

*/
int
backend_check_service_helper(const int debuglvl, char *value, struct rgx_ *reg)
{
    struct ServicesData_    service;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(strlen(value) < sizeof(service.helper))
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'HELPER' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  TCP

*/
int
backend_check_service_tcp(const int debuglvl, char *value, struct rgx_ *reg)
{
    struct ServicesData_    service;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(process_portrange(debuglvl, "TCP", value, &service) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'TCP' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  UDP

*/
int
backend_check_service_udp(const int debuglvl, char *value, struct rgx_ *reg)
{
    struct ServicesData_    service;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(process_portrange(debuglvl, "UDP", value, &service) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'UDP' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  ICMP

*/
int
backend_check_service_icmp(const int debuglvl, char *value, struct rgx_ *reg)
{
    struct ServicesData_    service;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(process_portrange(debuglvl, "ICMP", value, &service) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'ICMP' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  GRE

*/
int
backend_check_service_gre(const int debuglvl, char *value, struct rgx_ *reg)
{
    struct ServicesData_    service;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(process_portrange(debuglvl, "GRE", value, &service) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'GRE' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  AH

*/
int
backend_check_service_ah(const int debuglvl, char *value, struct rgx_ *reg)
{
    struct ServicesData_    service;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(process_portrange(debuglvl, "AH", value, &service) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'AH' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  ESP

*/
int
backend_check_service_esp(const int debuglvl, char *value, struct rgx_ *reg)
{
    struct ServicesData_    service;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(process_portrange(debuglvl, "ESP", value, &service) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'ESP' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


/*  PROTO_41

*/
int
backend_check_service_proto41(const int debuglvl, char *value, struct rgx_ *reg)
{
    struct ServicesData_    service;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(process_portrange(debuglvl, "PROTO_41", value, &service) == 0)
        return(0);

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "'%s' is not a valid value for variable 'PROTO_41' (in: %s:%d).", value, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}


int
backend_check_blocklist_rule(const int debuglvl, char *value, struct rgx_ *reg)
{
//    char                line[1024] = "";
//    char                action[32] = "";
//    struct RuleData_    rule;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);


    return(0);
}


/*  RULE

*/
int
backend_check_rule_rule(const int debuglvl, char *value, struct rgx_ *reg)
{
    char                line[1024] = "";
    char                action[32] = "";
    struct RuleData_    rule;

    /* safety */
    if(value == NULL || reg == NULL)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "parameter problem (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    /* empty is also possible for clearing */
    if (value[0] == '\0')
        return(0);

    /* check */
    if(strlcpy(line, value, sizeof(line)) >= sizeof(line))
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "value for variable 'RULE' to long (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_COMMANDLINE);
    }

    if(rules_decode_rule(debuglvl, line, sizeof(line)) < 0)
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "decoding 'RULE' failed (in: %s:%d).",
                                        __FUNC__, __LINE__);
        return(VRS_ERR_COMMANDLINE);
    }

    sscanf(line, "%s", action);
    if(strcasecmp(action, "block") == 0)
    {
        return(backend_check_blocklist_rule(debuglvl, value, reg));
    }
    else
    {
        if(rules_parse_line(debuglvl, line, &rule, reg) < 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "parsing rule failed (in: %s:%d).",
                                        __FUNC__, __LINE__);
            return(VRS_ERR_COMMANDLINE);
        }
    }

    return(0);
}


int
backend_check(const int debuglvl, int type, char *var, char *val, char overwrite, struct rgx_ *reg)
{
    int i = 0;

    for(i = 0; ; i++)
    {
        if(backend_vars[i].type == -1)
            break;

        if((backend_vars[i].type == type || backend_vars[i].type == TYPE_UNSET) &&
            strcmp(backend_vars[i].var, var) == 0)
        {
            if(overwrite == 0 && backend_vars[i].multi == 0)
            {
                (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "%s does not support appending (in: %s:%d).", var, __FUNC__, __LINE__);
                return(VRS_ERR_COMMANDLINE);
            }

            if(backend_vars[i].chk == NULL)
            {
                (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "could not check: no check function defined (in: %s:%d).", __FUNC__, __LINE__);
                return(VRS_ERR_INTERNAL);
            }

            return(backend_vars[i].chk(debuglvl, val, reg));
        }
    }

    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "%s is not a valid variable name (in: %s:%d).", var, __FUNC__, __LINE__);
    return(VRS_ERR_COMMANDLINE);
}

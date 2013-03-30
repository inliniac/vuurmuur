/***************************************************************************
 *   Copyright (C) 2005-2008 by Victor Julien                              *
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

int
script_print(const int debuglvl, VuurmuurScript *vr_script)
{
    char            found = FALSE;
    int             result = 0;
    unsigned int    rule_num = 1;

//TODO: check name

    if( vr_script->type == VRMR_TYPE_ZONE || vr_script->type == VRMR_TYPE_NETWORK ||
        vr_script->type == VRMR_TYPE_HOST || vr_script->type == VRMR_TYPE_GROUP)
    {
        while(zf->list(debuglvl, zone_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_ZONES) != NULL)
        {
            if(vr_script->zonetype == vr_script->type && strcmp(vr_script->bdat,vr_script->name) == 0)
            {
                found = TRUE;
            }
        }

        if(found == FALSE)
        {
            if(vr_script->type == VRMR_TYPE_ZONE)
                vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR, "zone '%s' doesn't exist.", vr_script->name);
            else if(vr_script->type == VRMR_TYPE_NETWORK)
                vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR, "network '%s' doesn't exist.", vr_script->name);
            else if(vr_script->type == VRMR_TYPE_HOST)
                vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR, "host '%s' doesn't exist.", vr_script->name);
            else if(vr_script->type == VRMR_TYPE_GROUP)
                vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR, "group '%s' doesn't exist.", vr_script->name);

            return(VRS_ERR_NOT_FOUND);
        }
    }
    else if(vr_script->type == VRMR_TYPE_SERVICE)
    {
        while(sf->list(debuglvl, serv_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_SERVICES) != NULL)
        {
            if(strcmp(vr_script->bdat,vr_script->name) == 0)
            {
                found = TRUE;
            }
        }

        if(found == FALSE)
        {
            vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR, "service '%s' doesn't exist.", vr_script->name);
            return(VRS_ERR_NOT_FOUND);
        }
    }
    else if(vr_script->type == VRMR_TYPE_INTERFACE)
    {
        while(af->list(debuglvl, ifac_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_INTERFACES) != NULL)
        {
            if(strcmp(vr_script->bdat,vr_script->name) == 0)
            {
                found = TRUE;
            }
        }

        if(found == FALSE)
        {
            vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR, "interface '%s' doesn't exist.", vr_script->name);
            return(VRS_ERR_NOT_FOUND);
        }
    }
    else if(vr_script->type == VRMR_TYPE_RULE)
    {
        while(rf->list(debuglvl, rule_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_RULES) != NULL)
        {
            if(strcmp(vr_script->bdat,vr_script->name) == 0)
            {
                found = TRUE;
            }
        }

        if(found == FALSE)
        {
            vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR, "ruleset '%s' doesn't exist.", vr_script->name);
            return(VRS_ERR_NOT_FOUND);
        }
    }

    if(vr_script->type == VRMR_TYPE_ZONE)
    {
        /* active */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"ACTIVE") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "ACTIVE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_ZONE, 0) == 1)
                printf("ACTIVE=\"%s\"\n", vr_script->bdat);
            else
                printf("ACTIVE=\"\"\n");
        }

        /* Comment */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"ACTIVE") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "COMMENT", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_ZONE, 0) == 1)
                printf("COMMENT=\"%s\"\n", vr_script->bdat);
            else
                printf("COMMENT=\"\"\n");
        }
    }
    else if(vr_script->type == VRMR_TYPE_NETWORK)
    {
        /* active */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"ACTIVE") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "ACTIVE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_NETWORK, 0) == 1)
                printf("ACTIVE=\"%s\"\n", vr_script->bdat);
            else
                printf("ACTIVE=\"\"\n");
        }

        /* Network Address */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"NETWORK") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "NETWORK", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_NETWORK, 0) == 1)
                printf("NETWORK=\"%s\"\n", vr_script->bdat);
            else
                printf("NETWORK=\"\"\n");
        }

        /* Netmask Address */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"NETMASK") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "NETMASK", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_NETWORK, 0) == 1)
                printf("NETMASK=\"%s\"\n", vr_script->bdat);
            else
                printf("NETMASK=\"\"\n");
        }

        /* Interface */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"INTERFACE") == 0)
        {
            result = 0;

            while(zf->ask(debuglvl, zone_backend, vr_script->name, "INTERFACE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_NETWORK, 1) == 1)
            {
                printf("INTERFACE=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("INTERFACE=\"\"\n");
        }

        /* Rules */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"RULE") == 0)
        {
            result = 0;

            while(zf->ask(debuglvl, zone_backend, vr_script->name, "RULE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_NETWORK, 1) == 1)
            {
                vrmr_rules_encode_rule(debuglvl, vr_script->bdat, sizeof(vr_script->bdat));

                printf("RULE=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("RULE=\"\"\n");
        }

        /* Comment */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"COMMENT") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "COMMENT", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_NETWORK, 0) == 1)
                printf("COMMENT=\"%s\"\n", vr_script->bdat);
            else
                printf("COMMENT=\"\"\n");
        }
    }
    else if(vr_script->type == VRMR_TYPE_HOST)
    {
        /* active */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"ACTIVE") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "ACTIVE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_HOST, 0) == 1)
                printf("ACTIVE=\"%s\"\n", vr_script->bdat);
            else
                printf("ACTIVE=\"\"\n");
        }

        /* IP Address */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"IPADDRESS") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "IPADDRESS", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_HOST, 0) == 1)
                printf("IPADDRESS=\"%s\"\n", vr_script->bdat);
            else
                printf("IPADDRESS=\"\"\n");
        }

        /* MAC Address */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"MAC") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "MAC", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_HOST, 0) == 1)
                printf("MAC=\"%s\"\n", vr_script->bdat);
            else
                printf("MAC=\"\"\n");
        }

        /* Comment */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"COMMENT") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "COMMENT", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_HOST, 0) == 1)
                printf("COMMENT=\"%s\"\n", vr_script->bdat);
            else
                printf("COMMENT=\"\"\n");
        }
    }
    else if(vr_script->type == VRMR_TYPE_GROUP)
    {
        /* active */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"ACTIVE") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "ACTIVE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_GROUP, 0) == 1)
                printf("ACTIVE=\"%s\"\n", vr_script->bdat);
            else
                printf("ACTIVE=\"\"\n");
        }

        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"MEMBER") == 0)
        {
            result = 0;
            /* Members */
            while(zf->ask(debuglvl, zone_backend, vr_script->name, "MEMBER", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_GROUP, 1) == 1)
            {
                printf("MEMBER=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("MEMBER=\"\"\n");
        }

        /* Comment */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"COMMENT") == 0)
        {
            if(zf->ask(debuglvl, zone_backend, vr_script->name, "COMMENT", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_GROUP, 0) == 1)
                printf("COMMENT=\"%s\"\n", vr_script->bdat);
            else
                printf("COMMENT=\"\"\n");
        }
    }
    else if(vr_script->type == VRMR_TYPE_SERVICE)
    {
        /* active */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"ACTIVE") == 0)
        {
            if(sf->ask(debuglvl, serv_backend, vr_script->name, "ACTIVE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 0) == 1)
                printf("ACTIVE=\"%s\"\n", vr_script->bdat);
            else
                printf("ACTIVE=\"\"\n");
        }

        /* BROADCAST */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"BROADCAST") == 0)
        {
            if(sf->ask(debuglvl, serv_backend, vr_script->name, "BROADCAST", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 0) == 1)
                printf("BROADCAST=\"%s\"\n", vr_script->bdat);
            else
                printf("BROADCAST=\"\"\n");
        }

        /* HELPER */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"HELPER") == 0)
        {
            if(sf->ask(debuglvl, serv_backend, vr_script->name, "HELPER", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 0) == 1)
                printf("HELPER=\"%s\"\n", vr_script->bdat);
            else
                printf("HELPER=\"\"\n");
        }

        /* TCP */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"TCP") == 0)
        {
            result = 0;
            while(sf->ask(debuglvl, serv_backend, vr_script->name, "TCP", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 1) == 1)
            {
                printf("TCP=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("TCP=\"\"\n");
        }

        /* UDP */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"UDP") == 0)
        {
            result = 0;
            while(sf->ask(debuglvl, serv_backend, vr_script->name, "UDP", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 1) == 1)
            {
                printf("UDP=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("UDP=\"\"\n");
        }

        /* ICMP */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"ICMP") == 0)
        {
            result = 0;
            while(sf->ask(debuglvl, serv_backend, vr_script->name, "ICMP", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 1) == 1)
            {
                printf("ICMP=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("ICMP=\"\"\n");
        }

        /* GRE */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"GRE") == 0)
        {
            result = 0;
            while(sf->ask(debuglvl, serv_backend, vr_script->name, "GRE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 1) == 1)
            {
                printf("GRE=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("GRE=\"\"\n");
        }

        /* AH */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"AH") == 0)
        {
            result = 0;
            while(sf->ask(debuglvl, serv_backend, vr_script->name, "AH", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 1) == 1)
            {
                printf("AH=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("AH=\"\"\n");
        }

        /* ESP */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"ESP") == 0)
        {
            result = 0;
            while(sf->ask(debuglvl, serv_backend, vr_script->name, "ESP", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 1) == 1)
            {
                printf("ESP=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("ESP=\"\"\n");
        }

        /* PROTO_41 */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"PROTO_41") == 0)
        {
            result = 0;
            while(sf->ask(debuglvl, serv_backend, vr_script->name, "PROTO_41", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 1) == 1)
            {
                printf("PROTO_41=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("PROTO_41=\"\"\n");
        }

        /* Comment */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"COMMENT") == 0)
        {
            if(sf->ask(debuglvl, serv_backend, vr_script->name, "COMMENT", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_SERVICE, 0) == 1)
                printf("COMMENT=\"%s\"\n", vr_script->bdat);
            else
                printf("COMMENT=\"\"\n");
        }
    }
    else if(vr_script->type == VRMR_TYPE_INTERFACE)
    {
        /* active */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"ACTIVE") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "ACTIVE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("ACTIVE=\"%s\"\n", vr_script->bdat);
            else
                printf("ACTIVE=\"\"\n");
        }
        /* IPADDRESS */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"IPADDRESS") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "IPADDRESS", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("IPADDRESS=\"%s\"\n", vr_script->bdat);
            else
                printf("IPADDRESS=\"\"\n");
        }
        /* DEVICE (INTERFACE) */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"DEVICE") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "DEVICE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("DEVICE=\"%s\"\n", vr_script->bdat);
            else
            {
                if(af->ask(debuglvl, ifac_backend, vr_script->name, "INTERFACE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                    printf("DEVICE=\"%s\"\n", vr_script->bdat);
                else
                    printf("DEVICE=\"\"\n");
            }
        }
        /* VIRTUAL */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"VIRTUAL") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "VIRTUAL", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("VIRTUAL=\"%s\"\n", vr_script->bdat);
            else
                printf("VIRTUAL=\"\"\n");
        }
        /* SHAPE */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"SHAPE") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "SHAPE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("SHAPE=\"%s\"\n", vr_script->bdat);
            else
                printf("SHAPE=\"\"\n");
        }
        /* BW_IN */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"BW_IN") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "BW_IN", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("BW_IN=\"%s\"\n", vr_script->bdat);
            else
                printf("BW_IN=\"\"\n");
        }
        /* BW_OUT */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"BW_OUT") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "BW_OUT", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("BW_OUT=\"%s\"\n", vr_script->bdat);
            else
                printf("BW_OUT=\"\"\n");
        }
        /* BW_IN_UNIT */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"BW_IN_UNIT") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "BW_IN_UNIT", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("BW_IN_UNIT=\"%s\"\n", vr_script->bdat);
            else
                printf("BW_IN_UNIT=\"\"\n");
        }
        /* BW_OUT_UNIT */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"BW_OUT_UNIT") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "BW_OUT_UNIT", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("BW_OUT_UNIT=\"%s\"\n", vr_script->bdat);
            else
                printf("BW_OUT_UNIT=\"\"\n");
        }
        /* TCPMSS */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"TCPMSS") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "TCPMSS", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("TCPMSS=\"%s\"\n", vr_script->bdat);
            else
                printf("TCPMSS=\"\"\n");
        }
        /* RULE */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"RULE") == 0)
        {
            result = 0;

            while(af->ask(debuglvl, ifac_backend, vr_script->name, "RULE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 1) == 1)
            {
                vrmr_rules_encode_rule(debuglvl, vr_script->bdat, sizeof(vr_script->bdat));

                printf("RULE=\"%s\"\n", vr_script->bdat);
                result = 1;
            }
            if(result == 0)
                printf("RULE=\"\"\n");
        }
        /* Comment */
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"COMMENT") == 0)
        {
            if(af->ask(debuglvl, ifac_backend, vr_script->name, "COMMENT", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_INTERFACE, 0) == 1)
                printf("COMMENT=\"%s\"\n", vr_script->bdat);
            else
                printf("COMMENT=\"\"\n");
        }
    }
    else if(vr_script->type == VRMR_TYPE_RULE)
    {
        if(strcasecmp(vr_script->var,"any") == 0 || strcmp(vr_script->var,"RULE") == 0)
        {
            /* RULE */
            result = 0;

            while(rf->ask(debuglvl, rule_backend, vr_script->name, "RULE", vr_script->bdat, sizeof(vr_script->bdat), VRMR_TYPE_RULE, 1) == 1)
            {
                vrmr_rules_encode_rule(debuglvl, vr_script->bdat, sizeof(vr_script->bdat));

                if(vr_script->print_rule_numbers == TRUE)
                {
                    printf("%4u: RULE=\"%s\"\n", rule_num, vr_script->bdat);
                    rule_num++;
                }
                else
                {
                    printf("RULE=\"%s\"\n", vr_script->bdat);
                }
                result = 1;
            }
            if(result == 0)
                printf("RULE=\"\"\n");
        }
    }
    else
    {
        vrmr_error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type %d.", vr_script->type);
        return(VRS_ERR_INTERNAL);
    }

    return(0);
}

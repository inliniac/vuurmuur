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

#include "vuurmuur.h"
#include "icmp.h"

int
get_icmp_name_short(int type, int code, char *name, size_t size, int only_code)
{
    int i=0,
        k=0;

    /* safety */
    if(name == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* type validation */
    if(type < 0 || type > 255)
    {
        snprintf(name, size, "illegal icmp (%d.%d)", type, code);
        return(0);
    }
#ifndef HAVE_IPV6
    else if(type > 40 && type <= 255)
    {
        snprintf(name, size, "reserved icmp (%d.%d)", type, code);
        return(0);
    }
#endif /* HAVE_IPV6 */

    /* loop trough vrmr_icmp_types until we reach the end (-1) */
    for(i=0; vrmr_icmp_types[i].type != -1; i++)
    {
        if(vrmr_icmp_types[i].type == type)
        {
            if(vrmr_icmp_types[i].has_code == 1)
            {
                /*
                    if we called with code == -1, it means we don't want to know about the code
                */
                if(code == -1)
                {
                    (void)strlcpy(name, vrmr_icmp_types[i].short_name, size);
                    return(0);
                }

                /*
                    now look for the code
                */
                for(k=0; vrmr_icmp_codes[k].type != -1; k++)
                {
                    if(vrmr_icmp_codes[k].type == type)
                    {
                        if(vrmr_icmp_codes[k].code == code)
                        {
                            if(only_code == 0)
                            {
                                snprintf(name, size, "%s(%s)", vrmr_icmp_types[i].short_name, vrmr_icmp_codes[k].short_name);
                            }
                            else
                            {
                                (void)strlcpy(name, vrmr_icmp_codes[k].short_name, size);
                            }

                            return(0);
                        }
                    }
                }
                /* if we get here, the code was not found */
                snprintf(name, size, "%s(err:%d)", vrmr_icmp_types[i].short_name, code);
                return(0);
            }
            else
            {
                (void)strlcpy(name, vrmr_icmp_types[i].short_name, size);
                return(0);
            }
        }
    }
    snprintf(name, size, "unknown icmp (%d.%d)", type, code);

    return(0);
}

// return 1 if found
//        0 if done
int list_icmp_types(int *type, int *has_code, int *number)
{
    if(vrmr_icmp_types[*number].type != -1)
    {
        //fprintf(stdout, "icmp type: %d(%d), %s\n", *type, vrmr_icmp_types[*number].type, vrmr_icmp_types[*number].short_name);

        *type = vrmr_icmp_types[*number].type;
        *has_code = vrmr_icmp_types[*number].has_code;

        *number = *number + 1;

        return(1);
    }
    else
        return(0);
}

// return 1 if found
//        0 if done
int list_icmp_codes(int type, int *code, int *number)
{
    // find the first of our type
    if(vrmr_icmp_codes[*number].type < type)
    {
        //fprintf(stdout, "find first type match\n");

        while(vrmr_icmp_codes[*number].type != type && vrmr_icmp_codes[*number].type != -1)
            *number = *number+1;

        //fprintf(stdout, "number: %d (%d %d)\n", *number, type, vrmr_icmp_codes[*number].type);
    }

    if(vrmr_icmp_codes[*number].type != -1)
    {
        //fprintf(stdout, "type match\n");

        if(vrmr_icmp_codes[*number].type == type)
        {
            *code = vrmr_icmp_codes[*number].code;

            *number = *number + 1;

            return(1);
        }

        return(0);
    }
    else
        return(0);
}

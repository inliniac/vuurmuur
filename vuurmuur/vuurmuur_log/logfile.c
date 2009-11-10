/***************************************************************************
 *   Copyright (C) 2003-2008 by Victor Julien                              *
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
#include "logfile.h"

/*  check_ipt_line

    checks if the rule is a iptables rule.
    returns 1 if yes 0 if no
    we only accept rules which contain our own 'vrmr:' prefix

    TODO: we could use a regex?
*/
int
check_ipt_line(char *line)
{
    size_t  start = 0,
            end = 0;

    search_in_ipt_line(line, LINE_START, "vrmr:", &start, &end);
    if(start == end)
        return(0);

    return(1);
}

/*  search_in_ipt_line

    Arguments:
        line:           line string
        search_start:   position in the line to start searching. Useful for
                        ommitting matching on the logprefix.
        keyword:        the keyword in the line we look for
        startpos:       pointer to the beginning of the value
        endpos:         idem, but the end

    Returncodes:
        -1: error
         0: ok
*/
int
search_in_ipt_line(char *line, size_t search_start, char *keyword, size_t *startpos, size_t *endpos)
{
    size_t  keyword_len = 0,
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

/*  parse the logline to the logrule_ptr

    Returncodes:
         1: ok
         0: invalid logline
        -1: error
*/
int
parse_ipt_logline(  const int debuglvl,
                    char *logline,
                    size_t logline_len,
                    char *sscanf_str,
                    struct log_rule *logrule_ptr,
                    struct draw_rule_format_ *rulefmt_ptr,
                    struct Counters_ *counter_ptr)
{
    int     result = 0;
    size_t  hostname_len = 0,
            pre_prefix_len = 0,
            str_begin = 0,
            str_end = 0,
            vrmr_start = 0;
    char    from_mac[18] = "",
            to_mac[18] = "";
    char    packet_len[6] = "";
    char    protocol[5] = "";
    char    port[6] = "";

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "parse_ipt_logline: start");


    /* safety first */
    if( logline == NULL || logrule_ptr == NULL || rulefmt_ptr == NULL ||
        sscanf_str == NULL || counter_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }


    memset(logrule_ptr, 0, sizeof(struct log_rule));
    memset(rulefmt_ptr, 0, sizeof(struct draw_rule_format_));

    /* get date, time, hostname */
    result = sscanf(logline, sscanf_str, logrule_ptr->month,
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

    /*  this will get us past 'kernel:' and all other stuff that might
        be in the line */
    result = search_in_ipt_line(logline, LINE_START, "vrmr:", &str_begin, &str_end);
    if(result == 0)
    {
        /*  start copying after 'vrmr:' keyword */
        str_begin = str_end = str_end + 1;
        /*  search for the end of the action (the action is a
            string with no spaces in it */
        while(  str_end < logline_len &&
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

    upd_action_ctrs (logrule_ptr->action, counter_ptr);

    hostname_len = strlen(logrule_ptr->hostname);
    if(hostname_len <= 0)
        return(-1);

    /*  get the input inferface (if any),
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
            /*  in the log for the following protocol netfilter uses the names:
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

static int
stat_logfile(const int debuglvl, const char *path, struct stat *logstat)
{
    if(path == NULL)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(lstat(path, logstat) == -1)
    {
        (void)vrprint.error(-1, VR_ERR, "lstat() on %s failed: %s (in: %s:%d).", path, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "file '%s' statted.", path);

    return(0);
}


static int
compare_logfile_stats(const int debuglvl, struct file_mon *filemon)
{
    if(filemon == NULL)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(filemon->old_file.st_size != filemon->new_file.st_size)
    {
        if(filemon->new_file.st_size == 0)
        {
            if(debuglvl >= LOW)
                (void)vrprint.debug(__FUNC__, "after reopening the systemlog the file is empty. Probably rotated.");
        }
        else if(filemon->old_file.st_size < filemon->new_file.st_size)
        {
            filemon->windback = filemon->new_file.st_size - filemon->old_file.st_size;

            if(debuglvl >= LOW)
                (void)vrprint.debug(__FUNC__, "while reopening the logfile %u bytes were added to it.", filemon->windback);
        }
        else if(filemon->old_file.st_size > filemon->new_file.st_size)
        {
            (void)vrprint.warning(VR_WARN, "possible logfile tampering detected! Please inspect the logfile.");
        }
    }
    else
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "after reopening the systemlog the files are of equal size.");
    }

    return(0);
}


static int
close_logfiles(const int debuglvl, FILE **system_log, FILE **vuurmuur_log, /*@null@*/struct file_mon *filemon)
{
    int retval = 0;

    /* close the logfiles */
    if(fclose(*vuurmuur_log) < 0)
    {
        (void)vrprint.error(-1, "Error", "closing the vuurmuur-log '%s' failed: %s.", conf.trafficlog_location, strerror(errno));
        retval = -1;
    }

    if(filemon != NULL)
    {
        (void)stat_logfile(debuglvl, conf.systemlog_location, &filemon->old_file);
    }
    
    if(fclose(*system_log) < 0)
    {
        (void)vrprint.error(-1, "Error", "closing the iptableslog '%s' failed: %s.", conf.systemlog_location, strerror(errno));
        retval = -1;
    }

    *vuurmuur_log = NULL;
    *system_log   = NULL;

    return(retval);
}


FILE *
open_logfile(const int debuglvl, const struct vuurmuur_config *cnf, const char *path, const char *mode)
{
    FILE    *fp = NULL;

    /* safety */
    if(path == NULL || mode == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    /* open the logfile */
    if(!(fp = vuurmuur_fopen(debuglvl, cnf, path, mode)))
    {
        (void)vrprint.error(-1, "Error", "the logfile '%s' could not be opened: %s (in: %s:%d).", path, strerror(errno), __FUNC__, __LINE__);
        return(NULL);
    }

    /* listen at the end of the file */
    if(fseek(fp, (off_t) 0, SEEK_END) == -1)
    {
        (void)vrprint.error(-1, "Error", "attaching to the end of the logfile failed: %s (in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(NULL);
    }

    return(fp);
}


int
open_logfiles(const int debuglvl, const struct vuurmuur_config *cnf, FILE **system_log, FILE **vuurmuur_log)
{
    /* open the system log */
    if(!(*system_log = fopen(conf.systemlog_location, "r")))
    {
        (void)vrprint.error(-1, "Error", "the systemlog '%s' could not be opened: %s (in: %s:%d).", conf.systemlog_location, strerror(errno), __FUNC__, __LINE__);

        *vuurmuur_log = NULL;
        return(-1);
    }

    /* listen at the end of the file */
    if(fseek(*system_log, (off_t) 0, SEEK_END) == -1)
    {
        (void)vrprint.error(-1, "Error", "attaching to the end of the logfile failed: %s (in: %s:%d).", strerror(errno), __FUNC__, __LINE__);

        /* close the systemlog again */
        (void)fclose(*system_log);
        *system_log = NULL;

        *vuurmuur_log = NULL;
        return(-1);
    }

    /* open the vuurmuur logfile */
    if(!(*vuurmuur_log = open_logfile(debuglvl, cnf, conf.trafficlog_location, "a")))
    {
        (void)vrprint.error(-1, "Error", "opening traffic log file '%s' failed: %s (in: %s:%d).", conf.trafficlog_location, strerror(errno), __FUNC__, __LINE__);

        /* close the systemlog again */
        (void)fclose(*system_log);
        *system_log = NULL;

        return(-1);
    }

    return(0);
}


int
reopen_logfiles(const int debuglvl, FILE **system_log, FILE **vuurmuur_log)
{
    int             waiting = 0;
    char            done = 0;
    struct file_mon filemon;
    int             result = 0;

    /* clear */
    memset(&filemon, 0, sizeof(filemon));

    /* close the logfiles */
    (void)close_logfiles(debuglvl, system_log, vuurmuur_log, &filemon);

    /*
        re-open the log, try for 5 minutes
    */
    while(done == 0 && waiting < 300)
    {
        (void)stat_logfile(debuglvl, conf.systemlog_location, &filemon.new_file);
        (void)compare_logfile_stats(debuglvl, &filemon);

        if(!(*system_log = fopen(conf.systemlog_location, "r")))
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "Re-opening iptableslog '%s' failed: %s.", conf.systemlog_location, strerror(errno));

            /* sleep and increase waitcounter */
            sleep(3);
            waiting += 3;
        }
        else
        {
            /* we're done: reset waitcounter */
            waiting = 0;
            done = 1;
        }
    }

    /* check if have successfully reopened the file */
    if(*system_log == NULL)
    {
        (void)vrprint.error(-1, "Error", "after 5 minutes of trying the iptableslog could still not be opened.");

        *system_log = NULL;
        *vuurmuur_log = NULL;

        return(-1);
    }

    /* listen at the end of the file */
    result = fseek(*system_log, (off_t) filemon.windback * -1, SEEK_END);
    if(result == -1)
    {
        (void)vrprint.error(-1, "Error", "attaching to the end of the logfile failed: %s (in: %s).", strerror(errno), __FUNC__);

        /* close the log */
        if(fclose(*system_log) < 0)
            (void)vrprint.error(-1, "Error", "closing the iptableslog '%s' failed: %s.", conf.systemlog_location, strerror(errno));

        *system_log = NULL;
        *vuurmuur_log = NULL;

        return(-1);
    }

    /* re-open the vuurmuur logfile */
    if(!(*vuurmuur_log = open_logfile(debuglvl, &conf, conf.trafficlog_location, "a")))
    {
        (void)vrprint.error(-1, "Error", "Re-opening traffic log file '%s' failed: %s.", conf.trafficlog_location, strerror(errno));

        if(fclose(*system_log) < 0)
            (void)vrprint.error(-1, "Error", "closing the iptableslog '%s' failed: %s.", conf.systemlog_location, strerror(errno));

        *system_log = NULL;

        return(-1);
    }

    return(0);
}

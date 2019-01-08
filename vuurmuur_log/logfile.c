/***************************************************************************
 *   Copyright (C) 2003-2019 by Victor Julien                              *
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

    TODO: we could use a regex or strstr?
*/
int check_ipt_line(char *line)
{
    size_t start = 0;
    size_t end = 0;

    int r = search_in_ipt_line(line, LINE_START, "vrmr:", &start, &end);
    if (r == -1 || start == end)
        return (0);

    return (1);
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
int search_in_ipt_line(char *line, size_t search_start, char *keyword,
        size_t *startpos, size_t *endpos)
{
    size_t keyword_len = 0, line_len = 0, x = 0, k = 0, startp = 0;

    if (!keyword || !line)
        return (-1);

    *startpos = 0;
    *endpos = 0;

    keyword_len = strlen(keyword);
    if (keyword_len <= 0)
        return (-1);

    line_len = strlen(line);
    if (line_len <= 0)
        return (-1);

    for (x = search_start, k = 0; x < line_len; x++) {

        // if keyword[k] is not what we expect, reset k
        if (k > 0 && k < keyword_len) {
            if (line[x] != keyword[k]) {
                k = 0;
                // fprintf(stdout, "reset\n");
            }
        }

        // if we match add to k
        if (line[x] == keyword[k]) {
            if (k == 0)
                startp = x;

            k++;
        }
    }

    if (keyword_len == k) {
        *startpos = startp;
        *endpos = startp;

        for (x = startp; line[x] != ' '; x++)
            *endpos = *endpos + 1;
    }
    // fprintf(stdout, "k: %d, keyword_len: %d, startp: %d\n", k, keyword_len,
    // startp);

    return (0);
}

/*  parse the logline to the log_record

    Returncodes:
         1: ok
         0: invalid logline
        -1: error
*/
int parse_ipt_logline(char *logline, size_t logline_len, char *sscanf_str,
        struct vrmr_log_record *log_record, struct logcounters *counter_ptr)
{
    size_t hostname_len = 0, pre_prefix_len = 0, str_begin = 0, str_end = 0,
           vrmr_start = 0;
    char from_mac[18] = "", to_mac[18] = "";
    char packet_len[6] = "";
    char protocol[5] = "";
    char port[6] = "";

    assert(logline && log_record && sscanf_str && counter_ptr);

    memset(log_record, 0, sizeof(struct vrmr_log_record));
    vrmr_debug(HIGH, "sscanf_str: %s", sscanf_str);

    /* get date, time, hostname */
    int result = sscanf(logline, sscanf_str, log_record->month,
            &log_record->day, &log_record->hour, &log_record->minute,
            &log_record->second, log_record->hostname);
    if (result < 6) {
        vrmr_debug(
                HIGH, "logline is invalid because sscanf reported an error.");
        return (0);
    }

    /*  this will get us past 'kernel:' and all other stuff that might
        be in the line */
    result = search_in_ipt_line(
            logline, LINE_START, "vrmr:", &str_begin, &str_end);
    if (result == 0) {
        /*  start copying after 'vrmr:' keyword */
        str_begin = str_end = str_end + 1;
        /*  search for the end of the action (the action is a
            string with no spaces in it */
        while (str_end < logline_len && logline[str_end] != ' ') {
            str_end++;
        }

        if (range_strcpy(log_record->action, logline, str_begin, str_end,
                    sizeof(log_record->action)) < 0) {
            return (0);
        }

        vrmr_debug(HIGH,
                "action '%s', "
                "str_begin %u, str_end %u",
                log_record->action, (unsigned int)str_begin,
                (unsigned int)str_end);

        /* the start of the prefix is the end of the action + 1 */
        pre_prefix_len = str_end + 1;
    } else {
        vrmr_error(
                -1, "Error", "Searching 'vrmr:' in iptables logline failed.");
        return (0);
    }

    hostname_len = strlen(log_record->hostname);
    if (hostname_len <= 0)
        return (-1);

    /*  get the input inferface (if any),
        we do this before the prefix because IN= should always be in
        the line and marks the end of the prefix
    */
    result = search_in_ipt_line(
            logline, pre_prefix_len, "IN=", &str_begin, &str_end);
    if (result == 0) {
        if (str_begin == str_end - strlen("IN=")) {
            memset(log_record->interface_in, 0,
                    sizeof(log_record->interface_in));
        } else if (str_begin == str_end) {
            // vrmr_error(-1, "Error", "Not a valid iptables line: No IN=
            // keyword: %s", line);
            return (0);
        } else {
            if (range_strcpy(log_record->interface_in, logline,
                        str_begin + strlen("IN="), str_end,
                        sizeof(log_record->interface_in)) < 0)
                return (0);

            snprintf(log_record->from_int, sizeof(log_record->from_int),
                    "in: %s ", log_record->interface_in);
        }
    } else {
        vrmr_error(-1, "Error", "Searching IN= in iptables logline failed.");
        return (0);
    }

    /* here we handle the user prefix */
    if (str_begin > pre_prefix_len + 1) {
        if (range_strcpy(log_record->logprefix, logline, pre_prefix_len,
                    str_begin - 1, sizeof(log_record->logprefix)) < 0)
            return (0);
    } else {
        strlcpy(log_record->logprefix, "none", sizeof(log_record->logprefix));
    }

    /* from now on, we only search after vrmr_start */
    vrmr_start = str_begin;

    /* get the output inferface (in any) */
    result = search_in_ipt_line(
            logline, vrmr_start, "OUT=", &str_begin, &str_end);
    if (result == 0) {
        if (str_begin == str_end - strlen("OUT=")) {
            memset(log_record->interface_out, 0,
                    sizeof(log_record->interface_out));
        } else if (str_begin == str_end) {
            // vrmr_error(-1, "Error", "Not a valid iptables line: No OUT=
            // keyword: %s", line);
            return (0);
        } else {
            if (range_strcpy(log_record->interface_out, logline,
                        str_begin + strlen("OUT="), str_end,
                        sizeof(log_record->interface_out)) < 0)
                return (0);

            snprintf(log_record->to_int, sizeof(log_record->to_int), "out: %s ",
                    log_record->interface_out);
        }
    } else {
        vrmr_error(-1, "Error", "Searching OUT= in iptables logline failed.");
        return (0);
    }

    /* get the source ip of the line */
    result = search_in_ipt_line(
            logline, vrmr_start, "SRC=", &str_begin, &str_end);
    if (result == 0) {
        if (str_begin == str_end - strlen("SRC=")) {
            memset(log_record->interface_in, 0,
                    sizeof(log_record->interface_in));
        } else if (str_begin == str_end) {
            // vrmr_error(-1, "Error", "Not a valid iptables line: No SRC=
            // keyword: %s", line);
            return (0);
        } else {
            if (range_strcpy(log_record->src_ip, logline,
                        str_begin + strlen("SRC="), str_end,
                        sizeof(log_record->src_ip)) < 0)
                return (0);
        }
    } else {
        vrmr_error(-1, "Error", "Searching SRC= in iptables logline failed.");
        return (0);
    }

    /* get the destination ip */
    result = search_in_ipt_line(
            logline, vrmr_start, "DST=", &str_begin, &str_end);
    if (result == 0) {
        if (str_begin == str_end - strlen("DST=")) {
            memset(log_record->interface_out, 0,
                    sizeof(log_record->interface_out));
        } else if (str_begin == str_end) {
            // vrmr_error(-1, "Error", "Not a valid iptables line: No DST=
            // keyword: %s", line);
            return (0);
        } else {
            if (range_strcpy(log_record->dst_ip, logline,
                        str_begin + strlen("DST="), str_end,
                        sizeof(log_record->dst_ip)) < 0)
                return (0);
        }
    } else {
        vrmr_error(-1, "Error", "Searching SRC= in iptables logline failed.");
        return (0);
    }

    /* get the mac (src & dst) if it exists */
    result = search_in_ipt_line(
            logline, vrmr_start, "MAC=", &str_begin, &str_end);
    if (result == 0) {
        if (str_begin == str_end - strlen("MAC=")) {
            /* keyword exists, but no data */
            memset(log_record->src_mac, 0, sizeof(log_record->src_mac));
            memset(log_record->dst_mac, 0, sizeof(log_record->dst_mac));
        } else if (str_begin == str_end) {
            /* keyword not found - not an error for MAC */
            memset(log_record->src_mac, 0, sizeof(log_record->src_mac));
            memset(log_record->dst_mac, 0, sizeof(log_record->dst_mac));
        } else {
            if (range_strcpy(to_mac, logline, str_begin + strlen("MAC="),
                        str_begin + strlen("MAC=") + 17, sizeof(to_mac)) < 0)
                return (0);
            else {
                if (range_strcpy(from_mac, logline,
                            str_begin + strlen("MAC=") + 18,
                            str_begin + strlen("MAC=") + 35,
                            sizeof(from_mac)) < 0)
                    return (0);
            }

            if (snprintf(log_record->src_mac, sizeof(log_record->src_mac),
                        "(%s)", from_mac) >= (int)sizeof(log_record->src_mac)) {
                vrmr_error(-1, "Error", "overflow in src_mac string");
                return (0);
            }

            if (snprintf(log_record->dst_mac, sizeof(log_record->dst_mac),
                        "(%s)", to_mac) >= (int)sizeof(log_record->dst_mac)) {
                vrmr_error(-1, "Error", "overflow in dst_mac string");
                return (0);
            }
        }
    } else {
        vrmr_error(-1, "Error", "Searching MAC= in iptables logline failed.");
        return (0);
    }

    /*
        get the packet length
    */
    result = search_in_ipt_line(
            logline, vrmr_start, "LEN=", &str_begin, &str_end);
    if (result == 0) {
        if (str_begin == str_end - strlen("LEN=")) {
            /* no length */
            log_record->packet_len = 0;
        }
        /* no len keyword */
        else if (str_begin == str_end) {
            vrmr_debug(HIGH, "No LEN keyword: no valid logline.");
            return (0);
        }
        /* if len is too long (4: LEN=, 5: 12345 max */
        else if (str_end > str_begin + (4 + 5)) {
            vrmr_debug(HIGH, "LEN too long: no valid logline.");
            return (0);
        } else {
            if (range_strcpy(packet_len, logline, str_begin + strlen("LEN="),
                        str_end, sizeof(packet_len)) < 0) {
                vrmr_debug(HIGH, "LEN: lenght copy failed: no valid logline.");
                return (0);
            } else {
                log_record->packet_len = (unsigned int)atoi(packet_len);
            }
        }
    } else {
        vrmr_error(-1, "Error", "Searching LEN= in iptables logline failed.");
        return (0);
    }

    /*
        get the packet ttl
    */
    result = search_in_ipt_line(
            logline, vrmr_start, "TTL=", &str_begin, &str_end);
    if (result == 0) {
        if (str_begin == str_end - strlen("TTL=")) {
            /* no length */
            log_record->ttl = 0;
        }
        /* no ttl keyword */
        else if (str_begin == str_end) {
            vrmr_debug(HIGH, "No TTL keyword: no valid logline.");
            return (0);
        }
        /* if len is too long (4: TTL=, 5: 12345 max */
        else if (str_end > str_begin + (4 + 5)) {
            vrmr_debug(HIGH, "TTL too long: no valid logline.");
            return (0);
        } else {
            if (range_strcpy(packet_len, logline, str_begin + strlen("TTL="),
                        str_end, sizeof(packet_len)) < 0) {
                vrmr_debug(HIGH, "TTL: lenght copy failed: no valid logline.");
                return (0);
            } else {
                log_record->ttl = (unsigned int)atoi(packet_len);
            }
        }
    } else {
        vrmr_error(-1, "Error", "Searching TTL= in iptables logline failed.");
        return (0);
    }

    /*
        get the protocol
    */
    result = search_in_ipt_line(
            logline, vrmr_start, "PROTO=", &str_begin, &str_end);
    if (result == 0) {
        if (str_begin == str_end - strlen("PROTO=")) {
            /* no proto */
            log_record->protocol = -1;
        }
        /* no proto keyword */
        else if (str_begin == str_end) {
            // vrmr_error(-1, "Error", "Not a valid iptables line: No PROTO=
            // keyword: %s", line);
            return (0);
        }
        /* if proto is too long (6: PROTO=, 4: ICMP max) */
        else if (str_end > str_begin + 6 + 4) {
            // vrmr_error(-1, "Error", "Not a valid iptables line: PROTO= value
            // is too long: %s", line);
            return (0);
        } else {
            /*  in the log for the following protocol netfilter uses the names:
                tcp,udp,icmp,ah,esp, for the rest numbers
            */
            if (range_strcpy(protocol, logline, str_begin + strlen("PROTO="),
                        str_end, sizeof(protocol)) < 0) {
                return (0);
            } else {
                if (strcasecmp(protocol, "tcp") == 0) {
                    log_record->protocol = 6;
                    counter_ptr->tcp++;
                } else if (strcasecmp(protocol, "udp") == 0) {
                    log_record->protocol = 17;
                    counter_ptr->udp++;
                } else if (strcasecmp(protocol, "icmp") == 0) {
                    log_record->protocol = 1;
                    counter_ptr->icmp++;
                } else if (strcasecmp(protocol, "ah") == 0) {
                    log_record->protocol = 51;
                    counter_ptr->other_proto++;
                } else if (strcasecmp(protocol, "esp") == 0) {
                    log_record->protocol = 50;
                    counter_ptr->other_proto++;
                } else {
                    log_record->protocol = atoi(protocol);
                    counter_ptr->other_proto++;
                }
            }

            /* protocol numbers bigger than 255 are not allowed */
            if (log_record->protocol < 1 || log_record->protocol > 255) {
                return (0);
            }
        }
    } else {
        vrmr_error(-1, "Error", "Searching PROTO= in iptables logline failed.");
        return (0);
    }

    /*
        ports TODO: all protocols except tcp,udp,icmp
    */

    /* tcp & udp */
    if (log_record->protocol == 6 || log_record->protocol == 17) {
        // set icmp to unused
        log_record->icmp_type = -1;
        log_record->icmp_code = -1;

        /*
            get the source port
        */
        result = search_in_ipt_line(
                logline, vrmr_start, "SPT=", &str_begin, &str_end);
        if (result == 0) {
            /* if the SPT= part is the only part */
            if (str_begin == str_end - strlen("SPT=")) {
                /* do ehhh, basicly nothing ;-) */
            }
            /* if the length of SPT=xxxxx is longer than expected */
            else if (str_end > str_begin + 4 + 5) {
                return (0);
            } else {
                if (range_strcpy(port, logline, str_begin + strlen("SPT="),
                            str_end, sizeof(port)) < 0) {
                    return (0);
                } else {
                    log_record->src_port = atoi(port);

                    if (!vrmr_valid_tcpudp_port(log_record->src_port)) {
                        return (0);
                    }
                }
            }
        } else {
            vrmr_error(
                    -1, "Error", "Searching SPT= in iptables logline failed.");
            return (0);
        }

        /*
            now the dst port
        */
        result = search_in_ipt_line(
                logline, vrmr_start, "DPT=", &str_begin, &str_end);
        if (result == 0) {
            /* if the DPT= part is the only part */
            if (str_begin == str_end - strlen("DPT=")) {
                /* do ehhh, basicly nothing ;-) */
            }
            /* if the length of DPT=xxxxx is longer than expected */
            else if (str_end > str_begin + 4 + 5) {
                return (0);
            } else {
                memset(port, 0, sizeof(port));

                if (range_strcpy(port, logline, str_begin + strlen("DPT="),
                            str_end, sizeof(port)) < 0) {
                    return (0);
                } else {
                    log_record->dst_port = atoi(port);

                    if (!vrmr_valid_tcpudp_port(log_record->dst_port)) {
                        return (0);
                    }
                }
            }
        } else {
            vrmr_error(
                    -1, "Error", "Searching DPT= in iptables logline failed.");
            return (0);
        }

        /* now look for tcp-options */
        if (log_record->protocol == 6) {
            /*
                get the SYN flag
            */
            result = search_in_ipt_line(
                    logline, vrmr_start, "SYN", &str_begin, &str_end);
            if (result == 0) {
                /* if the SYN part is the only part we are cool */
                if (str_begin == str_end - strlen("SYN")) {
                    log_record->syn = 1;
                }
                /* if the length of SYN is longer than expected */
                else if (str_end > str_begin + strlen("SYN")) {
                    return (0);
                } else {
                    log_record->syn = 0;
                }
            } else {
                vrmr_error(-1, "Error",
                        "Searching SYN in iptables logline failed.");
                return (0);
            }
            /*
                get the FIN flag
            */
            result = search_in_ipt_line(
                    logline, vrmr_start, "FIN", &str_begin, &str_end);
            if (result == 0) {
                /* if the FIN part is the only part we are cool */
                if (str_begin == str_end - strlen("FIN")) {
                    log_record->fin = 1;
                }
                /* if the length of FIN is longer than expected */
                else if (str_end > str_begin + strlen("FIN")) {
                    return (0);
                } else {
                    log_record->fin = 0;
                }
            } else {
                vrmr_error(-1, "Error",
                        "Searching FIN in iptables logline failed.");
                return (0);
            }
            /*
                get the RST flag
            */
            result = search_in_ipt_line(
                    logline, vrmr_start, "RST", &str_begin, &str_end);
            if (result == 0) {
                /* if the RST part is the only part we are cool */
                if (str_begin == str_end - strlen("RST")) {
                    log_record->rst = 1;
                }
                /* if the length of RST is longer than expected */
                else if (str_end > str_begin + strlen("RST")) {
                    return (0);
                } else {
                    log_record->rst = 0;
                }
            } else {
                vrmr_error(-1, "Error",
                        "Searching RST in iptables logline failed.");
                return (0);
            }
            /*
                get the ACK flag
            */
            result = search_in_ipt_line(
                    logline, vrmr_start, "ACK", &str_begin, &str_end);
            if (result == 0) {
                /* if the ACK part is the only part we are cool */
                if (str_begin == str_end - strlen("ACK")) {
                    log_record->ack = 1;
                }
                /* if the length of ACK is longer than expected */
                else if (str_end > str_begin + strlen("ACK")) {
                    return (0);
                } else {
                    log_record->ack = 0;
                }
            } else {
                vrmr_error(-1, "Error",
                        "Searching ACK in iptables logline failed.");
                return (0);
            }
            /*
                get the PSH flag
            */
            result = search_in_ipt_line(
                    logline, vrmr_start, "PSH", &str_begin, &str_end);
            if (result == 0) {
                /* if the PSH part is the only part we are cool */
                if (str_begin == str_end - strlen("PSH")) {
                    log_record->psh = 1;
                }
                /* if the length of PSH is longer than expected */
                else if (str_end > str_begin + strlen("PSH")) {
                    return (0);
                } else {
                    log_record->psh = 0;
                }
            } else {
                vrmr_error(-1, "Error",
                        "Searching PSH in iptables logline failed.");
                return (0);
            }
            /*
                get the URG flag

                Please note that we look for 'URG ' (inlcuding space) so we
               don't get confused with URGP.
            */
            result = search_in_ipt_line(
                    logline, vrmr_start, "URG ", &str_begin, &str_end);
            if (result == 0) {
                /* if the URG part is the only part we are cool */
                if (str_begin == str_end - strlen("URG ")) {
                    log_record->urg = 1;
                }
                /* if the length of URG is longer than expected */
                else if (str_end > str_begin + strlen("URG ")) {
                    return (0);
                } else {
                    log_record->urg = 0;
                }
            } else {
                vrmr_error(-1, "Error",
                        "Searching URG in iptables logline failed.");
                return (0);
            }
        }
    }

    /* icmp */
    else if (log_record->protocol == 1) {
        /* no 'normal' ports, set to unused */
        log_record->src_port = -1;
        log_record->dst_port = -1;

        /*
            get the ICMP TYPE
        */
        result = search_in_ipt_line(
                logline, vrmr_start, "TYPE=", &str_begin, &str_end);
        if (result == 0) {
            if (str_begin == str_end - strlen("TYPE=")) {
                // TODO: is this true?
                /* we dont NEED the type */
            } else {
                memset(port, 0, sizeof(port));

                if (range_strcpy(port, logline, str_begin + strlen("TYPE="),
                            str_end, sizeof(port)) < 0) {
                    return (0);
                } else {
                    // TODO: check number
                    log_record->icmp_type = atoi(port);
                    log_record->src_port = log_record->icmp_type;
                }
            }
        } else {
            vrmr_error(
                    -1, "Error", "Searching TYPE= in iptables logline failed.");
            return (0);
        }

        /*
            get the ICMP CODE
        */
        result = search_in_ipt_line(
                logline, vrmr_start, "CODE=", &str_begin, &str_end);
        if (result == 0) {
            if (str_begin == str_end - strlen("CODE=")) {
                /* we dont _need_ the code */
            } else {
                memset(port, 0, sizeof(port));

                if (range_strcpy(port, logline, str_begin + strlen("CODE="),
                            str_end, sizeof(port)) < 0) {
                    return (0);
                } else {
                    // TODO: check code
                    log_record->icmp_code = atoi(port);
                    log_record->dst_port = log_record->icmp_code;
                }
            }
        } else {
            vrmr_error(
                    -1, "Error", "Searching CODE= in iptables logline failed.");
            return (0);
        }
    } else if (log_record->protocol == 0) {
        return (0);
    } /* end ports */

    /* if we reach this, it's a valid logline */
    return (1);
}

static int stat_logfile(const char *path, struct stat *logstat)
{
    assert(path);

    if (lstat(path, logstat) == -1) {
        vrmr_error(
                -1, VR_ERR, "lstat() on %s failed: %s", path, strerror(errno));
        return (-1);
    }

    vrmr_debug(NONE, "file '%s' statted.", path);
    return (0);
}

static int compare_logfile_stats(struct file_mon *filemon)
{
    assert(filemon);

    if (filemon->old_file.st_size != filemon->new_file.st_size) {
        if (filemon->new_file.st_size == 0) {
            vrmr_debug(LOW, "after reopening the systemlog the file is empty. "
                            "Probably rotated.");
        } else if (filemon->old_file.st_size < filemon->new_file.st_size) {
            filemon->windback =
                    filemon->new_file.st_size - filemon->old_file.st_size;
            vrmr_debug(LOW,
                    "while reopening the logfile %ld bytes were added to it.",
                    filemon->windback);
        } else if (filemon->old_file.st_size > filemon->new_file.st_size) {
            vrmr_warning(VR_WARN, "possible logfile tampering detected! Please "
                                  "inspect the logfile.");
        }
    } else {
        vrmr_debug(HIGH,
                "after reopening the systemlog the files are of equal size.");
    }

    return (0);
}

static int close_syslog(const struct vrmr_config *conf, FILE **system_log,
        /*@null@*/ struct file_mon *filemon)
{
    int retval = 0;

    if (filemon != NULL) {
        vrmr_debug(NONE, "Calling stat_logfile");
        (void)stat_logfile(conf->systemlog_location, &filemon->old_file);
        vrmr_debug(NONE, "Done stat_logfile");
    }

    if (fclose(*system_log) < 0) {
        vrmr_error(-1, "Error", "closing the iptableslog '%s' failed: %s.",
                conf->systemlog_location, strerror(errno));
        retval = -1;
    }

    *system_log = NULL;

    vrmr_debug(NONE, "Closed syslog");
    return (retval);
}

static int close_vuurmuurlog(
        const struct vrmr_config *conf, FILE **vuurmuur_log)
{
    int retval = 0;

    /* close the logfiles */
    if (fclose(*vuurmuur_log) < 0) {
        vrmr_error(-1, "Error", "closing the vuurmuur-log '%s' failed: %s.",
                conf->trafficlog_location, strerror(errno));
        retval = -1;
    }

    *vuurmuur_log = NULL;

    return (retval);
}

FILE *open_logfile(
        const struct vrmr_config *cnf, const char *path, const char *mode)
{
    FILE *fp = NULL;

    assert(path && mode);

    /* open the logfile */
    if (!(fp = vuurmuur_fopen(cnf, path, mode))) {
        vrmr_error(-1, "Error", "the logfile '%s' could not be opened: %s",
                path, strerror(errno));
        return (NULL);
    }

    /* listen at the end of the file */
    if (fseek(fp, (off_t)0, SEEK_END) == -1) {
        vrmr_error(-1, "Error",
                "attaching to the end of the logfile failed: %s",
                strerror(errno));
        fclose(fp);
        return (NULL);
    }

    return (fp);
}

int open_syslog(const struct vrmr_config *cnf, FILE **system_log)
{
    /* open the system log */
    if (!(*system_log = fopen(cnf->systemlog_location, "r"))) {
        vrmr_error(-1, "Error", "the systemlog '%s' could not be opened: %s",
                cnf->systemlog_location, strerror(errno));
        return (-1);
    }

    /* listen at the end of the file */
    if (fseek(*system_log, (off_t)0, SEEK_END) == -1) {
        vrmr_error(-1, "Error",
                "attaching to the end of the logfile failed: %s",
                strerror(errno));

        /* close the systemlog again */
        (void)fclose(*system_log);
        *system_log = NULL;
        return (-1);
    }

    return (0);
}

int open_vuurmuurlog(const struct vrmr_config *cnf, FILE **vuurmuur_log)
{
    /* open the vuurmuur logfile */
    if (!(*vuurmuur_log = open_logfile(cnf, cnf->trafficlog_location, "a"))) {
        vrmr_error(-1, "Error", "opening traffic log file '%s' failed: %s",
                cnf->trafficlog_location, strerror(errno));
        return (-1);
    }
    return (0);
}

int reopen_syslog(const struct vrmr_config *cnf, FILE **system_log)
{
    int waiting = 0;
    char done = 0;
    struct file_mon filemon;

    /* clear */
    memset(&filemon, 0, sizeof(filemon));

    vrmr_debug(NONE, "Reopening syslog files");

    /* close the logfiles */
    (void)close_syslog(cnf, system_log, &filemon);

    /*
        re-open the log, try for 5 minutes
    */
    while (done == 0 && waiting < 300) {
        (void)stat_logfile(cnf->systemlog_location, &filemon.new_file);
        (void)compare_logfile_stats(&filemon);

        if (!(*system_log = fopen(cnf->systemlog_location, "r"))) {
            vrmr_debug(LOW, "Re-opening iptableslog '%s' failed: %s.",
                    cnf->systemlog_location, strerror(errno));

            /* sleep and increase waitcounter */
            sleep(3);
            waiting += 3;
        } else {
            /* we're done: reset waitcounter */
            waiting = 0;
            done = 1;
        }
    }

    /* check if have successfully reopened the file */
    if (*system_log == NULL) {
        vrmr_error(-1, "Error",
                "after 5 minutes of trying the iptableslog could still not be "
                "opened.");
        *system_log = NULL;
        return (-1);
    }

    /* listen at the end of the file */
    int result = fseek(*system_log, (off_t)filemon.windback * -1, SEEK_END);
    if (result == -1) {
        vrmr_error(-1, "Error",
                "attaching to the end of the logfile failed: %s",
                strerror(errno));

        /* close the log */
        if (fclose(*system_log) < 0)
            vrmr_error(-1, "Error", "closing the iptableslog '%s' failed: %s.",
                    cnf->systemlog_location, strerror(errno));

        *system_log = NULL;

        return (-1);
    }

    vrmr_debug(NONE, "Reopened syslog files");
    return (0);
}

int reopen_vuurmuurlog(const struct vrmr_config *cnf, FILE **vuurmuur_log)
{
    vrmr_debug(NONE, "Reopening vuurmuur log");

    /* close the logfiles */
    (void)close_vuurmuurlog(cnf, vuurmuur_log);

    /* re-open the vuurmuur logfile */
    if (!(*vuurmuur_log = open_logfile(cnf, cnf->trafficlog_location, "a"))) {
        vrmr_error(-1, "Error", "Re-opening traffic log file '%s' failed: %s.",
                cnf->trafficlog_location, strerror(errno));
        return (-1);
    }

    vrmr_debug(NONE, "Done reopening");
    return (0);
}

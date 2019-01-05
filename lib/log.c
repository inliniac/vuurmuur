/***************************************************************************
 *   Copyright (C) 2002-2017 by Victor Julien                              *
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

#include "config.h"
#include "vuurmuur.h"

int vrmr_logprint(char *logfile, char *logstring)
{
    int retval = 0;
    pid_t pid;
    time_t td;
    struct tm *dcp;
    FILE *fp;

    pid = getpid();
    (void)time(&td);
    dcp = localtime(&td);

    if (logfile == NULL || strlen(logfile) == 0) {
        fprintf(stdout, "Invalid logpath '%s' (%p).\n", logfile,
                (void *)logfile);
        return (-1);
    }

    fp = fopen(logfile, "a");
    if (!fp) {
        fprintf(stdout, "Error opening logfile '%s', %s.\n", logfile,
                strerror(errno));
        return (-1);
    }

    fprintf(fp, "%02d/%02d/%04d %02d:%02d:%02d : PID %-5d : %-13s : %s\n",
            dcp->tm_mon + 1,     // Month
            dcp->tm_mday,        // Day
            dcp->tm_year + 1900, // Year
            dcp->tm_hour,        // Hour
            dcp->tm_min,         // Minute
            dcp->tm_sec,         // Second
            pid,                 /* process id */
            vrprint.logger,      /* the name of the logger */
            logstring);

    fflush(fp);
    fclose(fp);

    return (retval);
}

int vrmr_logprint_error(int errorlevel, char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s (%d): %s", head, errorlevel,
            long_str);

    /* print in the error log */
    vrmr_logprint(vrprint.errorlog, prnt_str);
    /* and in the info log */
    vrmr_logprint(vrprint.infolog, prnt_str);

    return (0);
}

int vrmr_logprint_warning(char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);

    /* now print in the warning log */
    vrmr_logprint(vrprint.infolog, prnt_str);

    return (0);
}

int vrmr_logprint_info(char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);

    vrmr_logprint(vrprint.infolog, prnt_str);
    return (0);
}

int vrmr_logprint_audit(char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s : %s", vrprint.username, long_str);

    vrmr_logprint(vrprint.auditlog, prnt_str);
    return (0);
}

int vrmr_logprint_debug(char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    if (head != NULL)
        snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);
    else
        (void)strlcpy(prnt_str, long_str, sizeof(prnt_str));

    /* print in the debug log */
    vrmr_logprint(vrprint.debuglog, prnt_str);
    return (0);
}

int vrmr_stdoutprint_error(int errorlevel, char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s (%d): %s\n", head, errorlevel, long_str);
    fflush(stdout);

    return (0);
}

int vrmr_stdoutprint_warning(char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s: %s\n", head, long_str);
    fflush(stdout);

    return (0);
}

int vrmr_stdoutprint_info(char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s: %s\n", head, long_str);
    fflush(stdout);

    return (0);
}

int vrmr_stdoutprint_audit(char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s : %s\n", vrprint.username, long_str);
    fflush(stdout);

    return (0);
}

int vrmr_stdoutprint_debug(char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    if (head != NULL)
        fprintf(stdout, "%s: %s\n", head, long_str);
    else
        fprintf(stdout, "%s\n", long_str);

    fflush(stdout);

    return (0);
}

int vrmr_logstdoutprint_error(int errorlevel, char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s (%d): %s", head, errorlevel,
            long_str);

    /* print in the error log */
    vrmr_logprint(vrprint.errorlog, prnt_str);
    /* and in the info log */
    vrmr_logprint(vrprint.infolog, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return (0);
}

int vrmr_logstdoutprint_warning(char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);

    /* now print in the warning log */
    vrmr_logprint(vrprint.infolog, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return (0);
}

int vrmr_logstdoutprint_info(char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);

    vrmr_logprint(vrprint.infolog, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return (0);
}

int vrmr_logstdoutprint_audit(char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s : %s", vrprint.username, long_str);

    vrmr_logprint(vrprint.auditlog, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return (0);
}

int vrmr_logstdoutprint_debug(char *head, char *fmt, ...)
{
    va_list ap;
    char long_str[VRMR_MAX_LOGRULE_SIZE] = "",
         prnt_str[VRMR_MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    if (head != NULL)
        snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);
    else
        (void)strlcpy(prnt_str, long_str, sizeof(prnt_str));

    /* print in the debug log */
    vrmr_logprint(vrprint.debuglog, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return (0);
}

/* Input is packet and an seven-byte (including NULL) character array.  Results
 * are put into the character array.
 *
 * Shamelessly ripped from snort_inline 2.2.0 (c) Martin Roesch
 */
static void vrmr_log_record_create_tcp_flags(
        struct vrmr_log_record *log_record, char *flagBuffer)
{
    /* parse TCP flags */
    *flagBuffer++ = (char)(log_record->urg ? 'U' : '*');
    *flagBuffer++ = (char)(log_record->ack ? 'A' : '*');
    *flagBuffer++ = (char)(log_record->psh ? 'P' : '*');
    *flagBuffer++ = (char)(log_record->rst ? 'R' : '*');
    *flagBuffer++ = (char)(log_record->syn ? 'S' : '*');
    *flagBuffer++ = (char)(log_record->fin ? 'F' : '*');
    *flagBuffer = '\0';
}

/*
    get the vuurmuurnames with the ips and ports

    Returncodes:
         1: ok
         0: logline not ok
        -1: internal error

    NOTE: if the function returns -1 the memory is not cleaned up: the program
   is supposed to exit
*/
int vrmr_log_record_get_names(struct vrmr_log_record *log_record,
        struct vrmr_hash_table *zone_hash, struct vrmr_hash_table *service_hash)
{
    struct vrmr_zone *zone = NULL;
    struct vrmr_service *service = NULL;

    assert(log_record && zone_hash && service_hash);

    /* no support in looking up hosts, services, etc yet */
    if (log_record->ipv6 == 1) {
        if (strlcpy(log_record->from_name, log_record->src_ip,
                    sizeof(log_record->from_name)) >=
                sizeof(log_record->from_name))
            vrmr_error(-1, "Error", "buffer overflow attempt");
        if (strlcpy(log_record->to_name, log_record->dst_ip,
                    sizeof(log_record->to_name)) >= sizeof(log_record->to_name))
            vrmr_error(-1, "Error", "buffer overflow attempt");
    } else {
        /* search in the hash with the ipaddress */
        if (!(zone = vrmr_search_zone_in_hash_with_ipv4(
                      log_record->src_ip, zone_hash))) {
            /* not found in hash */
            if (strlcpy(log_record->from_name, log_record->src_ip,
                        sizeof(log_record->from_name)) >=
                    sizeof(log_record->from_name))
                vrmr_error(-1, "Error", "buffer overflow attempt");
        } else {
            /* found in the hash */
            if (strlcpy(log_record->from_name, zone->name,
                        sizeof(log_record->from_name)) >=
                    sizeof(log_record->from_name))
                vrmr_error(-1, "Error", "buffer overflow attempt");

            if (zone->type == VRMR_TYPE_NETWORK)
                strlcpy(log_record->from_name, "firewall",
                        sizeof(log_record->from_name));
        }
        zone = NULL;

        /*  do it all again for TO */
        if (!(zone = vrmr_search_zone_in_hash_with_ipv4(
                      log_record->dst_ip, zone_hash))) {
            /* not found in hash */
            if (strlcpy(log_record->to_name, log_record->dst_ip,
                        sizeof(log_record->to_name)) >=
                    sizeof(log_record->to_name))
                vrmr_error(-1, "Error", "buffer overflow attempt");
        } else {
            /* found in the hash */
            if (strlcpy(log_record->to_name, zone->name,
                        sizeof(log_record->to_name)) >=
                    sizeof(log_record->to_name))
                vrmr_error(-1, "Error", "buffer overflow attempt");

            if (zone->type == VRMR_TYPE_NETWORK)
                strlcpy(log_record->to_name, "firewall",
                        sizeof(log_record->to_name));
        }
        zone = NULL;
    }

    /*
        THE SERVICE
    */

    /*  icmp is treated different because of the type and code
        and we can call vrmr_get_icmp_name_short.
    */
    if (log_record->protocol == 1 || log_record->protocol == 58) {
        if (!(service = vrmr_search_service_in_hash(log_record->icmp_type,
                      log_record->icmp_code, log_record->protocol,
                      service_hash))) {
            /* not found in hash */
            snprintf(log_record->ser_name, sizeof(log_record->ser_name),
                    "%d.%d(icmp)", log_record->icmp_type,
                    log_record->icmp_code);

            /* try to get the icmp-names */
            if (vrmr_get_icmp_name_short(log_record->icmp_type,
                        log_record->icmp_code, log_record->ser_name,
                        sizeof(log_record->ser_name), 0) < 0) {
                vrmr_error(-1, "Internal Error",
                        "vrmr_get_icmp_name_short failed");
                return (-1);
            }
        } else {
            /* found in the hash, now copy the name */
            if (strlcpy(log_record->ser_name, service->name,
                        sizeof(log_record->ser_name)) >=
                    sizeof(log_record->ser_name))
                vrmr_error(-1, "Error", "buffer overflow attempt");
        }
    } else {
        /*  here we handle the rest */

        /* first a normal search */
        if (!(service = vrmr_search_service_in_hash(log_record->src_port,
                      log_record->dst_port, log_record->protocol,
                      service_hash))) {
            /* only do the reverse check for tcp and udp */
            if (log_record->protocol == 6 || log_record->protocol == 17) {
                /* not found, do a reverse search */
                if (!(service = vrmr_search_service_in_hash(
                              log_record->dst_port, log_record->src_port,
                              log_record->protocol, service_hash))) {
                    /* not found in the hash */
                    if (log_record->protocol == 6) /* tcp */
                    {
                        snprintf(log_record->ser_name,
                                sizeof(log_record->ser_name), "%d->%d(tcp)",
                                log_record->src_port, log_record->dst_port);
                    } else if (log_record->protocol == 17) /* udp */
                    {
                        snprintf(log_record->ser_name,
                                sizeof(log_record->ser_name), "%d->%d(udp)",
                                log_record->src_port, log_record->dst_port);
                    }
                } else {
                    /* found in the hash! (reverse) */
                    if (strlcpy(log_record->ser_name, service->name,
                                sizeof(log_record->ser_name)) >=
                            sizeof(log_record->ser_name))
                        vrmr_error(-1, "Error", "buffer overflow attempt");
                }
            } else {
                if (log_record->dst_port == 0 && log_record->src_port == 0)
                    snprintf(log_record->ser_name, sizeof(log_record->ser_name),
                            "proto-%d", log_record->protocol);
                else
                    snprintf(log_record->ser_name, sizeof(log_record->ser_name),
                            "%d*%d(%d)", log_record->src_port,
                            log_record->dst_port, log_record->protocol);
            }
        } else {
            /* found in the hash! */
            if (strlcpy(log_record->ser_name, service->name,
                        sizeof(log_record->ser_name)) >=
                    sizeof(log_record->ser_name))
                vrmr_error(-1, "Error", "buffer overflow attempt");
        }
    }

    return (1);
}

int vrmr_log_record_build_line(
        struct vrmr_log_record *log_record, char *outline, size_t size)
{
    /* TCP */
    switch (log_record->protocol) {
        case 6: /* TCP */
            vrmr_log_record_create_tcp_flags(log_record, log_record->tcpflags);
            snprintf(outline, size,
                    "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, "
                    "prefix: \"%s\" (%s%s%s%s:%d -> %s%s:%d TCP flags: %s "
                    "len:%u ttl:%u)\n",
                    log_record->month, log_record->day, log_record->hour,
                    log_record->minute, log_record->second, log_record->action,
                    log_record->ser_name, log_record->from_name,
                    log_record->to_name, log_record->logprefix,
                    log_record->from_int, log_record->to_int,
                    log_record->src_ip, log_record->src_mac,
                    log_record->src_port, log_record->dst_ip,
                    log_record->dst_mac, log_record->dst_port,
                    log_record->tcpflags, log_record->packet_len,
                    log_record->ttl);
            break;
        case 17: /* UDP */
            snprintf(outline, size,
                    "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, "
                    "prefix: \"%s\" (%s%s%s%s:%d -> %s%s:%d UDP len:%u "
                    "ttl:%u)\n",
                    log_record->month, log_record->day, log_record->hour,
                    log_record->minute, log_record->second, log_record->action,
                    log_record->ser_name, log_record->from_name,
                    log_record->to_name, log_record->logprefix,
                    log_record->from_int, log_record->to_int,
                    log_record->src_ip, log_record->src_mac,
                    log_record->src_port, log_record->dst_ip,
                    log_record->dst_mac, log_record->dst_port,
                    log_record->packet_len, log_record->ttl);
            break;
        case 1: /* ICMP */
            snprintf(outline, size,
                    "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, "
                    "prefix: \"%s\" (%s%s%s%s -> %s%s ICMP type %d code %d "
                    "len:%u ttl:%u)\n",
                    log_record->month, log_record->day, log_record->hour,
                    log_record->minute, log_record->second, log_record->action,
                    log_record->ser_name, log_record->from_name,
                    log_record->to_name, log_record->logprefix,
                    log_record->from_int, log_record->to_int,
                    log_record->src_ip, log_record->src_mac, log_record->dst_ip,
                    log_record->dst_mac, log_record->icmp_type,
                    log_record->icmp_code, log_record->packet_len,
                    log_record->ttl);
            // log_record->tcpflags, log_record->packet_len, log_record->ttl);
            break;
        case 47: /* GRE */
            snprintf(outline, size,
                    "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, "
                    "prefix: \"%s\" (%s%s%s%s -> %s%s GRE len:%u ttl:%u)\n",
                    log_record->month, log_record->day, log_record->hour,
                    log_record->minute, log_record->second, log_record->action,
                    log_record->ser_name, log_record->from_name,
                    log_record->to_name, log_record->logprefix,
                    log_record->from_int, log_record->to_int,
                    log_record->src_ip, log_record->src_mac, log_record->dst_ip,
                    log_record->dst_mac, log_record->packet_len,
                    log_record->ttl);
            break;
        case 50: /* ESP */
            snprintf(outline, size,
                    "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, "
                    "prefix: \"%s\" (%s%s%s%s -> %s%s ESP len:%u ttl:%u)\n",
                    log_record->month, log_record->day, log_record->hour,
                    log_record->minute, log_record->second, log_record->action,
                    log_record->ser_name, log_record->from_name,
                    log_record->to_name, log_record->logprefix,
                    log_record->from_int, log_record->to_int,
                    log_record->src_ip, log_record->src_mac, log_record->dst_ip,
                    log_record->dst_mac, log_record->packet_len,
                    log_record->ttl);
            break;
        case 51: /* AH */
            snprintf(outline, size,
                    "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, "
                    "prefix: \"%s\" (%s%s%s%s -> %s%s AH len:%u ttl:%u)\n",
                    log_record->month, log_record->day, log_record->hour,
                    log_record->minute, log_record->second, log_record->action,
                    log_record->ser_name, log_record->from_name,
                    log_record->to_name, log_record->logprefix,
                    log_record->from_int, log_record->to_int,
                    log_record->src_ip, log_record->src_mac, log_record->dst_ip,
                    log_record->dst_mac, log_record->packet_len,
                    log_record->ttl);
            break;
        case 58: /* ICMPv6 */
            snprintf(outline, size,
                    "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, "
                    "prefix: \"%s\" (%s%s%s%s -> %s%s ICMPv6 type %d code %d "
                    "len:%u ttl:%u)\n",
                    log_record->month, log_record->day, log_record->hour,
                    log_record->minute, log_record->second, log_record->action,
                    log_record->ser_name, log_record->from_name,
                    log_record->to_name, log_record->logprefix,
                    log_record->from_int, log_record->to_int,
                    log_record->src_ip, log_record->src_mac, log_record->dst_ip,
                    log_record->dst_mac, log_record->icmp_type,
                    log_record->icmp_code, log_record->packet_len,
                    log_record->ttl);
            break;
        default:
            snprintf(outline, size,
                    "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, "
                    "prefix: \"%s\" (%s%s%s%s -> %s%s PROTO %d len:%u "
                    "ttl:%u)\n",
                    log_record->month, log_record->day, log_record->hour,
                    log_record->minute, log_record->second, log_record->action,
                    log_record->ser_name, log_record->from_name,
                    log_record->to_name, log_record->logprefix,
                    log_record->from_int, log_record->to_int,
                    log_record->src_ip, log_record->src_mac, log_record->dst_ip,
                    log_record->dst_mac, log_record->protocol,
                    log_record->packet_len, log_record->ttl);

            vrmr_debug(LOW, "unknown protocol");
            break;
    }

    return (0);
}

void vrmr_log_record_parse_prefix(
        struct vrmr_log_record *log_record, char *prefix)
{
    char *needle;
    size_t i;

    if (prefix != NULL && strlen(prefix) > 6) {
        needle = strstr(prefix, "vrmr: ");
        if (needle != NULL) {
            needle += 6;

            i = 0;
            while (*needle != '\0' && *needle != ' ') {
                if (i < (sizeof(log_record->action) - 1))
                    log_record->action[i++] = *needle;

                needle++;
            }
            log_record->action[i] = '\0';

            if (strlen(log_record->action) == 0) {
                strlcpy(log_record->action, "<unknown>",
                        sizeof(log_record->action));
            }

            if (*needle != '\0') {
                needle++;

                /* skip leading spaces */
                while (*needle != '\0' && *needle == ' ') {
                    needle++;
                }

                i = 0;
                while (*needle != '\0') {
                    if (i < (sizeof(log_record->logprefix) - 1))
                        log_record->logprefix[i++] = *needle;

                    needle++;
                }
                log_record->logprefix[i] = '\0';
            } else {
                strlcpy(log_record->logprefix, "none",
                        sizeof(log_record->logprefix));
            }
        } else {
            strlcpy(log_record->action, "<unknown>",
                    sizeof(log_record->action));
            strlcpy(log_record->logprefix, "none",
                    sizeof(log_record->logprefix));
        }
    } else {
        strlcpy(log_record->action, "<exteral>", sizeof(log_record->action));
        strlcpy(log_record->logprefix, "none", sizeof(log_record->logprefix));
    }
}

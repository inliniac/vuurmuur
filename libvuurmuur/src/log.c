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

#include "config.h"
#include "vuurmuur.h"


int
vrmr_logprint(char *logfile, int logconsole, char *logstring)
{
    int         retval=0;
    pid_t       pid;
    time_t      td;
    struct tm   *dcp;
    FILE        *fp;

    pid = getpid();
    (void)time(&td);
    dcp = localtime(&td);

    if (logconsole == 1) {
        fprintf(stdout, "%s\n", logstring);
    }

    fp = fopen(logfile, "a");
    if(!fp)
    {
        fprintf(stdout, "Error opening logfile '%s', %s.\n", logfile, strerror(errno));
        retval=-1;
    }
    else
    {
        fprintf(fp, "%02d/%02d/%04d %02d:%02d:%02d : PID %-5d : %-13s : %s\n",  dcp->tm_mon +1, // Month
                dcp->tm_mday,       // Day
                dcp->tm_year + 1900,// Year
                dcp->tm_hour,       // Hour
                dcp->tm_min,        // Minute
                dcp->tm_sec,        // Second
                pid,
                vrprint.logger,     /* the name of the logger */
                logstring);

        fflush(fp);
        fclose(fp);
    }

    return(retval);
}


int
libvuurmuur_logprint_error(int errorlevel, char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s (%d): %s", head, errorlevel, long_str);

    /* print in the error log */
    vrmr_logprint(conf.errorlog_location, conf.verbose_out, prnt_str);
    /* and in the info log */
    vrmr_logprint(conf.vuurmuurlog_location, 0, prnt_str);

    return(0);
}


int
libvuurmuur_logprint_warning(char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);

    /* now print in the warning log */
    vrmr_logprint(conf.vuurmuurlog_location, conf.verbose_out, prnt_str);

    return(0);
}


int
libvuurmuur_logprint_info(char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);

    vrmr_logprint(conf.vuurmuurlog_location, conf.verbose_out, prnt_str);
    return(0);
}


int
libvuurmuur_logprint_audit(char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s : %s", vrprint.username, long_str);

    vrmr_logprint(conf.auditlog_location, 0, prnt_str);
    return(0);
}


int
libvuurmuur_logprint_debug(char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    if(head != NULL)
        snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);
    else
        (void)strlcpy(prnt_str, long_str, sizeof(prnt_str));

    /* print in the debug log */
    vrmr_logprint(conf.debuglog_location, 0, prnt_str);
    return(0);
}


int
libvuurmuur_stdoutprint_error(int errorlevel, char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s (%d): %s\n", head, errorlevel, long_str);
    fflush(stdout);

    return(0);
}


int
libvuurmuur_stdoutprint_warning(char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s: %s\n", head, long_str);
    fflush(stdout);

    return(0);
}


int
libvuurmuur_stdoutprint_info(char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s: %s\n", head, long_str);
    fflush(stdout);

    return(0);
}


int
libvuurmuur_stdoutprint_audit(char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s : %s\n", vrprint.username, long_str);
    fflush(stdout);

    return(0);
}


int
libvuurmuur_stdoutprint_debug(char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    if(head != NULL)
        fprintf(stdout, "%s: %s\n", head, long_str);
    else
        fprintf(stdout, "%s\n", long_str);

    fflush(stdout);

    return(0);
}

int
libvuurmuur_logstdoutprint_error(int errorlevel, char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s (%d): %s", head, errorlevel, long_str);

    /* print in the error log */
    vrmr_logprint(conf.errorlog_location, 0, prnt_str);
    /* and in the info log */
    vrmr_logprint(conf.vuurmuurlog_location, 0, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return(0);
}


int
libvuurmuur_logstdoutprint_warning(char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);

    /* now print in the warning log */
    vrmr_logprint(conf.vuurmuurlog_location, 0, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return(0);
}


int
libvuurmuur_logstdoutprint_info(char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);

    vrmr_logprint(conf.vuurmuurlog_location, 0, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return(0);
}


int
libvuurmuur_logstdoutprint_audit(char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    snprintf(prnt_str, sizeof(prnt_str), "%s : %s", vrprint.username, long_str);

    vrmr_logprint(conf.auditlog_location, 0, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return(0);
}


int
libvuurmuur_logstdoutprint_debug(char *head, char *fmt, ...)
{
    va_list ap;
    char    long_str[MAX_LOGRULE_SIZE] = "",
            prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    if(head != NULL)
        snprintf(prnt_str, sizeof(prnt_str), "%s: %s", head, long_str);
    else
        (void)strlcpy(prnt_str, long_str, sizeof(prnt_str));

    /* print in the debug log */
    vrmr_logprint(conf.debuglog_location, 0, prnt_str);

    fprintf(stdout, "%s\n", prnt_str);
    fflush(stdout);

    return(0);
}

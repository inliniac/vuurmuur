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

struct file_mon
{
    struct stat old_file;
    struct stat new_file;

    off_t       windback;
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

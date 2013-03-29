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

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <unistd.h>

#include "config.h"
#include "vuurmuur.h"


/*  vuurmuur_fopen

    A wrapper around fopen which can be used to open files. This
    function performs additionals checks on the file, appropriate for
    files with sensitive info (such as checking the owner, the
    permissions, etc.)

    This wrapper only works on a regular file, so no dirs, fifos, etc.

    The path and mode parameters are identical to the fopen(3) libc function.
*/
FILE *
vuurmuur_fopen(const int debuglvl, const struct vuurmuur_config *cnf, const char *path, const char *mode)
{
    FILE        *fp=NULL;

    /* Stat the file */
    if (!stat_ok(debuglvl, cnf, path, STATOK_WANT_FILE, STATOK_VERBOSE, STATOK_ALLOW_NOTFOUND))
        /* File not OK? Don't open it. stat_ok will have printed an error message already. */
        return NULL;

    /* now open the file, this should not fail because if we get here it exists and is readable,
       but we check to be sure. */
    if(!(fp=fopen(path, mode)))
    {
        (void)vrprint.error(-1, "Error", "opening '%s' failed: %s (in: vuurmuur_fopen).", path, strerror(errno));
        return NULL;
    }

    return(fp);
}


DIR *
vuurmuur_opendir(const int debuglvl, const struct vuurmuur_config *cnf, const char *name)
{
    DIR *dir_p = NULL;

    if(!(stat_ok(debuglvl, cnf, name, STATOK_WANT_DIR, STATOK_VERBOSE, STATOK_MUST_EXIST)))
        return(NULL);

    /* finally try to open */
    if(!(dir_p = opendir(name)))
    {
        (void)vrprint.error(-1, "Error", "opening '%s' failed: %s.", name, strerror(errno));
        return NULL;
    }

    return(dir_p);
}


/*  stat_ok

    A function to see if we want to open a file or directory.

    parameters for 'type' are:
        STATOK_WANT_BOTH
        STATOK_WANT_FILE
        STATOK_WANT_DIR

    parameters for 'output' are:
        STATOK_VERBOSE
        STATOK_QUIET

    parameters for 'must_exist' are:
        STATOK_MUST_EXIST
        STATOK_ALLOW_NOTFOUND

    Returncodes:
        1: file ok
        0: file not ok
*/
int
stat_ok(const int debuglvl, const struct vuurmuur_config *cnf, const char *file_loc, char type, char output, char must_exist)
{
    struct stat stat_buf;
    mode_t max, perm;

    /* safety */
    if(file_loc == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(0);
    }

    /* stat the damn thing */
    if(lstat(file_loc, &stat_buf) == -1)
    {
        if (errno == ENOENT) {
            if (must_exist == STATOK_ALLOW_NOTFOUND) {
                /* Allow the file to be non-existing. */
                return(1);
            } else {
                (void)vrprint.error(-1, "Error",  "File not found: '%s'.", file_loc);
                return(0);
            }
        } else {
            (void)vrprint.error(-1, "Error",  "checking failed for '%s': %s.", file_loc, strerror(errno));
            return(0);
        }
    }

    /* we wont open symbolic links */
    if(S_ISLNK(stat_buf.st_mode) == 1)
    {
        if(output == STATOK_VERBOSE)
            (void)vrprint.error(-1, "Error", "opening '%s': For security reasons Vuurmuur will not allow following symbolic-links.", file_loc);

        return(0);
    }
    else if(type == STATOK_WANT_FILE && S_ISREG(stat_buf.st_mode) != 1)
    {
        if(output == STATOK_VERBOSE)
            (void)vrprint.error(-1, "Error", "opening '%s' failed: not a file.", file_loc);

        return(0);
    }
    else if(type == STATOK_WANT_DIR && S_ISDIR(stat_buf.st_mode) != 1)
    {
        if(output == STATOK_VERBOSE)
            (void)vrprint.error(-1, "Error", "opening '%s' failed: not a directory.", file_loc);

        return(0);
    }
    else if(type == STATOK_WANT_BOTH && S_ISREG(stat_buf.st_mode) != 1 && S_ISDIR(stat_buf.st_mode) != 1)
    {
        if(output == STATOK_VERBOSE)
            (void)vrprint.error(-1, "Error", "opening '%s' failed: not a file or a directory.", file_loc);

        return(0);
    }

    /* we demand that all files are owned by root */
    if(stat_buf.st_uid != 0 || stat_buf.st_gid != 0)
    {
        if(output == STATOK_VERBOSE)
            (void)vrprint.error(-1, "Error", "opening '%s': For security reasons Vuurmuur will not open files or directories that are not owned by root.", file_loc);

        return(0);
    }

    if (cnf->max_permission != ANY_PERMISSION)
    {
        /* Extract the permission bits from the mode */
        perm = stat_buf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
        /* Maximum permissions. Remove +x for files */
        max = cnf->max_permission;
        if (S_ISREG(stat_buf.st_mode) == 1)
            max &= ~(S_IXUSR|S_IXGRP|S_IXOTH);

        /* See if the file mode has more bits set than the maximum allowed */
        if(perm & ~max)
        {
            (void)vrprint.info("Info", "'%s' has mode %o, which is more than maximum allowed mode %o. Resetting to %o.", file_loc, perm, max, max);

            if(chmod(file_loc, max) == -1)
            {
                (void)vrprint.error(-1, "Error", "failed to repair permissions for '%s': %s.", file_loc, strerror(errno));
                return(0);
            }
        }
    }

    return(1);
}


/**
 * \brief Check PID file for running process
 *
 * Check for existence of PID file; if it exists, check the PID therein
 * and check if the PID is indeed running. If neither is the case, return 0.
 *
 */
int
check_pidfile(char *pidfile_location, char *service, pid_t *thepid)
{
    FILE    *fp;
    pid_t   pid;
    char    pid_char[32],
            pid_small[16];

    if(!pidfile_location)
        return(-1);

    fp = fopen(pidfile_location, "r");
    if(fp)
    {
        if(fgets(pid_char, (int)sizeof(pid_char), fp) != NULL)
        {
            sscanf(pid_char, "%16s", pid_small);
            pid = atol(pid_small);
            /* We found a PID in a pidfile. Let's check if it's non stale */
            if (kill (pid, 0))
            {
                if (errno == ESRCH)     /* process didn't exist */
                {
                    if (unlink (pidfile_location))
                    {
                        fprintf (stderr, "Cannot unlink stale PID file %s: %s\n", pidfile_location, strerror(errno));
                        return (-1);
                    }
                    else
                    {
                        return 0;
                    }
                }
            }
            *thepid = pid;
            fclose(fp);
            return(-1);
        }

        fclose(fp);
    }

    return(0);
}


int
create_pidfile(char *pidfile_location, int shm_id)
{
    FILE    *fp;
    pid_t   pid;

    if(!pidfile_location)
        return(-1);

    /*
        first check if the pidfile already exists
    */
    if(check_pidfile(pidfile_location, "createsvc", &pid) == -1)
        return(-1);

    pid = getpid();

    fp = fopen(pidfile_location, "w+");
    if(!fp)
    {
        (void)vrprint.error(-1, "Error", "opening pid-file '%s' for writing failed: %s.", pidfile_location, strerror(errno));
        return(-1);
    }
    if(fprintf(fp, "%ld %d\n", (long)pid, shm_id) < 0)
    {
        (void)vrprint.error(-1, "Error", "writing pid-file '%s' failed: %s.", pidfile_location, strerror(errno));
        return(-1);
    }
    if(fclose(fp) < 0)
    {
        (void)vrprint.error(-1, "Error", "closing pid-file '%s' failed: %s.", pidfile_location, strerror(errno));
        return(-1);
    }

    return(0);
}


int
remove_pidfile(char *pidfile_location)
{
    if(!pidfile_location)
        return(-1);

    if(remove(pidfile_location) != 0)
    {
        (void)vrprint.error(-1, "Error", "removing pid-file '%s' failed: %s.", pidfile_location, strerror(errno));
        return(-1);
    }

    return(0);
}


/*  This opens the rulesfile, but first checks for the lock,
    and if the file is opened sets the lock.

    Returns the pointer to the file, or NULL if failed.
*/
FILE *
rules_file_open(const int debuglvl, const struct vuurmuur_config *cnf, const char *path, const char *mode, int caller)
{
    FILE    *lock_fp = NULL,
            *fp = NULL;
    char    *lock_path = NULL;
    size_t  i = 0,
            lockpath_len = 0;

    /* safety */
    if(!path || !mode)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    lockpath_len = strlen(path) + 6;
    if(lockpath_len == 0)
        return(NULL);

    if(!(lock_path = malloc(lockpath_len)))
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s "
            "(in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(NULL);
    }

    if(strlcpy(lock_path, path, lockpath_len) >= lockpath_len)
    {
        (void)vrprint.error(-1, "Error", "string overflow "
            "(in: %s:%d).", __FUNC__, __LINE__);
        free(lock_path);
        return(NULL);
    }
    if(strlcat(lock_path, ".LOCK", lockpath_len) >= lockpath_len)
    {
        (void)vrprint.error(-1, "Error", "string overflow "
            "(in: %s:%d).", __FUNC__, __LINE__);
        free(lock_path);
        return(NULL);
    }

    /* try to open the lockfile */
    lock_fp = fopen(lock_path, "r");
    if(lock_fp != NULL)
    {
        /* we are locked! enter wait loop */
        (void)vrprint.warning("Warning", "rulesfile is locked, will try for 60 seconds.");
        for(i = 0; i < 60; i++)
        {
            /* close the lockfile */
            if(fclose(lock_fp) < 0)
                return(NULL);

            lock_fp = fopen(lock_path, "r");
            if(lock_fp != NULL)
            {
                /* we are still locked! */
                sleep(1);
            }
            else
                break;
        }

        /* one last try */
        lock_fp = fopen(lock_path, "r");
        if(lock_fp != NULL)
        {
            (void)vrprint.error(-1, "Error", "opening rulesfile timed out, check if there was a crash.");

            fclose(lock_fp);
            free(lock_path);

            return(NULL);
        }
    }

    lock_fp = fopen(lock_path, "w");
    if(!lock_fp)
    {
        (void)vrprint.error(-1, "Error", "creating lockfile failed: %s.", strerror(errno));
        return(NULL);
    }
    else
    {
        fprintf(lock_fp, "%d\n", caller);

        fclose(lock_fp);
        free(lock_path);
    }

    fp = vuurmuur_fopen(debuglvl, cnf, path, mode);
    return(fp);
}


/*  rules_file_close
*/
int
rules_file_close(FILE *file, const char *path)
{
    FILE    *lock_fp = NULL;
    int     retval = 0;
    size_t  lockpath_len = 0;
    char    *lock_path = NULL;

    /* safety */
    if(!file || !path)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    lockpath_len = strlen(path) + 6;
    if(lockpath_len <= 0)
        return(-1);

    if(!(lock_path = malloc(lockpath_len)))
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s.", strerror(errno));
        return(-1);
    }

    if(strlcpy(lock_path, path, lockpath_len) >= lockpath_len)
    {
        (void)vrprint.error(-1, "Error", "string overflow "
            "(in: %s:%d).", __FUNC__, __LINE__);
        free(lock_path);
        return(-1);
    }
    if(strlcat(lock_path, ".LOCK", lockpath_len) >= lockpath_len)
    {
        (void)vrprint.error(-1, "Error", "string overflow "
            "(in: %s:%d).", __FUNC__, __LINE__);
        free(lock_path);
        return(-1);
    }

    /* try to open the lockfile */
    lock_fp = fopen(lock_path, "r");
    if(lock_fp != NULL)
    {
        if(fclose(lock_fp) < 0)
            retval = -1;

        /* good, the file exists */
        if(remove(lock_path) < 0)
        {
            (void)vrprint.error(-1, "Error", "removing lockfile failed: %s.", strerror(errno));
            retval = -1;
        }
    }
    else
    {
        (void)vrprint.warning("Warning", "lockfile was already removed.");
    }

    /* close the file */
    if(fclose(file) < 0)
    {
        (void)vrprint.error(-1, "Error", "closing file failed: %s (in: %s).", strerror(errno), __FUNC__);
        retval = -1;
    }

    /* free our path mem */
    free(lock_path);

    return(retval);
}


/*  pipe_command

    This function takes the 'command' and pipes it to the shell.

    Returncodes:
         0: ok
        -1: error
 */
int
pipe_command(const int debuglvl, struct vuurmuur_config *cnf, char *command,
        char ignore_error)
{
    int     retval=0;
    FILE    *p;

    /* safety */
    if(cnf == NULL || command == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= MEDIUM)
    {
        (void)vrprint.debug(__FUNC__, "command: %s", command);
        (void)vrprint.debug(__FUNC__, "strlen(command) = %d, max = %d",
                strlen(command), MAX_PIPE_COMMAND);
    }

    if(strlen(command) > MAX_PIPE_COMMAND)
    {
        (void)vrprint.error(-1, "Internal Error", "Command to pipe too "
                "long! (%d, while max is: %d).",
                strlen(command), MAX_PIPE_COMMAND);
        return(-1);
    }

    /* if in bash output mode we don't pipe, but just print to stdout */
    if(cnf->bash_out == 1)
    {
        fprintf(stdout, "%s\n", command);
        return(0);
    }

    if(!(p = popen(command,"r")))
    {
        (void)vrprint.error(-1, "Error", "opening pipe to '%s' failed.", command);
        return(-1);
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "pipe opened succesfully.");

    int r = pclose(p);
    if(r != 0)
    {
        if(!ignore_error)
        {
            (void)vrprint.error(-1, "Error", "command '%s' failed.",
                    command);
        }

        retval = -1;
    }
    else
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "pipe closed!");
    }

    return(retval);
}

/** \brief Execute a system command.
 *
 *  This functions blocks.
 *
 *  \param argv array of strings with a NULL as final member
 *  \param output array of strings with a NULL as final member
 *
 *  \retval: -1 if the command failed to start (ie not found)
 *              otherwise the return code of the command.
 */
int
libvuurmuur_exec_command(const int debuglvl, struct vuurmuur_config *cnf, char *path, char *argv[], char *output[])
{
    int retval = 0;
    FILE *fp = NULL;
    char dev_null[] = "/dev/null";
    char *output_path = NULL;

    if (debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "starting, path %s", path);

    pid_t pid = fork();
    if (pid == 0) {
        if (debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "(child) started");

        /* close stdout so we don't see the output of the
         * command we execute */
        fp = freopen("/dev/null", "rb", stdin);
        if (fp == NULL) {
            (void)vrprint.error(127, "Internal Error", "freopen stdin to /dev/null failed: %s",
                strerror(errno));
            exit(127);
        }

        if (output == NULL)
            output_path = dev_null;
        else
            output_path = output[0];

        fp = freopen(output_path, "wb", stdout);
        if (fp == NULL) {
            (void)vrprint.error(127, "Internal Error", "freopen stdout to %s failed: %s",
                output_path, strerror(errno));
            exit(127);
        }

        if (output == NULL)
            output_path = dev_null;
        else
            output_path = output[1];

        fp = freopen(output_path, "wb", stderr);
        if (fp == NULL) {
            (void)vrprint.error(127, "Internal Error", "freopen stdin to %s failed: %s",
                output_path, strerror(errno));
            exit(127);
        }

        /* actually exec the command */
        execv(path,argv);

        /* if we get here, the command didn't exec
         * so kill the child */
        exit(127);
    }
    if (debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "child pid is %u", pid);

    int status;
    pid_t rpid;
    do {
        rpid = waitpid(pid, &status, 0);
    } while (rpid == -1 && errno == EINTR);

    if (pid != -1 && WIFEXITED(status) && WEXITSTATUS(status)) {
        if (debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "WEXITSTATUS(status) %d", WEXITSTATUS(status));
        retval = WEXITSTATUS(status);
    }
    else if (rpid == -1)
        retval = -1;

    if (debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "(%s) retval %d", path, retval);
    return retval;
}

void
shm_update_progress(const int debuglvl, int semid, int *shm_progress, int set_percent)
{
    if(vrmr_lock(semid))
    {
        *shm_progress = set_percent;

        vrmr_unlock(semid);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "set_percent %d.", set_percent);
}


/*  get_vuurmuur_pid

    Gets the pid and shm_id from vuurmuur.

    Returncodes:
        -1: error
            otherwise the pid of vuurmuur
*/
pid_t
get_vuurmuur_pid(char *vuurmuur_pidfile_location, int *shmid)
{
    FILE    *fp = NULL;
    pid_t   pid = -1;
    char    line[32] = "",
            pid_c[16] = "",
            shm_c[16] = "";

    /* open the pidfile */
    if(!(fp = fopen(vuurmuur_pidfile_location, "r")))
        return(-1);

    /* read the first line */
    if(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        sscanf(line, "%15s %15s", pid_c, shm_c);
        pid = atol(pid_c);
        *shmid = atoi(shm_c);
    }
    else
    {
        /* no need to return, because pid isn't touched, so still -1 */
        (void)vrprint.error(-1, "Error", "empty or corrupted pid file: '%s' (in: %s).",
                vuurmuur_pidfile_location,
                __FUNC__);
    }

    /* close the file again */
    if(fclose(fp) < 0)
        return(-1);

    return(pid);
}


/*
    returns the filedescriptor, or -1 on error

    NOTE: pathname is changed!

    vuurmuur-XXXXXX becomes something like: vuurmuur-uTXhQZ
*/
int
create_tempfile(const int debuglvl, char *pathname)
{
    int fd = -1;

    /* safety */
    if(!pathname)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* we cannot be sure errno is set in case of error */
    errno = 0;

    /* call mkstemp */
    fd = mkstemp(pathname);
    if(fd == -1)
    {
        if(errno == 0)
            (void)vrprint.error(-1, "Error", "could not create tempfile (in: %s:%d).", __FUNC__, __LINE__);
        else
            (void)vrprint.error(-1, "Error", "could not create tempfile: %s (in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
    }

    return(fd);
}


void
sanitize_path(const int debuglvl, char *path, size_t size)
{
    size_t  i = 0;

    if(path == NULL)
        return;

    for(i = 0; i < size  && path[i] != '\0'; i++)
    {
        /* we don't want ; chars */
        if(path[i] == ';')
            path[i] = 'x';

        /* no directory traversal */
        if(i + 1 < size && i + 2 < size)
        {
            if( path[i] == '.' &&
                path[i+1] == '.' &&
                path[i+2] == '/')
            {
                path[i] = 'x';
                path[i+1] = 'x';
            }
        }
    }
}

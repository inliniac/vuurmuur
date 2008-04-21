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

int
read_proc_entry(const int debuglvl, char *proc_entry, int *value)
{
    int     retval = 0,
            result = 0;
    FILE    *fp = NULL;
    size_t  entry_length = 0,
            i = 0,
            j = 0;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "** start **");

    entry_length = strlen(proc_entry);
    if(entry_length >= MAX_PROC_ENTRY_LENGHT)
    {
        (void)vrprint.error(-1, "Error", "proc_entry is too long (%d, max: %d) (in: %s).", entry_length, MAX_PROC_ENTRY_LENGHT, __FUNC__);
        return(-1);
    }


    for(i=0, j=0; i <= entry_length; i++)
    {
        if(proc_entry[i] != '*')
        {
            j++;
        }
        else
        {
            (void)vrprint.error(-1, "Error", "Opening '%s' failed: %s (in: %s).", proc_entry, strerror(errno), __FUNC__);
            return(-1);
        }
    }


    if(retval >= 0)
    {
        fp = fopen(proc_entry, "r");
        if(!fp)
        {
            (void)vrprint.error(-1, "Error", "Opening '%s' failed: %s (in: %s).", proc_entry, strerror(errno), __FUNC__);
            return(-1);
        }
        else
        {
            /* just read the first character */
            result = fgetc(fp);
            result = result-48;

            fclose(fp);
            *value = result;
        }
    }

    return(retval);
}

int
set_proc_entry(const int debuglvl, struct vuurmuur_config *cnf, char *proc_entry, int proc_set, char *who)
{
    size_t  i = 0,
            j = 0,
            entry_length = 0;
    int     retval = 0;
    FILE    *fp = NULL;

    char    entry[MAX_PROC_ENTRY_LENGHT],
            entry_last[MAX_PROC_ENTRY_LENGHT],
            total_entry[MAX_PROC_ENTRY_LENGHT*2];
    int     proc_int = 0;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "** start **");

    /* safety */
    if(!cnf)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* first check if we have an '*' in the proc_entry */
    entry_length = strlen(proc_entry);
    if(entry_length >= MAX_PROC_ENTRY_LENGHT)
    {
        (void)vrprint.error(-1, "Error", "proc_entry is too long (%d, max: %d) (in: set_proc_entry).", entry_length, MAX_PROC_ENTRY_LENGHT);
        return(-1);
    }

    for(i=0, j=0; i <= entry_length; i++)
    {
        if(proc_entry[i] != '*')
        {
            if(proc_int == 0)
                entry[i]=proc_entry[i];

            if(proc_int == 1)
            {
                entry_last[j]=proc_entry[i];
                j++;
            }
        }
        else
        {
            entry[i]='\0';
            proc_int = 1;
        }
    }

    if(proc_int == 1)
    {
        if(who == NULL)
        {
            (void)vrprint.error(-1, "Error", "No 'who' supplied (set_proc_entry).");
            return(-1);
        }

        snprintf(total_entry, sizeof(total_entry), "%s%s%s", entry, who, entry_last);
        if(!cnf->bash_out)
        {
            fp = fopen(total_entry, "w");
            if(!fp)
            {
                (void)vrprint.error(-1, "Error", "opening proc entry '%s' failed: %s (in: set_proc_entry).", total_entry, strerror(errno));
                retval = -1;
            }
            else
            {
/* TODO: returncode */
                fputc(proc_set+48, fp);
                if(debuglvl >= MEDIUM)
                    (void)vrprint.debug(__FUNC__, "setting '%d' to proc entry '%s' succesfull.", proc_set, total_entry);

                fclose(fp);
            }
        }
        else
        {
            /* for bash output */
            fprintf(stdout, "echo \"%d\" > %s\n", proc_set, total_entry);
        }

    }
    else
    {
        if(!cnf->bash_out)
        {
            if(!(fp = fopen(proc_entry, "w")))
            {
                (void)vrprint.error(-1, "Error", "Opening proc entry '%s' failed: %s (in: set_proc_entry).", proc_entry, strerror(errno));
                retval=-1;
            }
            else
            {
/* TODO: returncode */
                fputc(proc_set+48, fp);
                if(debuglvl >= MEDIUM)
                    (void)vrprint.info("Info", "Setting '%d' to proc entry '%s' succesfull.", proc_set, proc_entry);

                fclose(fp);
            }
        }
        else
        {
            /* for bash output */
            fprintf(stdout, "echo \"%d\" > %s\n", proc_set, proc_entry);
        }
    }

    return(retval);
}

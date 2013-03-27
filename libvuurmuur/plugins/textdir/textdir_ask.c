/***************************************************************************
 *   Copyright (C) 2002-2008 by Victor Julien                              *
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

#include "textdir_plugin.h"

/*
    asking from and telling to the backend (TODO: name)

    returns
        -1 error
*/
int
ask_textdir(const int debuglvl,
            void *backend,
            char *name,
            char *question,
            char *answer,
            size_t max_answer,
            int type,
            int multi)
{
    int                     retval = 0;
    char                    *file_location = NULL;
    char                    line[MAX_LINE_LENGTH] = "",
                            variable[64] = "",
                            value[512] = "";
    size_t                  i = 0,
                            line_pos = 0,
                            val_pos = 0;
    char                    delt = 'a' - 'A';
    size_t                  line_length = 0;
    struct TextdirBackend_  *tb = NULL;
    size_t                  len = 0;

    /* better safe than sorry */
    if(!backend || !name || !question)
    {
        (void)tb->cfg->vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)tb->cfg->vrprint.debug(__FUNC__, "question: %s, name: %s, multi: %d", question, name, multi);

    if(!(tb = (struct TextdirBackend_ *)backend))
        return(-1);

    /* check if backend is open */
    if(!tb->backend_open)
    {
        (void)tb->cfg->vrprint.error(-1, "Error", "backend not opened yet (in: %s).", __FUNC__);
        return(-1);
    }

    /* convert question to uppercase: see pp 197 of 'sams teach yourself c in 24 hours' */
    while(question[i])
    {
        if((question[i] >= 'a') && (question[i] <= 'z')) question[i] -= delt;
        ++i;
    }

    /* determine the location of the file */
    if(!(file_location = get_filelocation(debuglvl, backend, name, type)))
        return(-1);

    /* check if we are clean */
    if(tb->file != NULL && multi == 0)
    {
        (void)tb->cfg->vrprint.warning("Warning", "the last 'multi' call to '%s' probably failed, because the file is still open when it shouldn't.", __FUNC__);

        fclose(tb->file);
        tb->file = NULL;
    }

    /* now open and read the file, but only if it is not already open */
    if(tb->file == NULL)
    {
        if(!(tb->file = vuurmuur_fopen(debuglvl, tb->cfg, file_location, "r")))
        {
            (void)tb->cfg->vrprint.error(-1, "Error", "Unable to open file '%s'.", file_location);

            free(file_location);
            return(-1);
        }
    }

    /* start (or continue) looping trough the file */
    while (fgets(line, (int)sizeof(line), tb->file) != NULL)
    {
        line_length = strlen(line);
        if(line_length < 0)
        {
            (void)tb->cfg->vrprint.error(-1, "Internal Error", "unable to determine the length of 'line' (in: %s).", __FUNC__);

            free(file_location);
            fclose(tb->file);
            tb->file = NULL;
            return(-1);
        }
        else if(line_length > MAX_LINE_LENGTH)
        {
            (void)tb->cfg->vrprint.error(-1, "Error", "line is longer than allowed (line: %d, max: %d) (in: %s).", line_length, MAX_LINE_LENGTH, __FUNC__);

            free(file_location);
            fclose(tb->file);
            tb->file = NULL;
            return(-1);
        }

        /* first check if the line is a comment. */
        if (line_length == 0 || line[0] == '#' || line[0] == ' ' || line[0] == '\0' ||
                line[0] == '\n' || line[0] == '\t')
        {
            /* continue with the next line, its a comment or an empty line. */
            continue;
        }

        /* look for the occurance of the = separator */
        char *val = strchr(line, '=');
        if (val == NULL) {
            /* not a valid line, ignore */
            continue;
        }

        /* val - line = var len */
        size_t var_len = val - line + 1;
        if (var_len > (sizeof(variable) - 1)) {
            /* invalid line, ignore */
            continue;
        }

        strlcpy(variable, line, var_len);

        if (debuglvl >= LOW)
            (void)tb->cfg->vrprint.debug(__FUNC__, "variable %s", variable);

        /* now see if this was what we were looking for */
        if(strcmp(question, variable) != 0) {
            /* nope, ignore line */
            continue;
        }

        /* skip pass the '=' char */
        val++;

        size_t val_len = strlen(val);

        /* copy the value into "value" */
        val_pos = 0; line_pos = 0;

        while(val[line_pos] != '\0' && val[line_pos] != '\n' && line_pos < val_len && val_pos < max_answer)
        {
            /* if the first character is a '"' we strip it. */
            if((val_pos == 0) && (val[line_pos] == '\"'))
                line_pos++;

            /* otherwise copy the char */
            else
            {
                value[val_pos]=val[line_pos];

                line_pos++;
                val_pos++;
            }
        }

        /* if the last character is a '"' we strip it. */
        if (val_pos > 0 && value[val_pos - 1] == '\"')
            value[val_pos - 1] = '\0';
        else
            value[val_pos] = '\0';

        if(debuglvl >= MEDIUM)
            (void)tb->cfg->vrprint.debug(__FUNC__, "question '%s' matched, value: '%s'", question, value);

        /* copy back the value to "answer" */
        len = strlcpy(answer, value, max_answer);
        if(len >= max_answer)
        {
            (void)tb->cfg->vrprint.error(-1, "Error", "buffer overrun when reading file '%s', question '%s': len %u, max: %u (in: %s:%d).",
                    file_location, question, len, max_answer, __FUNC__, __LINE__);

            free(file_location);
            fclose(tb->file);
            tb->file = NULL;
            return(-1);
        }

        /* only return when bigger than 0 */
        if(strlen(answer) > 0)
            retval = 1;

        /* break out of the loop so when we call multi again we continue where we were */
        break;
    }

    /* cleanup */
    if((multi == 1 && retval != 1) || multi == 0)
    {
        if(debuglvl >= HIGH)
            (void)tb->cfg->vrprint.debug(__FUNC__, "close the file.");

        if(fclose(tb->file) != 0)
        {
            (void)tb->cfg->vrprint.error(-1, "Error", "closing file '%s' failed: %s (in: %s).", file_location, strerror(errno), __FUNC__);
            retval = -1;
        }
        tb->file = NULL;
    }

    /* cleanup filelocation */
    free(file_location);

    if(debuglvl >= HIGH)
    {
        (void)tb->cfg->vrprint.debug(__FUNC__, "at exit: tb->file: %p (retval: %d).", tb->file, retval);
        (void)tb->cfg->vrprint.debug(__FUNC__, "** end **, retval=%d", retval);
    }

    return(retval);
}


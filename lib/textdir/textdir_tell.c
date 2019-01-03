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

#include "textdir_plugin.h"

/*

*/
int tell_textdir(void *backend, char *name, char *question, char *answer,
        int overwrite, int type)
{
    int retval = 0;
    char *file_location = NULL;
    char line[512] = "", *line_ptr = NULL, *tmp_line_ptr = NULL;
    int i = 0, found = 0, skip = 0;
    int delta = 'a' - 'A';
    FILE *fp = NULL;
    struct TextdirBackend_ *tb = NULL;
    struct vrmr_list storelist;
    struct vrmr_list_node *d_node = NULL;

    /*
        safety
    */
    if (!backend || !name || !question || !answer) {
        vrmr_error(
                -1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return (-1);
    }

    vrmr_debug(HIGH,
            "question: %s, answer: %s, name: %s, overwrite: %d, type: %d",
            question, answer, name, overwrite, type);

    tb = (struct TextdirBackend_ *)backend;
    if (!tb->backend_open) {
        vrmr_error(-1, "Error", "backend not opened yet (in: %s).", __FUNC__);
        return (-1);
    }

    /*
        convert question to uppercase
    */
    while (question[i]) {
        if ((question[i] >= 'a') && (question[i] <= 'z'))
            question[i] -= delta;
        ++i;
    }

    /*
        determine the location of the file
    */
    if (!(file_location = get_filelocation(backend, name, type)))
        return (-1);

    /*
        first open the file for reading
    */
    if (!(fp = vuurmuur_fopen(tb->cfg, file_location, "r"))) {
        vrmr_error(-1, "Error", "unable to open file '%s' for reading: %s.",
                file_location, strerror(errno));

        free(file_location);
        return (-1);
    }

    /* initialize the store list */
    vrmr_list_setup(&storelist, free);

    /*
        loop trough the current file
    */
    while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
        skip = 0;

        size_t line_size = sizeof(line);
        if (!(line_ptr = malloc(line_size))) {
            vrmr_error(-1, "Error", "malloc failed: %s (in: %s).",
                    strerror(errno), __FUNC__);
            /* cleanup */
            vrmr_list_cleanup(&storelist);
            free(file_location);
            fclose(fp);
            return (-1);
        }

        if (strncmp(question, line, strlen(question)) == 0 &&
                line[strlen(question)] == '=') {
            if (overwrite && !found) {
                snprintf(line_ptr, line_size, "%s=\"%s\"\n", question, answer);
                found = 1;
            } else if (overwrite && found) {
                skip = 1;
            } else {
                (void)strlcpy(line_ptr, line, line_size);
                found = 1;
            }
        } else {
            (void)strlcpy(line_ptr, line, line_size);
        }

        /*
            now append the line to the storelist, except if we were told to skip
           this one. Then just free the data.
        */
        if (!skip) {
            if (vrmr_list_append(&storelist, line_ptr) == NULL) {
                vrmr_error(-1, "Internal Error",
                        "inserting line into temporary storage list failed "
                        "(in: %s).",
                        __FUNC__);
                /* cleanup */
                vrmr_list_cleanup(&storelist);
                free(line_ptr);
                free(file_location);
                fclose(fp);
                return (-1);
            }
        } else {
            /* free and null */
            free(line_ptr);
            line_ptr = NULL;
        }
    }

    /*
        if we are not overwriting and the type of data is already found
       somewhere, we try to insert is just below the last one.
    */
    if (!overwrite && found) {
        if (!(line_ptr = malloc(sizeof(line)))) {
            vrmr_error(-1, "Error", "malloc failed: %s (in: %s).",
                    strerror(errno), __FUNC__);
            /* cleanup */
            vrmr_list_cleanup(&storelist);
            free(file_location);
            fclose(fp);
            return (-1);
        }

        /* assemble the line */
        snprintf(line_ptr, sizeof(line), "%s=\"%s\"\n", question, answer);

        /*
            loop the list bottom up so we match the last one first
        */
        for (d_node = storelist.bot; d_node; d_node = d_node->prev) {
            if (!(tmp_line_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer (in: %s)",
                        __FUNC__);
                /* cleanup */
                vrmr_list_cleanup(&storelist);
                free(file_location);
                free(line_ptr);
                fclose(fp);
                return (-1);
            }

            /*
                check if the line is the same. If so insert after it.
            */
            if (strncmp(question, tmp_line_ptr, strlen(question)) == 0) {
                if (vrmr_list_insert_after(&storelist, d_node, line_ptr) ==
                        NULL) {
                    vrmr_error(-1, "Internal Error",
                            "inserting line into temporary storage list failed "
                            "(in: %s).",
                            __FUNC__);
                    /* cleanup */
                    vrmr_list_cleanup(&storelist);
                    free(file_location);
                    free(line_ptr);
                    fclose(fp);
                    return (-1);
                }

                /* after inserting we're done */
                line_ptr = NULL;
                break;
            }
            /* Don't free line_ptr yet, because it might be used again in the
             * next iteration */
        }
        /* we no longer need these */
        tmp_line_ptr = NULL;
        free(line_ptr);
        line_ptr = NULL;
    }

    /*
        if its not found, we insert it at the end of the list
    */
    if (found == 0) {
        /* first alloc */
        if (!(line_ptr = malloc(sizeof(line)))) {
            vrmr_error(-1, "Error", "malloc failed: %s.", strerror(errno));

            /* cleanup */
            vrmr_list_cleanup(&storelist);
            free(file_location);
            fclose(fp);
            return (-1);
        }

        snprintf(line_ptr, sizeof(line), "%s=\"%s\"\n", question, answer);

        /* append into the list */
        if (vrmr_list_append(&storelist, line_ptr) == NULL) {
            vrmr_error(-1, "Internal Error",
                    "inserting line into temporary storage list failed (in: "
                    "%s).",
                    __FUNC__);
            /* cleanup */
            vrmr_list_cleanup(&storelist);
            free(file_location);
            free(line_ptr);
            fclose(fp);
            return (-1);
        }

        /* we no longer need this */
        line_ptr = NULL;
    }

    /* close the file */
    (void)fclose(fp);

    /* now open the file for writing */
    if (!(fp = vuurmuur_fopen(tb->cfg, file_location, "w+"))) {
        vrmr_error(-1, "Error",
                "unable to open file '%s' for writing: %s (in: %s).",
                file_location, strerror(errno), __FUNC__);

        /* cleanup */
        vrmr_list_cleanup(&storelist);
        free(file_location);
        return (-1);
    }

    /* print the list into the file */
    for (d_node = storelist.top; d_node; d_node = d_node->next) {
        if (d_node->data == NULL)
            continue;
        fprintf(fp, "%s", (char *)d_node->data);
    }

    (void)fclose(fp);

    /* destroy the temp storage */
    vrmr_list_cleanup(&storelist);
    free(file_location);
    return (retval);
}

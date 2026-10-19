/***************************************************************************
 *   Copyright (C) 2002-2026 by Victor Julien                              *
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

/*
 * vrmr_lineread: read one line from a stream that is being tailled.
 *
 * Returns 1 with a completed line in buf (the newline is kept), or 0 when the
 * caller should try again later. A line still being written is not consumed:
 * the stream is put back at its start, so the next call sees the same bytes.
 */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "vuurmuur.h"

int vrmr_lineread(FILE *fp, char *buf, size_t size)
{
    if (buf == NULL || size == 0)
        return (-1);

    errno = 0;
    if (fgets(buf, (int)size, fp) == NULL) {
        /*
         * Both eof and a read error end the attempt. The error has to be
         * cleared and the position re-anchored: after a failed operation the
         * position is indeterminate, so the caller could not trust ftell() or
         * a later seek on the same stream.
         */
        if (feof(fp) || ferror(fp)) {
            clearerr(fp);
            (void)fseek(fp, 0, SEEK_CUR);
        }
        return (0);
    }

    size_t len = strlen(buf);

    if (len == 0) {
        /* a NUL byte ends the string early. The byte is left consumed, else a
           stream full of them would never move the reader forward. */
        return (0);
    }

    if (len < size - 1 && buf[len - 1] != '\n') {
        /* short read without a newline: the line is not finished yet */
        if (fseek(fp, -(long)len, SEEK_CUR) != 0) {
            vrmr_debug(LOW, "fseek(): %s", strerror(errno));
        }
        return (0);
    }

    return (1);
}

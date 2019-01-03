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

char *vrmr_get_string(char *fmt, ...)
{
    va_list ap;
    char str[2048] = "";
    char *ptr = NULL;
    size_t len = 0;

    va_start(ap, fmt);
    vsnprintf(str, sizeof(str), fmt, ap);
    va_end(ap);

    len = strlen(str) + 1;

    ptr = malloc(len);
    if (ptr == NULL)
        return (NULL);

    strlcpy(ptr, str, len);

    return (ptr);
}

char *vrmr_get_len_string(size_t max, char *fmt, ...)
{
    va_list ap;
    char str[2048] = "";
    char *ptr = NULL;
    size_t len = 0;

    va_start(ap, fmt);
    vsnprintf(str, sizeof(str), fmt, ap);
    va_end(ap);

    len = strlen(str) + 1;
    if (len > max)
        len = max;

    ptr = malloc(len);
    if (ptr == NULL)
        return (NULL);

    strlcpy(ptr, str, len);

    return (ptr);
}

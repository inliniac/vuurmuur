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

#include "config.h"
#include "vuurmuur.h"

#include "tap.h"

static int tap_count = 0;
static int tap_fail = 0;

/* A TAP line must stay on one line, and descriptions can contain whole rule
 * lines, so flatten them. */
static void tap_report(int ok, const char *what)
{
    char flat[256] = "";
    size_t i = 0;

    strlcpy(flat, what, sizeof(flat));
    for (i = 0; i < sizeof(flat) && flat[i] != '\0'; i++) {
        if (flat[i] == '\n' || flat[i] == '\r')
            flat[i] = ' ';
    }

    tap_count++;
    if (!ok)
        tap_fail++;

    (void)fprintf(
            stdout, "%s %d - %s\n", ok ? "ok" : "not ok", tap_count, flat);
    (void)fflush(stdout);
}

void tap_ok(int cond, const char *what)
{
    tap_report(cond != 0, what);
}

void tap_int_eq(const char *what, long got, long want)
{
    const int ok = got == want;

    tap_report(ok, what);
    if (!ok)
        (void)tap_note("expected %ld, got %ld", want, got);
}

void tap_str_eq(const char *what, const char *got, const char *want)
{
    const int ok = got != NULL && want != NULL && strcmp(got, want) == 0;

    tap_report(ok, what);
    if (!ok) {
        (void)tap_note("expected \"%s\", got \"%s\"",
                want == NULL ? "(null)" : want, got == NULL ? "(null)" : got);
    }
}

void tap_non_null(const char *what, const void *p)
{
    tap_report(p != NULL, what);
}

void tap_is_null(const char *what, const void *p)
{
    tap_report(p == NULL, what);
}

void tap_note(const char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "# ");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");

    return;
}

int tap_finish(void)
{
    (void)fprintf(stdout, "1..%d\n", tap_count);
    if (tap_fail > 0)
        (void)fprintf(stderr, "# failed %d of %d\n", tap_fail, tap_count);

    return tap_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

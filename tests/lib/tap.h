/***************************************************************************
 *   TAP output for the test programs.                                     *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 ***************************************************************************/

#ifndef __VRMR_TAP_H__
#define __VRMR_TAP_H__

#include <vuurmuur.h>

/* Descriptions are plain strings, never format strings, so a '%' in a rule
 * line cannot upset the output. */

void tap_ok(int cond, const char *what);
void tap_int_eq(const char *what, long got, long want);
void tap_str_eq(const char *what, const char *got, const char *want);
void tap_non_null(const char *what, const void *p);
void tap_is_null(const char *what, const void *p);

/* detail for whoever reads the log; stdout is reserved for the plan */
void tap_note(const char *fmt, ...) ATTR_FMT_PRINTF(1, 2);

/* emits 1..N and the totals; returns the exit code for main() */
int tap_finish(void);

#endif

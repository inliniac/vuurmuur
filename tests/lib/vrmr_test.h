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

#ifndef __VRMR_TEST_H__
#define __VRMR_TEST_H__

#include <vuurmuur.h>

/* Context for tests that never read a config file: vrmr_init() gives us the
 * compile-time paths and the compiled regexes. */
extern struct vrmr_ctx vrmr_test_ctx;

int vrmr_test_setup(void);
void vrmr_test_teardown(void);

/* One rules.conf line into a fresh rule, NULL if the parser rejects it.
 * Release with vrmr_test_rule_free(). */
struct vrmr_rule *vrmr_test_rule_parse(const char *line);
void vrmr_test_rule_free(struct vrmr_rule *rule);

/* Options helpers: the struct owns its lists, so free it through
 * vrmr_rules_free_options(). */
struct vrmr_rule_options *vrmr_test_opt_new(void);
int vrmr_test_opt_read(struct vrmr_rule_options *opt, const char *optstr);

/* first port range of a port option list, or NULL when empty */
struct vrmr_portdata *vrmr_test_port_first(struct vrmr_list *list);

#endif

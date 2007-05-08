/***************************************************************************
 *   Copyright (C) 2002-2006 by Victor Julien                              *
 *   victor@nk.nl                                                          *
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

#ifndef __TEXTDIR_PLUGIN_H__
#define __TEXTDIR_PLUGIN_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vuurmuur.h>

#define MAX_LINE_LENGTH		512

#define MAX_RULE_NAME		32

struct TextdirBackend_
{
	/* 0: if backend is closed, 1: open */
	int	backend_open;

	/* not yet used */
	int	writable;

	DIR	*zone_p;
	DIR	*network_p;
	DIR	*host_p;
	DIR	*group_p;

	DIR	*service_p;

	DIR	*interface_p;

	DIR	*rule_p;

	FILE	*file;

	char	cur_zone[MAX_ZONE],
		cur_network[MAX_NETWORK],
		cur_host[MAX_HOST];

	char	interface[MAX_INTERFACE];

	char	rule[MAX_RULE_NAME];

	char	textdirlocation[512];

	void	*plugin_handle;

	/* regexes for checking the names */
	regex_t		*zonename_reg;
	regex_t		*servicename_reg;
	regex_t		*interfacename_reg;
};


char *get_filelocation(const int debuglvl, void *backend, char *name, const int type);
int ask_textdir(const int debuglvl, void *backend, char *name, char *question, char *answer, size_t max_answer, int type, int multi);
int tell_textdir(const int debuglvl, void *backend, char *name, char *question, char *answer, int overwrite, int type);
int open_textdir(int debuglvl, void *backend, int mode, int type);
int close_textdir(int debuglvl, void *backend, int type);
char *list_textdir(int debuglvl, void *backend, char *name, int *zonetype, int type);
int init_textdir(int debuglvl, void *backend, int type);
int add_textdir(const int debuglvl, void *backend, char *name, int type);
int del_textdir(const int debuglvl, void *backend, char *name, int type, int recurs);
int rename_textdir(const int debuglvl, void *backend, char *name, char *newname, int type);
int conf_textdir(const int debuglvl, void *backend);
int setup_textdir(int debuglvl, void **backend);

#endif

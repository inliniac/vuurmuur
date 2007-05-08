/***************************************************************************
 *   Copyright (C) 2003-2006 by Victor Julien                              *
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
 
#include "main.h"


/*	vuurmuur_check_lib_version

	This function checks the version of libvuurmuur.

		 0: ok
		-1: error
*/
int
vuurmuur_check_lib_version(const int debuglvl, int major, int minor, int sub, int min_lib_major, int min_lib_minor, int min_lib_sub)
{
	int	retval=0;
	int	lib_major,
		lib_minor,
		lib_sub;
	int	min_vuur_major,
		min_vuur_minor,
		min_vuur_sub;

	tell_libvuurmuur_version(&lib_major, &lib_minor, &lib_sub, &min_vuur_major, &min_vuur_minor, &min_vuur_sub);

	if(lib_major >= min_lib_major && lib_minor >= min_lib_minor && lib_sub >= min_lib_sub)
	{

	}
	else
	{
		fprintf(stdout, "Libvuurmuur version: %d.%d.%d, ", lib_major, lib_minor, lib_sub);
		fprintf(stdout, "minimal required version: %d.%d.%d: ", min_lib_major, min_lib_minor, min_lib_sub);
		fprintf(stdout, "error, update your libvuurmuur.\n");

		retval=-1;
	}


	if(major >= min_vuur_major && minor >= min_vuur_minor && sub >= min_vuur_sub)
	{

	}
	else
	{
		fprintf(stdout, "Vuurmuur version: %d.%d.%d, ", major, minor, sub);
		fprintf(stdout, "minimal required version (by libvuurmuur): %d.%d.%d, ", min_vuur_major, min_vuur_minor, min_vuur_sub);
		fprintf(stdout, "error, you need to update Vuurmuur.\n");

		retval=-1;
	}

	return(retval);
}


void
send_hup_to_vuurmuurlog(const int debuglvl)
{
	int	i = 0;
	pid_t	vuurmuur_pid;
	int	result = 0;

	/* get the pid (the i is bogus) */
	vuurmuur_pid = get_vuurmuur_pid("/var/run/vuurmuur_log.pid", &i);
	if(vuurmuur_pid > 0)
	{
		/* send a signal to vuurmuur_log */
		result = kill(vuurmuur_pid, SIGHUP);
		if(result < 0)
		{
			(void)vrprint.warning("Warning", "sending SIGHUP to Vuurmuur_log failed (PID: %ld): %s.",
								(long)vuurmuur_pid,
								strerror(errno));
		}
	}
	else
	{
		(void)vrprint.warning("Warning", "sending SIGHUP to Vuurmuur_log failed: could not get pid.");
	}

	return;
}

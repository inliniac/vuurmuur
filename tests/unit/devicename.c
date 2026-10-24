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

/* Tier 0: vrmr_validate_devicename(), the gate on the device of an interface.
 * The device is put in front of tc, iptables and ip as a bare word in a command
 * string that goes to a shell, so this is the one place that decides what may
 * appear there. Names the kernel itself would accept have to keep working. */

#include "config.h"
#include "vuurmuur.h"

#include <stdlib.h>
#include <string.h>

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"

int main(void)
{
    if (vrmr_test_setup() < 0) {
        (void)fprintf(stdout, "Bail out! vrmr_test_setup failed\n");
        return EXIT_FAILURE;
    }

    /* an empty device is a cleared one, and legal: it means no interface */
    (void)tap_int_eq(
            "device: empty is accepted", vrmr_validate_devicename(""), 0);

    /* ordinary names */
    (void)tap_int_eq("device: eth0", vrmr_validate_devicename("eth0"), 0);
    (void)tap_int_eq("device: a predictable name",
            vrmr_validate_devicename("enp0s25"), 0);
    (void)tap_int_eq(
            "device: a VLAN device", vrmr_validate_devicename("eth0.100"), 0);
    (void)tap_int_eq(
            "device: an alias", vrmr_validate_devicename("bond0:1"), 0);
    (void)tap_int_eq("device: the longest the kernel allows",
            vrmr_validate_devicename("123456789012345"), 0);

    /* too long for the field, so it would be truncated on the way in */
    (void)tap_int_eq("device: one over IFNAMSIZ is refused",
            vrmr_validate_devicename("1234567890123456"), -1);

    /* the shell */
    (void)tap_int_eq("device: a command separator is refused",
            vrmr_validate_devicename("eth0;rm -rf /"), -1);
    (void)tap_int_eq("device: a pipe is refused",
            vrmr_validate_devicename("eth0|tcp"), -1);
    (void)tap_int_eq("device: a substitution is refused",
            vrmr_validate_devicename("eth0$(id)"), -1);
    (void)tap_int_eq("device: backquotes are refused",
            vrmr_validate_devicename("eth0`id`"), -1);
    (void)tap_int_eq("device: a redirect is refused",
            vrmr_validate_devicename("eth0>log"), -1);
    (void)tap_int_eq(
            "device: a glob is refused", vrmr_validate_devicename("eth*"), -1);
    (void)tap_int_eq("device: whitespace is refused",
            vrmr_validate_devicename("eth 0"), -1);
    (void)tap_int_eq("device: a newline is refused",
            vrmr_validate_devicename("eth0\n"), -1);
    (void)tap_int_eq("device: a path is refused",
            vrmr_validate_devicename("../eth0"), -1);

    vrmr_test_teardown();

    return tap_finish();
}

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

/* Tier 0: the address gates. An address that reaches one of these is later put
 * into an ip6tables or iptables command line, so "looks like an address" is the
 * whole question, and the IPv6 side had no answer at all. */

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

    /* the address on its own */
    (void)tap_int_eq("ipv6: an address is valid",
            vrmr_check_ipv6address(NULL, NULL, "2001:db8::1", 1), 1);
    (void)tap_int_eq("ipv6: loopback is valid",
            vrmr_check_ipv6address(NULL, NULL, "::1", 1), 1);
    (void)tap_int_eq("ipv6: all zeroes is valid",
            vrmr_check_ipv6address(NULL, NULL, "::", 1), 1);
    (void)tap_int_eq("ipv6: garbage is not valid",
            vrmr_check_ipv6address(NULL, NULL, "wobble", 1), -1);
    (void)tap_int_eq("ipv6: an empty address is not valid",
            vrmr_check_ipv6address(NULL, NULL, "", 1), -1);
    (void)tap_int_eq("ipv6: a dotted quad is not an ipv6 address",
            vrmr_check_ipv6address(NULL, NULL, "10.1.2.3", 1), -1);
    (void)tap_int_eq("ipv6: a prefix on the address is not an address",
            vrmr_check_ipv6address(NULL, NULL, "2001:db8::/64", 1), -1);

    /* what a shell would make of it */
    (void)tap_int_eq("ipv6: a command separator is not an address",
            vrmr_check_ipv6address(NULL, NULL, "2001:db8::1; rm -rf /", 1), -1);
    (void)tap_int_eq("ipv6: a netmask argument is not an address",
            vrmr_check_ipv6address(NULL, NULL, "::/0", 1), -1);

    /* belonging to a network */
    (void)tap_int_eq("ipv6: an address in the network",
            vrmr_check_ipv6address("2001:db8::", "64", "2001:db8::1", 1), 1);
    (void)tap_int_eq("ipv6: an address out of the network",
            vrmr_check_ipv6address("2001:db8::", "64", "2001:db8:1::1", 1), 0);
    (void)tap_int_eq("ipv6: a /0 network holds everything",
            vrmr_check_ipv6address("::", "0", "fe80::2", 1), 1);
    (void)tap_int_eq("ipv6: a /127 network on the right side",
            vrmr_check_ipv6address("2001:db8::", "127", "2001:db8::1", 1), 1);
    (void)tap_int_eq("ipv6: a /127 network next door",
            vrmr_check_ipv6address("2001:db8::", "127", "2001:db8::2", 1), 0);
    (void)tap_int_eq("ipv6: a network that is not an address",
            vrmr_check_ipv6address("nonsense", "64", "2001:db8::1", 1), -1);
    (void)tap_int_eq("ipv6: a cidr over 128",
            vrmr_check_ipv6address("2001:db8::", "129", "2001:db8::1", 1), -1);
    (void)tap_int_eq("ipv6: a cidr that is not a number",
            vrmr_check_ipv6address(
                    "2001:db8::", "sixty-four", "2001:db8::1", 1),
            -1);

    /* the cidr on its own, as the form writes it */
    (void)tap_int_eq("cidr: 64", vrmr_check_ipv6cidr("64"), 1);
    (void)tap_int_eq("cidr: 128 is the widest", vrmr_check_ipv6cidr("128"), 1);
    (void)tap_int_eq(
            "cidr: 0 is the whole internet", vrmr_check_ipv6cidr("0"), 1);
    (void)tap_int_eq("cidr: 129", vrmr_check_ipv6cidr("129"), -1);
    (void)tap_int_eq("cidr: negative", vrmr_check_ipv6cidr("-1"), -1);
    (void)tap_int_eq("cidr: not a number", vrmr_check_ipv6cidr("64x"), -1);
    (void)tap_int_eq("cidr: empty", vrmr_check_ipv6cidr(""), -1);

    /* the IPv4 gate, so a change here cannot quietly move it */
    (void)tap_int_eq("ipv4: an address is valid",
            vrmr_check_ipv4address(NULL, NULL, "10.1.2.3", 1), 1);
    (void)tap_int_eq("ipv4: a command separator is not an address",
            vrmr_check_ipv4address(NULL, NULL, "10.1.2.3; rm -rf /", 1), -1);
    (void)tap_int_eq("ipv4: an address in the network",
            vrmr_check_ipv4address("10.1.2.0", "255.255.255.0", "10.1.2.5", 1),
            1);
    (void)tap_int_eq("ipv4: an address out of the network",
            vrmr_check_ipv4address("10.1.2.0", "255.255.255.0", "10.1.3.5", 1),
            0);

    vrmr_test_teardown();

    return tap_finish();
}

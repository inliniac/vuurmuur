/***************************************************************************
 *   Copyright (C) 2002-2007 by Victor Julien                              *
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

#ifndef __ICMP_H__
#define __ICMP_H__

/*  Array containing structures with icmp types:

    4 variables are given:
        1. long_name: the official name from iana.org
        2. short_name: the name vuurmuur uses in logs, because longname would be too long
        3. type: the type of the icmp
        4. if the icmp-type has codes assosiated with it

    !!! NOTE: the length of the type and code should be equal to or less than 29. !!!
*/
struct vrmr_icmp_types_
{
    char long_name[28];
    char short_name[17];
    int type;
    int has_code; // 0 no code, 1 yes
} vrmr_icmp_types[] =
    {
        // longname                     shortname           type    has_code
        //                               1234567890123456
        {"Echo Reply",                  "echo-reply",       0,      0},
        {"Unassigned",                  "unassigned",       1,      0},
        {"Unassigned",                  "unassigned",       2,      0},
        {"Destiation Unreachable",      "dest-unreach",     3,      1},//12
        {"Source Quench",               "source-quench",    4,      0},
        {"Redirect",                    "redirect",         5,      1},//8
        {"Alternate Host Address",      "alt-host-addr",    6,      0},
        {"Unassigned",                  "unassigned",       7,      0},
        {"Echo",                        "echo",             8,      0},
        {"Router Advertisement",        "router-advert",    9,      1},//13
        {"Router Selection",            "router-select",    10,     0},
        {"Time Exceeded",               "time-exceeded",    11,     1},//13
        {"Parameter Problem",           "param-problem",    12,     1},//13
        {"Timestamp",                   "time-stmp",        13,     0},
        {"Timestamp Reply",             "time-stmp-rply",   14,     0},
        {"Information Request",         "info-request",     15,     0},
        {"Information Reply",           "info-reply",       16,     0},
        {"Address Mask Request",        "addr-msk-req",     17,     0},
        {"Address Mask Reply",          "addr-msk-reply",   18,     0},
        {"Reserved",                    "reserved",         19,     0},
        {"Reserved",                    "reserved",         20,     0},
        {"Reserved",                    "reserved",         21,     0},
        {"Reserved",                    "reserved",         22,     0},
        {"Reserved",                    "reserved",         23,     0},
        {"Reserved",                    "reserved",         24,     0},
        {"Reserved",                    "reserved",         25,     0},
        {"Reserved",                    "reserved",         26,     0},
        {"Reserved",                    "reserved",         27,     0},
        {"Reserved",                    "reserved",         28,     0},
        {"Reserved",                    "reserved",         29,     0},
        {"Traceroute",                  "traceroute",       30,     0},
        {"Datagram Conversion Error",   "datagr-conv-err",  31,     0},
        {"Mobile Host Redirect",        "mobile-hst-redir", 32,     0},
        {"IPv6 Where-Are-You",          "ipv6-where-you",   33,     0},
        {"IPv6 I-Am-Here",              "ipv6-iam-here",    34,     0},
        {"Mobile Registration Request", "mobile-reg-req",   35,     0},
        {"Mobile Registration Reply",   "mobile-reg-reply", 36,     0},
        {"SKIP",                        "skip",             39,     0},
        {"Photuris",                    "photuris",         40,     1},//8
#ifdef HAVE_IPV6
        {"Echo Request",                "echo-request",     128,    0},
        {"Echo Reply",                  "echo-reply",       129,    0},
        {"Neighbor Solicitation",       "neigh-sollicit",   135,    0},
        {"Neighbor Advertisement",      "neigh-advert",     136,    0},
#endif /* HAVE_IPV6 */
        // last
        {"", "", -1, -1},
    };

/*  Array containing structures with icmp codes:

    4 variables are given:
        1. type: the type of icmp where this belongs to
        2. code: the code number
        3. long_name: the official name of the code
        4. short_name: the vuurmuur name of the code

    !!! NOTE: the length of the type and code should be equal to or less than 29. !!!
*/
struct vrmr_icmp_codes_
{
    int type;
    int code;
    char long_name[70];
    char short_name[32];
} vrmr_icmp_codes[] =
{
    // type // code //long                                                                  //short
    //                                                                                       12345678901234567
    {3,     0,      "Net Unreachable",                                                      "network"},
    {3,     1,      "Host Unreachable",                                                     "host"},
    {3,     2,      "Protocol Unreachable",                                                 "protocol"},
    {3,     3,      "Port Unreachable",                                                     "port"},
    {3,     4,      "Fragmentation Needed and Don't Fragment was Set",                      "frag-needed"},
    {3,     5,      "Source Route Failed",                                                  "src-rt-failed"},
    {3,     6,      "Destination Network Unknown",                                          "dst-net-unknown"},
    {3,     7,      "Destination Host Unknown",                                             "dst-host-unknown"},
    {3,     8,      "Source Host Isolated",                                                 "src-hst-isolated"},
    {3,     9,      "Communication with Destination Network is Administratively Prohibited","net-prohibited"},
    {3,     10,     "Communication with Destination Host is Administratively Prohibited",   "host-prohibited"},
    {3,     11,     "Destination Network Unreachable for Type of Service",                  "tos-net-unreach"},
    {3,     12,     "Destination Host Unreachable for Type of Service",                     "tos-host-unreach"},
    {3,     13,     "Communication Administratively Prohibited",                            "comm-prohibited"},
    {3,     14,     "Host Precedence Violation",                                            "hst-pre-violatio"},
    {3,     15,     "Precedence cutoff in effect",                                          "precedence-cutof"},

    //                                                                                       123456789012345678901
    {5,     0,      "Redirect Datagram for the Network (or subnet)",                        "redirect-net"},
    {5,     1,      "Redirect Datagram for the Host",                                       "redirect-host"},
    {5,     2,      "Redirect Datagram for the Type of Service and Network",                "redirect-tos-network"},
    {5,     3,      "Redirect Datagram for the Type of Service and Host",                   "redirect-tos-host"},

    //                                                                                       1234567890123456
    {9,     0,      "Normal router advertisement",                                          "normal"},
    {9,     16,     "Does not route common traffic",                                        "dont-rt-common"},

    //                                                                                       1234567890123456
    {11,    0,      "Time to Live exceeded in Transit",                                     "ttl-exc-transit"},
    {11,    1,      "Fragment Reassembly Time Exceeded",                                    "frag-reassebly"},

    //                                                                                       1234567890123456
    {12,    0,      "Pointer indicates the error",                                          "pointer"},
    {12,    1,      "Missing a Required Option",                                            "miss-req-option"},
    {12,    2,      "Bad Length",                                                           "bad-length"},

    //                                                                                       123456789012345678901
    {40,    0,      "Bad SPI",                                                              "bad-spi"},
    {40,    1,      "Authentication Failed",                                                "auth-fail"},
    {40,    2,      "Decompression Failed",                                                 "decomp-fail"},
    {40,    3,      "Decryption Failed",                                                    "decrypt-fail"},
    {40,    4,      "Need Authentication",                                                  "need-authentication"},
    {40,    5,      "Need Authorization",                                                   "need-authorization"},

    // last
    {-1, -1, "", ""},
};

#endif


# set the include path found by configure
INCLUDES = $(all_includes)

# the library search path.
lib_LTLIBRARIES =  libvuurmuur.la
libvuurmuur_la_LDFLAGS = -version-info 6:0:6
libvuurmuur_la_LIBADD = -ldl
libvuurmuur_la_SOURCES = backendapi.c config.c conntrack.c hash.c icmp.c info.c \
			interfaces.c io.c libvuurmuur.c linkedlist.c log.c proc.c rules.c services.c \
			zones.c strlcatu.c strlcpyu.c iptcap.c blocklist.c binreloc.c filter.c util.c shape.c
include_HEADERS =  vuurmuur.h

AM_CFLAGS = -DLIBDIR=$(libdir) -DSYSCONFDIR=$(sysconfdir)

noinst_HEADERS = binreloc.h

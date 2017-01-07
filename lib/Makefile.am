lib_LTLIBRARIES = libvuurmuur.la
libvuurmuur_la_LDFLAGS = -version-info 6:0:6
libvuurmuur_la_LIBADD = textdir/libtextdir.la

libvuurmuur_la_SOURCES = \
backendapi.c \
blocklist.c \
config.c \
conntrack.c conntrack.h \
filter.c \
hash.c \
icmp.c icmp.h \
info.c \
interfaces.c \
io.c \
iptcap.c \
libvuurmuur.c \
linkedlist.c \
log.c \
proc.c \
rules.c \
services.c \
shape.c \
strlcatu.c \
strlcpyu.c \
util.c \
zones.c

AM_CFLAGS = -DLIBDIR=$(libdir) -DSYSCONFDIR=$(sysconfdir)
noinst_HEADERS = conntrack.h icmp.h
SUBDIRS=textdir


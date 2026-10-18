METASOURCES = AUTO
AM_CPPFLAGS = -I$(top_srcdir)/lib

# The ruleset engine: everything the daemons run in-process, so a test can
# link it. No main() here.
noinst_LTLIBRARIES = libvuurmuur_engine.la
libvuurmuur_engine_la_SOURCES = \
createrule.c \
misc.c \
reload.c \
rules.c \
ruleset.c \
shape.c
libvuurmuur_engine_la_LIBADD = $(LIBVUURMUUR_LDADD)

bin_PROGRAMS = vuurmuur
vuurmuur_SOURCES = vuurmuur.c
vuurmuur_LDADD = libvuurmuur_engine.la $(LIBVUURMUUR_LDADD)
noinst_HEADERS = main.h

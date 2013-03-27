# textdir plugin

libdir = @VUURMUUR_PLUGIN_DIR@

lib_LTLIBRARIES = libtextdir.la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src
libtextdir_la_SOURCES = textdir_plugin.c textdir_ask.c textdir_tell.c textdir_list.c
libtextdir_la_LDFLAGS = -export-dynamic
libtextdir_la_CFLAGS = -fPIC
libtextdir_la_LIBADD = -lvuurmuur

noinst_HEADERS = textdir_plugin.h

EXTRA_DIST = textdir.conf textdir.conf.debian


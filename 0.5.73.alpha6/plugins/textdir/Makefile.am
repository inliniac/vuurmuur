
METASOURCES = AUTO
noinst_PROGRAMS = textdir.so


textdir_so_SOURCES = textdir_plugin.c textdir_ask.c textdir_tell.c \
	textdir_list.c
INCLUDES = -I$(top_srcdir)/src
AM_CFLAGS = -fPIC
textdir_so_LDFLAGS = -shared

vuurmuur_pluginsdir = "$(libdir)/vuurmuur/plugins"
vuurmuur_plugins_DATA = textdir.so
noinst_HEADERS = textdir_plugin.h

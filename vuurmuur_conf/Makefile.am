bin_PROGRAMS = vuurmuur_conf
vuurmuur_conf_SOURCES = \
bw_sec.c \
config.c \
config_section.c \
conn_sec.c \
filter.c \
gui.c gui.h \
help.c \
if_sec.c \
logview_section.c \
mainmenu.c \
navigation.c \
rules_form.c \
services_section.c \
statevent.c \
stat_sec.c \
sys_sec.c \
templates.c \
topmenu.c \
vuurmuur_conf.c \
zones_section.c

# set the include path found by configure
AM_CPPFLAGS = -I. -I.. -I$(top_srcdir)/intl $(all_includes)

# the library search path.
vuurmuur_conf_LDFLAGS = $(all_libraries) 
vuurmuur_conf_LDADD = $(LIBVUURMUUR_LDADD) $(NCURSES_LIBS)

LIBS = @LIBINTL@ @LIBS@

noinst_HEADERS = strings.h gui.h main.h gettext.h

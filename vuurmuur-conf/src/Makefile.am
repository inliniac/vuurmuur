bin_PROGRAMS = vuurmuur_conf
vuurmuur_conf_SOURCES = vuurmuur_conf.c config_section.c conn_sec.c if_sec.c \
				logview_section.c navigation.c rules_form.c services_section.c stat_sec.c sys_sec.c \
				templates.c topmenu.c zones_section.c help.c config.c mainmenu.c bw_sec.c filter.c \
        		gui.c statevent.c

# set the include path found by configure
AM_CPPFLAGS = -I. -I.. -I$(top_srcdir)/intl $(all_includes)

# the library search path.
vuurmuur_conf_LDFLAGS = $(all_libraries) 
vuurmuur_conf_LDADD = -lvuurmuur

#DEFS = -DLOCALEDIR=\"$(localedir)\" -DDATADIR=$(datadir) @DEFS@
LIBS = @LIBINTL@ @LIBS@

#localedir = $(datadir)/locale
noinst_HEADERS = strings.h gui.h main.h gettext.h

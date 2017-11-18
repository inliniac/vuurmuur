AC_INIT([vuurmuur],[0.8rc3])
m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([vuurmuur/vuurmuur.c])
AM_INIT_AUTOMAKE

AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])

AC_USE_SYSTEM_EXTENSIONS

AC_LANG([C])
AC_PROG_CC
AC_PROG_CC_C99
LT_INIT

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION

ac_build_ipv6=yes
AC_ARG_ENABLE([ipv6],
        [AS_HELP_STRING([--disable-ipv6],[disable IPv6 support])],
        [ if test "x$enableval" = "xno"; then
            ac_build_ipv6=$enableval
          fi
        ], [
            ac_build_ipv6=yes
        ] )

if test "x${ac_build_ipv6}" = "xyes"; then
    AC_DEFINE(IPV6_ENABLED, 1, [build with IPv6 support])
fi

# locale dir option for rpm building
# switch to VRMR_LOCALEDIR because LOCALEDIR conflicts with intl/ in
# make distcheck
AC_ARG_WITH(tmplocaledir,
       [  --with-localedir=DIR  vuurmuur locale dir (default $prefix/locale)],
       [tmplocaledir="$withval"],[tmplocaledir=no])

if test "$tmplocaledir" != "no"; then
    CPPFLAGS="${CPPFLAGS} -DVRMR_LOCALEDIR=\"${tmplocaledir}\""
else
    CPPFLAGS="${CPPFLAGS} -DVRMR_LOCALEDIR=\"${datadir}/locale\""
fi

# shared dir option for rpm building
AC_ARG_WITH(shareddir,
       [  --with-shareddir=DIR  vuurmuur shared dir (default $datadir/vuurmuur)],
       [shareddir="$withval"],[shareddir=no])

if test "$shareddir" != "no"; then
   CPPFLAGS="${CPPFLAGS} -DDATADIR=\"${shareddir}\""
else
   CPPFLAGS="${CPPFLAGS} -DDATADIR=\"${datadir}/vuurmuur\""
fi

# nfnetlink lib
AC_ARG_WITH(libnfnetlink_includes,
        [  --with-libnfnetlink-includes=DIR  libnfnetlink include directory],
        [with_libnfnetlink_includes="$withval"],[with_libnfnetlink_includes=no])
AC_ARG_WITH(libnfnetlink_libraries,
        [  --with-libnfnetlink-libraries=DIR    libnfnetlink library directory],
        [with_libnfnetlink_libraries="$withval"],[with_libnfnetlink_libraries="no"])

if test "$with_libnfnetlink_includes" != "no"; then
CPPFLAGS="${CPPFLAGS} -I${with_libnfnetlink_includes}"
fi
AC_CHECK_HEADER(libnfnetlink/libnfnetlink.h,,)

if test "$with_libnfnetlink_libraries" != "no"; then
LDFLAGS="${LDFLAGS}  -L${with_libnfnetlink_libraries}"
fi

AC_CHECK_LIB(nfnetlink, nfnl_fd, [LIBNFNETLINK_LIBS="-lnfnetlink"], NFNETLINK="no")
if test "$NFNETLINK" != "no"; then
    AC_DEFINE([HAVE_NFNETLINK],[1],[libnfnetlink available])
fi

# mnl lib
AC_ARG_WITH(libmnl_includes,
        [  --with-libmnl-includes=DIR  libmnl include directory],
        [with_libmnl_includes="$withval"],[with_libmnl_includes=no])
AC_ARG_WITH(libmnl_libraries,
        [  --with-libmnl-libraries=DIR    libmnl library directory],
        [with_libmnl_libraries="$withval"],[with_libmnl_libraries="no"])

if test "$with_libmnl_includes" != "no"; then
CPPFLAGS="${CPPFLAGS} -I${with_libmnl_includes}"
fi
AC_CHECK_HEADER(libmnl/libmnl.h,,)

if test "$with_libmnl_libraries" != "no"; then
LDFLAGS="${LDFLAGS}  -L${with_libmnl_libraries}"
fi

AC_CHECK_LIB(mnl, mnl_socket_open, [LIBMNL_LIBS="-lmnl"], MNL="no")
if test "$MNL" != "no"; then
    AC_DEFINE([HAVE_MNL],[1],[libmnl available])
fi

# netfilter_conntrack lib
AC_ARG_WITH(libnetfilter_conntrack_includes,
        [  --with-libnetfilter_conntrack-includes=DIR  libnetfilter_conntrack include directory],
        [with_libnetfilter_conntrack_includes="$withval"],[with_libnetfilter_conntrack_includes=no])
AC_ARG_WITH(libnetfilter_conntrack_libraries,
        [  --with-libnetfilter_conntrack-libraries=DIR    libnetfilter_conntrack library directory],
        [with_libnetfilter_conntrack_libraries="$withval"],[with_libnetfilter_conntrack_libraries="no"])

if test "$with_libnetfilter_conntrack_includes" != "no"; then
CPPFLAGS="${CPPFLAGS} -I${with_libnetfilter_conntrack_includes}"
fi
AC_CHECK_HEADER(libnetfilter_conntrack/libnetfilter_conntrack.h,,)

if test "$with_libnetfilter_conntrack_libraries" != "no"; then
LDFLAGS="${LDFLAGS}  -L${with_libnetfilter_conntrack_libraries}"
fi

AC_CHECK_LIB(netfilter_conntrack, nfct_nlmsg_parse, [LIBNETFILTER_CONNTRACK_LIBS="-lnetfilter_conntrack"], NFCONNTRACK="no")
if test "$NFCONNTRACK" != "no"; then
    AC_DEFINE([HAVE_LIBNETFILTER_CONNTRACK],[1],[libnetfilter_conntrack available])
fi

# netfilter_log lib
AC_ARG_WITH(libnetfilter_log_includes,
        [  --with-libnetfilter_log-includes=DIR  libnetfilter_log include directory],
        [with_libnetfilter_log_includes="$withval"],[with_libnetfilter_log_includes=no])
AC_ARG_WITH(libnetfilter_log_libraries,
        [  --with-libnetfilter_log-libraries=DIR    libnetfilter_log library directory],
        [with_libnetfilter_log_libraries="$withval"],[with_libnetfilter_log_libraries="no"])

if test "$with_libnetfilter_log_includes" != "no"; then
CPPFLAGS="${CPPFLAGS} -I${with_libnetfilter_log_includes}"
fi
AC_CHECK_HEADER(libnetfilter_log/libnetfilter_log.h,,)

if test "$with_libnetfilter_log_libraries" != "no"; then
LDFLAGS="${LDFLAGS}  -L${with_libnetfilter_log_libraries}"
fi

AC_CHECK_LIB(netfilter_log, nflog_open, [LIBNETFILTER_LOG_LIBS="-lnetfilter_log"], NFLOG="no")
if test "$NFLOG" != "no"; then
    AC_DEFINE([HAVE_LIBNETFILTER_LOG],[1],[libnetfilter_log available])
fi

AC_ARG_WITH(ncurses_includes,
	[  --with-libncurses-includes=DIR  libncurses includes directory],
	[with_libncurses_includes="$withval"],[with_libncurses_includes=no])

AC_ARG_WITH(ncurses_libraries,
	[  --with-libncurses-libraries=DIR  libncurses library directory],
	[with_libncurses_libraries="$withval"],[with_libncurses_libraries=no])

if test "$with_libncurses_includes" != "no"; then
	CPPFLAGS="${CPPFLAGS} -I${with_libncurses_includes}"
fi

if test "$with_libncurses_libraries" != "no"; then
	LDFLAGS="${LDFLAGS}  -L${with_libncurses_libraries}"
fi

AC_ARG_WITH(widec,
	[  --with-widec=yes|no|auto(default)  compile with widecharacter support (ncursesw)],
	[widec="$withval"],[widec=auto])

if test "$widec" = "auto"; then
	LCURS=""
	WCURS=""
	AC_CHECK_HEADERS(ncurses.h,, LCURS="no")
	AC_CHECK_HEADERS(ncursesw/ncurses.h,, WCURS="no")
	if test "$LCURS" = "no" && test "$WCURS" = "no"; then
		echo
		echo "   ERROR!  ncurses.h header not found!"
		echo "   Please install the development package of Ncurses."
		exit
	fi
	if test "$WCURS" != "no"; then
		CPPFLAGS="${CPPFLAGS} -DHAVE_NC_WIDE_HEADERS"
	fi

	LCURS=""
	WCURS=""
	AC_CHECK_HEADERS(panel.h,, LCURS="no")
	AC_CHECK_HEADERS(ncursesw/panel.h,, WCURS="no")
	if test "$LCURS" = "no" && test "$WCURS" = "no"; then
		echo
		echo "   ERROR!  panel.h header not found!"
		echo "   Please install the development package of Ncurses."
		exit
	fi

	LCURS=""
	WCURS=""
	AC_CHECK_HEADERS(menu.h,, LCURS="no")
	AC_CHECK_HEADERS(ncursesw/menu.h,, WCURS="no")
	if test "$LCURS" = "no" && test "$WCURS" = "no"; then
		echo
		echo "   ERROR!  menu.h header not found!"
		echo "   Please install the development package of Ncurses."
		exit
	fi

	NCURS=""
	NCURSW=""
	AC_CHECK_LIB(ncursesw,initscr,[NCURSES_LIBS="$NCURSES_LIBS -lncursesw"], NCURSW="no")
	if test "$NCURSW" = "no"; then
		AC_CHECK_LIB(ncurses,initscr,[NCURSES_LIBS="$NCURSES_LIBS -lncurses"], NCURS="no")
		if test "$NCURS" = "no" && test "$NCURSW" = "no"; then
			echo
			echo "   ERROR!  Ncurses library not found!"
	        	exit
		fi
	else
		CPPFLAGS="${CPPFLAGS} -DUSE_WIDEC"
	fi

	NCURS=""
	NCURSW=""
	AC_CHECK_LIB(menuw,new_menu,[NCURSES_LIBS="$NCURSES_LIBS -lmenuw"], NCURSW="no")
	if test "$NCURSW" = "no"; then
		AC_CHECK_LIB(menu,new_menu,, NCURS="no")
		if test "$NCURS" = "no"; then
			echo
			echo "   ERROR!  Ncurses/menu library not found!"
			exit
		fi
	fi

	NCURS=""
	NCURSW=""
	AC_CHECK_LIB(formw,new_form,[NCURSES_LIBS="$NCURSES_LIBS -lformw"], NCURSW="no")
	if test "$NCURSW" = "no"; then
		AC_CHECK_LIB(form,new_form,, NCURS="no")
		if test "$NCURS" = "no"; then
			echo
			echo "   ERROR!  Ncurses/form library not found!"
			exit
		fi
	fi

	NCURS=""
	NCURSW=""
	AC_CHECK_LIB(panelw,new_panel,[NCURSES_LIBS="$NCURSES_LIBS -lpanelw"], NCURSW="no")
	if test "$NCURSW" = "no"; then
		AC_CHECK_LIB(panel,new_panel,, NCURS="no")
		if test "$NCURS" = "no"; then
			echo
			echo "   ERROR!  Ncurses/panel library not found!"
			exit
		fi
	fi
elif test "$widec" = "yes"; then
	# check for normal ncurses headers as well, because some
	# distros seem to have placed the wide headers in
	# the path of the normal ones (suse 9.3)
	
	CPPFLAGS="${CPPFLAGS} -DUSE_WIDEC"

	LCURS=""
	WCURS=""
	AC_CHECK_HEADERS(ncursesw/ncurses.h,, WCURS="no")
	if test "$LCURS" = "no" && test "$WCURS" = "no"; then
		echo
		echo "   ERROR!  ncurses.h header not found!"
		echo "   Please install the development package of Ncurses."
		exit
	fi
	if test "$WCURS" != "no"; then
		CPPFLAGS="${CPPFLAGS} -DHAVE_NC_WIDE_HEADERS"
	fi

	LCURS=""
	WCURS=""
	AC_CHECK_HEADERS(panel.h,, LCURS="no")
	AC_CHECK_HEADERS(ncursesw/panel.h,, WCURS="no")
	if test "$LCURS" = "no" && test "$WCURS" = "no"; then
		echo
		echo "   ERROR!  panel.h header not found!"
		echo "   Please install the development package of Ncurses."
		exit
	fi

	LCURS=""
	WCURS=""
	AC_CHECK_HEADERS(menu.h,, LCURS="no")
	AC_CHECK_HEADERS(ncursesw/menu.h,, WCURS="no")
	if test "$LCURS" = "no" && test "$WCURS" = "no"; then
		echo
		echo "   ERROR!  menu.h header not found!"
		echo "   Please install the development package of Ncurses."
		exit
	fi

	NCURSW=""
	AC_CHECK_LIB(ncursesw,initscr,[NCURSES_LIBS="$NCURSES_LIBS -lncursesw"], NCURSW="no")
	if test "$NCURSW" = "no"; then
		echo
		echo "   ERROR!  Ncursesw library not found!"
        	exit
	fi

	NCURSW=""
	AC_CHECK_LIB(menuw,new_menu,[NCURSES_LIBS="$NCURSES_LIBS -lmenuw"], NCURSW="no")
	if test "$NCURSW" = "no"; then
		echo
		echo "   ERROR!  Ncursesw/menuw library not found!"
		exit
	fi

	NCURSW=""
	AC_CHECK_LIB(formw,new_form,[NCURSES_LIBS="$NCURSES_LIBS -lformw"], NCURSW="no")
	if test "$NCURSW" = "no"; then
		echo
		echo "   ERROR!  Ncursesw/formw library not found!"
		exit
	fi

	NCURSW=""
	AC_CHECK_LIB(panelw,new_panel,[NCURSES_LIBS="$NCURSES_LIBS -lpanelw"], NCURSW="no")
	if test "$NCURSW" = "no"; then
		echo
		echo "   ERROR!  Ncursesw/panelw library not found!"
		exit
	fi
else
	# No ncursesw. Just check for normal ncurses
	#
	#
	
	LCURS=""
	AC_CHECK_HEADERS(ncurses.h,, LCURS="no")
	if test "$LCURS" = "no"; then
		echo
		echo "   ERROR!  ncurses.h header not found!"
		echo "   Please install the development package of Ncurses."
		exit
	fi

	LCURS=""
	AC_CHECK_HEADERS(panel.h,, LCURS="no")
	if test "$LCURS" = "no"; then
		echo
		echo "   ERROR!  panel.h header not found!"
		echo "   Please install the development package of Ncurses."
		exit
	fi

	LCURS=""
	AC_CHECK_HEADERS(menu.h,, LCURS="no")
	if test "$LCURS" = "no"; then
		echo
		echo "   ERROR!  menu.h header not found!"
		echo "   Please install the development package of Ncurses."
		exit
	fi

	NCURS=""
	AC_CHECK_LIB(ncurses,initscr,[NCURSES_LIBS="$NCURSES_LIBS -lncurses"], NCURS="no")
	if test "$NCURS" = "no"; then
		echo
		echo "   ERROR!  Ncurses library not found!"
        	exit
	fi

	NCURS=""
	AC_CHECK_LIB(menu,new_menu,[NCURSES_LIBS="$NCURSES_LIBS -lmenu"], NCURS="no")
	if test "$NCURS" = "no"; then
		echo
		echo "   ERROR!  Ncurses/menu library not found!"
		exit
	fi

	NCURS=""
	AC_CHECK_LIB(form,new_form, [NCURSES_LIBS="$NCURSES_LIBS -lform"], NCURS="no")
	if test "$NCURS" = "no"; then
		echo
		echo "   ERROR!  Ncurses/form library not found!"
		exit
	fi

	NCURS=""
	AC_CHECK_LIB(panel,new_panel, [NCURSES_LIBS="$NCURSES_LIBS -lpanel"], NCURS="no")
	if test "$NCURS" = "no"; then
		echo
		echo "   ERROR!  Ncurses/panel library not found!"
		exit
	fi
fi

LIBVUURMUUR_LDADD="../lib/libvuurmuur.la"
AC_SUBST(LIBVUURMUUR_LDADD)
# make sure vuurmuur.h is added to the includes
CPPFLAGS="-I\${top_srcdir}/include/ ${CPPFLAGS}"
AC_SUBST(LIBNFNETLINK_LIBS)
AC_SUBST(LIBMNL_LIBS)
AC_SUBST(LIBNETFILTER_CONNTRACK_LIBS)
AC_SUBST(LIBNETFILTER_LOG_LIBS)
AC_SUBST(NCURSES_LIBS)

AC_CONFIG_FILES([Makefile include/Makefile lib/Makefile lib/textdir/Makefile
        vuurmuur/Makefile vuurmuur_log/Makefile vuurmuur_conf/Makefile
        po/Makefile.in
        vuurmuur_script/Makefile scripts/Makefile services/Makefile
        config/Makefile man/Makefile man/en/Makefile man/ru/Makefile
        debian/Makefile help/Makefile doc/Makefile])
AC_OUTPUT


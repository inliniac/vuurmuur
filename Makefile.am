# not a GNU package. You can remove this line, if
# have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign 1.4

SUBDIRS = po include lib vuurmuur vuurmuur_log vuurmuur_script vuurmuur_conf scripts services config man debian help doc tests

ACLOCAL_AMFLAGS = -I m4

# distcheck is the only job that compiles the check-phase programs, so it has to
# compile them strictly: a warning in a test-only file is otherwise invisible
# until someone runs --enable-werror by hand, and 'make' alone never builds them.
# automake passes this before $(DISTCHECK_CONFIGURE_FLAGS) (see Makefile.in:693-694),
# so a caller's own flag on the same knob still wins and --disable-werror on the
# command line stays effective.
AM_DISTCHECK_CONFIGURE_FLAGS = --enable-werror

EXTRA_DIST = config.rpath installer

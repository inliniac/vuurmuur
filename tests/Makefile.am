# subdir-objects: the programs here take sources from unit/, gen/ and lib/, and
# without it automake puts every .o in tests/, where the first repeated basename
# would collide
AUTOMAKE_OPTIONS = foreign 1.4 subdir-objects

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib -I$(top_srcdir)/vuurmuur \
	-I$(srcdir)/lib

check_PROGRAMS = unit/rules-parse unit/rules-options unit/lineread gen/ruleset

unit_rules_parse_SOURCES = lib/tap.c lib/tap.h lib/vrmr_test.c lib/vrmr_test.h \
	unit/rules_parse.c
unit_rules_parse_LDADD = $(LIBVUURMUUR_LDADD)

unit_rules_options_SOURCES = lib/tap.c lib/tap.h lib/vrmr_test.c lib/vrmr_test.h \
	unit/rules_options.c
unit_rules_options_LDADD = $(LIBVUURMUUR_LDADD)

unit_lineread_SOURCES = unit/lineread.c lib/tap.c lib/tap.h \
	lib/vrmr_test.c lib/vrmr_test.h
unit_lineread_LDADD = $(LIBVUURMUUR_LDADD)

# tier 1: drives the split-out engine over a fixture tree
gen_ruleset_SOURCES = lib/tap.c lib/tap.h lib/vrmr_test.c lib/vrmr_test.h \
	lib/sandbox.c lib/sandbox.h gen/ruleset.c
gen_ruleset_LDADD = \
	$(top_builddir)/vuurmuur/libvuurmuur_engine.la \
	$(top_builddir)/lib/libvuurmuur.la \
	$(LIBINTL)

# automake does not export srcdir to test programs, and the binaries live under
# the libtool wrapper: the .sh finds the fixtures and execs the program
AM_TESTS_ENVIRONMENT = abs_srcdir="$(abs_srcdir)"; export abs_srcdir; \
	UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"; export UBSAN_OPTIONS;

TESTS = unit/rules-parse unit/rules-options unit/lineread gen/ruleset.sh

EXTRA_DIST = DESIGN.md unit/README gen/ruleset.sh \
	cases/common/etc/state/interfaces/dmz.conf \
	cases/common/etc/state/interfaces/lan.conf \
	cases/common/etc/state/services/http \
	cases/common/etc/state/zones/dmz/networks/dmznet/network.config \
	cases/common/etc/state/zones/dmz/zone.config \
	cases/common/etc/state/zones/lan/networks/home/network.config \
	cases/common/etc/state/zones/lan/zone.config \
	cases/common/etc/vuurmuur/config.conf \
	cases/common/etc/vuurmuur/plugins/textdir.conf \
	cases/empty/etc/state/rules/rules.conf \
	cases/options/etc/state/rules/rules.conf \
	cases/protect/etc/state/interfaces/lan.conf \
	cases/protect/etc/state/rules/rules.conf \
	cases/simple/etc/state/rules/rules.conf \
	golden/empty.txt \
	golden/options.txt \
	golden/protect.txt \
	golden/simple.txt

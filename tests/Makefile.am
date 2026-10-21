# subdir-objects: the programs here take sources from unit/ and lib/, and
# without it automake puts every .o in tests/, where the first repeated basename
# would collide
AUTOMAKE_OPTIONS = foreign 1.4 subdir-objects

check_PROGRAMS = unit/rules-parse unit/rules-options

unit_rules_parse_SOURCES = \
unit/rules_parse.c \
lib/tap.c lib/tap.h \
lib/vrmr_test.c lib/vrmr_test.h
unit_rules_parse_LDADD = $(LIBVUURMUUR_LDADD)

unit_rules_options_SOURCES = \
unit/rules_options.c \
lib/tap.c lib/tap.h \
lib/vrmr_test.c lib/vrmr_test.h
unit_rules_options_LDADD = $(LIBVUURMUUR_LDADD)

TESTS = $(check_PROGRAMS)

# UBSan recovers by default, so a finding would print to stderr and still let the
# program exit 0: make it fatal where the test environment is defined rather than
# hoping a CI job sets it. Harmless in an unsanitized build.
AM_TESTS_ENVIRONMENT = UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"; \
	export UBSAN_OPTIONS;

EXTRA_DIST = DESIGN.md

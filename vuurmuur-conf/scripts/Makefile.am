vuurmuur_scriptdir = $(datadir)/vuurmuur/scripts/
vuurmuur_script_DATA = vuurmuur-searchlog.sh vuurmuur-wizard.sh
EXTRA_DIST = $(vuurmuur_script_DATA)

install:
	install -m 755 -d "$(DESTDIR)$(vuurmuur_scriptdir)"
	install -m 700 "vuurmuur-wizard.sh" "$(DESTDIR)$(vuurmuur_scriptdir)"

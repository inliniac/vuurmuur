scriptsdir = $(datadir)/vuurmuur/scripts
scripts_DATA = vuurmuur-config-setup.sh vuurmuur-initd.sh vuurmuur-initd.sh.suse vuurmuur-logrotate rc.vuurmuur

vcscriptsdir = $(scriptsdir)
vcscripts_DATA = vuurmuur-searchlog.sh vuurmuur-wizard.sh

install:
	install -m 755 -d "$(DESTDIR)$(vcscriptsdir)"
	install -m 700 "$(top_srcdir)/scripts/vuurmuur-wizard.sh" "$(DESTDIR)$(vcscriptsdir)"
	install -m 700 "$(top_srcdir)/scripts/vuurmuur-searchlog.sh" "$(DESTDIR)$(vcscriptsdir)"

EXTRA_DIST = $(scripts_DATA) $(vcscripts_DATA)

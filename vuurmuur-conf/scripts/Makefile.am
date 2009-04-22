INCLUDES = 
METASOURCES = AUTO
noinst_SCRIPTS = vuurmuur-searchlog.sh vuurmuur-wizard.sh
vuurmuur_scriptdir = "$(datadir)/vuurmuur/scripts/"
vuurmuur_script_DATA = vuurmuur-searchlog.sh vuurmuur-wizard.sh

install:
	test -z "$(vuurmuur_scriptdir)" || $(MKDIR_P) "$(DESTDIR)$(vuurmuur_scriptdir)"
	@for VRMRSCRIPT in $(vuurmuur_script_DATA) ; do \
		$(INSTALL) -m 755 $${VRMRSCRIPT} "$(DESTDIR)$(vuurmuur_scriptdir)"; \
	done


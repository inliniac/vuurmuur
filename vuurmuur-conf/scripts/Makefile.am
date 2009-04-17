INCLUDES = 
METASOURCES = AUTO
noinst_SCRIPTS = vuurmuur-searchlog.sh vuurmuur-wizard.sh
vuurmuur_scriptdir = "$(datadir)/vuurmuur/scripts/"
vuurmuur_script_DATA = vuurmuur-searchlog.sh vuurmuur-wizard.sh

install:
	@for VRMRSCRIPT in $(vuurmuur_script_DATA) ; do \
		$(INSTALL) -m 755 $${VRMRSCRIPT} "$(vuurmuur_scriptdir)"; \
	done


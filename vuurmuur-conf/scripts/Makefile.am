INCLUDES = 
METASOURCES = AUTO
noinst_SCRIPTS = vuurmuur-searchlog.sh vuurmuur-wizard.sh
vuurmuur_scriptdir = "$(datadir)/vuurmuur/scripts"
vuurmuur_script_DATA = vuurmuur-searchlog.sh vuurmuur-wizard.sh

install:
	@echo "Starting data $(vuurmuur_script_DATA) dir $(vuurmuur_scriptdir)"
	@for VRMRSCRIPT in $(vuurmuur_script_DATA) ; do \
		echo "VRMRSCRIPT $${VRMRSCRIPT}"; \
		S="$(vuurmuur_scriptdir)/$${VRMRSCRIPT}"; \
		echo "S $${S}"; \
		if [ -f "$${S}" ]; then \
			echo "File exists: $${S}"; \
			chmod 0755 "$${S}"; \
		else \
			echo "File doesnt exist: $${S}"; \
		fi; \
	done


# ripped from xine-ui package
mansubdir=/ru/man8
man_MANS = vuurmuur.8 vuurmuur_log.8 vuurmuur_script.8
EXTRA_DIST = $(man_MANS)

install-man8:
	$(mkinstalldirs) $(DESTDIR)$(mandir)$(mansubdir)
	@list='$(man1_MANS)'; \
	l2='$(man_MANS)'; for i in $$l2; do \
	  case "$$i" in \
	    *.8*) list="$$list $$i" ;; \
	  esac; \
	done; \
	for i in $$list; do \
	  if test -f $(srcdir)/$$i; then file=$(srcdir)/$$i; \
	  else file=$$i; fi; \
	  ext=`echo $$i | sed -e 's/^.*\\.//'`; \
	  inst=`echo $$i | sed -e 's/\\.[0-9a-z]*$$//'`; \
	  inst=`echo $$inst | sed '$(transform)'`.$$ext; \
	  echo " $(INSTALL_DATA) $$file $(DESTDIR)$(mandir)$(mansubdir)/$$inst"; \
	  $(INSTALL_DATA) $$file $(DESTDIR)$(mandir)$(mansubdir)/$$inst; \
	done

uninstall-man8:
	@list='$(man1_MANS)'; \
	l2='$(man_MANS)'; for i in $$l2; do \
	  case "$$i" in \
	    *.8*) list="$$list $$i" ;; \
	  esac; \
	done; \
	for i in $$list; do \
	  ext=`echo $$i | sed -e 's/^.*\\.//'`; \
	  inst=`echo $$i | sed -e 's/\\.[0-9a-z]*$$//'`; \
	  inst=`echo $$inst | sed '$(transform)'`.$$ext; \
	  echo " rm -f $(DESTDIR)$(mandir)$(mansubdir)/$$inst"; \
	  rm -f $(DESTDIR)$(mandir)$(mansubdir)/$$inst; \
	done

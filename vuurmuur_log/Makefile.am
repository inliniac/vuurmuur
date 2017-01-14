METASOURCES = AUTO
bin_PROGRAMS = vuurmuur_log

vuurmuur_log_SOURCES = \
conntrack.c conntrack.h \
logfile.c logfile.h \
nflog.c nflog.h \
stats.c stats.h \
vuurmuur_ipc.c vuurmuur_ipc.h \
vuurmuur_log.c vuurmuur_log.h

vuurmuur_log_LDADD = $(LIBVUURMUUR_LDADD) $(NFNETLINK_LIBS) $(LIBNETFILTER_LOG_LIBS) $(LIBMNL_LIBS) $(LIBNETFILTER_CONNTRACK_LIBS)
noinst_HEADERS = vuurmuur_log.h conntrack.h logfile.h stats.h nflog.h vuurmuur_ipc.h


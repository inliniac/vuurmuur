METASOURCES = AUTO
bin_PROGRAMS = vuurmuur_log

vuurmuur_log_SOURCES = \
logfile.c logfile.h \
nflog.c nflog.h \
stats.c stats.h \
vuurmuur_ipc.c vuurmuur_ipc.h \
vuurmuur_log.c vuurmuur_log.h

vuurmuur_log_LDADD = $(LIBVUURMUUR_LDADD) $(NFNETLINK_LIBS) $(LIBNETFILTER_LOG_LIBS)
noinst_HEADERS = vuurmuur_log.h logfile.h stats.h nflog.h vuurmuur_ipc.h


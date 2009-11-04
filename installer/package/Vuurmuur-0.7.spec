Name:		Vuurmuur
Version:	0.7
Release:	0%{?dist}
Summary:	Firewall manager built on top of iptables
Vendor:		Victor Julien <victor@vuurmuur.org>
Group:		System Environment/Daemonss
License:	GPLv2
URL:		http://www.vuurmuur.org/
Source0:	ftp://ftp.vuurmuur.org/releases/0.7/%{name}-%{version}.tar.gz
Patch0:		libvuurmuur-plugin-0.7.patch
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
Vuurmuur is a powerful middle-end/front-end for netfilter/iptables aimed
at system-administrators who need a decent firewall, but don't have netfilter
specific knowledge.

The program is basicly split into three pieces. One piece (the middle-end)
converts humanly-readable rules, hosts, groups, networks, zones, interfaces
and services into a iptables ruleset (or optional into a bash-script). The
second part is a little daemon that converts the netfiler logs to easy
readable logs, that reflect all the predefined objects described above. The
third part is a Ncurses-based Gui (the front-end) in which one can manage
the firewall. Most important here is the real-time feedback. Logs can be
viewed in real-time, using colours for easy interpretation. Also, the current
connections can be viewed in real-time. Filtering possibilities make it easy
to monitor specific hosts or services.

%package conf
Summary:	Ncurses based interface for modifying Vuurmuur configuration
Group:		Applications/System
Requires:	Vuurmuur-lib >= 0.7, Vuurmuur-daemon >= 0.7
BuildRequires:	gettext >= 0.14.6, ncurses-devel >= 5.5

%description conf
Ncurses based interface for modifying Vuurmuur configuration.

%package daemon
Summary:	Vuurmuur daemon
Group:		System Environment/Daemons
Requires:	Vuurmuur-lib >= 0.7

%description daemon
Vuurmuur daemon.

%package devel
Summary:	Development files for firewall manager built on top of iptables
Group:		Development/Libraries

%description devel
Development files for firewall manager built on top of iptables

%package lib
Summary:	Vuurmuur library
Group:		System Environment/Libraries

%description lib
Vuurmuur library and plugins needed by the vuurmuur daemon

%if %{?mandriva_version}
    echo "Can't build vuurmuur on Mandriva, issues with textdir plugin, quitting"
    exit 1
%endif

%prep
%setup -q
%{__tar} xzf libvuurmuur-%{version}.tar.gz
%{__tar} xzf vuurmuur-%{version}.tar.gz
%{__tar} xzf vuurmuur_conf-%{version}.tar.gz

cd libvuurmuur-%{version}
# Vuurmuur doesn't obey configure argument for plugin placement. This patch fixes it.
%patch0 -p1
%{__aclocal}
%{__libtoolize} --force
%{__autoconf}
%{__automake} --add-missing

%build
cd %{_builddir}/%{name}-%{version}/libvuurmuur-%{version}
%configure \
	--with-plugindir=%{_libdir}/vuurmuur/plugins

# Configure ignores --disable-rpath so we have to solve it this way
%{__sed} -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
%{__sed} -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
%{__make} %{?jobs:-j%jobs}

cd %{_builddir}/%{name}-%{version}/vuurmuur-%{version}
%configure \
	--with-libvuurmuur-includes=%{_builddir}/%{name}-%{version}/libvuurmuur-%{version}/src/ \
	--with-libvuurmuur-libraries=%{_builddir}/%{name}-%{version}/libvuurmuur-%{version}/src/.libs/

# Configure ignores --disable-rpath so we have to solve it this way
%{__sed} -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
%{__sed} -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
%{__make} %{?jobs:-j%jobs}

# Convert MAN pages to UTF-8
pushd man/en
for i in vuurmuur_script.8 vuurmuur_log.8 vuurmuur.8; do
	iconv --from=ISO-8859-1 --to=UTF-8 $i > new
	%{__mv} new $i
done
popd

# Convert MAN pages to UTF-8
pushd man/ru
for i in vuurmuur_script.8 vuurmuur_log.8 vuurmuur.8; do
	iconv --from=KOI-8 --to=UTF-8 $i > new
	%{__mv} new $i
done
popd

cd %{_builddir}/%{name}-%{version}/vuurmuur_conf-%{version}
%configure \
	--with-libvuurmuur-includes=%{_builddir}/%{name}-%{version}/libvuurmuur-%{version}/src/ \
	--with-libvuurmuur-libraries=%{_builddir}/%{name}-%{version}/libvuurmuur-%{version}/src/.libs/

# Configure ignores --disable-rpath so we have to solve it this way
%{__sed} -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
%{__sed} -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
%{__make} %{?jobs:-j%jobs}

# Convert MAN pages to UTF-8
pushd man/ru
iconv --from=KOI-8 --to=UTF-8 vuurmuur_conf.8 > new
%{__mv} new vuurmuur_conf.8
popd

%install

# Just cleaning up in case an old BUILD_ROOT exists
%{__rm} -rf $RPM_BUILD_ROOT

# Install libraries
cd %{_builddir}/%{name}-%{version}/libvuurmuur-%{version}
%{makeinstall} 

# Install textdir-plugin configuration file
%{__mkdir_p} $RPM_BUILD_ROOT/%{_sysconfdir}/vuurmuur/plugins
%{__install} -m600 plugins/textdir/textdir.conf \
	$RPM_BUILD_ROOT/%{_sysconfdir}/vuurmuur/plugins/textdir.conf

# Create the textdir folder location
%{__mkdir_p} $RPM_BUILD_ROOT/%{_sysconfdir}/vuurmuur/textdir

# Install daemon
cd %{_builddir}/%{name}-%{version}/vuurmuur-%{version}
%{makeinstall}

for i in `find %{_builddir}/%{name}-%{version}/vuurmuur-%{version}/skel -name .keep`
do
	%{__rm} -rf $i
done

# install SYSV init stuff
%{__mkdir_p} $RPM_BUILD_ROOT/%{_initrddir}

%if %{?suse_version}
    %{__install} -m755 scripts/vuurmuur-initd.sh.suse \
        $RPM_BUILD_ROOT/%{_initrddir}/vuurmuur
%else
    %{__install} -m755 scripts/vuurmuur-initd.sh \
         $RPM_BUILD_ROOT/%{_initrddir}/vuurmuur
%endif

# install log rotation stuff
%{__mkdir_p} $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d
%{__install} -m 644 -p scripts/vuurmuur-logrotate \
	$RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d/vuurmuur

# Install vuurmuur configuration file 
%{__mkdir_p} $RPM_BUILD_ROOT/%{_sysconfdir}/vuurmuur
%{__install} -m600 config/config.conf.sample \
	$RPM_BUILD_ROOT/%{_sysconfdir}/vuurmuur/config.conf

# Install ncurses configuration tool
cd %{_builddir}/%{name}-%{version}/vuurmuur_conf-%{version}
%{makeinstall}

# Remove unpackaged files
%{__rm} -rf $RPM_BUILD_ROOT%{_docdir}/vuurmuur
%{__rm} -f $RPM_BUILD_ROOT%{_libdir}/libvuurmuur.la
%{__rm} -f $RPM_BUILD_ROOT%{_libdir}/vuurmuur/plugins/libtextdir.la
%{__rm} -rf $RPM_BUILD_ROOT%{_datadir}/vuurmuur/scripts/

%find_lang vuurmuur_conf

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%post daemon
# Register the vuurmuur service
/sbin/chkconfig --add vuurmuur

%postun daemon
# Remove init-script when uninstalling
%insserv_cleanup

%preun daemon
if [ $1 = 0 ]; then
	/sbin/service vuurmuur stop > /dev/null 2>&1
	/sbin/chkconfig --del vuurmuur
fi

%clean
%{__rm} -rf $RPM_BUILD_ROOT

%files lib
%defattr(-,root,root,-)
%doc libvuurmuur-%{version}/doc/README libvuurmuur-%{version}/AUTHORS libvuurmuur-%{version}/COPYING
%config %{_sysconfdir}/vuurmuur/plugins/textdir.conf
%{_libdir}/libvuurmuur.so
%{_libdir}/libvuurmuur.so.0
%{_libdir}/libvuurmuur.so.0.6.0
%dir %{_libdir}/vuurmuur
%dir %{_sysconfdir}/vuurmuur/textdir
%{_libdir}/vuurmuur/plugins/libtextdir.so
%{_libdir}/vuurmuur/plugins/libtextdir.so.0
%{_libdir}/vuurmuur/plugins/libtextdir.so.0.0.0

%files daemon
%defattr(-,root,root,-)
%doc vuurmuur-%{version}/AUTHORS vuurmuur-%{version}/skel vuurmuur-%{version}/zones
%{_bindir}/vuurmuur
%{_bindir}/vuurmuur_log
%{_bindir}/vuurmuur_script
%doc %{_mandir}/man*/*
%doc %{_mandir}/ru/*
%doc %{_datadir}/doc/vuurmuur/*
%{_datadir}/vuurmuur
%config(noreplace) %{_sysconfdir}/vuurmuur
%config(noreplace) %{_sysconfdir}/logrotate.d/vuurmuur
%{_initrddir}/vuurmuur

%files devel
%defattr(-,root,root,-)
%{_includedir}/vuurmuur.h
%{_libdir}/libvuurmuur.a
%{_libdir}/libvuurmuur.so
%{_libdir}/vuurmuur/plugins/libtextdir.a
%{_libdir}/vuurmuur/plugins/libtextdir.so

%files conf -f vuurmuur_conf-%{version}/vuurmuur_conf.lang
%defattr(-,root,root,-)
%doc vuurmuur_conf-%{version}/AUTHORS vuurmuur_conf-%{version}/ChangeLog vuurmuur_conf-%{version}/COPYING
%doc %{_datadir}/vuurmuur/help
%doc %{_datadir}/vuurmuur/config
%{_bindir}/vuurmuur_conf
%{_mandir}/man8/vuurmuur_conf.8.gz
%{_mandir}/ru/man8/vuurmuur_conf.8.gz

%changelog
* Wed Nov 4 2009 Daniele K. Sluijters info (at) daenney,net
- Remove the initscript after uninstalling
- Check if we're trying to build on Mandriva and if so quit, textdir plugin won't build on Mandriva
- Add some versionrequirements to BuildRequires
- Add an if/else to determine wether we're building on SuSE and if so install a different init-script
- Replace wherever possible paths and commands with their corresponding macro's for cross-RPM-platformness
* Tue Nov 3 2009 Daniele K. Sluijters info (at) daenney.net
- Replace /etc/rc.d/init.d with the %{_initrddir} macro for compatibility
- Include /usr/share/doc/vuurmuur in the filelist
* Mon Nov 2 2009 Daniele K. Sluijters info (at) daenney.net
- Install vuurmuur and plugins/textdir configuration files
- Reorganise a few things, (re-)document the spec-file where needed
- Add the .so files to the filelist too
- Split the package even further, creating vuurmuur-devel since otherwise the vuurmuur package itself would be just that, devel
- Fix the BuildRequires
- Add Group per sub-package
- Add Requires per sub-package
- Rename tui to conf
- Require Vuurmuur-lib and Vuurmuur-daemon for Vuurmuur-conf as it needs both to function / be useful
* Wed Sep  2 2009 Sun Dec 29 2008 Stjepan Gros <stjepan.gros@gmail.com> - 0.7-1
- Initial package

%define name		vuurmuur
%define version		0.8
%define release		1
%define root_prefix_vm	%{_prefix}/
# %define conf_prefix_vm	%{_sysconfdir}/
%define conf_prefix_vm	/etc/
%define share_prefix	%{_datadir}/
%define logdir		/var/log/%{name}/
%define locale_prefix	%{share_prefix}locale/
%define docdir		%{_defaultdocdir}/

Name:		%{name}
Version:	%{version}
Release:	%{release}%{?dist}
Vendor:		Victor Julien <victor@vuurmuur.org>
License:	GNU GPL
URL:		https://www.vuurmuur.org/
Group:		System Environment/Daemons
Summary:	middle and front-end for netfilter/iptables with ncurses interface
BuildRoot:	%{_tmppath}/%{name}-%{version}-root
Packager:	Victor Julien <victor@vuurmuur.org>
Source0:	%{name}-%{version}.tar.gz
Requires:	iptables, libnetfilter_log, libnetfilter_conntrack, libmnl, ncurses

%define	root_prefix ${RPM_BUILD_ROOT}%{root_prefix_vm}
%define	conf_prefix ${RPM_BUILD_ROOT}%{conf_prefix_vm}

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

%prep
%setup

%build
libtoolize --copy -f
aclocal -I m4
autoheader
automake --copy --add-missing
autoconf
%configure --prefix=%{root_prefix_vm} \
            --sysconfdir=%{conf_prefix_vm}
make


%install
%makeinstall prefix=%{root_prefix}
mkdir -p -m 0700 %{conf_prefix}%{name}/plugins \
                 %{conf_prefix}%{name}/interfaces \
		 %{conf_prefix}%{name}/services \
		 %{conf_prefix}%{name}/zones \
		 %{conf_prefix}%{name}/rules \
		 %{conf_prefix}init.d \
		 ${RPM_BUILD_ROOT}%{logdir} \
		 %{root_prefix}

touch %{conf_prefix}%{name}/plugins/textdir.conf \
      %{conf_prefix}%{name}/rules/rules.conf \
      %{conf_prefix}%{name}/rules/blocklist.conf \
      %{conf_prefix}%{name}/config.conf
echo "LOCATION=\"%{conf_prefix_vm}%{name}\"" > %{conf_prefix}%{name}/plugins/textdir.conf
if [ %{root_prefix_vm} != %{_prefix}/ ]; then
    mv %{root_prefix}share ${RPM_BUILD_ROOT}%{_prefix}
fi
# if [ %{share_prefix}doc/ != %{docdir} ]; then
#    mkdir -p -m 0700 ${RPM_BUILD_ROOT}%{docdir}
#    mv ${RPM_BUILD_ROOT}%{share_prefix}doc/%{name} ${RPM_BUILD_ROOT}%{docdir}
# fi
#PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH"
#scr_suffix=""
#if [ -f /etc/*-release ]; then
#    case $(cat /etc/*-release) in
#	*[sS][uU][sS][eE]*)
#	    scr_suffix=".suse"
#    	    ;;
#	*[mM][aA][nN][dD][rR]*)
#	    scr_suffix=".mandr"
#	    ;;
#	*[fF][eE][dD][oO][rR][aA]*)
#	    scr_suffix=".fc"
#	    ;;
#    esac
#else
#    if [ $(which insserv) ]; then
#        scr_suffix=".suse"
#    fi
#fi
IPTABLES="/usr/sbin/iptables"
IP6TABLES="/usr/sbin/ip6tables"
IPTABLESR="/usr/sbin/iptables-restore"
IP6TABLESR="/usr/sbin/ip6tables-restore"
TC="/usr/sbin/tc"
MODPROBE="/usr/sbin/modprobe"

sed -e 's|=\/usr\/|='%{root_prefix_vm}'|' \
    ${RPM_BUILD_ROOT}%{share_prefix}%{name}/scripts/vuurmuur-initd.sh > %{conf_prefix}init.d/%{name}
sed -e 's|^\(IPTABLES=\).*|\1\"'$IPTABLES'\"|
    s|^\(IPTABLES_RESTORE=\).*|\1\"'$IPTABLESR'\"|
    s|^\(IP6TABLES=\).*|\1\"'$IP6TABLES'\"|
	s|^\(IP6TABLES_RESTORE=\).*|\1\"'$IP6TABLESR'\"|
	s|^\(TC=\).*|\1\"'$TC'\"|
	s|^\(MODPROBE=\).*|\1\"'$MODPROBE'\"|
	s|^\(LOGDIR=\).*|\1\"'%{logdir}'\"|
	' ${RPM_BUILD_ROOT}%{share_prefix}%{name}/config/config.conf.sample > %{conf_prefix}%{name}/config.conf
cp ${RPM_BUILD_ROOT}%{share_prefix}%{name}/services/* %{conf_prefix}%{name}/services/
cp -r --preserve=mode ${RPM_BUILD_DIR}/%{name}-%{version}/installer/zones/* %{conf_prefix}%{name}/zones/
								  
chmod 0744 %{conf_prefix}init.d/%{name}
chmod 0600 %{conf_prefix}%{name}/rules/blocklist.conf \
	   %{conf_prefix}%{name}/rules/rules.conf \
	   %{conf_prefix}%{name}/plugins/textdir.conf \
	   %{conf_prefix}%{name}/config.conf

%pre

%post
#chkconfig --add vuurmuur
#/etc/init.d/vuurmuur start > /dev/null 2>&1 || :

%preun
/etc/init.d/vuurmuurin stop > /dev/null 2>&1 || :
chkconfig --del vuurmuur
											   
%postun
												   

%clean
[ "${RPM_BUILD_ROOT}" != "/" ] && [ -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}


%files
%defattr(-, root, root)
%config(noreplace) %{conf_prefix_vm}%{name}/plugins/
%config(noreplace) %{conf_prefix_vm}%{name}/interfaces/
%config(noreplace) %{conf_prefix_vm}%{name}/rules/
%config(noreplace) %{conf_prefix_vm}%{name}/zones/
%config(noreplace) %{conf_prefix_vm}%{name}/services/*
%config(noreplace) %{conf_prefix_vm}%{name}/config.conf
%config /etc/init.d/%{name}
%{root_prefix_vm}include/vuurmuur.h
%{root_prefix_vm}bin/%{name}
%{root_prefix_vm}bin/%{name}_log
%{root_prefix_vm}bin/%{name}_script
%{root_prefix_vm}bin/%{name}_conf
%{_libdir}/libvuurmuur.a
%{_libdir}/libvuurmuur.la
%{_libdir}/libvuurmuur.so
%{_libdir}/libvuurmuur.so.0
%{_libdir}/libvuurmuur.so.0.6.0
%{_mandir}/man8/vuurmuur.8*
%{_mandir}/man8/vuurmuur_log.8*
%{_mandir}/man8/vuurmuur_script.8*
%{_mandir}/man8/vuurmuur_conf.8*
%{_mandir}/ru/man8/vuurmuur.8*
%{_mandir}/ru/man8/vuurmuur_log.8*
%{_mandir}/ru/man8/vuurmuur_script.8*
%{_mandir}/ru/man8/vuurmuur_conf.8*
%{locale_prefix}/*/LC_MESSAGES/%{name}.mo
%doc %{docdir}%{name}/
%dir %{logdir}
%{share_prefix}%{name}/
		     

%changelog


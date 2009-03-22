%define name		libvuurmuur
%define version		0.7rc2
%define release		1
# %define root_prefix_vm	/usr/
%define root_prefix_vm	%{_prefix}/
# %define conf_prefix_vm        %{_sysconfdir}/
%define conf_prefix_vm	/etc/
%define share_prefix	%{_datadir}/
%define docdir          %{_defaultdocdir}/

Name:		%{name}
Version:	%{version}
Release:	%{release}
Vendor:		Victor Julien <victor@vuurmuur.org>
License:	GNU GPL
URL:		http://www.vuurmuur.org/
Group:		System Environment/Daemons
Summary:	middle and front-end for netfilter/iptables with ncurses interface
BuildRoot:	%{_tmppath}/%{name}-%{version}-root
Packager:	Aleksandr Shubnik <alshu@tut.by>
Source0:        %{name}-%{version}.tar.gz
# Requires:     iptables
# Requires:	iptables >= 1.2.1, ncurses > 2.4, libjpeg-devel        - Example


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
    Common library package.


%prep
%setup

%build
CFLAGS="-g -Wall"
export CFLAGS
libtoolize -f
aclocal	
autoheader
automake
autoconf
%configure --prefix=%{root_prefix_vm} \
	   --sysconfdir=%{conf_prefix_vm} \
	   --with-plugindir=%{root_prefix_vm}lib/vuurmuur \
	   --with-shareddir=%{_datadir}/vuurmuur
make	


%install
%makeinstall prefix=${RPM_BUILD_ROOT}%{root_prefix_vm}

if [ %{share_prefix}doc/ != %{docdir} ]; then
    mkdir -p -m 0700 ${RPM_BUILD_ROOT}%{docdir}
    mv ${RPM_BUILD_ROOT}%{share_prefix}doc/vuurmuur ${RPM_BUILD_ROOT}%{docdir}
fi

%clean
[ "${RPM_BUILD_ROOT}" != "/" ] && [ -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}


%files
%defattr(-, root, root)
%{root_prefix_vm}lib/%{name}*
%{root_prefix_vm}lib/vuurmuur/
%{root_prefix_vm}include/vuurmuur.h
%doc %{docdir}vuurmuur/


%changelog


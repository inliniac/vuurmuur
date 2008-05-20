%define name		vuurmuur_conf
%define version		0.5.74.alpha4
%define release		1
# %define root_prefix_vm	/usr/
%define root_prefix_vm	%{_prefix}/
%define conf_prefix_vm	/etc/
%define share_prefix	%{_datadir}/
%define locale_prefix	%{share_prefix}locale/
%define share_prefix_vm	%{share_prefix}vuurmuur/

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
Requires:       libvuurmuur, iptables, ncurses

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
    This is the Ncurses frontend.


%prep
%setup


%build
CFLAGS="-g -Wall"
export CFLAGS
libtoolize -f
aclocal	
# fix gettext on older redhatbased systems
PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH"
GETTEXTIZE=`which gettextize`
if [ "x$GETTEXTIZE" = "x" ]; then
     GETTEXTIZE="gettextize"
fi
#  ripped from: http://cvs.saout.de/lxr/saout/source/cryptsetup/setup-gettext
tmpfl=/var/tmp/.temp-gettextize
sed 's:read .*< /dev/tty::' $GETTEXTIZE > $tmpfl
chmod +x $tmpfl
echo n | $tmpfl --copy --force --intl --no-changelog || abort
rm -f $tmpfl
#  gettext done
autoheader
automake
autoconf
%configure --prefix=%{root_prefix_vm} \
	   --sysconfdir=%{conf_prefix_vm} \
	   --with-libvuurmuur-includes=%{root_prefix_vm}include \
	   --with-libvuurmuur-libraries=%{root_prefix_vm}lib \
	   --with-localedir=%{locale_prefix}
make


%install
%makeinstall prefix=%{root_prefix}

mkdir -p -m 0700 %{root_prefix} \
		 %{conf_prefix}vuurmuur
if [ %{root_prefix_vm} != %{_prefix}/ ]; then
    mv %{root_prefix_vm}share ${RPM_BUILD_ROOT}%{_prefix}
fi

cp ${RPM_BUILD_ROOT}%{share_prefix_vm}config/%{name}.conf.sample %{conf_prefix}vuurmuur/%{name}.conf
chmod 0600 %{conf_prefix}vuurmuur/%{name}.conf


%clean
[ "${RPM_BUILD_ROOT}" != "/" ] && [ -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}


%files
%defattr(-, root, root)
%config(noreplace) %{conf_prefix_vm}vuurmuur/%{name}.conf
%{root_prefix_vm}bin/%{name}
%{share_prefix_vm}scripts/
%{share_prefix_vm}help/
%{share_prefix_vm}config/vuurmuur_conf.conf.sample
%{_mandir}/man8/vuurmuur_conf.8*
%{_mandir}/ru/man8/vuurmuur_conf.8*
%{locale_prefix}en@boldquot/LC_MESSAGES/%{name}.mo
%{locale_prefix}en@quot/LC_MESSAGES/%{name}.mo
%{locale_prefix}de/LC_MESSAGES/%{name}.mo
%{locale_prefix}nl/LC_MESSAGES/%{name}.mo
%{locale_prefix}pt_BR/LC_MESSAGES/%{name}.mo
%{locale_prefix}ru/LC_MESSAGES/%{name}.mo
%{locale_prefix}fr/LC_MESSAGES/%{name}.mo
%{locale_prefix}nb/LC_MESSAGES/%{name}.mo
%{locale_prefix}no/LC_MESSAGES/%{name}.mo


%changelog


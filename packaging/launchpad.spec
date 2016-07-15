Name:       launchpad
Summary:    Launchpad for launching applications
Version:    0.2.3.14
Release:    1
Group:      Application Framework/Daemons
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  launchpad-process-pool.service
Source102:  launchpad-process-pool.socket


BuildRequires:  cmake
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(security-manager)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(ttrace)

Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun): /usr/bin/systemctl

%define appfw_feature_priority_change 0

%description
Launchpad for launching applications

%package devel
Summary:    Launchpad for launching applications (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Launchpad for launching applications (devel)

%prep
%setup -q

%build
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif
%if 0%{?appfw_feature_priority_change}
_APPFW_FEATURE_PRIORITY_CHANGE=ON
%endif

%cmake -DVERSION=%{version} \
	-D_APPFW_FEATURE_PRIORITY_CHANGE:BOOL=${_APPFW_FEATURE_PRIORITY_CHANGE} \
	.
%__make %{?_smp_mflags}

%install
rm -rf %{buildroot}

%make_install
mkdir -p %{buildroot}%{_unitdir_user}/default.target.wants
mkdir -p %{buildroot}%{_unitdir_user}/sockets.target.wants
install -m 0644 %SOURCE101 %{buildroot}%{_unitdir_user}/launchpad-process-pool.service
install -m 0644 %SOURCE102 %{buildroot}%{_unitdir_user}/launchpad-process-pool.socket
ln -sf ../launchpad-process-pool.socket %{buildroot}%{_unitdir_user}/sockets.target.wants/launchpad-process-pool.socket
ln -sf ../launchpad-process-pool.service %{buildroot}%{_unitdir_user}/default.target.wants/launchpad-process-pool.service

mkdir -p %{buildroot}/usr/share/license
cp %{_builddir}/%{name}-%{version}/LICENSE  %{buildroot}/usr/share/license/%{name}

%post
chsmack -e System::Privileged %{_bindir}/launchpad-process-pool

%files
%manifest launchpad.manifest
%{_prefix}/share/license/%{name}
%{_prefix}/share/aul/default.loader
%{_unitdir_user}/launchpad-process-pool.service
%{_unitdir_user}/launchpad-process-pool.socket
%{_unitdir_user}/sockets.target.wants/launchpad-process-pool.socket
%{_unitdir_user}/default.target.wants/launchpad-process-pool.service
%caps(cap_mac_admin,cap_setgid=ei) %{_bindir}/launchpad-process-pool
%caps(cap_setgid=ei) %{_bindir}/launchpad-loader
%attr(0644,root,root) %{_libdir}/liblaunchpad.so.*

%files devel
%{_includedir}/launchpad/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc

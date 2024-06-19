%{!?_version: %define _version 0}
%{!?_release: %define _release 0}
%{!?_reversion: %define _reversion "000000"}

Name:           cas
Version:        %{_version}
Release:        %{_release}.%{_reversion}%{?dist}
License:        GPLv2 and GPLv2+ and LGPLv2+
Group:          cas
Summary:        Cache Acceleration Software
BuildRequires:  libuuid-devel
Source:	cas-%{version}.tar.gz

%if 0%{?rhel}
ExclusiveArch: i686 x86_64 s390x ppc64le aarch64
%endif

Requires:       libuuid

%description
cas is a acceleration software.

%prep
%setup -c -q -n cas-%{version}

%build
CFLAGS=$RPM_OPT_FLAGS make all

%install
install -Dm 0644 libcas/libcas.a %{buildroot}/%{_libdir}/libcas.a
install -Dm 0644 libcas/libcas.pc %{buildroot}/%{_libdir}/pkgconfig/libcas.pc
install -Dm 0644 libcas/src/libcas.h %{buildroot}/%{_includedir}/libcas.h
install -Dm 0644 libcas/src/cas_logger.h %{buildroot}/%{_includedir}/cas_logger.h
install -Dm 0644 cascli/cascli %{buildroot}/%{_sbindir}/cascli

%post
# %systemd_post xxx.service

%preun
# %systemd_preun xxx.service

%postun
# %systemd_postun_with_restart xxx.service
# $1为0是卸载，1为更新
if [ "$1" = "0" ] ; then
rm -f %{_sbindir}/cascli
fi

%files
%defattr(0777,root,root,-)
%{_sbindir}/cascli


%package        lib
Summary:        Library for %{name}
Group:          System Environment/Libraries

%description    lib
The %{name}-lib package contains the libraries needed to use the cas from applications.

%post lib -p /sbin/ldconfig

%postun lib -p /sbin/ldconfig

%files          lib
%defattr(-,root,root,-)
%{_libdir}/libcas.a



%package        devel
Summary:        Development files for %{name}
Group:          Development/Libraries
Requires:       %{name}-lib = %{version}-%{release}

%description    devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%files          devel
%defattr(-,root,root,-)
%{_includedir}/libcas.h
%{_includedir}/cas_logger.h
%{_libdir}/pkgconfig/*.pc

%changelog

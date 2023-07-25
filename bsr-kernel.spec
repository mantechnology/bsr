# Conditionals
%bcond_with modsign

# BSR-659 disable debug pakage build
%define debug_package %{nil}
%define __strip /bin/true
# BSR-1089 use it temporarily. the cause must be determined and removed.
%define _unpackaged_files_terminate_build 0

Name: bsr-kernel
Summary: Kernel driver for BSR
Version: 1.6.6.0
# do not modify Release field
Release: 1%{?dist}

# always require a suitable userland
# Requires: 

%global tarball_version %(echo "%{version}" | sed -e "s,%{?dist}$,,")
Source: bsr-%{tarball_version}.tar.gz
License: GPLv2+
Group: System Environment/Kernel
# URL: 
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-XXXXXX)
# BSR-1089 support for suse
%if ! %{defined suse_version}
BuildRequires: redhat-rpm-config
%endif
%if %{defined kernel_module_package_buildreqs}
BuildRequires: %kernel_module_package_buildreqs
%endif

%description
This module is the kernel-dependent driver for BSR.  This is split out so
that multiple kernel driver versions can be installed, one for each
installed kernel.

%prep
%setup -q -n bsr-%{tarball_version}

# BSR-1089 support for suse
%if %{defined suse_kernel_module_package}
# Support also sles10, where kernel_module_package was not yet defined.
# In sles11, suse_k_m_p became a wrapper around k_m_p.

# BSR-1089 support for suse
%if 0%{?suse_version} < 1110
# We need to exclude some flavours on sles10 etc,
# or we hit an rpm internal buffer limit.
%suse_kernel_module_package -n bsr -f filelist-suse -p preamble-suse kdump kdumppae vmi vmipae um
%else
%suse_kernel_module_package -n bsr -f filelist-suse -p preamble-suse
%endif
%else
# Concept stolen from sles kernel-module-subpackage:
# include the kernel version in the package version,
# so we can have more than one kmod-bsr.
# Needed, because even though kABI is still "compatible" in RHEL 6.0 to 6.1,
# the actual functionality differs very much: 6.1 does no longer do BARRIERS,
# but wants FLUSH/FUA instead.
# For convenience, we want both 6.0 and 6.1 in the same repository,
# and have yum/rpm figure out via dependencies, which kmod version should be installed.
# This is a dirty hack, non generic, and should probably be enclosed in some "if-on-rhel6".
%define _this_kmp_version %{version}_%(echo %kernel_version | sed -r 'y/-/_/; s/\.el.\.(x86_64|i.86)$//;')
%kernel_module_package -v %_this_kmp_version -n bsr -f filelist-redhat -p preamble
%endif

%build
rm -rf obj
mkdir obj
ln -s ../bsr-headers obj/
ln -s ../bsr-platform obj/

for flavor in %flavors_to_build; do
    cp -r bsr obj/$flavor
    #make -C %{kernel_source $flavor} M=$PWD/obj/$flavor
    make -C obj/$flavor %{_smp_mflags} all KDIR=%{kernel_source $flavor}
    # BSR-659 module sign for secure boot support
    %if %{with modsign}
    ln -s -f ../pki obj/
    make -C obj/$flavor modsign KDIR=%{kernel_source $flavor}
    %endif
done

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT

%if %{defined kernel_module_package_moddir}
export INSTALL_MOD_DIR=%{kernel_module_package_moddir bsr}
%else
# BSR-1089 support for suse
%if %{defined suse_kernel_module_package}
export INSTALL_MOD_DIR=updates
%else
export INSTALL_MOD_DIR=extra/bsr
%endif
%endif

# Very likely kernel_module_package_moddir did ignore the parameter,
# so we just append it here. The weak-modules magic expects that location.
[ $INSTALL_MOD_DIR = extra ] && INSTALL_MOD_DIR=extra/bsr

for flavor in %flavors_to_build ; do
    make -C %{kernel_source $flavor} modules_install \
	M=$PWD/obj/$flavor
    kernelrelease=$(cat %{kernel_source $flavor}/include/config/kernel.release || make -s -C %{kernel_source $flavor} kernelrelease)
    find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;
    mv obj/$flavor/.kernel.config.gz obj/k-config-$kernelrelease.gz
    mv obj/$flavor/Module.symvers ../../RPMS/Module.symvers.$kernelrelease.$flavor.%{_arch}
done
# BSR-1089 support for suse
%if %{defined suse_kernel_module_package}
# On SUSE, putting the modules into the default path determined by
# %kernel_module_package_moddir is enough to give them priority over
# shipped modules.
rm -f bsr.conf
%endif
# BSR-659 install public key for secure boot support
%if %{with modsign}
mkdir -p $RPM_BUILD_ROOT/etc/pki/mantech
install -m 0644 pki/bsr_signing_key_pub.der $RPM_BUILD_ROOT/etc/pki/mantech
%endif

mkdir -p $RPM_BUILD_ROOT/var/log/bsr
mkdir -p $RPM_BUILD_ROOT/var/log/bsr/perfmon

mkdir -p $RPM_BUILD_ROOT/etc/depmod.d
echo "override bsr * weak-updates" \
    > $RPM_BUILD_ROOT/etc/depmod.d/bsr.conf

%clean
rm -rf %{buildroot}

%changelog
* Tue Jul 25 2023 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.6.0
- New upstream release.

* Fri Jul 7 2023 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.5.2
- New upstream release.

* Wed Jun 21 2023 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.5.1
- New upstream release.

* Thu Jun 15 2023 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.5.0
- New upstream release.

* Fri May 12 2023 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.4.0
- New upstream release.

* Fri Mar 24 2023 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.3.0-A4
- New upstream release.

* Tue Mar 21 2023 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.3.0-A3
- New upstream release.

* Tue Mar 7 2023 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.3.0-A2
- New upstream release.

* Fri Feb 24 2023 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.3.0-A1
- New upstream release.

* Wed Nov 9 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.2.4-A1
- New upstream release.

* Wed Sep 28 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.2.3-A1
- New upstream release.

* Tue Sep 20 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.2.2-A1
- New upstream release.

* Thu Sep 8 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.2.1-A1
- New upstream release.

* Fri Aug 5 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.2-A5
- New upstream release.

* Wed Aug 3 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.2-A4
- New upstream release.

* Fri Jul 22 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.2-A3
- New upstream release.

* Wed Jun 22 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.2-A2
- New upstream release.

* Fri May 6 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.2-A1
- New upstream release.

* Thu Mar 10 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.1-A9
- New upstream release.

* Wed Mar 2 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.1-A8
- New upstream release.

* Wed Jan 19 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.1-A7
- New upstream release.

* Tue Jan 11 2022 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.1-A6
- New upstream release.

* Fri Dec 17 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.1-A5
- New upstream release.

* Thu Nov 12 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.1-A4
- New upstream release.

* Tue Nov 2 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.1-A3
- New upstream release.

* Wed Oct 20 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.1-A2
- New upstream release.

* Tue Oct 12 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.1-A1
- New upstream release.

* Mon Jul 5 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A13
- New upstream release.

* Thu Jun 3 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A12
- New upstream release.

* Wed May 26 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A11
- New upstream release.

* Wed Apr 7 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A10
- New upstream release.

* Thu Feb 4 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A9
- New upstream release.

* Thu Jan 21 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A8
- New upstream release.

* Wed Jan 6 2021 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A7
- New upstream release.

* Thu Nov 19 2020 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A6
- New upstream release.

* Fri Nov 6 2020 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A5
- New upstream release.

* Mon Aug 31 2020 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A4
- New upstream release.

* Tue Aug 25 2020 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A3
- New upstream release.

* Mon Jul 13 2020 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A2
- New upstream release.

* Mon Jul 6 2020 Man Technology Inc. <bsr@mantech.co.kr> - 1.6-A1
- New upstream release.

* Wed Jun 24 2020 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.0-PREALPHA5
- New upstream release.

* Wed May 06 2020 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.0-PREALPHA4
- New upstream release.

* Mon Jan 06 2020 Man Technology Inc. <bsr@mantech.co.kr> - 1.6.0-PREALPHA3
- New upstream release.
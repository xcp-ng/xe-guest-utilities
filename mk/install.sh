#!/usr/bin/env bash

# Copyright Citrix Systems, Inc.
# All rights reserved.
#
# This script installs or updates the XE support packages installed in a guest.

os_distro=""
os_majorver=""
install_kernel=1
interactive=1

if [ -z "${DATADIR}" ] ; then
    DATADIR=$(dirname $0)
fi

usage()
{
    echo "usage: install.sh [-d <DISTRO> -m <MAJOR>] [-k]"
    echo ""
    echo "    -d <DISTRO>       Specifies the distro name."
    echo "    -m <MAJOR>        Specifies the major version of the distro release."
    echo "    -k                Do not update the kernel."
    echo "    -n                Non interactive mode."
    echo ""
    echo "The -d and -m options must be used together. If neither is given then"
    echo "auto-detection will be attempted."
    exit 1
}
while getopts d:hkm:n OPT ; do
    case $OPT in
	d) os_distro="$OPTARG" ;;
	k) install_kernel=0 ;;
	m) os_majorver="$OPTARG" ;;
	n) interactive=0 ;;

	h|\?) usage ;;
    esac
done

if [ -z "${os_distro}" -a -n "${os_majorver}" ] || \
   [ -n "${os_distro}" -a -z "${os_majorver}" ] ; then
    echo "Distribution name (-d) and major version (-m) must be specified"
    echo "together on the command line."
    exit 1
fi

if [ -z "${os_distro}" ] ; then
    if [ -z "${XE_LINUX_DISTRIBUTION}" ] ; then
	XE_LINUX_DISTRIBUTION=${DATADIR}/xe-linux-distribution
    fi

    if [ ! -f "${XE_LINUX_DISTRIBUTION}" ] ; then
	echo "Fatal Error: xe-linux-distribution script not found in ${DATADIR}."
	exit 1
    fi

    if [ ! -f "${DATADIR}/versions.deb" -o ! -f "${DATADIR}/versions.rpm" ] ; then
	echo "Fatal Error: versions.deb or versions.rpm not found in ${DATADIR}."
	exit 1
    fi

    eval $(${XE_LINUX_DISTRIBUTION})
    if [ $? -ne 0 -o -z "${os_distro}" -o -z "${os_majorver}" ] ; then
	echo "Fatal Error: Failed to determine Linux distribution and version."
	exit 1
    fi

    echo "Detected \`${os_name}' (${os_distro} version ${os_majorver})."
    echo
else
    echo "Distribution \`${os_distro}' version \`${os_majorver}' given on command line."
    echo
fi

ARCH=$(uname -m | sed -e 's/i.86/i386/g')
case "${ARCH}" in
    i386|x86_64|amd64) ;;
    *)
	echo "Architecture ${ARCH} is not supported"
	exit 1
	;;
esac

failure()
{
	echo "Unable to install guest packages for distribution"
	if [ -n "${os_name}" ] ; then
	    echo "${os_name} (${os_distro})."
	else
	    echo "${os_distro}."
	fi
	echo
	if [ $# -gt 0 ] ; then
	    echo $@
	    echo
	fi
	echo "You should manually install a version of"
	echo "xe-guest-utilities which is suitable for your"
	echo "distribution."
	exit 1
}

select_rpm_utilities()
{
    if [ -f "${DATADIR}/versions.rpm" ] ; then
        source ${DATADIR}/versions.rpm
        XGU=
        if command -v systemctl >/dev/null 2>&1; then
            LEGACY=
        else
            LEGACY="LEGACY_"
        fi
        for p in $(eval echo \${XE_GUEST_UTILITIES_PKG_FILE_${LEGACY}${ARCH}}) ; do
            XGU="$XGU ${DATADIR}/${p}"
        done
    else
        echo "Warning: Guest utilities not found in ${DATADIR}."
    fi
}

select_pkgs_rhel()
{
    GUEST_PKG_TYPE=rpm

    case "${os_distro}${os_majorver}" in
	rhel4|centos4)
	    # RHEL 4.9 already contains a Xen aware kernel
	    if [ "${ARCH}" == "i386" -a "${install_kernel}" -gt 0 ] ; then
		REQUIRE_XENBLK_KO=yes
		REQUIRE_XENNET_KO=yes
	    fi
	    ;;
	rhel5|centos5|oracle5|scientific5)
	    # No additional kernel package
	    ;;
	rhel6|centos6|oracle6|scientific6|neokylin5|neokylin6|asianux4|turbo12)
	    # No additional kernel package
	    ;;
	rhel7|centos7|oracle7|scientific7|neokylin7|cloudlinux7)
	    # No additional kernel package
	    ;;
    rhel8|oracle8|centos8|rocky8|cloudlinux8|almalinux8)
	    # No additional kernel package
	    ;;
	rhel9|oracle9|centos9|rocky9|cloudlinux9|almalinux9)
	    # No additional kernel package
	    ;;
	sangoma*)
	    # No additional kernel package
	    ;;
	rhel3|fedora*)
	    # Not officially supported therefore no additional packages required.
	    ;;
	*)
	    failure "Unknown RedHat Linux variant \`${os_distro} ${os_majorver}'."
	    ;;
    esac

    select_rpm_utilities
}

select_pkgs_sles()
{
    GUEST_PKG_TYPE=rpm

    case "${os_distro}${os_majorver}" in
	sles9|"suse linux9")
            # SLES9.4+ already contains a Xen aware kernel
	    ;;
	sles10|"suse linux10") 
            # SLES10 already contains a Xen aware kernel
	    ;;
	sles11|"suse linux11")
            # SLES11 already contains a Xen aware kernel
	    ;;
	sles12|"suse linux12")
            # SLES12 already contains a Xen aware kernel
	    ;;
	sles15|"suse linux15")
            # SLES15 already contains a Xen aware kernel
	    ;;
	*)
	    failure "Unknown SuSE Linux variant \`${os_distro} ${os_majorver}'."
	    ;;
    esac

    select_rpm_utilities
}

select_pkgs_coreos()
{
    GUEST_PKG_TYPE=coreos
    XGU="xe-linux-distribution"
}

select_pkgs_debian()
{
    GUEST_PKG_TYPE=deb

    case ${os_distro}:${os_majorver}:${os_minorver} in
	debian:[0-5]:*)
	    failure "This version of Debian is no longer supported by these utilities."
	    ;;
	debian:[6-9]:*)      ;;
	debian:[1-9][0-9]:*) ;;
	debian:testing:*|debian:unstable:*) ;;
	linx:*:*) ;;
	yinhe:*:*) ;;
	Gooroom:*:*) ;;

	ubuntu:[1-9]:*)
	    failure "This version of Ubuntu is no longer supported by these utilities."
	    ;;
	ubuntu:[1-9][0-9]:*) ;;
        *)
	    failure "Unknown Debian variant ${os_distro}:${os_majorver}:${os_minorver}"
	    ;;
    esac

    case ${ARCH} in
	i386) DARCH=i386 ;;
	x86_64) DARCH=amd64 ;;
    esac

    if [ -f "${DATADIR}/versions.deb" ] ; then
	source ${DATADIR}/versions.deb
	XGU=${DATADIR}/$(eval echo \${XE_GUEST_UTILITIES_PKG_FILE_${DARCH}})
    else
	echo "Warning: Guest utilities not found in ${DATADIR}."
    fi
}

select_pkgs_xe()
{
    GUEST_PKG_TYPE=rpm

    select_rpm_utilities
}

select_pkgs_freebsd()
{
    GUEST_PKG_TYPE=pkg
    PKGNAME=$(pkg info xe-guest-utilities 2>&1)
    ERROR=$?
    if [ $ERROR != 0 ]
    then
        XGU="xe-guest-utilities"
    else
        set $PKGNAME
        PKGNAME="$1"
        echo "${PKGNAME} already installed"
    fi
}

update_lvm_configuration_required()
{
    if test "${os_distro}" != rhel
    then
        return 1
    fi
    if test ${os_majorver} != 4
    then
        return 1
    fi
    if test \! -f /etc/lvm/lvm.conf
    then
        return 1
    fi
    lvm_types="`grep -e '^[ \t]*types' /etc/lvm/lvm.conf`"
    if [[ -z "$lvm_types" || "$lvm_types" != *\"xvd\"* ]]
    then
        return 0
    fi
    return 1
}

update_lvm_configuration()
{
    if test -z "`grep -e '^[ \t]*types' /etc/lvm/lvm.conf`"
    then
        sed -i '/^[ \t]*devices[ \t]*{[ \t]*/a \    types = ["xvd", 16]' /etc/lvm/lvm.conf
    else
        sed -i 's/^[ \t]*types.*/    types = ["xvd", 16]/g' /etc/lvm/lvm.conf
    fi
}

update_inittab_configuration_required()
{
    case "${os_distro}${os_majorver}" in
    sles10|"suse linux10"|sles11|"suse linux11")
      # SLES10 starts up two gettys, and we want to disable one of them
      if grep -Eq '^cons:12345:respawn:/sbin/smart_agetty -L 42 console' /etc/inittab; then
        if grep -Eq '^x0:12345:respawn:/sbin/agetty -L 9600 xvc0 xterm' /etc/inittab; then
            return 0
        fi
      fi
      ;;
    *)
      ;;
    esac
    return 1
}

update_inittab_configuration()
{
    case "${os_distro}${os_majorver}" in
    sles10|"suse linux10"|sles11|"suse linux11")
      # Disable duplicate getty
      sed -i 's/^x0:12345:respawn:/# x0:12345:respawn:/g' /etc/inittab
      ;;
    *)
      ;;
    esac
    /sbin/telinit q
}

update_arp_notify_required()
{
    # PV ops kernels do not emit gratuitous ARPs on migrate unless this is set
    file=/proc/sys/net/ipv4/conf/all/arp_notify
    if [ -f ${file} ] ; then
	val=$(cat ${file})
	if [ "${val}" = 0 ] ; then
	    return 0;
	fi
    fi
    return 1
}

update_arp_notify_configuration()
{
    file=/etc/sysctl.conf
    if [ -e "${file}" ] ; then
        sed -i -e 's/\(^\s*net\.ipv4\.conf\.[^.]\+\.arp_notify\s*=\s*0\)/#Auto-disabled by xs-tools:install.sh\n#\1/' ${file}
    else
        folder=/etc/sysctl.d/
        if [ ! -d "${folder}" ] ; then
            echo "Cannot update arp_notify configuration as neither ${file} nor ${folder} present" >&2
            return 1
        fi
        file=${folder}/10-enable-arp-notify.conf
    fi
    echo -e  "# Auto-enabled by xs-tools:install.sh\nnet.ipv4.conf.all.arp_notify = 1" >> ${file}
    return 0
}

update_modules_configuration_required()
{
    if [ -f "/etc/modprobe.conf" ] ; then
	conf="/etc/modprobe.conf"
    elif [ -f "/etc/modules.conf" ] ; then
	conf="/etc/modules.conf"
    else
	return 1
    fi

    if [ -z "${KERNEL}" ] ; then
	return 1
    fi

    if [ X"${REQUIRE_XENNET_KO}" = "Xyes" ] ; then
	if ! grep -Eq '^alias eth0 xennet$' "${conf}" ; then
	    # Required module alias not present!
	    return 0
	fi
    else
	if grep -Eq '^[^#]*eth0' "${conf}" ; then
	    # Module alias shouldn't be present as driver is kernel resident!
	    return 0 
	fi
    fi
    if [ X"${REQUIRE_XENBLK_KO}" = "Xyes" ] ; then
	if ! grep -Eq '^alias scsi_hostadapter xenblk$' "${conf}" ; then
	    # Required module alias not present!
	    return 0
	fi
    else
	if grep -Eq '^[^#]*scsi_hostadapter' "${conf}" ; then
	    # Module alias shouldn't be present as driver is kernel resident!
	    return 0 
	fi
    fi

    # no need to update modules configuration
    return 1
}

update_modules_configuration()
{
    if [ -f "/etc/modprobe.conf" ] ; then
	conf="/etc/modprobe.conf"
    elif [ -f "/etc/modules.conf" ] ; then
	conf="/etc/modules.conf"
    else
	return 1
    fi

    echo "Updating ${conf}, original saved in ${conf}.bak"
    cp "${conf}" "${conf}.bak"

    # Flush lines concerning PV modules
    grep -Ev '\beth0\b|\bscsi_hostadapter\b' "${conf}.bak" >"${conf}" || true

    # Add lines to alias any PV modules needed
    if [ X"${REQUIRE_XENNET_KO}" = "Xyes" ] ; then
	echo 'alias eth0 xennet' >>"${conf}"
    fi
    if [ X"${REQUIRE_XENBLK_KO}" = "Xyes" ] ; then
	echo 'alias scsi_hostadapter xenblk' >>"${conf}"
    fi

    return 0
}

update_grub_configuration()
{
    if [ -f "/boot/grub/menu.lst" ] ; then
	conf=$(readlink -f "/boot/grub/menu.lst")
    elif [ -f "/boot/grub/grub.conf" ] && [ ! -L "/boot/grub/grub.conf" ] ; then
	conf=$(readlink -f "/boot/grub/grub.conf")
    else
	echo "No grub configuration found. Not updating"
	return 1
    fi

    cmdline=$(cat /proc/cmdline)
    if [ -z "${cmdline}" ] ; then
	echo "No kernel command line found. Not updating grub configuration."
	return 1
    fi
    
    echo "Updating ${conf}, original saved in ${conf}.bak"
    cp "${conf}" "${conf}.bak"

    # Correct kernel command line.
    echo "  * set kernel command line to \`${cmdline}'."
    

    # Ensure kernel initrd and module lines include /boot/ if it is
    # not a separate filesystem.
    root_stat=$(stat --format='%d' --terse "/")
    boot_stat=$(stat --format='%d' --terse "/boot")
    if [ "${root_stat}" == "${boot_stat}" ] ; then 
	echo "  * prepend /boot/ to kernel path."
	rewrite_path="s;^\(\([^\#]*\|\)\(kernel\|initrd\|module\)\) \(/boot\)\?/\?;\1 /boot/;g"
    fi

    sed -e "s;^\(\([^\#]*\|\)kernel [^ ]*\) .*;\1 ${cmdline};g ; ${rewrite_path}" \
	<"${conf}.bak" >"${conf}"

    # Make sure there is an entry for the kernel pointed to by /boot/xenkernel
    if [ -L "/boot/xenkernel" ] && [ -x "/sbin/grubby" ] ; then
	kernel=$(readlink -f "/boot/xenkernel")
	initrd=$(readlink -f "/boot/xeninitrd")
	k="$(basename ${kernel} | sed -e 's/vmlinu.-//g')"
	echo "  * add entry for ${k} (/boot/xenkernel)."
	[ -n "${initrd}" ] && INITRD="--initrd ${initrd}"
	/sbin/grubby --add-kernel=${kernel} $INITRD \
	    --copy-default --make-default --title="${k}"
    fi

    echo

    return 0
}

update_vmlinuz_symlink()
{
    local symlink=$(readlink -f "/boot/vmlinuz")

    case ${symlink} in
	/boot/xenu-linux-*)
	    ;;
	*)
	    echo "\`/boot/vmlinuz' does not point to a Xen kernel. Leaving."
	    return 1
	    ;;
    esac

    local version=${symlink/\/boot\/xenu-linux-}

    mv -v "/boot/vmlinuz" "/boot/vmlinuz-xenu-${version}"

    if [ -L "/boot/initrd.img" ] && \
	[ "$(readlink -f /boot/initrd.img)" = "/boot/initrd.img-${version}" ] ; then
	mv -v "/boot/initrd.img" "/boot/initrd.img-xenu-${version}"
    fi
}

install_rpms()
{
    if [ -n "${XGU}" ] ; then
	rpm -Uvh ${XGU}
    fi

    if [ -n "${MKINITRD}" ] ; then
	rpm -Fvh --replacefiles --replacepkgs "${MKINITRD}"
    fi

    if [ -n "${ECRYPTFS_UTILS}" ] ; then
	rpm -Fvh --replacefiles --replacepkgs "${ECRYPTFS_UTILS}"
    fi

    # Install not upgrade so that old kernel is retained.
    if [ -n "${KERNEL}" ] ; then
	rpm -ivh "${KERNEL}"
	version=$(rpm -qp --qf "%{V}-%{R}\n" "${KERNEL}")
	if [ -f "/boot/vmlinuz-${version}xenU" ] && [ -x "/sbin/grubby" ] ; then
	    echo "Making kernel ${version}xenU"
	    echo "the default in grub configuration."
	    /sbin/grubby --set-default="/boot/vmlinuz-${version}xenU"
	    echo ""
	fi
    fi
    echo ""
}

install_debs()
{
    dpkg -i ${KERNEL} ${MKINITRD} ${XGU}

    echo ""
}

install_coreos()
{
    echo "Installing the agent..."
    xe_install_path=/opt/oem/xs
    mkdir -p $xe_install_path
    mkdir -p /etc/udev/rules.d/

    cp -f ${DATADIR}/xe-daemon \
          ${DATADIR}/xe-linux-distribution $xe_install_path
    cp -f ${DATADIR}/xen-vcpu-hotplug.rules /etc/udev/rules.d/
    cp -f ${DATADIR}/xe-linux-distribution.service /etc/systemd/system/
    sed -i "s#/usr/share/oem/xs#$xe_install_path#g" /etc/systemd/system/xe-linux-distribution.service
    systemctl enable /etc/systemd/system/xe-linux-distribution.service
    echo "Installation complete."
    systemctl start xe-linux-distribution.service
}

install_freebsd()
{
    echo "Installing xe-guest-utilities from FreeBSD pkg..."
    pkg install xe-guest-utilities
    echo "Installation complete. Starting xenguest"
    service xenguest start
}

case "${os_distro}" in
    rhel|centos|oracle|fedora|rocky)         select_pkgs_rhel ;;
    scientific|neokylin|asianux|turbo) select_pkgs_rhel ;;
    cloudlinux|sangoma|almalinux)      select_pkgs_rhel ;;
    sles|"suse linux")                 select_pkgs_sles ;;
    debian|ubuntu|linx|yinhe|Gooroom)  select_pkgs_debian ;;
    xe-ddk|xe-sdk)                     select_pkgs_xe ;;
    *CoreOS)                            select_pkgs_coreos ;;
    FreeBSD)                           select_pkgs_freebsd ;;
    *)                  failure "Unknown Linux distribution \`${os_distro}'." ;;
esac

if [ -n "${KERNEL}" ] ; then
    for K in ${KERNEL} ; do
	if [ ! -f "${K}" ] ; then
	    echo "Warning: kernel ${K} not found."
	    echo ""
	    KERNEL=""
	fi
    done
fi
if [ -n "${MKINITRD}" -a ! -f "${MKINITRD}" ] ; then
    echo "Warning: mkinitrd ${MKINITRD} not found."
    echo ""
    MKINITRD=""
fi
if [ -n "${ECRYPTFS_UTILS}" ] ; then
    for E in ${ECRYPTFS_UTILS} ; do
	if [ ! -f "${E}" ] ; then
	    echo "Warning: ecryptfs-utils ${E} not found."
	    echo ""
	    ECRYPTFS_UTILS=""
	fi
    done
fi
if [ -n "${XGU}" ] && [ "${os_distro}" != "FreeBSD" ] ; then
    for P in ${XGU} ; do
	if [ ! -f "${P}" ] ; then
	    echo "Warning: xe-guest-utilities ${P} not found."
	    XGU=""
	fi
    done
fi
if [ -z "${XGU}" ] && [ "${os_distro}" != "FreeBSD" ] ; then
    echo ""
    echo "Certain guest features will not be active until a version of "
    echo "xe-guest-utilities is installed."
    echo ""
fi

if [ -z "${KERNEL}" -a -z "${MKINITRD}" -a -z "${XGU}" -a -z "${ECRYPTFS_UTILS}" ] ; then
    echo "No updates required to this Virtual Machine."
    exit 0
fi

echo "The following changes will be made to this Virtual Machine:"

if [ -n "${KERNEL}" -a -L "/boot/xenkernel" ] ||
   [ -n "${KERNEL}" -a -L "/boot/vmlinuz" ] ; then
    echo "  * grub configuration update."
    echo "  * remove legacy kernel and initrd symbolic links."
    update_grub=1
else
    update_grub=0
fi

if update_modules_configuration_required ; then
    echo "  * modules configuration update."
    update_modules=1
else
    update_modules=0
fi

if update_lvm_configuration_required ; then
    echo "  * lvm configuration update."
    update_lvm=1
else
    update_lvm=0
fi

if update_inittab_configuration_required ; then
    echo "  * update gettys in inittab."
    update_inittab=1
else
    update_inittab=0
fi

if update_arp_notify_required ; then
    echo "  * update arp_notify sysctl."
    update_arp_notify=1
else
    update_arp_notify=0
fi

echo "  * packages to be installed/upgraded:"
for K in ${KERNEL}; do
    echo -e                           "    - $(basename ${K})"
done
[ -n "${MKINITRD}" ] && echo -e       "    - $(basename ${MKINITRD})"
for E in ${ECRYPTFS_UTILS}; do
    echo -e                           "    - $(basename ${E})"
done
for P in ${XGU}; do
    echo -e                           "    - $(basename ${P})"
done
echo ""

if [ ${interactive} -gt 0 ] ; then
    while read -p "Continue? [y/n] " -n 1 ans ; do
	echo
	case "$ans" in
	    Y|y)
		break
		;;
	    N|n)
		echo "Aborting."
		exit 0
		;;
	    *)
		echo "Invalid response \`$ans'"
		;;
	esac
    done
    echo
fi

set -e # Any failures from here onwards should be fatal

if [ "${update_grub}" -gt 0 ] ; then
    update_grub_configuration

    # Remove /boot/xenkernel
    if [ -L "/boot/xenkernel" ] || [ -L "/boot/xeninitrd" ] || [ -L "/boot/vmlinuz" ] ; then
	echo "Removing legacy boot kernel and initrd symbolic links."
	[ -L "/boot/xenkernel" ] && mv -v "/boot/xenkernel" "/boot/xenkernel.bak"
	[ -L "/boot/xeninitrd" ] && mv -v "/boot/xeninitrd" "/boot/xeninitrd.bak"
	[ -L "/boot/vmlinuz" ] && update_vmlinuz_symlink
	echo
    fi
fi

if [ "${update_modules}" -gt 0 ] ; then
    update_modules_configuration
fi

if [ "${update_lvm}" -gt 0 ] ; then
    update_lvm_configuration
fi

if [ "${update_inittab}" -gt 0 ] ; then
    update_inittab_configuration
fi

if [ "${update_arp_notify}" -gt 0 ] ; then
    update_arp_notify_configuration
fi

case ${GUEST_PKG_TYPE} in
    rpm) install_rpms ;;
    deb) install_debs ;;
    coreos) install_coreos ;;
    pkg) install_freebsd ;;
esac

if [ -n "${KERNEL}" -o -n "${XGU}" ] ; then
    echo "You should now reboot this Virtual Machine."
fi

exit 0

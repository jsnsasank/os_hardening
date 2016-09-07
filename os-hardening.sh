#!/usr/bin/env bash
########################################################################
# Script Name          : os-hardening.sh
# Author               : LAL PASHA SHAIK 
# Creation Date        : 23-Jun-2016
# Description          : Update Security settings for
#                        Oracle Enterprise Linux
########################################################################

## Variable
########################################################################
# sourced from /etc/org-install/config
# listed in the configvars variable on next line
configvars="pkgurl nameservers dnssearch ntpservers"

# Source the /etc/org-install/config file
# Exit if the /etc/org-install/config file is not found
if [ ! -f /etc/org-install/config ]; then
echo "ERROR: /etc/org-install/config file not found."
  exit 1
else
source /etc/org-install/config
fi

for configvar in ${configvars}
do
  if [[ -z $(eval echo \$${configvar}) ]]; then
	echo "ERROR: ${configvar} not defined in /etc/org-install/config."
    exit 1
  fi
done

## Logging
#####################################################################
logdir=${logdir:-/var/adm/install-logs}
[[ -d $logdir ]] || mkdir -p $logdir
logfile=$logdir/${0##*/}.$(date +%Y%m%d-%H%M%S).log
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>${logfile} 2>&1

tempdir=$(mktemp -d /tmp/orgtmp.XXXXXXXXXX)
cd ${tempdir}

#syslog
logger -s -- "[$$] $0 start: $(date)"
logger -s -- "[$$] script started in $(pwd)"
logger -s -- "[$$] logfile is in $logfile"

export PS4="+ [\t] "

## Functions
#####################################################################

function cleanup_before_exit() {
  logger -s -- "[$$] $0 end :  $(date)"
  echo "$0 end: $(date)" >&3
  if [[ "${err}" != "0" ]] ; then
    cat ${logfile} >&3
  fi
  cd /tmp && rm -rf ${tempdir}
}

## Main
#####################################################################
trap cleanup_before_exit EXIT
echo "$0 start: $(date)" >&3

# Applying CIS Redhat-documentation recommendations

### ---------- Section1 ---------
[[ -z ${hostname} ]] && hostname=org-linux
hostnamectl set-hostname ${hostname}

grep -q "[[:space:]]/tmp[[:space:]]" /etc/fstab || echo "Failed: separate partition for /tmp not found"
grep -q "[[:space:]]/var[[:space:]]" /etc/fstab || echo "Failed: separate partition for /var not found"
grep -q "[[:space:]]/var/log[[:space:]]" /etc/fstab || echo "Failed: separate partition for /var/log not found"
grep -q "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab || echo "Failed: separate partition for /var/log/audit not found"
grep -q "[[:space:]]/home[[:space:]]" /etc/fstab || echo "Failed: separate partition for /home not found"

# Update mount options for /tmp , /home , /dev/shm
# Take fstab backup
cp -p /etc/fstab /etc/fstab.$(date +%F.%H%M)
grep  "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep -q nodev  || sed -i '/[[:space:]]\/tmp[[:space:]]/ s/defaults/defaults,nodev/' /etc/fstab
grep  "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep -q nosuid || sed -i '/[[:space:]]\/tmp[[:space:]]/ s/defaults/defaults,nosuid/' /etc/fstab
mount -o remount /tmp
grep  "[[:space:]]/home[[:space:]]" /etc/fstab | grep -q nodev || sed -i '/[[:space:]]\/home[[:space:]]/ s/defaults/defaults,nodev/' /etc/fstab
mount -o remount /home
grep -e "^/tmp[[:space:]]" /etc/fstab | grep -q /var/tmp || echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab
grep -q /dev/shm /etc/fstab || echo "shmfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0" >> /etc/fstab

# Remove support for unneeded file systems
cat > /etc/modprobe.d/orgo_security.conf <<-EOFa
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOFa

# Enable gpgcheck globally
grep -q gpgcheck=1 /etc/yum.conf || sed -i -e 's/gpgcheck=0/gpgcheck=1/' /etc/yum.conf

# Disable the rhnsd daemon
systemctl disable rhnsd

sed -i.$(date +%F.%H%M) '/^GRUB_CMDLINE_LINUX/s/[^"].*[^"]/& audit=1/' /etc/default/grub
/usr/sbin/grub2-mkconfig -o /boot/grub2/grub.cfg

# Set permissions on grub.cfg
[[ "$(stat -L -c "%u:%g" /boot/grub2/grub.cfg)" == "0:0" ]] || chown root:root /boot/grub2/grub.cfg
stat -L -c "%a" /boot/grub2/grub.cfg | egrep -q ".00" || chmod og-rwx /boot/grub2/grub.cfg

# Set hard limit on core dumps
grep -q  "* hard core 0" /etc/security/limits.conf  || echo "* hard core 0" >> /etc/security/limits.conf
grep -q "fs.suid_dumpable = 0" /etc/sysctl.conf 	|| echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
grep -q "kernel.randomize_va_space = 2" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

### ---------- Section2&3 : OS services ---------

# Remove legacy services if exists
for pkg in telnet-server telnet rsh-server rsh ypbind ypserv tftp tftp-server talk talk-server xinetd xorg-x11-server dhcp openldap-servers bind vsftpd dovecot samba squid chrony
do
 rpm -q ${pkg} 1>/dev/null && yum -y remove ${pkg}
done

# Disable services
for _service in chargen-dgram chargen-stream daytime-dgram daytime-stream echo-dgram tcpmux-server avhi-daemon cups
do
  [[ "$(systemctl is-enabled ${_service} 2>/dev/null)" == "enabled" ]] && systemctl disable ${_service}
done

# set the default umask for all processes started at boot time

grep -q "umask 027" /etc/sysconfig/init || echo "umask 027" >> /etc/sysconfig/init

# Configure NTP :
rpm -q ntp 1>/dev/null || yum -y install ntp

#Enable ntpd
systemctl enable ntpdate
systemctl enable ntpd

# ntp.conf
sed -i.$(date +%F.%H%M) \
  -e "s/^server/#server/" \
  -e "s/^#server.*127.127.1.0/server 127.127.1.0/" \
/etc/ntp.conf

# add lines to ntp.conf
grep -q '^logfile' /etc/ntp.conf || echo "logfile   /var/log/ntp          # alternate log file" >> /etc/ntp.conf

IFS=,
for i in $ntpservers
do
  sed -i -e "s/^#server.*${i}/server ${i}/" /etc/ntp.conf
  grep -q "^server ${i}" /etc/ntp.conf || echo server $i >> /etc/ntp.conf
done
IFS=

# Check and update correct parameters

sed -i -e "s/^restrict default/#restrict default/" /etc/ntp.conf
grep -q "^restrict default kod" /etc/ntp.conf || echo "restrict default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
grep -q "restrict -6 default kod" /etc/ntp.conf || echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
sed -i -e 's/OPTIONS=.*/OPTIONS="-u ntp:ntp"/' /etc/sysconfig/ntpd
grep -q 'inet_interfaces = localhost' /etc/postfix/main.cf || echo "inet_interfaces = localhost" >> /etc/postfix/main.cf

systemctl start ntpdate
systemctl start ntpd

### ---------- Section4: Network configuration ---------

if ! grep -q "#orgO RHEL7.2 Autobuild Ipv4 Security Settings" /etc/sysctl.conf
then
cat >> /etc/sysctl.conf <<-EOFb
#orgO RHEL7.2 Autobuild Ipv4 Security Settings
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
#ipv6
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.disable_ipv6=1
EOFb

fi

# Populate kernel parameters
sysctl -p 1> /dev/null
# Install tcp_wrappers
rpm -q tcp_wrappers 1>/dev/null || yum -y install tcp_wrappers

# setup TCP wrappers to allow only network connections from Specific Networks
# For example. This build allows connections from. following networks
# 127.x.x.x ; 10.x.x.x ; 172.x.x.x ; 192.x.x.x.x
grep -q 'ALL: 127.0.0.1 ' /etc/hosts.allow || echo "ALL: 127.0.0.1 " >> /etc/hosts.allow
grep -q 'ALL: 10. ' /etc/hosts.allow || echo "ALL: 10. " >> /etc/hosts.allow
grep -q 'ALL: 172. ' /etc/hosts.allow || echo "ALL: 172. " >> /etc/hosts.allow
grep -q 'ALL: 192. ' /etc/hosts.allow || echo "ALL: 192. " >> /etc/hosts.allow
grep -q 'ALL: ALL' /etc/hosts.deny || echo "ALL: ALL" >> /etc/hosts.deny

/bin/chmod 644 /etc/hosts.allow
/bin/chmod 644 /etc/hosts.deny

### ---------- Section5: Logging & Auditing ---------

# Enable auditd
systemctl enable auditd
cp -p /etc/audit/auditd.conf /etc/audit/auditd.conf.$(date +%F.%H%M)

sed -i '/^space_left_action/s/space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i '/^max_log_file_action/s/max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf

# Update Audit rules
curl -k ${pkgurl}/configs/audit.rules  --create-dirs -o /etc/audit/rules.d/audit.rules

# Restart auditd to reload new rules.
service auditd restart

### ---------- Section6: System Access,Authentication ---------

# cron setup
rpm -q cronie-anacron 1>/dev/null || yum -y install cronie-anacron
systemctl enable crond

for cronfile in /etc/anacrontab /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.monthly /etc/cron.weekly /etc/cron.d
  do
    chown root:root ${cronfile}
    chmod og-rwx ${cronfile}
done

[[ -f /etc/cron.deny ]]  && /bin/rm /etc/cron.deny
[[ -f /etc/at.deny ]]    && /bin/rm /etc/at.deny
[[ ! -f /etc/cron.allow ]] && touch /etc/cron.allow
[[ -f /etc/cron.allow ]] && chmod 600 /etc/cron.allow
[[ ! -f /etc/at.allow ]] && touch /etc/at.allow
[[ -f /etc/at.allow ]]   && chmod 600 /etc/at.allow
[[ -f /etc/cron.allow ]] && chown root:root /etc/cron.allow
[[ -f /etc/at.allow ]]   && chown root:root /etc/at.allow

# SSH configuration
cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.$(date +%F.%H%M)
sed -i \
-e 's/^#Protocol 2.*/Protocol 2/' \
-e 's/^#IgnoreRhosts.*/IgnoreRhosts yes/' \
-e 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' \
-e 's/^#Banner.*/Banner \/etc\/issue/' \
-e 's/^#LogLevel.*/LogLevel INFO/' \
-e 's/^#HostbasedAuthentication.*/HostbasedAuthentication no/' \
-e 's/^#PermitRootLogin.*/PermitRootLogin yes/' \
/etc/ssh/sshd_config

# configure security:
# Allow only root and SA logins from the local consoles
cat > /etc/securetty <<-EOFe
tty1
tty2
tty3
tty4
tty5
tty6
EOFe

# Setup password policy.
# Passwords should have at least 1-uppercase, 1-lowercase, 1-digit
if ! grep -q "orgO Password policy" /etc/security/pwquality.conf
then
cat >> /etc/security/pwquality.conf <<-EOFx
# orgO Password policy
minlen = 8
dcredit = -1
ucredit = -1
lcredit = -1
EOFx
fi




### ---------- Section7: User Accounts and Environment ---------
# 		password change options
#       PASS_MAX_DAYS   Maximum number of days a password may be used.
#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
#       PASS_WARN_AGE   Number of days warning given before a password expires.

sed -i.$(date +%F.%H%M) \
  -e "/UMASK/s/022/077/" \
  -e "/PASS_MAX_DAYS/s/99999/90/" \
  -e "/PASS_MIN_DAYS/s/0/7/" \
  -e "/PASS_WARN_AGE/s/7/14/" \
  /etc/login.defs

# Set users default umask to 077
grep -q "umask 77" /etc/bashrc || echo "umask 77" >> /etc/bashrc

sed -i.$(date +%F.%H%M) "/^INACTIVE/s/INACTIVE.*/INACTIVE=45/" /etc/default/useradd

### ---------- Section8: Set warning Banner ---------

# /etc/issue to conform IAPP policies
cat > /etc/issue <<-EOFf
#############################################################################
#  <message by your organization>                                                                         #
#############################################################################
EOFf

# /etc/motd for bogus IAPP requirement
cat > /etc/motd <<-EOFg
<replace with your own message>
EOFg

### ---------- Section9: System Maintenance ---------

# Ensure permissions
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group

echo -n "search" > /etc/resolv.conf
IFS=,
for i in $dnssearch
do
  echo -n " $i" >> /etc/resolv.conf
done
IFS=
echo  >> /etc/resolv.conf

IFS=,
for i in $nameservers
do
  echo nameserver $i >> /etc/resolv.conf
done
IFS=

# add DNS options to resolv.conf
echo "options attempts:2" >> /etc/resolv.conf
echo "options timeout:1" >> /etc/resolv.conf
echo "options rotate" >> /etc/resolv.conf

# Add a 12-org-dns script to NetworkManager dispatcher.d
# This make sures that our dns settings are not overwritten by NetworkManager
cp -p /etc/resolv.conf /etc/resolv.conf.org-dns
echo "cp -f /etc/resolv.conf.org-dns /etc/resolv.conf" > /etc/NetworkManager/dispatcher.d/12-org-dns
chmod +x /etc/NetworkManager/dispatcher.d/12-org-dns
systemctl restart NetworkManager

# disable ipv6 module
grep -q "options ipv6 disable=1" /etc/modprobe.d/ipv6.conf || echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

# Mail configuration
[[ -z ${rootmaildest} ]] && rootmaildest=lxs85190@orgo.edu
grep -q "${rootmaildest}" /root/.forward || echo ${rootmaildest} >> /root/.forward
chmod 644 /root/.forward
postconf -e inet_interfaces=localhost inet_protocols=ipv4 disable_vrfy_command=yes


# Disable Control-Alt-Delete
systemctl mask ctrl-alt-del.target

# set up root shell environment to record separate history files
[[ -d /root/.histdir ]] || /bin/mkdir /root/.histdir

cat > /tmp/roothist <<-EOFj
#org Autobuild roothist config
USER=\$(whoami)  
if [ "\$RUSER" = "" ]; then
  PARID=\$(</proc/\$\$/loginuid)
  RUSER=\$(getent passwd \$PARID | awk -F: '{print \$1}')
else
  HISTSIZE=1000
  HISTFILE=\$HOME/.histdir/\$USER.\$RUSER.\$(date +%Y%m%d-%H%M%S)
  HOST=\$(uname -n); HOST=\${HOST%%.*}
  PS1='[\$USER@\$HOST:\$PWD]# '

  export USER HISTSIZE HISTFILE RUSER HOST PS1
fi
# fix broken cmd line editing
shopt -s checkwinsize
EOFj

cat /tmp/roothist > /root/.bashrc
grep -qi "org" /root/.bash_profile || cat /tmp/roothist >> /root/.bash_profile
cat /tmp/roothist > /root/.profile
/bin/rm -f /tmp/roothist
# Add crontab entry
( echo '# cleanup of old files in /root/.histdir' ; echo ; echo '0 8 * * * root cd $HOME/.histdir && find . -type f -mtime +90 -print -exec rm {} \; >> /var/log/histdir.log 2>&1' ) > /etc/cron.d/histdir_cleanup

err=0
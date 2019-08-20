#!/bin/bash
{
    svn=`svnserve --version | awk 'NR==1{print $3}'|wc -l`
}
if
[ $svn -eq 1 ]
then
    echo "检查已安装svnserve --version=1.9.9";svnserve --version
fi
if
[ $svn -ne 1 ]
then
    echo "请安装svnserve 1.9.9"
    read -ep "是否安装svnserve 1.9.9 请确保pwd: /root/subversion_installer_1.9.sh 存在,文件在[安装 <y> ] [不安装并退出 <q> ]" okFirst
    case $okFirst in
        [yY][eE][sS]|[yY])
        chmod +x /root/subversion_installer_1.9.sh
        sh /root/subversion_installer_1.9.sh
    ;;
        [qQ][uU][iI][tT]|[qQ])
        exit 0
    ;;
    esac
fi
###!/bin/bash
#while (:)  
#do 
#   svnsync sync file:///database/$the_svn_repository_name
#   if [ $? != 0 ]
#   then  
#   svn propdel svn:sync-lock --revprop -r0 file:///database/$the_svn_repository_name
#   fi  
#   sleep 60  
#done
# script.
#ps -ef | grep rsync,svnserve
#pstree
#netstat -ntpl | grep rsync,svnserve
#Failed to get lock on destination repos, currently held by 'localhost.localdomain:7d4732d5-a0eb-4f4c-b42e-ae75b43c0f37'
#--steal-lock
#svn propdel svn:sync-lock --revprop -r0 file:///database/$the_svn_repository_name
#echo "*/2  *  *  *  * root echo -e \`date;svnsync sync svn://$ipbackup6/$the_svn_repository_name/ --username bigone --password bigone\` >> /$rsyncd_hostback_pathname/logs/logsyncsvn.log" >> /etc/crontab
#echo -e `date;svnsync sync svn://192.168.84.6/$the_svn_repository_name/ --source-username bigone --source-password bigone --sync-username bigone --sync-password bigone --non-interactive` >> /$rsyncd_hostback_pathname/logs/logsyncsvn.log
#echo "*/2  *  *  *  * root echo -e \`date;svnsync sync svn://$ipbackup6/$the_svn_repository_name/ --source-username bigone --source-password bigone --sync-username bigone --sync-password bigone --non-interactive\` >> /$rsyncd_hostback_pathname/logs/logsyncsvn.log" >> /etc/crontab
#svn pdel --revprop -r 0 --username bigonetoict --password bigonetoict svn:sync-lock file:///database/$the_svn_repository_name
ip a
read -ep "主备服务器选择操作: [安装 < y > ] [备机IP切换主机 < n > ] [退出 < q > ] >> " ok0
case $ok0 in
    [yY][eE][sS]|[yY])
    read -ep "----->the_svn_repository_name            创库名称: 如：SVN_NAME               (不建议中文、空格、-：创库名称不能与创库路径名称开头相同)----->>=" the_svn_repository_name
    read -ep "----->the_svn_repository_path            创库路径: 如：SVN_PATH               (不建议中文和有空格)------------------------------------------>>=" the_svn_repository_path
    read -ep "----->the_svn_repository_admin_username  用户名称: 如：SVN_USERNAME           (不建议中文和有空格) ----------------------------------------->>=" the_svn_repository_admin_username
    read -ep "----->the_svn_repository_admin_password  用户密码: 如：SVN_PASSWORD           (不建议中文和有空格) ----------------------------------------->>=" the_svn_repository_admin_password
    read -ep "----->rsyncd_admin_username              用户名称: 如：rsyncd_admin_username  (不建议中文和有空格) ----------------------------------------->>=" rsyncd_admin_username
    read -ep "----->rsyncd_admin_password              用户密码: 如：rsyncd_admin_password  (不建议中文和有空格) ----------------------------------------->>=" rsyncd_admin_password
    read -ep "----->rsyncd_hostback_pathname           主机路名: 如：Rsycd_Path             (不建议中文和有空格) ----------------------------------------->>=" rsyncd_hostback_pathname
;;
    [nN][oO]|[nN])
    hostname Host
    ip a
    ##备机操作切换主机IP地址：
    Rsyncd_SVN_Back_Path=`cat /Rsyncd_Host_Path/rsyncd_hostback_pathname`
    mkdir -p /SVN_BACK_FULL_COPY/;\cp -p -r /$Rsyncd_SVN_Back_Path /SVN_BACK_FULL_COPY/
    Passwd_Aes_Top0=`gzexe -d /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_Name;rm -f /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_Name*~;cat /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_Name`
    Passwd_Aes_Top1=`gzexe -d /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_PATH;rm -f /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_PATH*~;cat /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_PATH`
    Passwd_Aes_Top2=`gzexe -d /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_Admin_Name;rm -f /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_Admin_Name*~;cat /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_Admin_Name`
    Passwd_Aes_Top3=`gzexe -d /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_Admin_Passwd;rm -f /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_Admin_Passwd*~;cat /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/SVN_Admin_Passwd`
    Passwd_Aes_Top4=`gzexe -d /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/Rsyncd_SVN_Admin_Name;rm -f /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/Rsyncd_SVN_Admin_Name*~;cat /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/Rsyncd_SVN_Admin_Name`
    Passwd_Aes_Top5=`gzexe -d /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/Rsyncd_SVN_Admin_Passwd;rm -f /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/Rsyncd_SVN_Admin_Passwd*~;cat /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/Rsyncd_SVN_Admin_Passwd`
    Passwd_Aes_Top6=`gzexe -d /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/Rsyncd_SVN_Back_Path;rm -f /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/Rsyncd_SVN_Back_Path*~;cat /SVN_BACK_FULL_COPY/$Rsyncd_SVN_Back_Path/Rsyncd_SVN_Back_Path`
    ###
    RE_SVN_Name=`echo $Passwd_Aes_Top0 | openssl aes-128-cbc -d -k 123 -base64`
    RE_SVN_PATH=`echo $Passwd_Aes_Top1 | openssl aes-128-cbc -d -k 123 -base64`
    RE_SVN_Admin_Name=`echo $Passwd_Aes_Top2 | openssl aes-128-cbc -d -k 123 -base64`
    RE_SVN_Admin_Passwd=`echo $Passwd_Aes_Top3 | openssl aes-128-cbc -d -k 123 -base64`
    RE_Rsyncd_SVN_Admin_Name=`echo $Passwd_Aes_Top4 | openssl aes-128-cbc -d -k 123 -base64`
    RE_Rsyncd_SVN_Admin_Passwd=`echo $Passwd_Aes_Top5 | openssl aes-128-cbc -d -k 123 -base64`
    RE_Rsyncd_SVN_Back_Path=`echo $Passwd_Aes_Top6| openssl aes-128-cbc -d -k 123 -base64`
    ###
    echo $RE_SVN_Name
    echo $RE_SVN_PATH
    echo $RE_SVN_Admin_Name
    echo $RE_SVN_Admin_Passwd
    echo $RE_Rsyncd_SVN_Admin_Name
    echo $RE_Rsyncd_SVN_Admin_Passwd
    echo $RE_Rsyncd_SVN_Back_Path
    read -ep "rsync服务端允许访问本机的IP/掩码: 如192.168.1.2/24 >> " ipbackup0
    ipmask1=$ipbackup0
    read -ep "主机服务器IP是:" ipserver0
    ipserver1=$ipserver0
    read -ep "备机服务器操作: 请输入网卡名如:eth0 >> " -t 300 ifcfg0
    ipbackup0=`ifconfig $ifcfg0|grep broadcast |awk '{print $2}'`
    ipbackup1=$ipbackup0
    echo "备机服务器操作: 请输入主服务器IP进行备机服务器同步 >> $ipbackup1"
    if test "$ipserver1" = "$ipbackup1";then
    echo "主备IP相同请重新输入>>>>>..."
    read -ep "主机服务器IP是:" ipserver0
    ipserver1=$ipserver0
    read -ep "备机服务器操作: 请输入网卡名如:eth0 >> " -t 300 ifcfg0
    ipbackup0=`ifconfig $ifcfg0|grep broadcast |awk '{print $2}'`
    ipbackup1=$ipbackup0
    echo  "备机服务器操作: 请输入主服务器IP进行备机服务器同步 >> $ipbackup1"
        if test "$ipserver1" = "$ipbackup1";then
        exit 0
        fi
    fi
    svnuuid=`cat /$RE_Rsyncd_SVN_Back_Path/svnuuid.txt`
    echo "$svnuuid"
    svnadmin setuuid /$RE_SVN_PATH/$RE_SVN_Name/ $svnuuid
    sed -i s/$ipbackup1/$ipserver1/g /etc/sysconfig/network-scripts/ifcfg-$ifcfg0
    sed -i '17,20s/^/#/' /etc/crontab
    echo -e "uid = root\ngid = root\nuse chroot = no\nmax connections = 3\nstrict modes =yes\npid file = /var/run/rsyncd.pid\nlock file = /var/run/rsync.lock\nlog file = /var/run/rsyncd.log\nexclude = lost+found/\n#transfer logging = yes\nport = 873\ntimeout = 900\nignore nonreadable = yes\ndont compress = *.gz *.tgz *.zip *.z *.Z *.rpm *.deb *.bz2\n[$RE_Rsyncd_SVN_Back_Path]\npath = /$RE_Rsyncd_SVN_Back_Path/\n[$RE_SVN_Name]\nignore errors\npath = /$RE_SVN_PATH/$RE_SVN_Name/conf/\ncomment = $RE_SVN_Name export area\nread only = no\nwrite only = no\nlist = no\nhosts allow = $ipbackup0\nauth users = $RE_Rsyncd_SVN_Admin_Name\nsecrets file = /$RE_Rsyncd_SVN_Back_Path/pw/$RE_SVN_Name.passwd" > /etc/rsyncd.conf
    service network restart
    exit 0
;;
    [qQ][uU][iI][tT]|[qQ])
    exit 0
;;
esac
systemctl stop firewalld.service
setenforce 0
systemctl disable firewalld.service
sudo yum install ntp -y
sudo systemctl start ntpd
timedatectl set-timezone "Asia/Shanghai"
systemctl enable ntpd
ntpdate cn.pool.ntp.org
sudo systemctl restart ntpd
#sudo yum install -y tcp_wrappers psmisc tree cyrus-sasl-md5 vim chrony iptables-services apr* rsync xinetd vixie-cron crontabs wget lrzsz vim autoconf automake bison bzip2 bzip2* cloog-ppl compat* cpp curl curl-devel fontconfig fontconfig-devel freetype freetype* freetype-devel gcc gcc-c++ gtk+-devel gd gettext gettext-devel glibc kernel kernel-headers keyutils keyutils-libs-devel krb5-devel libcom_err-devel libpng libpng-devel libjpeg* libsepol-devel libselinux-devel libstdc++-devel libtool* libgomp libxml2 libxml2-devel libXpm* libxml* libXaw-devel libXmu-devel libtiff libtiff* make mpfr ncurses* ntp openssl openssl-devel patch pcre-devel perl php-common php-gd policycoreutils telnet t1lib t1lib* nasm nasm* wget zlib-devel iptables-services net-tools
#yum clean all
cat > /etc/sysconfig/iptables <<END
# sample configuration for iptables service
# you can edit this manually or use system-config-firewall
# please do not ask us to add additional ports/services to this default configuration
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 9496 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 123 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 873 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 3690 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
END
systemctl restart iptables.service
systemctl enable iptables.service
/usr/libexec/iptables/iptables.init restart
systemctl stop firewalld.service
systemctl disable firewalld.service
cat > /etc/selinux/config <<END
# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#     enforcing - SELinux security policy is enforced.
#     permissive - SELinux prints warnings instead of enforcing.
#     disabled - No SELinux policy is loaded.
#SELINUX=enforcing
SELINUX=disabled
# SELINUXTYPE= can take one of three two values:
#     targeted - Targeted processes are protected,
#     minimum - Modification of targeted policy. Only selected processes are protected.
#     mls - Multi Level Security protection.
#SELINUXTYPE=targeted
END
mkdir /$the_svn_repository_path/
chmod 755 /$the_svn_repository_path/
svnadmin create /$the_svn_repository_path/$the_svn_repository_name
sudo chown -R root:root /$the_svn_repository_path/$the_svn_repository_name
sudo chmod -R g+rws /$the_svn_repository_path/$the_svn_repository_name
cat > /$the_svn_repository_path/$the_svn_repository_name/conf/svnserve.conf <<END
### This file controls the configuration of the svnserve daemon, if you
### use it to allow access to this repository.  (If you only allow
### access through http: and/or file: URLs, then this file is
### irrelevant.)

### Visit http://subversion.apache.org/ for more information.
[general]
### The anon-access and auth-access options control access to the
### repository for unauthenticated (a.k.a. anonymous) users and
### authenticated users, respectively.
### Valid values are "write", "read", and "none".
### Setting the value to "none" prohibits both reading and writing;
### "read" allows read-only access, and "write" allows complete
### read/write access to the repository.
### The sample settings below are the defaults and specify that anonymous
### users have read-only access to the repository, while authenticated
### users have read and write access to the repository.
anon-access = none
auth-access = write
### The password-db option controls the location of the password
### database file.  Unless you specify a path starting with a /,
### the file's location is relative to the directory containing
### this configuration file.
### If SASL is enabled (see below), this file will NOT be used.
### Uncomment the line below to use the default password file.
password-db = passwd
### The authz-db option controls the location of the authorization
### rules for path-based access control.  Unless you specify a path
### starting with a /, the file's location is relative to the
### directory containing this file.  The specified path may be a
### repository relative URL (^/) or an absolute file:// URL to a text
### file in a Subversion repository.  If you don't specify an authz-db,
### no path-based access control is done.
### Uncomment the line below to use the default authorization file.
authz-db = authz
### The groups-db option controls the location of the file with the
### group definitions and allows maintaining groups separately from the
### authorization rules.  The groups-db file is of the same format as the
### authz-db file and should contain a single [groups] section with the
### group definitions.  If the option is enabled, the authz-db file cannot
### contain a [groups] section.  Unless you specify a path starting with
### a /, the file's location is relative to the directory containing this
### file.  The specified path may be a repository relative URL (^/) or an
### absolute file:// URL to a text file in a Subversion repository.
### This option is not being used by default.
# groups-db = groups
### This option specifies the authentication realm of the repository.
### If two repositories have the same authentication realm, they should
### have the same password database, and vice versa.  The default realm
### is repository's uuid.
realm = $the_svn_repository_name
### The force-username-case option causes svnserve to case-normalize
### usernames before comparing them against the authorization rules in the
### authz-db file configured above.  Valid values are "upper" (to upper-
### case the usernames), "lower" (to lowercase the usernames), and
### "none" (to compare usernames as-is without case conversion, which
### is the default behavior).
# force-username-case = none
### The hooks-env options specifies a path to the hook script environment
### configuration file. This option overrides the per-repository default
### and can be used to configure the hook script environment for multiple
### repositories in a single file, if an absolute path is specified.
### Unless you specify an absolute path, the file's location is relative
### to the directory containing this file.
# hooks-env = hooks-env
[sasl]
### This option specifies whether you want to use the Cyrus SASL
### library for authentication. Default is false.
### This section will be ignored if svnserve is not built with Cyrus
### SASL support; to check, run 'svnserve --version' and look for a line
### reading 'Cyrus SASL authentication is available.'
# use-sasl = true
### These options specify the desired strength of the security layer
### that you want SASL to provide. 0 means no encryption, 1 means
### integrity-checking only, values larger than 1 are correlated
### to the effective key length for encryption (e.g. 128 means 128-bit
### encryption). The values below are the defaults.
# min-encryption = 0
# max-encryption = 256
END
cat > /$the_svn_repository_path/$the_svn_repository_name/conf/authz <<END
### This file is an example authorization file for svnserve.
### Its format is identical to that of mod_authz_svn authorization
### files.
### As shown below each section defines authorizations for the path and
### (optional) repository specified by the section name.
### The authorizations follow. An authorization line can refer to:
###  - a single user,
###  - a group of users defined in a special [groups] section,
###  - an alias defined in a special [aliases] section,
###  - all authenticated users, using the '$authenticated' token,
###  - only anonymous users, using the '$anonymous' token,
###  - anyone, using the '*' wildcard.
###
### A match can be inverted by prefixing the rule with '~'. Rules can
### grant read ('r') access, read-write ('rw') access, or no access
### ('').

[aliases]
# joe = /C=XZ/ST=Dessert/L=Snake City/O=Snake Oil, Ltd./OU=Research Institute/CN=Joe Average

[groups]
# harry_and_sally = harry,sally
# harry_sally_and_joe = harry,sally,&joe

# [/foo/bar]
# harry = rw
# &joe = r
# * =

# [repository:/baz/fuz]
# @harry_and_sally = rw
# * = r

#[repository:/baz/file.xxx],e.g.:bigone.ppt
# @harry_and_sally = rw
# * = r
#start.list_useradd

admin = $the_svn_repository_admin_username
ictadmin = ict
jl = hj
zs = cgs
gcs = lh,wcl


[/]
@admin = rw
* =

[$the_svn_repository_name:/]
@admin = rw
@jl = rw
@zs = rw
@gcs = rw
* =

[$the_svn_repository_name:/ict项目部]
@admin = rw
@ictadmin = rw
@jl = rw
@zs = rw
@gcs = rw
* =

[$the_svn_repository_name:/ict项目部/ppt]
@admin = rw
@ictadmin = rw
@jl = rw
@zs = rw
@gcs = rw
* =

[$the_svn_repository_name:/ict项目部/word]
@admin = rw
@ictadmin = rw
@jl = rw
@zs = rw
@gcs = rw
* =

[$the_svn_repository_name:/ict项目部/excel]
@admin = rw
@ictadmin = rw
@jl = rw
@zs = rw
@gcs = rw
* =

[$the_svn_repository_name:/ict项目部/other]
@admin = rw
@ictadmin = rw
@jl = rw
@zs = rw
@gcs = rw
* =

END
cat > /$the_svn_repository_path/$the_svn_repository_name/conf/passwd <<END
### This file is an example password file for svnserve.
### Its format is similar to that of svnserve.conf. As shown in the
### example below it contains one section labelled [users].
### The name and password for each user follow, one account per line.
[users]
# harry = harryssecret
# sally = sallyssecret
$the_svn_repository_admin_username = $the_svn_repository_admin_password
hj = hujian
cgs = chengengsheng
wcl = wuchunlin
lh = lihui
ict = ict
END
mkdir -p /$rsyncd_hostback_pathname/{pw,logs}
echo "$rsyncd_admin_username:$rsyncd_admin_password" >> /$rsyncd_hostback_pathname/pw/$the_svn_repository_name.passwd
chmod 0600 /$rsyncd_hostback_pathname/pw/$the_svn_repository_name.passwd
chown root.root /$rsyncd_hostback_pathname/pw/$the_svn_repository_name.passwd
systemctl restart rsyncd.service
rpm -aq |grep xinetd >> /$rsyncd_hostback_pathname/logs/xinetd.log
rm -rf /var/run/rsyncd.pid
rsync --daemon
cat > /etc/xinetd.d/rsync <<END
service rsync
{
        disable         = no
        socket_type     = stream
        flags           = IPv4
        socket_type     = stream
        wait            = no
        user            = root
        server          = /usr/bin/rsync
        server_args     = --daemon
        log_on_failure  += USERID
}
END
cat> /etc/xinetd.d/svnserve <<END
# default: on
# description: Subversion server for the $the_svn_repository_name protocol
service svnserve
{
  disabled        = no
  port            = 3690
  socket_type     = stream
  protocol        = tcp
  wait            = no
  user            = subversion
  server          = /usr/local/bin/svnserve
  server_args     = -i -r /path/to/repositories
}
END
echo "$rsyncd_admin_password" >> /$rsyncd_hostback_pathname/pw/$the_svn_repository_name.pwd
chmod 00600 /$rsyncd_hostback_pathname/pw/$the_svn_repository_name.pwd
chown root.root /$rsyncd_hostback_pathname/pw/$the_svn_repository_name.pwd
cd /$the_svn_repository_path/$the_svn_repository_name/hooks
cp pre-revprop-change.tmpl pre-revprop-change
cat > pre-revprop-change <<END
#!/bin/sh
REPOS="\$1"
REV="\$2"
USER="\$3"
PROPNAME="\$4"
ACTION="\$5"
export LANG=zh_CN.UTF-8
echo "Code Deployed at `date "+%Y-%m-%d %H:%M"`" >> /tmp/deploy.log
if [ "\$ACTION" = "M" -a "\$PROPNAME" = "svn:log" ]; then exit 0; fi
echo "Changing revision properties other than svn:log is prohibited" >&2
exit 0
END
chkconfig --add svnserve
chkconfig rsync on
echo '/usr/bin/rsync --daemon on' >> /etc/rc.local
/usr/bin/rsync --daemon on
/bin/systemctl restart  xinetd.service
echo '/bin/systemctl restart  xinetd.service' >> /etc/rc.d/rc.local
echo 'rsync --daemon' >> /etc/rc.d/rc.local
echo 'svnserve -d --listen-port 3690 -r /$the_svn_repository_path/' >> /etc/rc.d/rc.local
systemctl enable xinetd.service
systemctl enable rsyncd 
svnserve -d --listen-port 3690 -r /$the_svn_repository_path/
chmod +x /etc/rc.local
chmod +x /etc/rc.d/rc.local
killall -HUP rsync
killall -HUP xinetd
systemctl restart xinetd
systemctl restart rsyncd
netstat -lnp|grep 873 > /$rsyncd_hostback_pathname/logs/rsync.log
cat <<EOF
主/备服务器选择: <y> <n>
EOF
echo $?
ip a 
read -ep "主备服务器选择操作: [主机 < y > ] [备机 < n > ] >> " ok2
case $ok2 in
    [yY][eE][sS]|[yY])
    hostname Host
    read -ep "主机服务器操作: 请输入网卡名如:eth0 >> " -t 300 ifcfg2
    ipserver2=`ifconfig $ifcfg2|grep broadcast |awk '{print $2}'`
    ipserver3=$ipserver2
    echo "主机服务器IP: >> $ipserver3"
    read -ep "rsync服务端允许访问本机的IP/掩码: 如192.168.1.2/24 >> " ipbackup2
    ipmask3=$ipbackup2
    echo "rsync服务端允许访问本机的IP/掩码: >> $ipmask3"
    read -ep "主机服务器操作: 主份服务器IP是: $ipserver3 [正确 < y > ] [错误 < n > ] >> " ok3
    case $ok3 in
        [yY][eE][sS]|[yY])
        mkdir -p /$the_svn_repository_name/ict项目部/word
        mkdir -p /$the_svn_repository_name/ict项目部/other
        mkdir -p /$the_svn_repository_name/ict项目部/excel
        mkdir -p /$the_svn_repository_name/ict项目部/ppt
        yes|svn import /$the_svn_repository_name/ict项目部/ppt svn://$ipserver3/$the_svn_repository_name/ict项目部/ppt -m "Initial commit." --username $the_svn_repository_admin_username --password $the_svn_repository_admin_password
        svn import /$the_svn_repository_name/ict项目部/excel svn://$ipserver3/$the_svn_repository_name/ict项目部/excel -m "Initial commit." --username $the_svn_repository_admin_username --password $the_svn_repository_admin_password
        svn import /$the_svn_repository_name/ict项目部/word svn://$ipserver3/$the_svn_repository_name/ict项目部/word -m "Initial commit." --username $the_svn_repository_admin_username --password $the_svn_repository_admin_password
        svn import /$the_svn_repository_name/ict项目部/other svn://$ipserver3/$the_svn_repository_name/ict项目部/other -m "Initial commit." --username $the_svn_repository_admin_username --password $the_svn_repository_admin_password
        rm -rf /$the_svn_repository_name
        echo "*/1  *  *  *  * root echo -e \`date;sh /root/runbash_crontab.sh\` >> /$rsyncd_hostback_pathname/logs/runbash_crontab.log" >> /etc/crontab
        echo -e "uid = root\ngid = root\nuse chroot = no\nmax connections = 3\nstrict modes =yes\npid file = /var/run/rsyncd.pid\nlock file = /var/run/rsync.lock\nlog file = /var/run/rsyncd.log\nexclude = lost+found/\n#transfer logging = yes\nport = 873\ntimeout = 900\nignore nonreadable = yes\ndont compress = *.gz *.tgz *.zip *.z *.Z *.rpm *.deb *.bz2\n[$rsyncd_hostback_pathname]\npath = /$rsyncd_hostback_pathname/\n[$the_svn_repository_name]\nignore errors\npath = /$the_svn_repository_path/$the_svn_repository_name/conf/\ncomment = $the_svn_repository_name export area\nread only = no\nwrite only = no\nlist = no\nhosts allow = $ipmask3\nauth users = $rsyncd_admin_username\nsecrets file = /$rsyncd_hostback_pathname/pw/$the_svn_repository_name.passwd" > /etc/rsyncd.conf
        echo -e "`svnlook uuid /$the_svn_repository_path/$the_svn_repository_name`" > /$rsyncd_hostback_pathname/svnuuid.txt
    ;;
        [nN][oO]|[nN])
        echo "请求失败..............."
    ;;
    esac
;;
    [nN][oO]|[nN])
    #!/bin/bash
    #备机服务器追加文本bash
    #ip替换
    #echo "*/1  *  *  *  * root sh /root/runbash_crontab.sh >> /$rsyncd_hostback_pathname/logw/runbash_crontab.log" >> /etc/crontab
    #sed -i 's/192.168.84.5/192.168.84.6/g' /etc/sysconfig/network-scripts/ifcfg-eth0
    #6-8行首删除注释
    #[$USER@localhost `pwd | awk -F "/" '{print $NF}'`]#
    #tail  -f  /var/log/messages
    #sed -i '6,8s/^#//' /etc/crontab
    hostname Backup
    ip a
    read -ep "备机服务器操作: 请输入网卡名如:eth0 >> " -t 300 ifcfg5
    ipbackup5=`ifconfig $ifcfg5|grep broadcast |awk '{print $2}'`
    ipbackup6=$ipbackup5
    echo "备机服务器IP: >> $ipbackup6"
    read -ep "rsync服务端允许访问本机的IP/掩码: 如192.168.1.2/24 >> " ipmask5
    ipmask6=$ipmask5
    echo "rsync服务端允许访问本机的IP/掩码: >> $ipmask6"
    read -ep "备机服务器操作: 请输入主服务器IP进行备机服务器同步 >> " ipserver5
    ipserver6=$ipserver5
    if  test "$ipserver6" = "$ipbackup6";then
        echo "主备IP相同请重新输入>>>>>..."
        echo "备机服务器IP: >> $ipbackup6"
        read -ep "备机服务器操作: 请输入主服务器IP进行备机服务器同步 >> " ipserver5
        ipserver6=$ipserver5
        if  test "$ipserver6" = "$ipbackup6";then
            exit 0
        fi
    fi
    read -ep "备机服务器操作: 主份服务器IP是: $ipserver6 [正确 < y > ] [错误 < n > ] >> " ok5
    case $ok5 in
        [yY][eE][sS]|[yY])
        #mkdir /$rsyncd_fullback_pathname/
        echo "*/1  *  *  *  * root echo -e \`date;sh /root/runbash_crontab.sh\` >> /$rsyncd_hostback_pathname/logs/runbash_crontab.log" >> /etc/crontab
        echo "*/1  *  *  *  * root echo -e \`date;svnsync initialize --allow-non-empty svn://$ipbackup6/$the_svn_repository_name/ svn://$ipserver6/$the_svn_repository_name/ --username $the_svn_repository_admin_username --password $the_svn_repository_admin_password --steal-lock --non-interactive\` >> /$rsyncd_hostback_pathname/logs/syncinit.log" >> /etc/crontab
        echo "*/2  *  *  *  * root echo -e \`date;svnsync sync svn://$ipbackup6/$the_svn_repository_name/ --username $the_svn_repository_admin_username --password $the_svn_repository_admin_password --non-interactive --steal-lock\` >> /$rsyncd_hostback_pathname/logs/logsyncsvn.log" >> /etc/crontab
        echo "*/2  *  *  *  * root echo -e \`date;rsync -avcpogltzADHP --password-file=/$rsyncd_hostback_pathname/pw/$the_svn_repository_name.pwd $rsyncd_admin_username@$ipserver6::$the_svn_repository_name /$the_svn_repository_path/$the_svn_repository_name/conf/\` >> /$rsyncd_hostback_pathname/logs/logsvnbackup.log" >> /etc/crontab
        echo "*/2  *  *  *  * root echo -e \`date;rsync -avcpogltzADHP --password-file=/$rsyncd_hostback_pathname/pw/$the_svn_repository_name.pwd $rsyncd_admin_username@$ipserver6::$rsyncd_hostback_pathname /$rsyncd_hostback_pathname/\` >> /$rsyncd_hostback_pathname/logs/logsvnbackupall.log" >> /etc/crontab
        echo -e "uid = root\ngid = root\nuse chroot = no\nmax connections = 3\nstrict modes =yes\npid file = /var/run/rsyncd.pid\nlock file = /var/run/rsync.lock\nlog file = /var/run/rsyncd.log\nexclude = lost+found/\n#transfer logging = yes\nport = 873\ntimeout = 900\nignore nonreadable = yes\ndont compress = *.gz *.tgz *.zip *.z *.Z *.rpm *.deb *.bz2\n[$rsyncd_hostback_pathname]\npath = /$rsyncd_hostback_pathname/\n[$the_svn_repository_name]\nignore errors\npath = /$the_svn_repository_path/$the_svn_repository_name/conf/\ncomment = $the_svn_repository_name export area\nread only = no\nwrite only = no\nlist = no\nhosts allow = $ipmask6\nauth users = $rsyncd_admin_username\nsecrets file = /$rsyncd_hostback_pathname/pw/$the_svn_repository_name.passwd" > /etc/rsyncd.conf
        tail -n 4 /etc/crontab
        #Failed to get lock on destination repos, currently held by 'localhost.localdomain:7d4732d5-a0eb-4f4c-b42e-ae75b43c0f37'
        #svn pdel --revprop -r 0 --username bigonetoict --password bigonetoict svn:sync-lock file:///database/$the_svn_repository_name
        echo $?
    ;;
        [nN][oO]|[nN])
        echo "请求失败..............."
    ;;
    esac
;;
esac
echo -e "cat <<EOF\n\n\`date\` >>> rsyncd xinetd svnserve >> 定时任务即将开启> <----------The_SVN_repository$the_svn_repository_admin_username---------->\n\nEOF\n\nproc_name0=\"rsync\"\nproc_num0()\n{\n   um0=\`ps -ef | grep \$proc_name0 | grep -v grep | wc -l\`\n   return \$um0\n}\nproc_num0\nnumber0=\$?\nif [ \$number0 -eq 0 ]\nthen\n   systemctl restart rsyncd.service\nfi\nproc_name1=\"svnserve\"\nproc_num1()\n{\n   um1=\`ps -ef | grep \$proc_name1 | grep -v grep | wc -l\`\n   return \$um1\n}\nproc_num1\nnumber1=\$?\nif [ \$number1 -eq 0 ]\nthen\n   svnserve -d --listen-port 3690 -r /$the_svn_repository_path/\nfi\nproc_name2=\"xinetd\"\nproc_num2()\n{\n   um2=\`ps -ef | grep \$proc_name2 | grep -v grep | wc -l\`\n   return \$um2\n}\nproc_num2\nnumber2=\$?\nif [ \$number2 -eq 0 ]\nthen\n   systemctl restart xinetd.service\nfi\n" >> /root/runbash_crontab.sh
chmod +x /root/runbash_crontab.sh
echo $?
###
echo "<<--------------------------------------请记录下面重要信息-------------------------------------->>"
echo "----->SVN_NAME----------------------->=$the_svn_repository_name"
echo "----->SVN_PATH----------------------->=$the_svn_repository_path"
echo "----->SVN_Admin_Name----------------->=$the_svn_repository_admin_username"
echo "----->SVN_Admin_Passwd--------------->=$the_svn_repository_admin_password"
echo "----->Rsyncd_SVN_Admin_Name---------->=$rsyncd_admin_username"
echo "----->Rsyncd_SVN_Admin_Passwd-------->=$rsyncd_admin_password"
echo "----->Rsyncd_hostback_pathname------->=$rsyncd_hostback_pathname"
###写入信息到txt
echo "$the_svn_repository_name" > /$rsyncd_hostback_pathname/SVN_Name
echo "$the_svn_repository_path" > /$rsyncd_hostback_pathname/SVN_PATH
echo "$the_svn_repository_admin_username" > /$rsyncd_hostback_pathname/SVN_Admin_Name
echo "$the_svn_repository_admin_password" > /$rsyncd_hostback_pathname/SVN_Admin_Passwd
echo "$rsyncd_admin_username" > /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Name
echo "$rsyncd_admin_password" > /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Passwd
echo "$rsyncd_hostback_pathname" > /$rsyncd_hostback_pathname/Rsyncd_SVN_Back_Path
###查看输出txt
#echo "SVN_Name=`cat /$rsyncd_hostback_pathname/SVN_Name.txt`"
#echo "SVN_PATH=`cat /$rsyncd_hostback_pathname/SVN_PATH.txt`"
#echo "SVN_Admin_Name=`cat /$rsyncd_hostback_pathname/Admin_Name.txt`"
#echo "SVN_Admin_Passwd=`cat /$rsyncd_hostback_pathname/SVN_Admin_Passwd.txt`"
#echo "Rsyncd_SVN_Admin_Name=`cat /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Name.txt`"
#echo "Rsyncd_SVN_Admin_Passwd=`cat /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Passwd.txt`"
#echo "Rsyncd_SVN_Admin_Path=`cat /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Path.txt"
#echo "Rsyncd_SVN_Back_Path=`cat /$rsyncd_hostback_pathname/Rsyncd_SVN_Back_Path.txt`"
#echo "Rsyncd_SVN_Back_Path_Full=`cat /$rsyncd_hostback_pathname/Rsyncd_SVN_Back_Path_Full.txt`"
###
#安装加密并删除加密文件输出AES：
SVN_Name=`cat /$rsyncd_hostback_pathname/SVN_Name`
SVN_PATH=`cat /$rsyncd_hostback_pathname/SVN_PATH`
SVN_Admin_Name=`cat /$rsyncd_hostback_pathname/SVN_Admin_Name`
SVN_Admin_Passwd=`cat /$rsyncd_hostback_pathname/SVN_Admin_Passwd`
Rsyncd_SVN_Admin_Name=`cat /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Name`
Rsyncd_SVN_Admin_Passwd=`cat /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Passwd`
Rsyncd_SVN_Back_Path=`cat /$rsyncd_hostback_pathname/Rsyncd_SVN_Back_Path`
###
echo $SVN_Name | openssl aes-128-cbc -k 123 -base64 > /$rsyncd_hostback_pathname/SVN_Name;gzexe /$rsyncd_hostback_pathname/SVN_Name;rm -f /$rsyncd_hostback_pathname/*~
echo $SVN_PATH | openssl aes-128-cbc -k 123 -base64 > /$rsyncd_hostback_pathname/SVN_PATH;gzexe /$rsyncd_hostback_pathname/SVN_PATH;rm -f /$rsyncd_hostback_pathname/*~
echo $SVN_Admin_Name | openssl aes-128-cbc -k 123 -base64 > /$rsyncd_hostback_pathname/SVN_Admin_Name;gzexe /$rsyncd_hostback_pathname/SVN_Admin_Name;rm -f /$rsyncd_hostback_pathname/*~
echo $SVN_Admin_Passwd | openssl aes-128-cbc -k 123 -base64 > /$rsyncd_hostback_pathname/SVN_Admin_Passwd;gzexe /$rsyncd_hostback_pathname/SVN_Admin_Passwd;rm -f /$rsyncd_hostback_pathname/*~
echo $Rsyncd_SVN_Admin_Name | openssl aes-128-cbc -k 123 -base64 > /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Name;gzexe /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Name;rm -f /$rsyncd_hostback_pathname/*~
echo $Rsyncd_SVN_Admin_Passwd | openssl aes-128-cbc -k 123 -base64 > /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Passwd;gzexe /$rsyncd_hostback_pathname/Rsyncd_SVN_Admin_Passwd;rm -f /$rsyncd_hostback_pathname/*~
echo $Rsyncd_SVN_Back_Path | openssl aes-128-cbc -k 123 -base64 > /$rsyncd_hostback_pathname/Rsyncd_SVN_Back_Path;gzexe /$rsyncd_hostback_pathname/Rsyncd_SVN_Back_Path;rm -f /$rsyncd_hostback_pathname/*~
###
mkdir -p /Rsyncd_Host_Path/
echo "$rsyncd_hostback_pathname" > /Rsyncd_Host_Path/rsyncd_hostback_pathname
exit 0

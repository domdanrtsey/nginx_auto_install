#!/bin/bash
# script_name: nginx_install.sh
# Author: Danrtsey.Shun
# Email:mydefiniteaim@126.com
# auto_install_nginx version=1.19.1
#################### Upload nginx software ####################
#|     version: nginx-1.19.1       |#
#|     version: openssl-1.1.1      |#
#|     version: pcre-8.44          |#
#|     version: zlib-1.2.11        |#
#|     packages: packages_gcc      |#
#|     packages: packages_nginx    |#
#|     configfile: nginx.conf      |#
#|     script: nginx_install.sh    |#
#
#################### Install nginx software ####################
# attentions:
# 1.上传软件包/依赖包/nginx_install.sh/nginx.conf至服务器任意路径下，如 /opt
#
# 2.执行
# chmod + nginx_install.sh
# sh -x nginx_install.sh


export PATH=$PATH
#Source function library.
. /etc/init.d/functions

#Require root to run this script.
uid=`id | cut -d\( -f1 | cut -d= -f2`
if [ $uid -ne 0 ];then
  action "Please run this script as root." /bin/false
  exit 1
fi

###set firewalld & optimize the os system & set selinux
echo "################# Optimize system parameters  ##########################"
firewall_status=`systemctl status firewalld | grep Active |awk '{print $3}'`
if [ ${firewall_status} == "(running)" ];then
  firewall-cmd --permanent --zone=public --add-port=80/tcp && firewall-cmd --reload
else
  systemctl start firewalld
  firewall-cmd --permanent --zone=public --add-port=80/tcp && firewall-cmd --reload
fi

SELINUX=`cat /etc/selinux/config |grep ^SELINUX=|awk -F '=' '{print $2}'`
if [ ${SELINUX} == "enforcing" ];then
  sed -i "s@SELINUX=enforcing@SELINUX=disabled@g" /etc/selinux/config
else
  if [ ${SELINUX} == "permissive" ];then
    sed -i "s@SELINUX=permissive@SELINUX=disabled@g" /etc/selinux/config
  fi
fi
setenforce 0

###set the ip in hosts
echo "############################   Ip&Hosts Configuration  #######################################"
hostname=`hostname`
HostIP=`ip a|grep 'inet '|grep -v '127.0.0.1'|awk '{print $2}'|awk -F '/' '{print $1}'`
for i in ${HostIP}
do
    A=`grep "${i}" /etc/hosts`
    if [ ! -n "${A}" ];then
        echo "${i} ${hostname}" >> /etc/hosts 
    else
        break
    fi
done

###set the sysctl,limits and profile
echo "############################   Configure environment variables #######################################"
D=`grep 'ip_local_port_range' /etc/sysctl.conf`
if [ ! -n "${D}" ];then
cat << EOF >> /etc/sysctl.conf
fs.file-max = 6815744
net.ipv4.ip_forward = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
kernel.sysrq = 0
kernel.core_uses_pid = 1
net.ipv4.tcp_syncookies = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 262144
net.core.somaxconn = 40960
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_fin_timeout = 1
net.ipv4.tcp_keepalive_time = 30
net.ipv4.ip_local_port_range = 1024 65000
EOF
/sbin/sysctl -p
fi
E=`grep '65535' /etc/security/limits.conf`
if [ ! -n "${E}" ];then
cat << EOF >> /etc/security/limits.conf
* soft nproc 16384
* hard nproc 16384
* soft nofile 65535
* hard nofile 65535
EOF
fi

PRENAME="/usr/local"
OPENSSLPATH=${PRENAME}/openssl
PCREPATH=${PRENAME}/pcre
ZLIBPATH=${PRENAME}/zlib

echo "############################   Create Group&User  #######################################"
ng_user=nginx
ng_group=nginx
groupadd -r ${ng_group} && useradd -s /sbin/nologin -r -g ${ng_group} ${ng_user}

count=0
while [ $count -lt 3 ]
do
        read -p "Please input the NGINXPATH(e.g:/usr/local/nginx):" S1
        read -p "Please input the NGINXPATH again(/usr/local/nginx):" S2
        if [ "${S1}" == "${S2}" ];then
                export NGINXPATH=${S1}
                break
        else    
                echo "You input NGINXPATH not same."
                count=$[${count}+1]
        fi 
done
if [ ! -d ${NGINXPATH} ];then
    mkdir -pv ${NGINXPATH}/{logs,client_body,proxy,fastcgi,uwsgi,scgi}
fi
chown -R ${ng_user}:${ng_group}  ${NGINXPATH}

#------------------------------------------------OFF--VERSION------------------------------------------------------#
openssl_version=`basename openssl-*.tar.gz .tar.gz | awk -F '-' '{print$2}'`
pcre_version=`basename pcre-*.tar.gz .tar.gz | awk -F '-' '{print$2}'`
zlib_version=`basename zlib-*.tar.gz .tar.gz | awk -F '-' '{print$2}'`
nginx_version=`basename nginx-*.tar.gz .tar.gz | awk -F '-' '{print$2}'`
#------------------------------------------------ON---VERSION------------------------------------------------------#
opensslv="1.1.1g"
pcrev="8.44"
zlibv="1.2.11"
nginxv="1.19.1"
#------------------------------------------------SOFTWARE_PATH--------------------------------------------------------#
softwarepath=$(cd `dirname $0`; pwd)
gccoffpath=${softwarepath}/packages_gcc
nginxoffpath=${softwarepath}/packages_nginx

 #------------------------------------------------------GCCSTRAT----------------------------------------------------#
function environment(){
    echo "|------------------------ CHECK GCC--------------------------|"
    GCCBIN=`which gcc`
    GCCV=$(echo $GCCBIN | grep "gcc")
    if [[ "$GCCV" != "" ]]
    then
        echo "gcc was installed "
    else
        echo "install gcc starting"
        httpcode=`curl -I -m 10 -o /dev/null -s -w %{http_code}'\n' http://www.baidu.com`
        net1=$(echo $httpcode | grep "200")
        if [[ "$net1" != "" ]];then
          echo "|-----------------------[    成功    ]-----------------------|"
          echo "|-----------------------[准备联网安装]-----------------------|"
          /usr/bin/sleep 2
          yum install gcc gcc-c++ -y >/dev/null 2>&1
          gcc -v >/dev/null 2>&1
          if [[ $? -eq 0 ]]; then
            echo "gcc was on_installed successed"
          else
            echo "gcc was on_installed failed"
          exit 2
          fi
        else
          echo "|-----------------------[    失败    ]-----------------------|"
          echo "|-----------------------[检测不到网络]-----------------------|"
          echo "|-----------------------[准备离线安装]-----------------------|"
          /usr/bin/sleep 2
          gccinstall_off
        fi
    fi
}

function gccinstall_off(){
    echo "|---------------------[正在安装离线包]----------------------|"
    cd ${gccoffpath}
    rpm -ivh *.rpm --nodeps --force
    gcc -v
    if [[ $? -eq 0 ]]; then
        echo "gcc was off_installed successed"
    else
        echo "gcc was off_installed failed"
		exit 3
    fi
}
 #------------------------------------------------------GCCEND----------------------------------------------------#
 #------------------------------------------------------SSLSTRAT----------------------------------------------------#
function Openssl(){
    echo "install openssl starting"
    httpcode=`curl -I -m 10 -o /dev/null -s -w %{http_code}'\n' http://www.baidu.com`
    net1=$(echo $httpcode | grep "200")
    if [[ "$net1" != "" ]]
      then
      echo "|-----------------------[    成功    ]-----------------------|"
      echo "|-----------------------[准备联网安装]-----------------------|"
      /usr/bin/sleep 2
      yum install openssl-devel -y >/dev/null 2>&1
    else
      echo "|-----------------------[    失败    ]-----------------------|"
      echo "|-----------------------[检测不到网络]-----------------------|"
      echo "|-----------------------[准备离线安装]-----------------------|"
      /usr/bin/sleep 2
      opensslinstall_off
    fi
}

function opensslinstall_off(){
    echo "|---------------------[正在安装离线包]----------------------|"
    cd ${nginxoffpath}
	rpm -ivh *.rpm --nodeps --force
    cd ${softwarepath}
    ssl=`ls | grep openssl-*.tar.gz`
    if [[ "$ssl" != "" ]];then
      mkdir -p logs && touch logs/{openssl.log,pcre.log,zlib.log,nginx.log}
      tar -zxvf openssl-${openssl_version}.tar.gz >/dev/null 2>&1
	  cd openssl-${openssl_version}
      ./config --prefix=${OPENSSLPATH} >${softwarepath}/logs/openssl.log >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
          echo "openssl was off_configed failed"
          exit 4
        else
          make && make install >>${softwarepath}/logs/openssl.log >/dev/null 2>&1
          if [[ $? -ne 0 ]]; then
              echo "openssl was off_make_installed failed"
              exit 5
          else
             ln -s ${OPENSSLPATH}/lib/libssl.so.1.1 /usr/local/lib/
             ln -s ${OPENSSLPATH}/lib/libcrypto.so.1.1  /usr/local/lib/
             ln -s /usr/local/lib/libssl.so.1.1  /usr/lib/
             ln -s /usr/local/lib/libcrypto.so.1.1  /usr/lib/
             ln -s /usr/local/lib/libssl.so.1.1  /usr/lib64/
             ln -s /usr/local/lib/libcrypto.so.1.1  /usr/lib64/
             ${OPENSSLPATH}/bin/openssl version
             ldd ${OPENSSLPATH}/bin/openssl
             ldconfig -v
             mv /usr/bin/openssl /usr/bin/openssl.old
             ln -s ${OPENSSLPATH}/bin/openssl /usr/bin/openssl
             openssl_nowv=`openssl version |awk -F' ' '{print $2}'|awk -F'-' '{print $1}'`
             if [ "$openssl_nowv" = "$openssl_version" ];then
			   echo "openssl update successed"
			 else
			   echo "openssl update failed"
			   exit 6
			 fi
          fi
        fi
    else
      echo "please upload the openssl-*.tar.gz"
      exit 7
    fi
}
#---------------------------------------------------SSLEND---------------------------------------------------------#
#--------------------------------------------------PCRESTART-------------------------------------------------------#
function pcre(){
    echo "install pcre starting"
    httpcode=`curl -I -m 10 -o /dev/null -s -w %{http_code}'\n' http://www.baidu.com`
    net1=$(echo $httpcode | grep "200")
    if [[ "$net1" != "" ]]
      then
      echo "|-----------------------[    成功    ]-----------------------|"
      echo "|-----------------------[准备联网安装]-----------------------|"
      /usr/bin/sleep 2
      yum install pcre-devel -y >/dev/null 2>&1
    else
      echo "|-----------------------[    失败    ]-----------------------|"
      echo "|-----------------------[检测不到网络]-----------------------|"
      echo "|-----------------------[准备离线安装]-----------------------|"
      /usr/bin/sleep 2
      pcreinstall_off
    fi
}

function pcreinstall_off(){
    echo "|---------------------[正在安装离线包]----------------------|"
    cd ${softwarepath}
    pcr=`ls | grep pcre-*.tar.gz`
    if [[ "$pcr" != "" ]];then
      tar -zxvf pcre-${pcre_version}.tar.gz >/dev/null 2>&1
	  cd pcre-${pcre_version}
      ./configure >${softwarepath}/logs/pcre.log >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
          echo "pcre was off_configed failed"
          exit 8
        else
          make && make install >>${softwarepath}/logs/pcre.log
          if [[ $? -ne 0 ]]; then
              echo "pcre was off_make_installed failed"
              exit 9
          else
             echo "pcre update successed"
          fi
        fi
    else
      echo "please upload the pcre-*.tar.gz"
      exit 10
    fi
}
#----------------------------------------------------PCREEND-------------------------------------------------------#
#---------------------------------------------------STARTZLIB------------------------------------------------------#
function zlib(){
    echo "install zlib starting"
    httpcode=`curl -I -m 10 -o /dev/null -s -w %{http_code}'\n' http://www.baidu.com`
    net1=$(echo $httpcode | grep "200")
    if [[ "$net1" != "" ]]
      then
      echo "|-----------------------[    成功    ]-----------------------|"
      echo "|-----------------------[准备联网安装]-----------------------|"
      /usr/bin/sleep 2
      yum install zlib-devel -y >/dev/null 2>&1
    else
      echo "|-----------------------[    失败    ]-----------------------|"
      echo "|-----------------------[检测不到网络]-----------------------|"
      echo "|-----------------------[准备离线安装]-----------------------|"
      /usr/bin/sleep 2
      zlibinstall_off
    fi
}

function zlibinstall_off(){
    echo "|---------------------[正在安装离线包]----------------------|"
    cd ${softwarepath}
    zli=`ls | grep zlib-*.tar.gz`
    if [[ "$zli" != "" ]];then
      tar -zxvf zlib-${zlib_version}.tar.gz >/dev/null 2>&1
	  cd zlib-${zlib_version}
      ./configure >${softwarepath}/logs/zlib.log >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
          echo "zlib was off_configed failed"
          exit 11
        else
          make && make install >>${softwarepath}/logs/zlib.log
          if [[ $? -ne 0 ]]; then
              echo "zlib was off_make_installed failed"
              exit 12
          else
             echo "zlib update successed"
          fi
        fi
    else
      echo "please upload the zlib-*.tar.gz"
      exit 13
    fi
}
#----------------------------------------------------ZLIBEND-------------------------------------------------------#
#---------------------------------------------------STRATNGINX-----------------------------------------------------#
function nginx(){
    echo "install nginx dependent packages starting"
    httpcode=`curl -I -m 10 -o /dev/null -s -w %{http_code}'\n' http://www.baidu.com`
    net1=$(echo $httpcode | grep "200")
    if [[ "$net1" != "" ]]
      then
      echo "|-----------------------[    成功    ]-----------------------|"
      echo "|-----------------------[准备联网安装]-----------------------|"
      /usr/bin/sleep 2
      yum install automake autoconf libtool make wget net-tools libxslt* libxml2* gd-devel perl-devel perl-ExtUtils-Embed GeoIP \
	  GeoIP-devel GeoIP-data -y >/dev/null 2>&1
      if [[ $? -eq 0 ]];then
        cd ${softwarepath}
        ngin=`ls | grep nginx-*.tar.gz`
        if [[ "$ngin" != "" ]];then
          tar -zxvf nginx-${nginx_version}.tar.gz >/dev/null 2>&1
	      cd nginx-${nginx_version}
      ./configure --prefix=${NGINXPATH} --pid-path=${NGINXPATH}/logs/nginx.pid  --user=${ng_user} --group=${ng_group} \
	  --with-http_ssl_module --with-http_v2_module --with-http_dav_module --with-http_flv_module --with-http_realip_module \
	  --with-http_addition_module --with-http_xslt_module --with-http_stub_status_module --with-http_sub_module \
	  --with-http_random_index_module --with-http_degradation_module --with-http_secure_link_module --with-http_gzip_static_module \
	  --with-http_perl_module --with-debug --with-file-aio --with-mail --with-mail_ssl_module \
	  --http-client-body-temp-path=${NGINXPATH}/client_body --http-proxy-temp-path=${NGINXPATH}/proxy \
	  --http-fastcgi-temp-path=${NGINXPATH}/fastcgi --http-uwsgi-temp-path=${NGINXPATH}/uwsgi --http-scgi-temp-path=${NGINXPATH}/scgi \
	  --with-stream --with-ld-opt="-Wl,-E"
          if [[ $? -ne 0 ]]; then
            echo "nginx was off_configed failed"
            exit 14
          else
            make && make install
            if [[ $? -ne 0 ]]; then
                echo "nginx was off_make_installed failed"
                exit 15
            else
               echo "nginx installed successed"
			   mkdir ${NGINXPATH}/conf/conf.d/ -p
			   \cp ${softwarepath}/nginx.conf ${NGINXPATH}/conf/
			   sed -i "s!/usr/local/nginx!${NGINXPATH}!g" ${NGINXPATH}/conf/nginx.conf
            fi
          fi
        else
          echo "please upload the nginx-*.tar.gz"
		  exit 16
        fi
      else
        echo "yum install failed"
        exit 17
      fi
    else
      echo "|-----------------------[    失败    ]-----------------------|"
      echo "|-----------------------[检测不到网络]-----------------------|"
      echo "|-----------------------[准备离线安装]-----------------------|"
      /usr/bin/sleep 2
      nginxinstall_off
    fi
}

function nginxinstall_off(){
    echo "|---------------------[正在安装离线包]----------------------|"
    cd ${softwarepath}
    ngin=`ls | grep nginx-*.tar.gz`
    if [[ "$ngin" != "" ]];then
      tar -zxvf nginx-${nginx_version}.tar.gz >/dev/null 2>&1
	  cd nginx-${nginx_version}
      ./configure --prefix=${NGINXPATH} --pid-path=${NGINXPATH}/logs/nginx.pid  --user=${ng_user} --group=${ng_group} \
	  --with-http_ssl_module --with-http_v2_module --with-http_dav_module --with-http_flv_module --with-http_realip_module \
	  --with-http_addition_module --with-http_xslt_module --with-http_stub_status_module --with-http_sub_module \
	  --with-http_random_index_module --with-http_degradation_module --with-http_secure_link_module --with-http_gzip_static_module \
	  --with-http_perl_module --with-pcre=${softwarepath}/pcre-${pcre_version} --with-zlib=${softwarepath}/zlib-${zlib_version} \
	  --with-openssl=${softwarepath}/openssl-${openssl_version} --with-debug --with-file-aio --with-mail --with-mail_ssl_module \
	  --http-client-body-temp-path=${NGINXPATH}/client_body --http-proxy-temp-path=${NGINXPATH}/proxy \
	  --http-fastcgi-temp-path=${NGINXPATH}/fastcgi --http-uwsgi-temp-path=${NGINXPATH}/uwsgi --http-scgi-temp-path=${NGINXPATH}/scgi \
	  --with-stream --with-ld-opt="-Wl,-E" >${softwarepath}/logs/nginx.log >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
          echo "nginx was off_configed failed"
          exit 18
        else
          make && make install >>${softwarepath}/logs/nginx.log
          if [[ $? -ne 0 ]]; then
              echo "nginx was off_make_installed failed"
              exit 19
          else
             echo "nginx installed successed"
			 mkdir ${NGINXPATH}/conf/conf.d/ -p
			 \cp ${softwarepath}/nginx.conf ${NGINXPATH}/conf/
             sed -i "s!/usr/local/nginx!${NGINXPATH}!g" ${NGINXPATH}/conf/nginx.conf
          fi
        fi
    else
      echo "please upload the nginx-*.tar.gz"
      exit 20
    fi
}

function ng_service(){
echo "############################   nginx sys_service  #######################################"
cat >/etc/systemd/system/nginx.service <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target

[Service]
Type=forking
PIDFile=${NGINXPATH}/logs/nginx.pid
ExecStart=${NGINXPATH}/sbin/nginx -c ${NGINXPATH}/conf/nginx.conf
ExecReload=${NGINXPATH}/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=false

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable nginx
systemctl start nginx
if [ $? -ne 0 ];then
  action "nginx service start failed." /bin/false
  exit 21
fi

systemctl stop nginx
if [ $? -ne 0 ];then
  action "nginx service stop failed." /bin/false
  exit 22
fi

systemctl restart nginx
if [ $? -ne 0 ];then
  action "nginx service restart failed." /bin/false
  exit 23
fi
ps -ef|grep nginx
}

#----------------------------------------------------NGINXEND-------------------------------------------------------#
function ok(){
echo "|****************************************************************************************************************|"
echo "|            WW             WW EEEEEEE LL     CCCCC   OOOOOO      MM      MM     EEEEEEE                         |"
echo "|             WW    WWWW   WW  EE      LL    CC      OO    OO    MMMM    MMMM    EE                              |"
echo "|              WW  WW WW  WW   EEEEE   LL   CC      OO      OO  MM  MM  MM  MM   EEEEE                           |"
echo "|               WW W   W WW    EE      LL    CC      OO    OO  MM    M M     MM  EE                              |"
echo "|                WW     WW     EEEEEEE LLLLLL CCCCC   OOOOOO  MM     MMM      MM EEEEEEE                         |"
echo "|****************************************************************************************************************|"
}

function main(){
environment
Openssl
pcre
zlib
nginx
ng_service
ok
}
main
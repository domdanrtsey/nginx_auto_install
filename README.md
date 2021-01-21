### nginx 自动化安装脚本

#### 脚本使用安装前配置

> 需要使用root用户执行
> 下载脚本：https://github.com/domdanrtsey/nginx_auto_install/tree/master

1. **请注意：**本脚是在Centos7.X上做测试，其他版本的操作系统可能不适合

2. 安装前请将`packages_nginx`依赖包、`packages_gcc`依赖包、`nginx_install.sh`安装脚本、`nginx.conf`配置文件、`nginx-1.19.1.tar.gz`、`openssl-1.1.1g.tar.gz`、`pcre-8.44.tar.gz`、`zlib-1.2.11.tar.gz`软件安装包全数放置在 /opt/ 目录下（可根据情况随意存储）

3. 脚本默认开启80端口，如果不需要开启防火墙，请在以下代码段前添加`#`号注释

   ```shell
   firewall_status=`systemctl status firewalld | grep Active |awk '{print $3}'`
   if [ ${firewall_status} == "(running)" ];then
     firewall-cmd --permanent --zone=public --add-port=80/tcp && firewall-cmd --reload
   else
     systemctl start firewalld
     firewall-cmd --permanent --zone=public --add-port=80/tcp && firewall-cmd --reload
   fi
   ```

   

5. 软件运行用户与组是`middle`，如果需要使用其他用户我中，请注意修改

   ```shell
   ng_user=nginx
   ng_group=nginx
   ```

   

6. 脚本自行判断连接`curl -I -m 10 -o /dev/null -s -w %{http_code}'\n' http://www.baidu.com`是否返回200，返回200表示有网络，将使用`yum`安装相关依赖，否则为无网络情况，使用`rpm`安装所需依赖包（在无网络条件时，请切记上传`packages_nginx`、`packages_gcc`、`openssl-1.1.1g.tar.gz`、`pcre-8.44.tar.gz`、`zlib-1.2.11.tar.gz`否则脚本将无法自动安装自动安装部署）

7. 脚本提示软件的安装路径是`/usr/local`，请根据实际情况填写，如`/data`、`/app`、`/home/app/`等

   ```shell
   脚本执行提示如下:
   read -p "Please input the NGINXPATH(e.g:/usr/local/nginxnginx):" S1
   Please input the NGINXPATH(/usr/local/nginx):
   ```

   

#### 支持系统

- CentOS 7.x 64

> 脚本已经配置`nginx`服务自启动，并配置为系统服务，启动与停止时使用`root`用户操作
```shell
停止
# systemctl stop nginx
启动
# systemctl start nginx
```
> 熟知以上说明之后，开始操作安装部署

```shell
# chmod + nginx_install.sh
# sh -x nginx_install.sh
```

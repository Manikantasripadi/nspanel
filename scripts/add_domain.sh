#!/bin/bash
# Copyright (C) 2019 - 2020 Neoistone <support@neoistone.com>
# 
# This file is part of the NSPANEL script.
#
# NSPANEL is a powerful contorlpanel for the installation of 
# Apache + PHP + MySQL/MariaDB/ + Email Server + NSVRITUAL contorl panel .
# And all things will be done in a few minutes.
#
#
# This program is free software; you can't redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free Software
# Foundation; either version 3.0 of the License, or (at your option) any later
# version.
#
# NEOISTONE is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with NEOISTONE; if not, see <http://www.gnu.org/licenses/>.

# NEOISTONE(NSPANEL) is an open source conferencing system.  For more information see
#    http://www.neoistone.com/.
#
# This adddomain.sh script automates many of the installation and configuration
# steps at
#    http://www.neoistone.com/nspanel/installtion

# System Required:  Centos7-8 or rhel7-8
# Description:  Install LAMP(Linux + pache + PHP + MySQL/MariaDB/ + Email Server + NSVRITUAL contorl panel )
# Website:  https://www.neoistone.com
# Github:   https://github.com/neoistone/lempp

webserver="/etc/neoistone"
user="neoistone"
document_root="/var/www/vhosts"

_red(){
    printf '\033[1;31;31m%b\033[0m' "$1"
    printf "\n"
}

_green(){
    printf '\033[1;31;32m%b\033[0m' "$1"
}

_yellow(){
    printf '\033[1;31;33m%b\033[0m' "$1"
    printf "\n"
}

_printargs(){
    printf -- "%s" "$1"
    printf "\n"
}

_info(){
    _printargs "$@"
}

_error(){
    _red "$1"
    exit 
}

if [ "${1}" == "" ]; then
	while true; do
	   read -e -p "Enter your domain name : " domain
	   if [ "${domain}" == "" ]; then
	   	   exit;
	   	else 
	   	 break;
	   fi
	done
else 
	domain=${1}
fi

if [ -e /usr/bin/openssl ]; then
	break;
else
	yum install -y openssl openssl-dev
fi

if [ "${2}" == "" ]; then
	while true; do
	   read -e -p "Enter your Email Adress : " adder
	   if [ "${adder}" == "" ]; then
	   	   exit;
	   	else 
	   	 break;
	   fi
	done
else 
	adder=${2}
fi

if [ -e ${webserver}/conf.d/${domain}.conf ]; then
	 _error "Already have virtual file exist "
	 exit;
fi

domain_ip=`php -er "echo gethostbyname('${domain}');";`
server_ip=`curl cpanel.net/showip.cgi`
if [ "${domain_ip}" == "${server_ip}" ]; then
	break;
else
	_error "domain not pointed this server $domain (${domain_ip}) need this ip ${server_ip}"
	exit;
fi

mkdir ${document_root}/${domain}
chmod 0755 ${document_root}/${domain}
chown ${user}:${user} ${document_root}/${domain}

mkdir ${document_root}/${domain}/public_html
chmod 0755 ${document_root}/${domain}/public_html
chown ${user}:${user} ${document_root}/${domain}/public_html


mkdir ${document_root}/${domain}/ssl
chmod 0755 ${document_root}/${domain}/ssl
chown ${user}:${user} ${document_root}/${domain}/ssl

mkdir ${document_root}/${domain}/log
chmod 0755 ${document_root}/${domain}/log
chown ${user}:${user} ${document_root}/${domain}/log

mkdir ${document_root}/${domain}/tmp
chmod 0755 ${document_root}/${domain}/tmp
chown ${user}:${user} ${document_root}/${domain}/tmp

cat <<EFO>> ${document_root}/${domain}/.contactaddress
${adder}
EFO

cat <<EFO>> ${webserver}/conf.d/${domain}.conf
server {
    listen       80;
    server_name  ${domain} www.${domain} mail.${domain};
    root  ${document_root}/${domain}/public_html;
    access_log  ${document_root}/${domain}/log/host.access.log  main;

    index index.php  index.html index.htm index.cgi index.php7 home.htm home.html home.php home.php7 home.cgi;

    error_page 404 ${document_root}/${domain}/public_html/404.html;
    error_page 500 502 503 504 /var/www/html/50x.html;
    location = /50x.html {
        root ${document_root}/${domain}/public_html;
    }

    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    location ~ \.php\$ {
        root           ${document_root}/${domain}/public_html;
        fastcgi_pass unix:/var/run/php-fpm/php-fpm.sock;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
        include        fastcgi_params;
    }
}

## ssl 

server {
    listen   443 http2 ssl;
    server_name  ${domain} www.${domain} mail.${domain};
    access_log  ${document_root}/${domain}/log/host.access.log  main;
    #ssl configs

    ssl_certificate ${document_root}/${domain}/ssl/${domain}.crt;
    ssl_certificate_key ${document_root}/${domain}/ssl/${domain}.key;
    ssl_trusted_certificate ${document_root}/${domain}/ssl/${domain}.ca;

    location / {
        root   ${document_root}/${domain}/public_html;
        index index.php  index.html index.htm index.cgi index.php7 home.htm home.html home.php home.php7 home.cgi;
    }
    error_page  404              /404.html;
    location = /404.html {
        root   ${document_root}/${domain}/public_html;
    }
    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   ${document_root}/${domain}/public_html;
    }
    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    location ~ \.php\$ {
        root           ${document_root}/${domain}/public_html;
        fastcgi_pass unix:/var/run/php-fpm/php-fpm.sock;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
        include        fastcgi_params;
    }
}

EFO

## ssl genrate
openssl genrsa -out ${document_root}/${domain}/tmp/rootCA.key 4096
openssl req -x509 -new -nodes -key ${document_root}/${domain}/tmp/rootCA.key -sha256 -days 5000 -out ${document_root}/${domain}/tmp/rootCA.crt -subj "/C=IN/ST=TG/O=neoistone./CN=neoistone.com"
openssl genrsa -out ${document_root}/${domain}/tmp/${domain}.key 2048
openssl req -new -sha256 -key ${document_root}/${domain}/tmp/${domain}.key -subj "/C=IN/ST=TG/O=Neoistone/CN=${domain}" -out ${document_root}/${domain}/tmp/${domain}.csr
openssl x509 -req -in ${document_root}/${domain}/tmp/${domain}.csr -CA ${document_root}/${domain}/tmp/rootCA.crt -CAkey ${document_root}/${domain}/tmp/rootCA.key -CAcreateserial -out ${document_root}/${domain}/ssl/${domain}.crt -days 5000 -sha256

mv ${document_root}/${domain}/tmp/${domain}.key ${document_root}/${domain}/ssl/${domain}.key
mv ${document_root}/${domain}/tmp/rootCA.crt ${document_root}/${domain}/ssl/${domain}.ca
rm -rf ${document_root}/${domain}/tmp/*
#restart neoistone
systemctl restart neoistone
rm -rf ${document_root}/*.srl

if [ "${3}" == "" ]; then
	while true; do
    read -e -p "Would you like to Install Wordpress (y/n)? " yn
      case $yn in
          [Yy]* ) wp=0 break;;
          [Nn]* ) wp=1;
      esac
    done
else
	case ${3} in
          [Yy]* ) wp=0 break;;
          [Nn]* ) wp=1 ;;
          [*]* ) wp=1;
      esac
fi

if [ "${wp}" == "0" ]; then
	dbname=`strings /dev/urandom | grep -o '[[:alnum:]]' | head -n 30 | tr -d '\n'; echo`
    mysqlpwd=`strings /dev/urandom | grep -o '[[:alnum:]]' | head -n 30 | tr -d '\n'; echo`
    wget https://wordpress.org/latest.zip -P ${document_root}/${domain}/tmp
    unzip ${document_root}/${domain}/tmp/latest.zip -d ${document_root}/${domain}/tmp
    if [ -e /bin/perl ]; then
    	 break;
    else
    	yum install -y perl
    fi
    mv ${document_root}/${domain}/tmp/wordpress/wp-config-sample.php ${document_root}/${domain}/tmp/wordpress/wp-config.php
    mysqlroot_passwd=`/opt/sneoistone`
    mysql -uroot -p${mysqlroot_passwd} <<EOF
      CREATE DATABASE IF NOT EXISTS \`${dbname}\` CHARACTER SET utf8 COLLATE utf8_general_ci;
      GRANT ALL PRIVILEGES ON \`${dbname}\` . * TO '${dbname}'@'localhost' IDENTIFIED BY '${mysqlpwd}';
      FLUSH PRIVILEGES;
EOF
#set database details with perl find and replace
perl -pi -e "s/database_name_here/$dbname/g" ${document_root}/${domain}/tmp/wordpress/wp-config.php
perl -pi -e "s/username_here/$dbname/g" ${document_root}/${domain}/tmp/wordpress/wp-config.php
perl -pi -e "s/password_here/$mysqlpwd/g" ${document_root}/${domain}/tmp/wordpress/wp-config.php
#set WP salts
perl -i -pe'
  BEGIN {
    @chars = ("a" .. "z", "A" .. "Z", 0 .. 9);
    push @chars, split //, "!@#$%^&*()-_ []{}<>~\`+=,.;:/?|";
    sub salt { join "", map $chars[ rand @chars ], 1 .. 64 }
  }
  s/put your unique phrase here/salt()/ge
' ${document_root}/${domain}/tmp/wordpress/wp-config.php
mv ${document_root}/${domain}/tmp/wordpress/*  ${document_root}/${domain}/public_html
rm -rf ${document_root}/${domain}/tmp/wordpress
rm -rf ${document_root}/${domain}/tmp/latest.zip

else
 exit;	
fi

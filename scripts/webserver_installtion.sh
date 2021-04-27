runpath=`pwd`
wget https://raw.githubusercontent.com/neoistone/lempp/main/servers/neoistone.zip
unzip neoistone.zip
cd neoistone
useradd --system --home /var/cache/neoistone --shell /sbin/nologin --comment "neoistone user" --user-group neoistone
useradd neoistone
dir="/etc/neoistone"
[ -z "${1}" ] && dir="/etc/neoistone" || dir=${1}
if [[ -e ${dir} ]]; then
    echo "Already install in this server start service or uninstall webserver"
    break;
else
    mkdir ${dir}
fi
yum install -y zip unzip zlib zlib-devel pcre openssl-devel openssl perl cmake make curl wget apr gcc git tree gcc-c++ bison screen gc gcc++ nano perl-devel perl-ExtUtils-Embed libxslt libxslt-devel libxml2 libxml2-devel gd gd-devel GeoIP GeoIP-devel pcre-devel
mkdir /opt/neoistone
mkdir /opt/neoistone/pid/
mkdir ${dir}
mkdir ${dir}/modules
mkdir /etc/ssl/neoistone
mkdir /etc/ssl/nspanel
mkdir /etc/neoistone/logs
echo "install neoistone"
./configure --prefix=${dir} \
            --sbin-path=/bin/neoistone \
            --modules-path=${dir}/modules \
            --conf-path=${dir}/neoistone.conf \
            --error-log-path=/var/log/neoistone/error.log \
            --pid-path=/opt/neoistone/pid/neoistone.pid \
            --lock-path=/var/run/neoistone.lock \
            --with-pcre \
            --without-http_scgi_module \
            --without-http_uwsgi_module \
            --user=neoistone \
            --group=neoistone \
            --with-select_module \
            --with-poll_module \
            --with-threads \
            --with-file-aio \
            --with-http_ssl_module \
            --with-http_v2_module \
            --with-http_realip_module \
            --with-http_addition_module \
            --with-http_xslt_module=dynamic \
            --with-http_image_filter_module=dynamic \
            --with-http_geoip_module=dynamic \
            --with-http_sub_module \
            --with-http_dav_module \
            --with-http_flv_module \
            --with-http_mp4_module \
            --with-http_gunzip_module \
            --with-http_gzip_static_module \
            --with-http_auth_request_module \
            --with-http_random_index_module \
            --with-http_secure_link_module \
            --with-http_degradation_module \
            --with-http_slice_module \
            --with-http_stub_status_module \
            --http-log-path=/var/log/neoistone/access.log \
            --http-client-body-temp-path=/var/cache/neoistone/client_temp \
            --http-proxy-temp-path=/var/cache/neoistone/proxy_temp \
            --http-fastcgi-temp-path=/var/cache/neoistone/fastcgi_temp \
            --http-uwsgi-temp-path=/var/cache/neoistone/uwsgi_temp \
            --http-scgi-temp-path=/var/cache/neoistone/scgi_temp \
            --with-mail=dynamic \
            --with-mail_ssl_module \
            --with-stream=dynamic \
            --with-stream_ssl_module \
            --with-stream_realip_module \
            --with-stream_geoip_module=dynamic \
            --with-stream_ssl_preread_module \
            --with-compat \
            --with-openssl-opt=no-nextprotoneg \
            --with-debug
make && make install
mkdir /var/cache/neoistone/ /var/log/neoistone/ /var/cache/neoistone/uwsgi_temp /var/cache/neoistone/fastcgi_temp /var/cache/neoistone/scgi_temp
echo "unwanted file removing"
rm -rf ${dir}/nginx.conf.default ${dir}/mime.types.default ${dir}/uwsgi_params.default ${dir}/scgi_params.default ${dir}/fastcgi_params.default ${dir}/fastcgi.conf.default

chmod +x /bin/neoistone
echo "unwanted file removing"
rm -rf /var/www/html
mv ${dir}/html /var/www/html
rm -rf ${dir}/html
rm -rf ${dir}/neoistone.conf
rm -rf ${dir}/fastcgi.conf
rm -rf ${dir}/mime.types
rm -rf ${dir}/proxy.conf
echo "writing configure fastcgi file"
cat <<EFO>> ${dir}/fastcgi.conf
#copyright resverd by nginx
#modify neoistone
#nginx some change do this webserver 
#neoistone version 0.0.2
fastcgi_param  SCRIPT_FILENAME    \$document_root\$fastcgi_script_name;
fastcgi_param  QUERY_STRING       \$query_string;
fastcgi_param  REQUEST_METHOD     \$request_method;
fastcgi_param  CONTENT_TYPE       \$content_type;
fastcgi_param  CONTENT_LENGTH     \$content_length;
fastcgi_param  SCRIPT_NAME        \$fastcgi_script_name;
fastcgi_param  REQUEST_URI        \$request_uri;
fastcgi_param  DOCUMENT_URI       \$document_uri;
fastcgi_param  DOCUMENT_ROOT      \$document_root;
fastcgi_param  SERVER_PROTOCOL    \$server_protocol;
fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/\$nginx_version;
fastcgi_param  REMOTE_ADDR        \$remote_addr;
fastcgi_param  REMOTE_PORT        \$remote_port;
fastcgi_param  SERVER_ADDR        \$server_addr;
fastcgi_param  SERVER_PORT        \$server_port;
fastcgi_param  SERVER_NAME        \$server_name;
fastcgi_index  index.php;
fastcgi_param  REDIRECT_STATUS    200;
EFO
echo "writing configure mime file"
cat <<EFO>> ${dir}/mime.types
#copyright resverd by nginx
#modify neoistone
#nginx some change do this webserver 
#neoistone version 0.0.2
types {
  text/html                             html htm shtml;
  text/ns                               ns;
  text/css                              css;
  text/xml                              xml rss;
  image/gif                             gif;
  image/jpeg                            jpeg jpg;
  application/x-javascript              js;
  text/plain                            txt;
  text/x-component                      htc;
  text/mathml                           mml;
  image/png                             png;
  image/x-icon                          ico;
  image/x-jng                           jng;
  image/vnd.wap.wbmp                    wbmp;
  application/java-archive              jar war ear;
  application/mac-binhex40              hqx;
  application/pdf                       pdf;
  application/x-cocoa                   cco;
  application/x-java-archive-diff       jardiff;
  application/x-java-jnlp-file          jnlp;
  application/x-makeself                run;
  application/x-perl                    pl pm;
  application/x-pilot                   prc pdb;
  application/x-rar-compressed          rar;
  application/x-redhat-package-manager  rpm;
  application/x-sea                     sea;
  application/x-shockwave-flash         swf;
  application/x-stuffit                 sit;
  application/x-tcl                     tcl tk;
  application/x-x509-ca-cert            der pem crt;
  application/x-xpinstall               xpi;
  application/zip                       zip;
  application/octet-stream              deb;
  application/octet-stream              bin exe dll;
  application/octet-stream              dmg;
  application/octet-stream              eot;
  application/octet-stream              iso img;
  application/octet-stream              msi msp msm;
  audio/mpeg                            mp3;
  audio/x-realaudio                     ra;
  video/mpeg                            mpeg mpg;
  video/quicktime                       mov;
  video/x-flv                           flv;
  video/x-msvideo                       avi;
  video/x-ms-wmv                        wmv;
  video/x-ms-asf                        asx asf;
  video/x-mng                           mng;
}
EFO
echo "writing configure proxy file"
cat <<EFO>> ${dir}/proxy.conf
#copyright resverd by nginx
#modify neoistone
#nginx some change do this webserver 
#neoistone version 0.0.2
proxy_redirect          off;
proxy_set_header        Host            \$host;
proxy_set_header        X-Real-IP       \$remote_addr;
proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
client_max_body_size    1024m;
client_body_buffer_size 128k;
proxy_connect_timeout   90;
proxy_send_timeout      90;
proxy_read_timeout      90;
proxy_buffers           32 4k;
EFO
echo "writing configure file"
cat <<EFO>> ${dir}/neoistone.conf
#copyright resverd by nginx
#modify neoistone
#this nginx webserver but some optimization php reduce the server response
#neoistone version 0.0.2
user  neoistone;
error_log  logs/error.log;
pid        logs/neoistone.pid;
worker_processes auto;
worker_rlimit_nofile 65535;
events {
    multi_accept on;
    use epoll;
    worker_connections 65535;
}
http {
    include    mime.types;
    include    proxy.conf;
    include    fastcgi.conf;
    default_type  application/octet-stream;
    index    index.htm index.html index.php index.php7 home.php home.php7 home.html home.htm home.cgi index.cgi;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';
   
    access_log  logs/access.log  main;
    charset     utf-8;
    sendfile    on;
    tcp_nopush  on;
    tcp_nodelay          on;
    types_hash_max_size  2048;
    server_names_hash_bucket_size 1024;
    client_body_timeout            30s; # Use 5s for high-traffic sites
    client_header_timeout          30s; # Use 5s for high-traffic sites
    open_file_cache                max=200000 inactive=20s;
    open_file_cache_errors         on;
    open_file_cache_min_uses       2;
    open_file_cache_valid          30s;
    port_in_redirect               off;
    reset_timedout_connection      on;
    server_name_in_redirect        off;
    server_names_hash_max_size     1024;
    server_tokens                  off;
    # Limits
    limit_req_log_level  warn;
    limit_req_zone       \$binary_remote_addr zone=login:10m rate=10r/m;
    # SSL
    ssl_session_timeout  1d;
    ssl_session_cache    shared:SSL:10m;
    ssl_session_tickets  off;
    keepalive_timeout  65;
    # gzip
    gzip              on;
    gzip_vary         on;
    gzip_proxied      any;
    gzip_comp_level   6;
    gzip_types        text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;
    # Mozilla Intermediate configuration
    ssl_protocols        TLSv1.2 TLSv1.3;
    ssl_ciphers          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    # OCSP Stapling
    ssl_stapling         on;
    ssl_stapling_verify  on;
    resolver             1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 208.67.222.222 208.67.220.220 8.26.56.26 valid=60s;
    resolver_timeout     2s;
    # security headers
     add_header X-Frame-Options           "SAMEORIGIN" always;
     add_header X-XSS-Protection          "1; mode=block" always;
     add_header X-Content-Type-Options    "nosniff" always;
     add_header Referrer-Policy           "no-referrer-when-downgrade" always;
     add_header Content-Security-Policy   "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
     add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
     add_header X-Nginx-Cache-Status     \$upstream_cache_status;
    
    include    conf.d/*.conf;
    #thank you using neoistone control panel 
}
EFO
echo "writing root file"
sys_hostname=`hostname`
mkdir /etc/ssl/neoistone
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/neoistone/neoistone.key -out /etc/ssl/neoistone/neoistone.crt \
            -subj "/C=IN/ST=NONE/L=NONE/O=NEOISTONE/OU=NONE/CN=${sys_hostnamw}/emailAddress=webmaster@${sys_hostnamw}"
mkdir ${dir}/conf.d/
cat <<EFO>> ${dir}/conf.d/root.conf
server {
    listen       80;
    server_name  localhost;
    root  /var/www/html;
    
    index index.php  index.html index.htm neoistone.php;
    error_page 404 /var/www/html/404.html;
    error_page 500 502 503 504 /var/www/html/50x.html;
    location = /50x.html {
        root /var/www/html;
    }
}
server {
    listen   443 http2 ssl;
    server_name  _ ;
    access_log  /var/log/neoistone/host.access.log  main;
    #ssl configs
    ssl_certificate /etc/ssl/nspanel/nspanel.crt;
    ssl_certificate_key /etc/ssl/nspanel/nspanel.key;
    location / {
        root   /var/www/html;
        index index.php  index.html index.htm neoistone.php;
    }
    error_page  404              /404.html;
    location = /404.html {
        root   /var/www/html;
    }
    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /var/www/html;
    }
    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    location ~ \.php\$ {
        root           /var/www/html;
        fastcgi_pass unix:/var/run/php-fpm/php-fpm.sock;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
        include        fastcgi_params;
    }
}
EFO
mkdir /var/www
mkdir /var/www/html/
mkdir /var/www/html/.well-known
mkdir /var/www/html/.well-known/acme-challenge
if [[ -e /etc/systemd/system/neoistone.service ]]; then
  rm -rf /etc/systemd/system/neoistone.service
fi
cat <<EFO>> /etc/sysconfig/neoistone
# Command line options to use when starting nginx
#CLI_OPTIONS=""
EFO
cat <<EFO>> /etc/systemd/system/neoistone.service
[Unit]
Description=Neoistone Server Optimization Your Site
Documentation=https://www.neoistone.com
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target
[Service]
Type=forking
EnvironmentFile=/etc/sysconfig/neoistone
ExecStartPre=/bin/neoistone -t -c ${dir}/neoistone.conf
ExecStart=/bin/neoistone -c ${dir}/neoistone.conf
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s TERM \$MAINPID
[Install]
WantedBy=multi-user.target
EFO
cat <<EFO>> /opt/var
 echo ${dir}
EFO
chmod +x /opt/var
chown neoistone:neoistone /var/www/html/
yum install -y firewalld
systemctl start firewalld
systemctl enable firewalld
firewall-cmd --zone=public --add-service=http
firewall-cmd --zone=public --add-service=https
firewall-cmd --zone=public --permanent --add-service=http
firewall-cmd --zone=public --permanent --add-service=https
firewall-cmd --reload
systemctl restart neoistone
systemctl enable neoistone
rm -rf ${runpath}/neoistone 
rm -rf ${runpath}/neoistone.sh
rm -rf ${runpath}/neoistone.tar.gz

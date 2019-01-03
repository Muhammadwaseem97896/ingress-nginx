#!/bin/bash

# Copyright 2015 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -o errexit
set -o nounset
set -o pipefail

export NGINX_VERSION=1.15.8
export NDK_VERSION=0.3.1rc1
export SETMISC_VERSION=0.32
export MORE_HEADERS_VERSION=0.33
export NGINX_DIGEST_AUTH=274490cec649e7300fea97fed13d84e596bbc0ce
export NGINX_SUBSTITUTIONS=bc58cb11844bc42735bbaef7085ea86ace46d05b
export NGINX_OPENTRACING_VERSION=ea9994d7135be5ad2e3009d0f270e063b1fb3b21
export OPENTRACING_CPP_VERSION=1.5.0
export ZIPKIN_CPP_VERSION=0.5.2
export JAEGER_VERSION=ba0fa3fa6dbb01995d996f988a897e272100bf95
export MODSECURITY_VERSION=fc061a57a8b0abda79b17cbe103d78db803fa575
export LUA_NGX_VERSION=1c72f57ce87d4355d546a97c2bd8f5123a70db5c
export LUA_STREAM_NGX_VERSION=0.0.6rc2
export LUA_UPSTREAM_VERSION=0.07
export NGINX_INFLUXDB_VERSION=0e2cb6cbf850a29c81e44be9e33d9a15d45c50e8
export GEOIP2_VERSION=3.2
export NGINX_AJP_VERSION=bf6cd93f2098b59260de8d494f0f4b1f11a84627
export LUAJIT_VERSION=520d53a87dd44c637dddb6de313204211c2b212b

export BUILD_PATH=/tmp/build

ARCH=$(uname -m)

get_src()
{
  hash="$1"
  url="$2"
  f=$(basename "$url")

  curl -sSL "$url" -o "$f"
  echo "$hash  $f" | sha256sum -c - || exit 10
  tar xzf "$f"
  rm -rf "$f"
}

apt-get update && apt-get dist-upgrade -y

# install required packages to build
clean-install \
  bash \
  build-essential \
  curl ca-certificates \
  libgeoip1 \
  libgeoip-dev \
  patch \
  libpcre3 \
  libpcre3-dev \
  libssl-dev \
  zlib1g \
  zlib1g-dev \
  libaio1 \
  libaio-dev \
  openssl \
  libperl-dev \
  cmake \
  util-linux \
  lua5.1 liblua5.1-0 liblua5.1-dev \
  lmdb-utils \
  wget \
  libcurl4-openssl-dev \
  libprotobuf-dev protobuf-compiler \
  libz-dev \
  procps \
  git g++ pkgconf flex bison doxygen libyajl-dev liblmdb-dev libtool dh-autoreconf libxml2 libpcre++-dev libxml2-dev \
  lua-cjson \
  python \
  luarocks \
  libmaxminddb-dev \
  authbind \
  dumb-init \
  gdb \
  valgrind \
  bc \
  || exit 1

if [[ ${ARCH} == "x86_64" ]]; then
  ln -s /usr/lib/x86_64-linux-gnu/liblua5.1.so /usr/lib/liblua.so
  ln -s /usr/lib/x86_64-linux-gnu /usr/lib/lua-platform-path
fi

if [[ ${ARCH} == "aarch64" ]]; then
  ln -s /usr/lib/aarch64-linux-gnu/liblua5.1.so /usr/lib/liblua.so
  ln -s /usr/lib/aarch64-linux-gnu /usr/lib/lua-platform-path
fi

mkdir -p /etc/nginx

# Get the GeoIP data
GEOIP_FOLDER=/etc/nginx/geoip
mkdir -p $GEOIP_FOLDER

function geoip2_get {
  wget -O $GEOIP_FOLDER/$1.tar.gz $2 || { echo "Could not download $1, exiting." ; exit 1; }
  mkdir $GEOIP_FOLDER/$1 \
    && tar xf $GEOIP_FOLDER/$1.tar.gz -C $GEOIP_FOLDER/$1 --strip-components 1 \
    && mv $GEOIP_FOLDER/$1/$1.mmdb $GEOIP_FOLDER/$1.mmdb \
    && rm -rf $GEOIP_FOLDER/$1 \
    && rm -rf $GEOIP_FOLDER/$1.tar.gz
}

# geoip_get "GeoIPASNum.dat.gz"  "http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz"
# geoip_get "GeoIP.dat.gz"       "https://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz"
# geoip_get "GeoLiteCity.dat.gz" "https://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz"
geoip2_get "GeoLite2-Country"  "http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz"
geoip2_get "GeoLite2-City"     "http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz"
geoip2_get "GeoLite2-ASN"      "http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz"

mkdir --verbose -p "$BUILD_PATH"
cd "$BUILD_PATH"

# download, verify and extract the source files
get_src a8bdafbca87eb99813ae4fcac1ad0875bf725ce19eb265d28268c309b2b40787 \
        "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"

get_src 49f50d4cd62b166bc1aaf712febec5e028d9f187cedbc27a610dfd01bdde2d36 \
        "https://github.com/simpl/ngx_devel_kit/archive/v$NDK_VERSION.tar.gz"

get_src f1ad2459c4ee6a61771aa84f77871f4bfe42943a4aa4c30c62ba3f981f52c201 \
        "https://github.com/openresty/set-misc-nginx-module/archive/v$SETMISC_VERSION.tar.gz"

get_src a3dcbab117a9c103bc1ea5200fc00a7b7d2af97ff7fd525f16f8ac2632e30fbf \
        "https://github.com/openresty/headers-more-nginx-module/archive/v$MORE_HEADERS_VERSION.tar.gz"

get_src ede0ad490cb9dd69da348bdea2a60a4c45284c9777b2f13fa48394b6b8e7671c \
        "https://github.com/atomx/nginx-http-auth-digest/archive/$NGINX_DIGEST_AUTH.tar.gz"

get_src 618551948ab14cac51d6e4ad00452312c7b09938f59ebff4f93875013be31f2d \
        "https://github.com/yaoweibin/ngx_http_substitutions_filter_module/archive/$NGINX_SUBSTITUTIONS.tar.gz"

get_src 343b4293ca0d4afa55bf1ab54c866766043b2585b6ce81467d3d3e25987fc186 \
        "https://github.com/opentracing-contrib/nginx-opentracing/archive/$NGINX_OPENTRACING_VERSION.tar.gz"

get_src 4455ca507936bc4b658ded10a90d8ebbbd61c58f06207be565a4ffdc885687b5 \
        "https://github.com/opentracing/opentracing-cpp/archive/v$OPENTRACING_CPP_VERSION.tar.gz"

get_src 30affaf0f3a84193f7127cc0135da91773ce45d902414082273dae78914f73df \
        "https://github.com/rnburn/zipkin-cpp-opentracing/archive/v$ZIPKIN_CPP_VERSION.tar.gz"

get_src 073deba39f74eff81da917907465e1343c89b335244349d3d3b4ae9331de86f2 \
        "https://github.com/SpiderLabs/ModSecurity-nginx/archive/$MODSECURITY_VERSION.tar.gz"

get_src b68286966f292fb552511b71bd8bc11af8f12c8aa760372d1437ac8760cb2f25 \
        "https://github.com/jaegertracing/jaeger-client-cpp/archive/$JAEGER_VERSION.tar.gz"

get_src 6c8a2792222f6bfad927840bf64cb890466fcca703a0133cbde0e5b808461279 \
        "https://github.com/openresty/lua-nginx-module/archive/$LUA_NGX_VERSION.tar.gz"

get_src 5420dbf59bac52cef8021658d7eae1667a2bd14dda23602c985cae2604de77dd \
        "https://github.com/openresty/stream-lua-nginx-module/archive/v$LUA_STREAM_NGX_VERSION.tar.gz"

get_src 2a69815e4ae01aa8b170941a8e1a10b6f6a9aab699dee485d58f021dd933829a \
        "https://github.com/openresty/lua-upstream-nginx-module/archive/v$LUA_UPSTREAM_VERSION.tar.gz"

get_src 2349dd0b7ee37680306ee76bc4b6bf5c7509a4a4be16d246d9bbff44f564e4a0 \
        "https://github.com/openresty/lua-resty-lrucache/archive/v0.08.tar.gz"

get_src bc9a00f4dd6dd3928c6e878dc84fa7a1073d5a65900cd77a5c1c7ce2d863b22a \
        "https://github.com/openresty/lua-resty-core/archive/v0.1.16rc3.tar.gz"

get_src eaf84f58b43289c1c3e0442ada9ed40406357f203adc96e2091638080cb8d361 \
        "https://github.com/openresty/lua-resty-lock/archive/v0.07.tar.gz"

get_src 3917d506e2d692088f7b4035c589cc32634de4ea66e40fc51259fbae43c9258d \
        "https://github.com/hamishforbes/lua-resty-iputils/archive/v0.3.0.tar.gz"

get_src 5d16e623d17d4f42cc64ea9cfb69ca960d313e12f5d828f785dd227cc483fcbd \
        "https://github.com/openresty/lua-resty-upload/archive/v0.10.tar.gz"

get_src 4aca34f324d543754968359672dcf5f856234574ee4da360ce02c778d244572a \
        "https://github.com/openresty/lua-resty-dns/archive/v0.21.tar.gz"

get_src 095615fe94e64615c4a27f4f4475b91c047cf8d10bc2dbde8d5ba6aa625fc5ab \
        "https://github.com/openresty/lua-resty-string/archive/v0.11.tar.gz"

get_src a77bf0d7cf6a9ba017d0dc973b1a58f13e48242dd3849c5e99c07d250667c44c \
        "https://github.com/openresty/lua-resty-balancer/archive/v0.02rc4.tar.gz"

get_src d81b33129c6fb5203b571fa4d8394823bf473d8872c0357a1d0f14420b1483bd \
        "https://github.com/cloudflare/lua-resty-cookie/archive/v0.1.0.tar.gz"

get_src d04df883adb86c96a8e0fe6c404851b9c776840dbb524419c06ae3fac42c4e64 \
        "https://github.com/openresty/luajit2/archive/$LUAJIT_VERSION.tar.gz"

get_src c673fcee37c1c4794f921b6710b09e8a0e1e58117aa788f798507d033f737192 \
        "https://github.com/influxdata/nginx-influxdb-module/archive/$NGINX_INFLUXDB_VERSION.tar.gz"

get_src 15bd1005228cf2c869a6f09e8c41a6aaa6846e4936c473106786ae8ac860fab7 \
        "https://github.com/leev/ngx_http_geoip2_module/archive/$GEOIP2_VERSION.tar.gz"

get_src 5f629a50ba22347c441421091da70fdc2ac14586619934534e5a0f8a1390a950 \
        "https://github.com/yaoweibin/nginx_ajp_module/archive/$NGINX_AJP_VERSION.tar.gz"

# improve compilation times
CORES=$(($(grep -c ^processor /proc/cpuinfo) - 0))

export MAKEFLAGS=-j${CORES}
export CTEST_BUILD_FLAGS=${MAKEFLAGS}
export HUNTER_JOBS_NUMBER=${CORES}
export HUNTER_KEEP_PACKAGE_SOURCES=false
export HUNTER_USE_CACHE_SERVERS=true

# Install luajit from openresty fork
export LUAJIT_LIB=/usr/local/lib
export LUA_LIB_DIR="$LUAJIT_LIB/lua"

cd "$BUILD_PATH/luajit2-$LUAJIT_VERSION"
make CCDEBUG=-g
make install

export LUAJIT_INC=/usr/local/include/luajit-2.1

# Installing luarocks packages
if [[ ${ARCH} == "x86_64" ]]; then
  export PCRE_DIR=/usr/lib/x86_64-linux-gnu
fi

if [[ ${ARCH} == "aarch64" ]]; then
  export PCRE_DIR=/usr/lib/aarch64-linux-gnu
fi

cd "$BUILD_PATH"
luarocks install lrexlib-pcre 2.7.2-1 PCRE_LIBDIR=${PCRE_DIR}
luarocks install lua-resty-jwt 0.2.0-0

cd "$BUILD_PATH/lua-resty-core-0.1.16rc3"
make install

cd "$BUILD_PATH/lua-resty-lrucache-0.08"
make install

cd "$BUILD_PATH/lua-resty-lock-0.07"
make install

cd "$BUILD_PATH/lua-resty-iputils-0.3.0"
make install

cd "$BUILD_PATH/lua-resty-upload-0.10"
make install

cd "$BUILD_PATH/lua-resty-dns-0.21"
make install

cd "$BUILD_PATH/lua-resty-string-0.11"
make install

cd "$BUILD_PATH/lua-resty-balancer-0.02rc4"
make all
make install

cd "$BUILD_PATH/lua-resty-cookie-0.1.0"
make install

# build and install lua-resty-waf with dependencies
/install_lua_resty_waf.sh

# install openresty-gdb-utils
cd /
git clone --depth=1 https://github.com/openresty/openresty-gdb-utils.git
cat > ~/.gdbinit << EOF
directory /openresty-gdb-utils

py import sys
py sys.path.append("/openresty-gdb-utils")

source luajit20.gdb
source ngx-lua.gdb
source luajit21.py
source ngx-raw-req.py
set python print-stack full
EOF

# build opentracing lib
cd "$BUILD_PATH/opentracing-cpp-$OPENTRACING_CPP_VERSION"
mkdir .build
cd .build

cmake   -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_FLAGS="-fPIC" \
        -DBUILD_TESTING=OFF \
        -DBUILD_MOCKTRACER=OFF \
        ..

make
make install

# build jaeger lib
cd "$BUILD_PATH/jaeger-client-cpp-$JAEGER_VERSION"
sed -i 's/-Werror/-Wno-psabi/' CMakeLists.txt

cat <<EOF > export.map
{
    global:
        OpenTracingMakeTracerFactory;
    local: *;
};
EOF

mkdir .build
cd .build

cmake -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=OFF \
      -DJAEGERTRACING_BUILD_EXAMPLES=OFF \
      -DJAEGERTRACING_BUILD_CROSSDOCK=OFF \
      -DJAEGERTRACING_COVERAGE=OFF \
      -DJAEGERTRACING_PLUGIN=ON \
      -DHUNTER_CONFIGURATION_TYPES=Release \
      -DJAEGERTRACING_WITH_YAML_CPP=ON ..

make
make install

export HUNTER_INSTALL_DIR=$(cat _3rdParty/Hunter/install-root-dir) \

mv libjaegertracing_plugin.so /usr/local/lib/libjaegertracing_plugin.so

# build zipkin lib
cd "$BUILD_PATH/zipkin-cpp-opentracing-$ZIPKIN_CPP_VERSION"

cat <<EOF > export.map
{
    global:
        OpenTracingMakeTracerFactory;
    local: *;
};
EOF

mkdir .build
cd .build

cmake -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DBUILD_PLUGIN=ON \
      -DBUILD_TESTING=OFF ..

make
make install

# Get Brotli source and deps
cd "$BUILD_PATH"
git clone --depth=1 https://github.com/google/ngx_brotli.git
cd ngx_brotli
git submodule init
git submodule update

# build modsecurity library
cd "$BUILD_PATH"
git clone -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
cd ModSecurity/
git checkout 9ada0a28c8100f905014c128b0e6d11dd75ec7e5
git submodule init
git submodule update
sh build.sh
./configure --disable-doxygen-doc --disable-examples --disable-dependency-tracking
make
make install

mkdir -p /etc/nginx/modsecurity
cp modsecurity.conf-recommended /etc/nginx/modsecurity/modsecurity.conf
cp unicode.mapping /etc/nginx/modsecurity/unicode.mapping

# Download owasp modsecurity crs
cd /etc/nginx/
git clone -b v3.0/master --single-branch https://github.com/SpiderLabs/owasp-modsecurity-crs
cd owasp-modsecurity-crs
git checkout a216353c97dd6ef767a6db4dbf9b724627811c9b

mv crs-setup.conf.example crs-setup.conf
mv rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
mv rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
cd ..

# OWASP CRS v3 rules
echo "
Include /etc/nginx/owasp-modsecurity-crs/crs-setup.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-910-IP-REPUTATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-912-DOS-PROTECTION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-950-DATA-LEAKAGES.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-980-CORRELATION.conf
Include /etc/nginx/owasp-modsecurity-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
" > /etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf

# build nginx
cd "$BUILD_PATH/nginx-$NGINX_VERSION"

# apply Nginx patches
patch -p1 < /patches/openresty-ssl_cert_cb_yield.patch

WITH_FLAGS="--with-debug \
  --with-compat \
  --with-pcre-jit \
  --with-http_ssl_module \
  --with-http_stub_status_module \
  --with-http_realip_module \
  --with-http_auth_request_module \
  --with-http_addition_module \
  --with-http_dav_module \
  --with-http_geoip_module \
  --with-http_gzip_static_module \
  --with-http_sub_module \
  --with-http_v2_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-threads \
  --with-http_secure_link_module \
  --with-http_gunzip_module"

if [[ ${ARCH} != "aarch64" ]]; then
  WITH_FLAGS+=" --with-file-aio"
fi

# "Combining -flto with -g is currently experimental and expected to produce unexpected results."
# https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
CC_OPT="-g -Og -fPIE -fstack-protector-strong \
  -Wformat \
  -Werror=format-security \
  -Wno-deprecated-declarations \
  -fno-strict-aliasing \
  -D_FORTIFY_SOURCE=2 \
  --param=ssp-buffer-size=4 \
  -DTCP_FASTOPEN=23 \
  -fPIC \
  -I$HUNTER_INSTALL_DIR/include \
  -Wno-cast-function-type"

LD_OPT="-fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now -L$HUNTER_INSTALL_DIR/lib"

if [[ ${ARCH} == "x86_64" ]]; then
  CC_OPT+=' -m64 -mtune=native'
fi

WITH_MODULES="--add-module=$BUILD_PATH/ngx_devel_kit-$NDK_VERSION \
  --add-module=$BUILD_PATH/set-misc-nginx-module-$SETMISC_VERSION \
  --add-module=$BUILD_PATH/headers-more-nginx-module-$MORE_HEADERS_VERSION \
  --add-module=$BUILD_PATH/nginx-http-auth-digest-$NGINX_DIGEST_AUTH \
  --add-module=$BUILD_PATH/ngx_http_substitutions_filter_module-$NGINX_SUBSTITUTIONS \
  --add-module=$BUILD_PATH/lua-nginx-module-$LUA_NGX_VERSION \
  --add-module=$BUILD_PATH/stream-lua-nginx-module-$LUA_STREAM_NGX_VERSION \
  --add-module=$BUILD_PATH/lua-upstream-nginx-module-$LUA_UPSTREAM_VERSION \
  --add-module=$BUILD_PATH/nginx-influxdb-module-$NGINX_INFLUXDB_VERSION \
  --add-dynamic-module=$BUILD_PATH/nginx-opentracing-$NGINX_OPENTRACING_VERSION/opentracing \
  --add-dynamic-module=$BUILD_PATH/ModSecurity-nginx-$MODSECURITY_VERSION \
  --add-dynamic-module=$BUILD_PATH/ngx_http_geoip2_module-${GEOIP2_VERSION} \
  --add-module=$BUILD_PATH/nginx_ajp_module-${NGINX_AJP_VERSION} \
  --add-module=$BUILD_PATH/ngx_brotli"

./configure \
  --prefix=/usr/share/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --modules-path=/etc/nginx/modules \
  --http-log-path=/var/log/nginx/access.log \
  --error-log-path=/var/log/nginx/error.log \
  --lock-path=/var/lock/nginx.lock \
  --pid-path=/run/nginx.pid \
  --http-client-body-temp-path=/var/lib/nginx/body \
  --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
  --http-proxy-temp-path=/var/lib/nginx/proxy \
  --http-scgi-temp-path=/var/lib/nginx/scgi \
  --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
  ${WITH_FLAGS} \
  --without-mail_pop3_module \
  --without-mail_smtp_module \
  --without-mail_imap_module \
  --without-http_uwsgi_module \
  --without-http_scgi_module \
  --with-cc-opt="${CC_OPT}" \
  --with-ld-opt="${LD_OPT}" \
  --user=www-data \
  --group=www-data \
  ${WITH_MODULES}

make || exit 1
make install || exit 1

echo "Cleaning..."

cd /

mv /usr/share/nginx/sbin/nginx /usr/sbin

apt-mark unmarkauto \
  bash \
  curl ca-certificates \
  libgeoip1 \
  libpcre3 \
  zlib1g \
  libaio1 \
  gdb \
  geoip-bin \
  libyajl2 liblmdb0 libxml2 libpcre++ \
  gzip \
  openssl

apt-get remove -y --purge \
  build-essential \
  libgeoip-dev \
  libpcre3-dev \
  libssl-dev \
  zlib1g-dev \
  libaio-dev \
  linux-libc-dev \
  cmake \
  wget \
  patch \
  protobuf-compiler \
  python \
  xz-utils \
  bc \
  git g++ pkgconf flex bison doxygen libyajl-dev liblmdb-dev libgeoip-dev libtool dh-autoreconf libpcre++-dev libxml2-dev

apt-get autoremove -y

rm -rf "$BUILD_PATH"
rm -Rf /usr/share/man /usr/share/doc
rm -rf /tmp/* /var/tmp/*
rm -rf /var/lib/apt/lists/*
rm -rf /var/cache/apt/archives/*
rm -rf /usr/local/modsecurity/bin
rm -rf /usr/local/modsecurity/include
rm -rf /usr/local/modsecurity/lib/libmodsecurity.a

rm -rf /root/.cache

rm -rf /etc/nginx/owasp-modsecurity-crs/.git
rm -rf /etc/nginx/owasp-modsecurity-crs/util/regression-tests

rm -rf $HOME/.hunter

# move geoip directory
mv /geoip/* /etc/nginx/geoip
rm -rf /geoip

# update image permissions
writeDirs=( \
  /etc/nginx \
  /var/lib/nginx \
  /var/log/nginx \
  /opt/modsecurity/var/log \
  /opt/modsecurity/var/upload \
  /opt/modsecurity/var/audit \
);

for dir in "${writeDirs[@]}"; do
  mkdir -p ${dir};
  chown -R www-data.www-data ${dir};
done

for value in {1..1023};do
  touch /etc/authbind/byport/$value
  chown www-data /etc/authbind/byport/$value
  chmod 755 /etc/authbind/byport/$value
done

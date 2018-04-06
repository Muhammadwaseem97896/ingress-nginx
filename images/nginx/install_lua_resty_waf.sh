#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

# build and install lua-resty-waf
cd "$BUILD_PATH"
git clone --recursive --single-branch -b v0.11.1 https://github.com/p0pr0ck5/lua-resty-waf
cd lua-resty-waf
make
make install-check
# we can not use "make install" directly here because it also calls "install-deps" which requires OPM
# to avoid that we install the libraries "install-deps" would install manually
cd "$BUILD_PATH/lua-resty-iputils-0.3.0"
make install
# this library's latest version is not released therefore cloning directly
git clone -b master --single-branch https://github.com/cloudflare/lua-resty-cookie.git "$BUILD_PATH/lua-resty-cookie"
cd "$BUILD_PATH/lua-resty-cookie"
make install
# this library's latest version is not released therefore cloning directly
git clone -b master --single-branch https://github.com/p0pr0ck5/lua-ffi-libinjection.git "$BUILD_PATH/lua-ffi-libinjection"
cd "$BUILD_PATH/lua-ffi-libinjection"
install lib/resty/*.lua "$LUA_LIB_DIR/resty/"
# this library's latest version is not released therefore cloning directly
git clone -b master --single-branch https://github.com/cloudflare/lua-resty-logger-socket.git "$BUILD_PATH/lua-resty-logger-socket"
cd "$BUILD_PATH/lua-resty-logger-socket"
install -d "$LUA_LIB_DIR/resty/logger"
install lib/resty/logger/*.lua "$LUA_LIB_DIR/resty/logger/"
# and do the rest of what "make instal" does
cd "$BUILD_PATH/lua-resty-waf"
install -d "$LUA_LIB_DIR/resty/waf/storage"
install -d "$LUA_LIB_DIR/rules"
install -m 644 lib/resty/*.lua "$LUA_LIB_DIR/resty/"
install -m 644 lib/resty/waf/*.lua "$LUA_LIB_DIR/resty/waf/"
install -m 644 lib/resty/waf/storage/*.lua "$LUA_LIB_DIR/resty/waf/storage/"
install -m 644 lib/*.so $LUA_LIB_DIR
install -m 644 rules/*.json "$LUA_LIB_DIR/rules/"

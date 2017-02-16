#!/bin/bash

LIBRESSL_VERSION="2.5.1"
LIBRESSL_SHA256="f71ae0a824b78fb1a47ffa23c9c26e9d96c5c9b29234eacedce6b4c7740287cd"

PCRE_VERSION="8.40"
PCRE_SHA256="00e27a29ead4267e3de8111fcaa59b132d0533cdfdbdddf4b0604279acbcf4f4"

LIBSLZ_VERSION="v1.1.0"

HAPROXY_RELEASE="1.7"
HAPROXY_VERSION="1.7.2"
HAPROXY_MD5="7330b36f3764ebe409e9305803dc30e2"

LUA_VERSION="5.3.4"
LUA_MD5="53a9c68bcc0eda58bdc2095ad5cdfc63"

###############################################################################

TMP_DIR=$(mktemp -dt "haproxy_build.XXXXXX")

trap "rm -rf ${TMP_DIR}" EXIT

LIBRESSL_LATEST_VERSION=''

function get_latest_libressl_version()
{
    SRC='http://ftp.openbsd.org/pub/OpenBSD/LibreSSL';
    wget $SRC -O "${TMP_DIR}/libressl.releases" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "An error occurred while getting LibreSSL releases: ${SRC}"
        return $ERR
    fi

    LIBRESSL_LATEST_VERSION=$(cat "${TMP_DIR}/libressl.releases" | perl -ne 'print "$1\n" if /href="libressl-(\d\.\d\.\d)\.tar\.gz"/' | sort -Vr | head -1)
    if [[ -z $LIBRESSL_LATEST_VERSION ]]; then
        >&2 echo "An error occurred while parsing LibreSSL releases: ${SRC}"
        return 1
    fi

    return 0
}

function build_libressl()
{
    echo "Getting latest version number of LibreSSL..."

    get_latest_libressl_version ;ERR=$?
    if [ $ERR -ne 0 ]; then
        return $ERR
    fi

    if [ "${LIBRESSL_VERSION}" != "${LIBRESSL_LATEST_VERSION}" ]; then
        echo "LibreSSL ${LIBRESSL_VERSION} is outdated, ${LIBRESSL_LATEST_VERSION} available. Please update version and signature on this script."
        return 1
    else
        echo "LibreSSL ${LIBRESSL_VERSION} is latest version."
    fi

    SRC="http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz";

    wget $SRC -O "${TMP_DIR}/libressl-${LIBRESSL_VERSION}.tar.gz" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "An error occurred while downloading LibreSSL: ${SRC}"
        return $ERR
    fi

    echo "${LIBRESSL_SHA256}" "${TMP_DIR}/libressl-${LIBRESSL_VERSION}.tar.gz" | sha256sum -c ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to validate downloaded file: ${SRC}"
        return $ERR
    fi

    tar xzvf "${TMP_DIR}/libressl-${LIBRESSL_VERSION}.tar.gz" -C "${TMP_DIR}/" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to extract downloaded file: ${SRC}"
        return $ERR
    fi

    pushd ${TMP_DIR}/libressl-${LIBRESSL_VERSION} ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to access extracted directory: ${SRC}"
        return $ERR
    fi

    ./configure \
        --prefix="${TMP_DIR}/libressl" \
        --disable-shared ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "LibreSSL building failure!"
        return $ERR
    fi

    make -j$(nproc) ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "LibreSSL building failure!"
        return $ERR
    fi

    make install ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "LibreSSL building failure!"
        return $ERR
    fi

    popd

    return 0
}

function build_pcre()
{
    SRC="ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-${PCRE_VERSION}.tar.bz2"
    wget $SRC -O "${TMP_DIR}/pcre-${PCRE_VERSION}.tar.bz2" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "An error occurred while downloading PCRE: ${SRC}"
        return $ERR
    fi

    echo "${PCRE_SHA256}" "${TMP_DIR}/pcre-${PCRE_VERSION}.tar.bz2" | sha256sum -c ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to validate downloaded file: ${SRC}"
        return $ERR
    fi

    tar xjvf "${TMP_DIR}/pcre-${PCRE_VERSION}.tar.bz2" -C "${TMP_DIR}/" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to extract downloaded file: ${SRC}"
        return $ERR
    fi

    pushd ${TMP_DIR}/pcre-${PCRE_VERSION} ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to access extracted directory: ${SRC}"
        return $ERR
    fi

    ./configure \
        --enable-static                     `# build static libraries` \
        --enable-utf                        `# enable UTF-8/16/32 support` \
        --enable-unicode-properties         `# enable Unicode properties support` \
        --disable-cpp                       `# disable C++ support` \
        --enable-jit                        `# enable Just-In-Time compiling support` \
        --with-parens-nest-limit=10         `# nested parentheses limit` \
        --with-match-limit=1000             `# limit on internal looping` \
        --with-match-limit-recursion=1000   `# default limit on internal recursion` \
        --with-pcregrep-bufsize=8192        `# pcregrep buffer size` \
        --prefix="${TMP_DIR}/pcre" \
        CPPFLAGS="-D_FORTIFY_SOURCE=2" \
        LDFLAGS="-fPIE -pie -Wl,-z,relro -Wl,-z,now" \
        CFLAGS="-pthread -g -O3 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wall -fvisibility=hidden" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "PCRE building failure!"
        return $ERR
    fi

    make -j$(nproc) ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "PCRE building failure!"
        return $ERR
    fi

    make install ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "PCRE building failure!"
        return $ERR
    fi

    popd

    return 0
}

function build_libslz()
{
    SRC="http://git.1wt.eu/web?p=libslz.git;a=snapshot;h=${LIBSLZ_VERSION};sf=tgz"
    wget $SRC -O "${TMP_DIR}/libslz-${LIBSLZ_VERSION}.tar.gz" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "An error occurred while downloading libSLZ: ${SRC}"
        return $ERR
    fi

    tar xzvf "${TMP_DIR}/libslz-${LIBSLZ_VERSION}.tar.gz" -C "${TMP_DIR}/" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to extract downloaded file: ${SRC}"
        return $ERR
    fi

    pushd "${TMP_DIR}/libslz" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to access extracted directory: ${SRC}"
        return $ERR
    fi

    make -j$(nproc) static ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "libSLZ building failure!"
        return $ERR
    fi

    popd

    return 0
}

function build_lua()
{
    SRC="http://www.lua.org/ftp/lua-${LUA_VERSION}.tar.gz"
    wget $SRC -O "${TMP_DIR}/lua-${LUA_VERSION}.tar.gz" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "An error occurred while downloading LUA: ${SRC}"
        return $ERR
    fi

    echo "${LUA_MD5}" "${TMP_DIR}/lua-${LUA_VERSION}.tar.gz" | md5sum -c ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to validate downloaded file: ${SRC}"
        return $ERR
    fi

    tar xzvf "${TMP_DIR}/lua-${LUA_VERSION}.tar.gz" -C "${TMP_DIR}/" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to extract downloaded file: ${SRC}"
        return $ERR
    fi

    pushd "${TMP_DIR}/lua-${LUA_VERSION}" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to access extracted directory: ${SRC}"
        return $ERR
    fi

    make -j$(nproc) linux LUA_LIB_NAME=lua53 ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "LUA building failure!"
        return $ERR
    fi

    make install INSTALL_TOP="${TMP_DIR}/lua-${LUA_VERSION}" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "LUA building failure!"
        return $ERR
    fi

    popd

    return 0
}

function build_haproxy()
{
    SRC="http://www.haproxy.org/download/${HAPROXY_RELEASE}/src/haproxy-${HAPROXY_VERSION}.tar.gz"
    wget $SRC -O "${TMP_DIR}/haproxy-${HAPROXY_VERSION}.tar.gz" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "An error occurred while downloading HA-Proxy: ${SRC}"
        return $ERR
    fi

    echo "${HAPROXY_MD5}" "${TMP_DIR}/haproxy-${HAPROXY_VERSION}.tar.gz" | md5sum -c ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to validate downloaded file: ${SRC}"
        return $ERR
    fi

    tar xzvf "${TMP_DIR}/haproxy-${HAPROXY_VERSION}.tar.gz" -C "${TMP_DIR}/" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to extract downloaded file: ${SRC}"
        return $ERR
    fi

    pushd "${TMP_DIR}/haproxy-${HAPROXY_VERSION}" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to access extracted directory: ${SRC}"
        return $ERR
    fi

    patch --silent -p0 << EOP
--- src/ssl_sock.c	2017-01-13 09:03:00 UTC
+++ src/ssl_sock.c
@@ -793,7 +793,7 @@ static int ssl_sock_load_ocsp(SSL_CTX *c
 
 #ifndef SSL_CTX_get_tlsext_status_cb
 # define SSL_CTX_get_tlsext_status_cb(ctx, cb) \\
-	*cb = (void (*) (void))ctx->tlsext_status_cb;
+	*cb = SSL_CTX_ctrl(ctx,128,0, (void (**)(void))cb)
 #endif
 	SSL_CTX_get_tlsext_status_cb(ctx, &callback);
 
@@ -821,11 +821,7 @@ static int ssl_sock_load_ocsp(SSL_CTX *c
 		int key_type;
 		EVP_PKEY *pkey;
 
-#ifdef SSL_CTX_get_tlsext_status_arg
-		SSL_CTX_ctrl(ctx, SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG, 0, &cb_arg);
-#else
-		cb_arg = ctx->tlsext_status_arg;
-#endif
+		SSL_CTX_ctrl(ctx, 129, 0, &cb_arg);
 
 		/*
 		 * The following few lines will convert cb_arg from a single ocsp to multi ocsp
@@ -3537,7 +3533,7 @@ int ssl_sock_handshake(struct connection
 					OSSL_HANDSHAKE_STATE state = SSL_get_state((SSL *)conn->xprt_ctx);
 					empty_handshake = state == TLS_ST_BEFORE;
 #else
-					empty_handshake = !((SSL *)conn->xprt_ctx)->packet_length;
+					empty_handshake = SSL_state((SSL *)conn->xprt_ctx) == SSL_ST_BEFORE;
 #endif
 
 					if (empty_handshake) {
@@ -3615,7 +3611,7 @@ int ssl_sock_handshake(struct connection
 			state = SSL_get_state((SSL *)conn->xprt_ctx);
 			empty_handshake = state == TLS_ST_BEFORE;
 #else
-			empty_handshake = !((SSL *)conn->xprt_ctx)->packet_length;
+			empty_handshake = SSL_state((SSL *)conn->xprt_ctx) == SSL_ST_BEFORE;
 #endif
 			if (empty_handshake) {
 				if (!errno) {
EOP
    ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "Unable to patch haproxy: ${SRC}"
        return $ERR
    fi


    make -j$(nproc) \
        TARGET=linux2628 \
        CPU=native \
        USE_LINUX_SPLICE=1 `# enable kernel 2.6 splicing. Automatic.` \
        USE_LUA=1          `# enable Lua support.` \
        USE_OPENSSL=1      `# enable use of OpenSSL. Recommended, but see below.` \
        USE_LIBCRYPT=1     `# enable crypted passwords using -lcrypt` \
        USE_VSYSCALL=1     `# enable vsyscall on Linux x86, bypassing libc` \
        USE_SLZ=1          `# enable slz library instead of zlib (pick at most one).` \
        USE_DL=1           `# enable it if your system requires -ldl. Automatic on Linux.` \
        USE_STATIC_PCRE=1  `# enable static libpcre. Recommended.` \
        USE_PCRE_JIT=1     `# enable JIT for faster regex on libpcre >= 8.32` \
        USE_REGPARM=1      `# enable regparm optimization. Recommended on x86.` \
        USE_TFO=1          `# enable TCP fast open. Supported on Linux >= 3.7.` \
        USE_CPU_AFFINITY=1 `# enable pinning processes to CPU on Linux.` \
        USE_LUA=1          `# enable Lua support.` \
        ADDLIB=-ldl \
        SLZ_INC="${TMP_DIR}/libslz/src" \
        SLZ_LIB="${TMP_DIR}/libslz" \
        PCREDIR="${TMP_DIR}/pcre" \
        SSL_INC="${TMP_DIR}/libressl/include" \
        SSL_LIB="${TMP_DIR}/libressl/lib" \
        LUA_LIB="${TMP_DIR}/lua-${LUA_VERSION}/lib" \
        LUA_INC="${TMP_DIR}/lua-${LUA_VERSION}/include" ;ERR=$?
    if [ $ERR -ne 0 ]; then
        >&2 echo "HA-Proxy building failure!"
        return $ERR
    fi

    popd

    return 0
}

echo "LibreSSL ${LIBRESSL_VERSION} building..."
build_libressl ;ERR=$?
if [ $ERR -ne 0 ]; then
    >&2 echo "An error occurred while building LibreSSL ${LIBRESSL_VERSION}"
    exit $ERR
fi
echo "LibreSSL ${LIBRESSL_VERSION} building completed."

echo "PCRE ${PCRE_VERSION} building..."
build_pcre ;ERR=$?
if [ $ERR -ne 0 ]; then
    >&2 echo "An error occurred while building PCRE ${PCRE_VERSION}"
    exit $ERR
fi
echo "PCRE ${PCRE_VERSION} building completed."

echo "libSLZ ${LIBSLZ_VERSION} building..."
build_libslz ;ERR=$?
if [ $ERR -ne 0 ]; then
    >&2 echo "An error occurred while building libSLZ ${LIBSLZ_VERSION}"
    exit $ERR
fi
echo "libSLZ ${LIBSLZ_VERSION} building completed."

echo "LUA ${LUA_VERSION} building..."
build_lua ;ERR=$?
if [ $ERR -ne 0 ]; then
    >&2 echo "An error occurred while building LUA ${LUA_VERSION}"
    exit $ERR
fi
echo "LUA ${LUA_VERSION} building completed."

echo "HA-Proxy ${HAPROXY_VERSION} building..."
build_haproxy ;ERR=$?
if [ $ERR -ne 0 ]; then
    >&2 echo "An error occurred while building HA-Proxy ${HAPROXY_VERSION}"
    exit $ERR
fi
echo "HA-Proxy ${HAPROXY_VERSION} building completed."

mkdir "haproxy-${HAPROXY_VERSION}"

cp "${TMP_DIR}/haproxy-${HAPROXY_VERSION}/haproxy" "haproxy-${HAPROXY_VERSION}/"
cp -r "${TMP_DIR}/haproxy-${HAPROXY_VERSION}/examples/errorfiles" "haproxy-${HAPROXY_VERSION}/"

echo ""
echo "HA-Proxy building completed."
echo "  HA-Proxy: ${HAPROXY_VERSION}"
echo "  LibreSSL: ${LIBRESSL_VERSION}"
echo "  PCRE    : ${PCRE_VERSION}"
echo "  LUA     : ${LUA_VERSION}"
echo "  libSLZ  : ${LIBSLZ_VERSION}"

exit 0

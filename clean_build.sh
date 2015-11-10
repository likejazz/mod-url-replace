#!/bin/bash

MOD_SRC_PATH=/Users/likejazz/workspace/github/httpd-2.2.29/modules/url-replace
BUILD_PATH=/Users/likejazz/workspace/github/httpd-build

# cd ../../
# ./buildconf

cd ../../

# Apache Stop
$BUILD_PATH/bin/apachectl stop
rm -rf $BUILD_PATH

#./configure \
#  --prefix=$BUILD_PATH \
#  --enable-url-replace=shared

make && make install

# Symlinks for conf, index.html
rm -rf $BUILD_PATH/conf/httpd.conf
rm -rf $BUILD_PATH/htdocs/index.html

cd $MOD_SRC_PATH

ln -s $MOD_SRC_PATH/httpd.conf $BUILD_PATH/conf/httpd.conf
ln -s $MOD_SRC_PATH/index.html $BUILD_PATH/htdocs/index.html

# Check if url-replace module is well-compiled.
ls -al $BUILD_PATH/modules

$BUILD_PATH/bin/apachectl start

# Verify output
echo "GET / HTTP/1.0\n" | nc localhost 8080

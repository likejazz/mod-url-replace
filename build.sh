#!/bin/bash

MOD_SRC_PATH=/Users/likejazz/workspace/github/httpd-2.2.29/modules/url-replace
BUILD_PATH=/Users/likejazz/workspace/github/httpd-build

$BUILD_PATH/bin/apxs -i -a -c mod_url_replace.c

# Check if url-replace module is well-compiled.
ls -al $BUILD_PATH/modules

$BUILD_PATH/bin/apachectl restart

# Verify output
echo "GET / HTTP/1.0\n" | nc localhost 8080

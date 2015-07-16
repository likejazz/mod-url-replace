mod_url_replace
================

Replace OLD urls to NEW urls based on mod_substitute.c

```
LoadModule url_replace_module modules/mod_url_replace.so
...
<Directory "/Users/likejazz/workspace/github/httpd-build/htdocs">
...
    # Replace OLD to NEW servers.
    SetOutputFilter URL-REPLACE
</Directory>
```

You should not edit original urls.

## Output

### Original
```
$ cat index.html
<h1>https://t1.search.daumcdn.net/argon/0x200_85_hr/IHxzswBdipQ</h1>
<h1>https://t2.search.daumcdn.net/argon/0x200_85_hr/ClTWD6PQvux</h1>
<h1>https://t4.search.daumcdn.net/argon/0x200_85_hr/GWIqfBjaDrt</h1>
```

### Service
```
$ echo "GET / HTTP/1.0\n" | nc localhost 8080
HTTP/1.1 200 OK
Date: Thu, 16 Jul 2015 11:29:06 GMT
Server: Apache/2.2.29 (Unix)
Last-Modified: Thu, 16 Jul 2015 09:22:27 GMT
ETag: "2057850-cf-51afa9c1f5ac0"
Accept-Ranges: bytes
Connection: close
Content-Type: text/html

<h1>https://t1.search.daumcdn.net/argon/0x200_85_hr/IHxzswBdipQ</h1>
<h1>https://t99.search.daumcdn.net/argon/0x200_85_hr/ClTWD6PQvux</h1>
<h1>https://t99.search.daumcdn.net/argon/0x200_85_hr/GWIqfBjaDrt</h1>
```

It will convert old urls to new urls automatically.

# Installation

Edit `build.sh` path in `modules/url-replace` directory.

```
$ sh ./build.sh
```

You can see `mod_url_replace.so` below `modules` from build output directory.

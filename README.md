HDown - Simple HTTP downloader
==============================

## Notes

 * Linux only [splice()](https://linux.die.net/man/2/splice) call used
 * Optimized for big files(megabytes)

## Build

Build requirements: C++11+ compatible compiler, Linux

Run

```shell
make
```

## Usage

Example of usage

```shell
./hdown http://lunduke.com/justme.png
```

## How to test

```shell
dd if=/dev/urandom bs=1 count=10000000 > server/test.bin 

# Run in different terminal
./run_http_server.sh

./hdown http://localhost:8000/test.bin
./cmp_files.sh test.bin server/test.bin
```

Compare with wget

```shell
./test_download.sh
```

## Features

  * HTTP 1.0/1.1

Unsupported features

 * HTTPS
 * IPv6
 * Basic auth

## Tested platforms

 * GNU/Linux Ubuntu 16.04 LTS 4.13.0-39-generic  gcc 5.4.0 / clang 3.8.0

## References

 * [nginx mail list: How about to add splice](http://mailman.nginx.org/pipermail/nginx/2015-December/049398.html)
 * [blog.netherlabs.nl: The ultimate SO_LINGER page, or: why is my tcp not reliable](https://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable)

## TODO

  * Kernel TLS support
  * Allocate space for file before downloading
  * strace fault injection test
  * In-app profiler

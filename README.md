# HttpAsm
## Overview
Small HTTP server written for educational purposes in x86_64 assembly (NASM syntax)

## Build and run
Server can be build via provided Makefile:
```sh
$ make
```
and than run with:
```sh
./server
```

It operates on port 8080 and can be seen in action at `localhost:8080/index.html`

## Features
So far, it supports only `GET` requests.
Sadly, index.html isn't file served by default, so entering `localhost:8080` will result in HTTP 404 Not Found error.

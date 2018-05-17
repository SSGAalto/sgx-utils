Aalto SSG SGX utility libraries
===========================

Introduction
------------

This repository contains various libraries used in other projects of Aalto Secure Systems Group.

### Prerequisites

- Install SGX SDK:
  * Download [Intel SGX SDK for Linux](https://github.com/01org/linux-sgx)
  * By default Makefile's expect to have SDK installed in ``/opt/intel/sgxsdk``.
  * If the SDK is in a different directory, change `SGX_SDK` variable in Makefile.

Build
-----

Run `make` for each library.

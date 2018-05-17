#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## Dependencies and output ########
Build_Dir := .
Generated_Dir := .

Lib_NrtTke := ../lib_tke

######## Lib Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
	Trts_Library_Name := sgx_trts_sim
	UService_Library_Name := sgx_uae_service_sim
	Service_Library_Name := sgx_tservice_sim
else
	Urts_Library_Name := sgx_urts
	Trts_Library_Name := sgx_trts
	UService_Library_Name := sgx_uae_service
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

Lib_Cpp_Files := uke_nrt.cpp

Lib_Include_Paths := -I$(SGX_SDK)/include \
			 -I$(SGX_SDK)/include/stlport  \
			 -I$(SGX_SDK)/include/tlibc \
			 -I$(Lib_NrtTke)

Lib_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Lib_Include_Paths) \
			-nostdinc -fvisibility=hidden -fpie -fstack-protector

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Lib_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Lib_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Lib_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Lib_Cpp_Flags := $(Lib_C_Flags) -std=c++03 -nostdinc++

Lib_Libs :=   -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name)

Lib_Link_Flags := $(SGX_COMMON_CFLAGS) $(Lib_Libs)

Lib_Cpp_Objects := $(Lib_Cpp_Files:%.cpp=%.o)

Lib_Name := libnrt_uke.a

.PHONY: all run

all: $(Lib_Name)

######## Lib Objects ########

$(Generated_Dir)/nrt_tke_u.c: $(SGX_EDGER8R) $(Lib_NrtTke)/nrt_tke.edl
	$(SGX_EDGER8R) --untrusted $(Lib_NrtTke)/nrt_tke.edl \
		--search-path $(SGX_SDK)/include \
		--trusted-dir   $(Generated_Dir) \
		--untrusted-dir $(Generated_Dir)
	@echo "GEN  =>  $@"

$(Lib_Cpp_Objects): $(Lib_Cpp_Files) $(Generated_Dir)/nrt_tke_u.o
	@$(CXX) $(Lib_Cpp_Flags) -c $< -o $@

$(Generated_Dir)/nrt_tke_u.o: $(Generated_Dir)/nrt_tke_u.c
	@$(CXX) $(Lib_Cpp_Flags) -c $< -o $@

$(Lib_Name): $(Lib_Cpp_Objects) $(Generated_Dir)/nrt_tke_u.o
	$(AR) rcsD $@ $^
	@echo "AR =>  $@"

.PHONY: clean

clean:
	@rm -f $(Lib_Name) $(Lib_Cpp_Objects) \
		$(Generated_Dir)/nrt_tke_u.* \
		$(Generated_Dir)/nrt_tke_t.*

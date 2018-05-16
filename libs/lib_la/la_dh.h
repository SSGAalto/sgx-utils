/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LOCAL_ATTESTATION_DIFFIE_HELLMAN_H_
#define LOCAL_ATTESTATION_DIFFIE_HELLMAN_H_

#include "sgx_report.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"

#include "sgx_key.h"
#include "sgx_attributes.h"

#define DH_KEY_SIZE        20
#define NONCE_SIZE         16
#define MAC_SIZE           16
#define MAC_KEY_SIZE       16
#define PADDING_SIZE       16

#define TAG_SIZE           16
#define IV_SIZE            12

#define DERIVE_MAC_KEY      0x0
#define DERIVE_SESSION_KEY  0x1
#define DERIVE_VK1_KEY      0x3
#define DERIVE_VK2_KEY      0x4

// DH session type status options
#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

#define INVALID_ARGUMENT      -2   // Invalid function argument
#define LOGIC_ERROR           -3   // Functional logic error
#define FILE_NOT_FOUND        -4   // File not found

#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}

#define VMC_ATTRIBUTE_MASK  0xFFFFFFFFFFFFFFCB

#define LA_LOGGING_ENABLED true

typedef uint8_t dh_nonce[NONCE_SIZE];
typedef uint8_t cmac_128[MAC_SIZE];

#pragma pack(push, 1)

// Contact information of a remote enclave
typedef struct _enclave {

    char ip[16];
    char port[6];
    // sgx_measurement_t mrenclave;

} remote_enclave_t;

// Format of the AES-GCM message being exchanged
// between the source and the destination enclaves
typedef struct _secure_message_t {

    // Session ID identifyting the session to which the message belongs
    uint32_t session_id;
    sgx_aes_gcm_data_t message_aes_gcm_data;    

} secure_message_t;

// Format of the input function parameter structure
typedef struct _attestation_msg_t {

    uint32_t msg_type;         // Type of Call E2E or general message exchange
    uint32_t inparam_buff_len; // Length of the serialized input parameters
    char inparam_buff[];       // Serialized input parameters

} attestation_msg_t;

#pragma pack(pop)

#define MSG_BUF_LEN        sizeof(ec_pub_t)*2
#define MSG_HASH_SZ        32

// Session information structure
typedef struct _la_dh_session_t
{
    uint32_t  session_id; // Identifies the current session
    uint32_t  status;     // In progress, active or closed
    union
    {
        struct
        {
			sgx_dh_session_t dh_session;
        } in_progress;

        struct
        {
            sgx_key_128bit_t AEK; // Session Key
            uint32_t counter;     // Message Sequence Number
            // Enclave identity of the peer.
            sgx_dh_session_enclave_identity_t identity;
        } active;
    };
} dh_session_t;


// Attestation result
typedef uint32_t ATTESTATION_STATUS;

#define SGX_ATTESTATION_MK_ERROR(x)              (0x00010000|(x))

typedef enum _att_status_t
{
    // Network erros
    /* Migration Library has not been initialized */
    SGX_ATT_ERROR_SOCKET_ERROR               = SGX_ATTESTATION_MK_ERROR(0x10),

    // Session Errors
    SGX_ATT_ERROR_VALID_SESSION              = SGX_ATTESTATION_MK_ERROR(0x20),
    SGX_ATT_ERROR_INVALID_SESSION            = SGX_ATTESTATION_MK_ERROR(0x21),
    SGX_ATT_ERROR_DUPLICATE_SESSION          = SGX_ATTESTATION_MK_ERROR(0x22),
    SGX_ATT_ERROR_NO_AVAILABLE_SESSION_ERROR = SGX_ATTESTATION_MK_ERROR(0x23),

    // Attestation errros
    SGX_ATT_ERROR_ATTESTATION_ERROR          = SGX_ATTESTATION_MK_ERROR(0x30),
    SGX_ATT_ERROR_ATTESTATION_SE_ERROR       = SGX_ATTESTATION_MK_ERROR(0x31),
    SGX_ATT_ERROR_MALLOC_ERROR               = SGX_ATTESTATION_MK_ERROR(0x32),
    SGX_ATT_OUT_BUFFER_LENGTH_ERROR          = SGX_ATTESTATION_MK_ERROR(0x33),

    // Encryption errors
    SGX_ATT_ERROR_ENCRYPT_DECRYPT_ERROR      = SGX_ATTESTATION_MK_ERROR(0x40),

    // Higher level errors
    SGX_ATT_ERROR_ENCLAVE_TRUST_ERROR        = SGX_ATTESTATION_MK_ERROR(0x91),
    SGX_ATT_ERROR_INVALID_REQUEST_TYPE_ERROR = SGX_ATTESTATION_MK_ERROR(0x92),

    SGX_ATT_ERROR_UNKNOWN                    = SGX_ATTESTATION_MK_ERROR(0),

} sgx_att_status_t;

#endif


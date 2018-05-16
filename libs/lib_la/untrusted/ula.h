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

#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_dh.h"
#include <cstddef>

#include "la_dh.h"

#ifndef ULOCALATTESTATION_H_
#define ULOCALATTESTATION_H_

#ifdef __cplusplus
extern "C" {
#endif

void ocall_log(const char *str);

uint32_t la_session_request_ocall(remote_enclave_t *dest, sgx_dh_msg1_t *dh_msg1,uint32_t *session_id);
uint32_t la_exchange_report_ocall(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id);
uint32_t la_send_request_ocall(uint32_t session_id, secure_message_t* req_message,
        size_t req_message_size, size_t max_payload_size,
        secure_message_t* resp_message, size_t resp_message_size);
uint32_t la_send_nested_request_ocall(uint32_t session_id, secure_message_t* req_message,
        size_t req_message_size, attestation_msg_t* req_message_plaintext,
        size_t req_message_plaintext_size, size_t max_payload_size,
        secure_message_t* resp_message, size_t resp_message_size);
uint32_t la_end_session_ocall(uint32_t session_id);

/*
 * This ocall sends a message to the session ID. Plain and simple.
 */
uint32_t la_send_message_ocall(
        uint32_t session_id,
        secure_message_t* req_message,
        size_t req_message_size);

/*
 * This ocall synchronously receives a message from the session ID.
 * Blocks until message is received and returns it
 */
uint32_t la_receive_message_ocall(
        uint32_t session_id,
        size_t max_payload_size,
        secure_message_t* resp_message,
        size_t resp_message_size);

#ifdef __cplusplus
}
#endif

#endif

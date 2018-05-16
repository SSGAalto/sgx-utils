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

#include "tla.h"

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include <map>
#include "sgx_dh.h"
#include "sgx_tcrypto.h"

#include "string.h"     //logging

#include <stdbool.h>
#include <stdio.h>      /* vsnprintf */

#include "la_dh.h"
#include "la_t.h"


#ifdef __cplusplus
extern "C" {
#endif

ATTESTATION_STATUS la_response_generator(sgx_dh_session_enclave_identity_t* identity,
        char* decrypted_data, char** resp_buffer, size_t* resp_length);
ATTESTATION_STATUS la_verify_peer_enclave(sgx_dh_session_enclave_identity_t* peer_enclave_identity);
ATTESTATION_STATUS la_restart(uint32_t *session_id);

#ifdef __cplusplus
}
#endif

// global session counter. Shows the next session ID that will be assigned
uint32_t g_la_session_counter = 0;

ATTESTATION_STATUS generate_session_id(uint32_t *session_id);
ATTESTATION_STATUS la_ecall_end_session(uint32_t session_id);

// Map between the session id and the session information associated with that particular session
std::map<uint32_t, dh_session_t> g_la_id_session_map;

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void local_attestation_log(const char *fmt, ...)
{
    if(LA_LOGGING_ENABLED){
        char buf[BUFSIZ] = {'\0'};
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, BUFSIZ, fmt, ap);
        va_end(ap);
        ocall_log(buf);
    }
}

void print_measurement(sgx_measurement_t m){
    local_attestation_log("MRENCLAVE: ");
    for(int i=0; i<SGX_HASH_SIZE; i++){
        local_attestation_log("%X", m.m[i]);
    }
    local_attestation_log("\n");
}

// Create a session with the destination enclave
ATTESTATION_STATUS la_create(remote_enclave_t *dest, uint32_t *session_id)
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_key_128bit_t dh_aek;          //Session Key
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    uint32_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    dh_session_t session_info;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    if(!session_id || !dest)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Check if session is already open
    std::map<uint32_t, dh_session_t>::iterator it = g_la_id_session_map.find(*session_id);
    if(it != g_la_id_session_map.end())
    {
        dh_session_t *sess = &it->second;
        if(sess->status == ACTIVE)
        {
            // We are already active, simply return a success
            return SGX_SUCCESS;
        }
    }



    memset_s(&dh_aek, sizeof(sgx_key_128bit_t), 0, sizeof(sgx_key_128bit_t));
    memset_s(&dh_msg1, sizeof(sgx_dh_msg1_t), 0, sizeof(sgx_dh_msg1_t));
    memset_s(&dh_msg2, sizeof(sgx_dh_msg2_t), 0, sizeof(sgx_dh_msg2_t));
    memset_s(&dh_msg3, sizeof(sgx_dh_msg3_t), 0, sizeof(sgx_dh_msg3_t));
    memset_s(&session_info, sizeof(dh_session_t), 0, sizeof(dh_session_t));

    // Intialize the session as a session initiator
    status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return status;
    }
    
    // Ocall to request for a session with the destination enclave
    // and obtain session id and Message 1 if successful
    local_attestation_log("[LA] Requesting local attestation from target\n");
    status = la_session_request_ocall(&retstatus, dest, &dh_msg1, session_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SGX_SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return status;
    }
    local_attestation_log("[LA] Received DH message 1 from target, processing now...\n");
    // Process the message 1 obtained from desination enclave and generate message 2
    status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
         return status;
    }

    // Send Message 2 to Destination Enclave and get Message 3 in return
    local_attestation_log("[LA] Sending DH message 2 to target\n");
    status = la_exchange_report_ocall(&retstatus, &dh_msg2, &dh_msg3, *session_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SGX_SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return SGX_ATT_ERROR_ATTESTATION_SE_ERROR;
    }

    local_attestation_log("[LA] Received DH message 3.\n");
    // Process Message 3 obtained from the destination enclave
    status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if(SGX_SUCCESS != status)
    {
        return status;
    }

    local_attestation_log("[LA] Peer enclave has ");
    print_measurement(responder_identity.mr_enclave);
    local_attestation_log("[LA] Checking trustworthiness of Peer...\n");

    // Verify the identity of the destination enclave
    if(la_verify_peer_enclave(&responder_identity) != SGX_SUCCESS)
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    local_attestation_log("[LA] Peer trustworthy. Proceed with attestation.\n");

    memcpy(session_info.active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    memcpy(&session_info.active.identity, &responder_identity, sizeof(sgx_dh_session_enclave_identity_t));
    session_info.session_id = *session_id;
    session_info.active.counter = 0;
    session_info.status = ACTIVE;

    // Store session in map
    g_la_id_session_map.insert(std::pair<uint32_t, dh_session_t>(*session_id, session_info));

    local_attestation_log("[LA] DH Exchange complete. Local attestation successful.\n");

    // cleanup key
    memset_s(&dh_aek, sizeof(sgx_key_128bit_t), 0, sizeof(sgx_key_128bit_t));

    return status;
}

// Handle the request from Source Enclave for a session
ATTESTATION_STATUS la_ecall_session_request(sgx_dh_msg1_t *dh_msg1, uint32_t *session_id )
{
    dh_session_t session_info;
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;

    if(!session_id || !dh_msg1)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return status;
    }
    
    // Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1(dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return status;
    }

    // get a new SessionID
    if ((status = (sgx_status_t)generate_session_id(session_id)) != SGX_SUCCESS)
        return status;
    session_info.session_id = *session_id;

    // Store the session info in the map with status In progress
    session_info.status = IN_PROGRESS;
    memcpy(&session_info.in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));
    // Store the session information under the corresponding session id
    g_la_id_session_map.insert(std::pair<uint32_t, dh_session_t>(*session_id, session_info));
    
    return status;
}

// Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
ATTESTATION_STATUS la_ecall_exchange_report(sgx_dh_msg2_t *dh_msg2,
                          sgx_dh_msg3_t *dh_msg3,
                          uint32_t session_id)
{

    sgx_key_128bit_t dh_aek;   // Session key
    dh_session_t *session_info;
    ATTESTATION_STATUS status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t initiator_identity;

    if(!dh_msg2 || !dh_msg3)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memset_s(&dh_aek, sizeof(sgx_key_128bit_t), 0, sizeof(sgx_key_128bit_t));
    do
    {
        // Retreive the session information for the corresponding source enclave id
        std::map<uint32_t, dh_session_t>::iterator it = g_la_id_session_map.find(session_id);
        if(it != g_la_id_session_map.end())
        {
            session_info = &it->second;
        }
        else
        {
            status = SGX_ATT_ERROR_INVALID_SESSION;
            break;
        }

        if(session_info->status != IN_PROGRESS)
        {
            status = SGX_ATT_ERROR_INVALID_SESSION;
            break;
        }

        memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

        dh_msg3->msg3_body.additional_prop_length = 0;
        // Process message 2 from source enclave and obtain message 3
        sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2, 
                                                       dh_msg3, 
                                                       &sgx_dh_session, 
                                                       &dh_aek, 
                                                       &initiator_identity);
        if(SGX_SUCCESS != se_ret)
        {
            status = se_ret;
            break;
        }

        local_attestation_log("[LA] Peer enclave has ");
        print_measurement(initiator_identity.mr_enclave);
        local_attestation_log("[LA] Checking trustworthiness of Peer...\n");

        // Verify source enclave's trust
        if(la_verify_peer_enclave(&initiator_identity) != SGX_SUCCESS)
        {
            return SGX_ATT_ERROR_INVALID_SESSION;
        }

        local_attestation_log("[LA] Peer trustworthy. Proceed with attestation.\n");

        // save the status and initialize the session nonce
        session_info->status = ACTIVE;
        session_info->active.counter = 0;
        memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
        memcpy(&session_info->active.identity, &initiator_identity, sizeof(sgx_dh_session_enclave_identity_t));
        memset_s(&dh_aek, sizeof(sgx_key_128bit_t), 0, sizeof(sgx_key_128bit_t));
    }while(0);

    if(status != SGX_SUCCESS)
    {
        la_ecall_end_session(session_id);
    }

    return status;
}

// Request for the response size, send the request message to the destination enclave
// and receive the response message back
ATTESTATION_STATUS la_exchange(uint32_t *session_id,
                                  char *inp_buff,
                                  size_t inp_buff_len,
                                  attestation_msg_t *plaintext_msg,
                                  size_t plaintext_msg_len,
                                  size_t max_out_buff_size,
                                  char **out_buff,
                                  size_t* out_buff_len)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    sgx_status_t status;
    dh_session_t *session_info;
    uint32_t retstatus;
    secure_message_t* req_message;
    secure_message_t* resp_message;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    uint8_t l_tag[TAG_SIZE];
    size_t max_resp_message_length;
    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!inp_buff || !session_id)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Get the session information from the map corresponding to the session id
    std::map<uint32_t, dh_session_t>::iterator it = g_la_id_session_map.find(*session_id);
    if(it != g_la_id_session_map.end())
    {
        session_info = &it->second;
    }
    else
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    // Check if the nonce for the session has not exceeded 2^32-2
    // If so end session and start a new session
    if(session_info->active.counter == ((uint32_t) - 2))
    {
        // Let the implementing code handle restarting
        // There might be adjustments necessary
        // (or if not, session will just be closed and restarted)
        la_restart(session_id);
    }

    // Allocate memory for the AES-GCM request message
    req_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ inp_buff_len);
    if(!req_message)
    {
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }

    memset(req_message,0,sizeof(secure_message_t)+ inp_buff_len);
    const uint32_t data2encrypt_length = (uint32_t)inp_buff_len;
    // Set the payload size to data to encrypt length
    req_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    // Use the session nonce as the payload IV
    memcpy(req_message->message_aes_gcm_data.reserved,&session_info->active.counter,sizeof(session_info->active.counter));

    // Set the session ID of the message to the current session id
    req_message->session_id = session_info->session_id;

    // Prepare the request message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)inp_buff, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), plaintext, plaintext_length, 
                &(req_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        return status;
    }
    
    // Allocate memory for the response payload to be copied
    *out_buff = (char*)malloc(max_out_buff_size);
    if(!*out_buff)
    {
        SAFE_FREE(req_message);
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }

    memset(*out_buff, 0, max_out_buff_size);

    // Allocate memory for the response message
    resp_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ max_out_buff_size);
    if(!resp_message)
    {
        SAFE_FREE(req_message);
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }

    memset(resp_message, 0, sizeof(secure_message_t)+ max_out_buff_size);

    local_attestation_log("[LA] [LMESS] Sending message and waiting for response.\n");

    // Do ocall based on plaintext size:
    // Ocall to send the request to the Destination Enclave and get the response message back
    if(plaintext_msg_len > 0 && plaintext_msg != NULL && plaintext_msg->inparam_buff_len > 0){
        status = la_send_nested_request_ocall(&retstatus, *session_id, req_message,
                                    (sizeof(secure_message_t)+ inp_buff_len),
                                    plaintext_msg, plaintext_msg_len,
                                    max_out_buff_size,
                                    resp_message, (sizeof(secure_message_t)+ max_out_buff_size));
    } else {
        status = la_send_request_ocall(&retstatus, *session_id, req_message,
                                    (sizeof(secure_message_t)+ inp_buff_len),
                                    max_out_buff_size,
                                    resp_message, (sizeof(secure_message_t)+ max_out_buff_size));
    }

    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SGX_SUCCESS)
        {
            local_attestation_log("[LA] [LMESS] Ocall returned an error %u.\n", retstatus);
            SAFE_FREE(req_message);
            SAFE_FREE(resp_message);
            return ((ATTESTATION_STATUS)retstatus);
        }
        local_attestation_log("[LA] [LMESS] Received response. Decrypting it now.\n");
    }
    else
    {
        local_attestation_log("[LA] [LMESS] Ocall returned an error %u.\n", status);
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return SGX_ATT_ERROR_ATTESTATION_SE_ERROR;
    }

    max_resp_message_length = sizeof(secure_message_t)+ max_out_buff_size;

    if(sizeof(resp_message) > max_resp_message_length)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Code to process the response message from the Destination Enclave

    decrypted_data_length = resp_message->message_aes_gcm_data.payload_size;
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if(!decrypted_data)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }
    memset(&l_tag, 0, 16);

    memset(decrypted_data, 0, decrypted_data_length);

    // Decrypt the response message payload
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, resp_message->message_aes_gcm_data.payload, 
                decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.reserved)),
                sizeof(resp_message->message_aes_gcm_data.reserved), &(resp_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length, 
                &resp_message->message_aes_gcm_data.payload_tag);
    
    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(decrypted_data);
        SAFE_FREE(resp_message);
        return status;
    }

    // Verify if the nonce obtained in the response
    // is equal to the session nonce + 1 (Prevents replay attacks)
    if(*(resp_message->message_aes_gcm_data.reserved) != (session_info->active.counter + 1 ))
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        SAFE_FREE(decrypted_data);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Update the value of the session nonce in the source enclave
    session_info->active.counter = session_info->active.counter + 1;

    memcpy(out_buff_len, &decrypted_data_length, sizeof(decrypted_data_length));
    memcpy(*out_buff, decrypted_data, decrypted_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(req_message);
    SAFE_FREE(resp_message);
    return SGX_SUCCESS;

}

// Send the request message to the destination enclave
ATTESTATION_STATUS la_send(uint32_t *session_id,
                                  char *inp_buff,
                                  size_t inp_buff_len)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    sgx_status_t status;
    dh_session_t *session_info;
    uint32_t retstatus;
    secure_message_t* req_message;
    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!inp_buff || !session_id)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Get the session information from the map corresponding to the session id
    std::map<uint32_t, dh_session_t>::iterator it = g_la_id_session_map.find(*session_id);
    if(it != g_la_id_session_map.end())
    {
        session_info = &it->second;
    }
    else
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    // Check if the nonce for the session has not exceeded 2^32-2
    // If so end session and start a new session
    if(session_info->active.counter == ((uint32_t) - 2))
    {
        // Let the implementing code handle restarting
        // There might be adjustments necessary
        // (or if not, session will just be closed and restarted)
        la_restart(session_id);
    }

    // Allocate memory for the AES-GCM request message
    req_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ inp_buff_len);
    if(!req_message)
    {
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }

    memset(req_message,0,sizeof(secure_message_t)+ inp_buff_len);
    const uint32_t data2encrypt_length = (uint32_t)inp_buff_len;
    // Set the payload size to data to encrypt length
    req_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    // Use the session nonce as the payload IV
    memcpy(req_message->message_aes_gcm_data.reserved,&session_info->active.counter,sizeof(session_info->active.counter));

    // Set the session ID of the message to the current session id
    req_message->session_id = session_info->session_id;

    // Prepare the request message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)inp_buff, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                &(req_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        return status;
    }

    local_attestation_log("[LA] [LMESS] Sending single one directed message.\n");

    // Do ocall based on plaintext size:
    // Ocall to send the request to the Destination Enclave and get the response message back
    status = la_send_message_ocall(&retstatus, *session_id, req_message,
                                   (sizeof(secure_message_t)+ inp_buff_len));


    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SGX_SUCCESS)
        {
            local_attestation_log("[LA] [LMESS] Ocall returned an error %u.\n", retstatus);
            SAFE_FREE(req_message);
            return ((ATTESTATION_STATUS)retstatus);
        }
        local_attestation_log("[LA] [LMESS] Sent message successfully.\n");
    }
    else
    {
        local_attestation_log("[LA] [LMESS] Ocall returned an error %u.\n", status);
        SAFE_FREE(req_message);
        return SGX_ATT_ERROR_ATTESTATION_SE_ERROR;
    }


    SAFE_FREE(req_message);
    return SGX_SUCCESS;

}

// Receive the response message back
ATTESTATION_STATUS la_receive(uint32_t *session_id,
                                  size_t max_out_buff_size,
                                  char **out_buff,
                                  size_t* out_buff_len)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    sgx_status_t status;
    dh_session_t *session_info;
    uint32_t retstatus;
    secure_message_t* resp_message;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    uint8_t l_tag[TAG_SIZE];
    size_t max_resp_message_length;
    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!session_id)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Get the session information from the map corresponding to the session id
    std::map<uint32_t, dh_session_t>::iterator it = g_la_id_session_map.find(*session_id);
    if(it != g_la_id_session_map.end())
    {
        session_info = &it->second;
    }
    else
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    // Allocate memory for the response payload to be copied
    *out_buff = (char*)malloc(max_out_buff_size);
    if(!*out_buff)
    {
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }

    memset(*out_buff, 0, max_out_buff_size);

    // Allocate memory for the response message
    resp_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ max_out_buff_size);
    if(!resp_message)
    {
        SAFE_FREE(out_buff);
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }

    memset(resp_message, 0, sizeof(secure_message_t)+ max_out_buff_size);

    local_attestation_log("[LA] [LMESS] Waiting for incoming message...\n");

    // Do ocall based on plaintext size:
    // Ocall to get the response message back
    status = la_receive_message_ocall(&retstatus, *session_id,
                                      max_out_buff_size,
                                      resp_message, (sizeof(secure_message_t)+ max_out_buff_size));


    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SGX_SUCCESS)
        {
            local_attestation_log("[LA] [LMESS] Ocall returned an error %u.\n", retstatus);
            SAFE_FREE(resp_message);
            return ((ATTESTATION_STATUS)retstatus);
        }
        local_attestation_log("[LA] [LMESS] Received message. Decrypting it now.\n");
    }
    else
    {
        local_attestation_log("[LA] [LMESS] Ocall returned an error %u.\n", status);
        SAFE_FREE(resp_message);
        return SGX_ATT_ERROR_ATTESTATION_SE_ERROR;
    }

    max_resp_message_length = sizeof(secure_message_t)+ max_out_buff_size;

    if(sizeof(resp_message) > max_resp_message_length)
    {
        SAFE_FREE(resp_message);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // TODO looks exactly like the one from above
    // Code to process the response message from the Destination Enclave

    decrypted_data_length = resp_message->message_aes_gcm_data.payload_size;
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if(!decrypted_data)
    {
        SAFE_FREE(resp_message);
        return SGX_ATT_ERROR_MALLOC_ERROR;
    }
    memset(&l_tag, 0, 16);

    memset(decrypted_data, 0, decrypted_data_length);

    // Decrypt the response message payload
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, resp_message->message_aes_gcm_data.payload,
                decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.reserved)),
                sizeof(resp_message->message_aes_gcm_data.reserved), &(resp_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length,
                &resp_message->message_aes_gcm_data.payload_tag);

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(decrypted_data);
        SAFE_FREE(resp_message);
        return status;
    }

    // Verify if the nonce obtained in the response is equal to the session nonce + 1 (Prevents replay attacks)
    if(*(resp_message->message_aes_gcm_data.reserved) != (session_info->active.counter + 1 ))
    {
        SAFE_FREE(resp_message);
        SAFE_FREE(decrypted_data);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Update the value of the session nonce in the source enclave
    session_info->active.counter = session_info->active.counter + 1;

    memcpy(out_buff_len, &decrypted_data_length, sizeof(decrypted_data_length));
    memcpy(*out_buff, decrypted_data, decrypted_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(resp_message);
    return SGX_SUCCESS;

}

// Process the request from the Source enclave and send the response message back to the Source enclave
ATTESTATION_STATUS la_ecall_generate_response(uint32_t session_id,
                                     secure_message_t* req_message,
                                     size_t req_message_size,
                                     size_t max_payload_size,
                                     secure_message_t* resp_message,
                                     size_t resp_message_size)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    attestation_msg_t * ms;
    size_t resp_data_length;
    size_t resp_message_calc_size;
    char* resp_data;
    uint8_t l_tag[TAG_SIZE];
    size_t header_size, expected_payload_size;
    dh_session_t *session_info;
    secure_message_t* temp_resp_message;
    uint32_t ret;
    sgx_status_t status;

    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!req_message || !resp_message)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Get the session information from the map corresponding to the session id
    std::map<uint32_t, dh_session_t>::iterator it = g_la_id_session_map.find(session_id);
    if(it != g_la_id_session_map.end())
    {
        session_info = &it->second;
    }
    else
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    if(session_info->status != ACTIVE)
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    // Set the decrypted data length to the payload size obtained from the message
    decrypted_data_length = req_message->message_aes_gcm_data.payload_size;

    header_size = sizeof(secure_message_t);
    expected_payload_size = req_message_size - header_size;

    // Verify the size of the payload
    if(expected_payload_size != decrypted_data_length)
        return SGX_ERROR_INVALID_PARAMETER;

    memset(&l_tag, 0, 16);
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if(!decrypted_data)
    {
            return SGX_ATT_ERROR_MALLOC_ERROR;
    }

    memset(decrypted_data, 0, decrypted_data_length);

    // Decrypt the request message payload from source enclave
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, req_message->message_aes_gcm_data.payload, 
                decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), &(req_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length, 
                &req_message->message_aes_gcm_data.payload_tag);

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(decrypted_data);
        return status;
    }

    // Casting the decrypted data to the marshaling structure type
    // to obtain type of request (generic message exchange/enclave to enclave call)
    ms = (attestation_msg_t *)decrypted_data;


    // Verify if the nonce obtained in the request is equal to the session nonce
    if((uint32_t)*(req_message->message_aes_gcm_data.reserved) != session_info->active.counter || *(req_message->message_aes_gcm_data.reserved) > ((2^32)-2))
    {
        SAFE_FREE(decrypted_data);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Call the generic secret response generator for message exchange
    ret = la_response_generator(&session_info->active.identity,
            (char*)decrypted_data, &resp_data, &resp_data_length);
    if(ret !=0)
    {
        SAFE_FREE(decrypted_data);
        SAFE_FREE(resp_data);
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    if(resp_data_length > max_payload_size)
    {
        local_attestation_log("ERROR: Response requires at least size %u", resp_data_length);
        SAFE_FREE(resp_data);
        SAFE_FREE(decrypted_data);
        return SGX_ATT_OUT_BUFFER_LENGTH_ERROR;
    }

    resp_message_calc_size = sizeof(secure_message_t)+ resp_data_length;

    if(resp_message_calc_size > resp_message_size)
    {
        local_attestation_log("ERROR: Required size larger than allowed size %u", resp_message_calc_size);
        SAFE_FREE(resp_data);
        SAFE_FREE(decrypted_data);
        return SGX_ATT_OUT_BUFFER_LENGTH_ERROR;
    }

    // Code to build the response back to the Source Enclave
    temp_resp_message = (secure_message_t*)malloc(resp_message_calc_size);
    if(!temp_resp_message)
    {
            SAFE_FREE(resp_data);
            SAFE_FREE(decrypted_data);
            return SGX_ATT_ERROR_MALLOC_ERROR;
    }

    memset(temp_resp_message,0,sizeof(secure_message_t)+ resp_data_length);
    const uint32_t data2encrypt_length = (uint32_t)resp_data_length;
    temp_resp_message->session_id = session_info->session_id;
    temp_resp_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    // Increment the Session Nonce (Replay Protection)
    session_info->active.counter = session_info->active.counter + 1;

    // Set the response nonce as the session nonce
    memcpy(&temp_resp_message->message_aes_gcm_data.reserved,&session_info->active.counter,sizeof(session_info->active.counter));

    // Prepare the response message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)resp_data, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.reserved)),
                sizeof(temp_resp_message->message_aes_gcm_data.reserved), plaintext, plaintext_length, 
                &(temp_resp_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(resp_data);
        SAFE_FREE(decrypted_data);
        SAFE_FREE(temp_resp_message);
        return status;
    }

    memset(resp_message, 0, sizeof(secure_message_t)+ resp_data_length);
    memcpy(resp_message, temp_resp_message, sizeof(secure_message_t)+ resp_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(resp_data);
    SAFE_FREE(temp_resp_message);

    return SGX_SUCCESS;
}

// Close a local attestation session
ATTESTATION_STATUS la_close(uint32_t session_id)
{
    int status;

    uint32_t retstatus;

    // Ocall to ask the destination enclave to end the session
    status = la_end_session_ocall(&retstatus, session_id);

    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SGX_SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return SGX_ATT_ERROR_ATTESTATION_SE_ERROR;
    }

    // Erase the session locally if remote deletion worked
    if(g_la_id_session_map.erase(session_id) == 0){
        status = SGX_ATT_ERROR_INVALID_SESSION;
    }

    return SGX_SUCCESS;
}

// Respond to the request from the Source Enclave to close the session
ATTESTATION_STATUS la_ecall_end_session(uint32_t session_id)
{
    ATTESTATION_STATUS status = SGX_SUCCESS;

    //Erase the session information for the current session
    if(g_la_id_session_map.erase(session_id) == 0){
        status = SGX_ATT_ERROR_INVALID_SESSION;
    }

    return status;

}


// Returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id)
{
    ATTESTATION_STATUS status = SGX_SUCCESS;

    if(!session_id)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    *session_id = g_la_session_counter;
    g_la_session_counter += 1;

    return status;

}

/**
 * Sends a request and receives a response to an MRENCLAVE value of a local attested enclave.
 * This is basically a wrapper for send_receive to not take a session id but
 * rather an sgx identity
 */
ATTESTATION_STATUS la_exchange_with_eid(sgx_measurement_t *enclave_id,
                                  char *inp_buff,
                                  size_t inp_buff_len,
                                  attestation_msg_t *plaintext_msg,
                                  size_t plaintext_msg_len,
                                  size_t max_out_buff_size,
                                  char **out_buff,
                                  size_t* out_buff_len){

    /*
     * Look through all elements of the map and compare the enclave id to our enclave id.
     * Make a backwards search through the map for that
     */
    uint32_t session;
    bool session_exists = false;

    for (auto const& x : g_la_id_session_map)
    {
        // Loop through MRENCLAVE to check for differences
        bool found = true;
        for(int i = 0; i < SGX_HASH_SIZE; i++){
            if(enclave_id->m[i] != x.second.active.identity.mr_enclave.m[i]){
                // MRENCLAVE values differ, required session id not found, abort
                found = false;
                break;
            }
        }
        // If no difference was found, found is true - Store this session and set exists to true
        if(found){
            session = x.first;
            session_exists = true;
            break;
        }
    }


    /*
     * If we have found a valid session, send a message to that session
     */
    if(session_exists){
        return la_exchange(&session, inp_buff, inp_buff_len,
                plaintext_msg, plaintext_msg_len, max_out_buff_size,
                out_buff, out_buff_len);
    }

    // Otherwise, return session not found error
    return SGX_ATT_ERROR_NO_AVAILABLE_SESSION_ERROR;
}

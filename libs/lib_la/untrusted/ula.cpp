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

#include "ula.h"

#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_dh.h"
#include <map>
#include <cstdio>
#include "string.h"

#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>

#include "network_types.h"
#include "network_common.h"

using boost::asio::ip::tcp;

std::map<uint32_t, tcp::socket* >g_session_socket_map;

void ocall_log(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}


/*
 * contact remote enclave to get session id and dh message1
 */
ATTESTATION_STATUS la_session_request_ocall(
        remote_enclave_t *dest,
        sgx_dh_msg1_t *dh_msg1,
        uint32_t *session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	message_t msg, msg_resp;
	boost::system::error_code error;

	sgx_dh_msg1_t response_dh;

    try
    {
        boost::asio::io_service io_service;
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(dest->ip, dest->port);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket* socket(new tcp::socket(io_service));
        //socket->non_blocking(false);
        boost::system::error_code error;
        boost::asio::connect(*socket, endpoint_iterator);

        // Prepare a DH request message and send it
        msg.size_encrypted = 0;
        msg.size_plaintext = 0;
        msg.type = NETWORK_DH_REQUEST;
        msg.session_id = 0;
        msg.data_encrypted = NULL;

        error = send_message_read_response(socket, &msg, &msg_resp);
        if (error == boost::asio::error::eof){
            std::cout << "Connection closed by peer" << std::endl;
            return SGX_ERROR_NETWORK_FAILURE;
        }

        // Get session ID and store it with this session
        g_session_socket_map.insert(std::pair<uint32_t, tcp::socket* >(msg_resp.session_id, socket));
        *session_id = msg_resp.session_id;

        // Store response data_encrypted
        if(msg_resp.size_encrypted == sizeof(sgx_dh_msg1_t)){
            memcpy(&response_dh, msg_resp.data_encrypted, sizeof(sgx_dh_msg1_t));
            free(msg_resp.data_encrypted);
            *dh_msg1 = response_dh;
        } else {
            std::cout << "Received data has not expected size: "
                    << msg_resp.size_encrypted
                    << " != " << sizeof(sgx_dh_msg1_t)
                    << std::endl;
        }

        if (error){
            std::cout << "Unknown error" << std::endl;
            return SGX_ERROR_NETWORK_FAILURE;
        }
    }
    catch (std::exception& e)
    {
        std::cout << "Exception thrown during request local Attestation (session connect): "
                << e.what() << std::endl;
        return SGX_ERROR_NETWORK_FAILURE;
    }

	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS)status;
	else	
	    return SGX_ATT_ERROR_INVALID_SESSION;

}
/*
 * Sends dh msg 2 to peer and returns dh msg 3
 */
ATTESTATION_STATUS la_exchange_report_ocall(
        sgx_dh_msg2_t *dh_msg2,
        sgx_dh_msg3_t *dh_msg3,
        uint32_t session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	tcp::socket* socket;
	boost::system::error_code error;
	message_t msg, msg_resp;

	sgx_dh_msg3_t dh_response;

	std::map<uint32_t, tcp::socket* >::iterator it = g_session_socket_map.find(session_id);
    if(it != g_session_socket_map.end())
	{
		socket = it->second;
	}
    else
	{
		return SGX_ATT_ERROR_INVALID_SESSION;
	}

    try
    {
        // Prepare a DH message 2 and send it
        msg.size_encrypted = sizeof(sgx_dh_msg2_t);
        msg.size_plaintext = 0;
        msg.type = NETWORK_DH_MESSAGE_2;
        msg.session_id = session_id;
        msg.data_encrypted = dh_msg2;
        error = send_message_read_response(socket, &msg, &msg_resp);

        // Store response data_encrypted
        if(msg_resp.size_encrypted == sizeof(sgx_dh_msg3_t)){
            memcpy(&dh_response, msg_resp.data_encrypted, sizeof(sgx_dh_msg3_t));
            free(msg_resp.data_encrypted);
            *dh_msg3 = dh_response;
        } else {
            return SGX_ERROR_NETWORK_FAILURE;
        }

    }
    catch (std::exception& e)
    {
        return SGX_ERROR_NETWORK_FAILURE;
    }

	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS)status;
	else	
	    return SGX_ATT_ERROR_INVALID_SESSION;

}


/*
 * send message to peer that generates the response and returns response message
 */
ATTESTATION_STATUS la_send_request_ocall(
        uint32_t session_id,
        secure_message_t* req_message,
        size_t req_message_size,
        size_t max_payload_size,
        secure_message_t* resp_message,
        size_t resp_message_size)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    tcp::socket* socket;
    boost::system::error_code error;
    message_t msg, msg_resp;

    secure_message_t *secure_response;

    std::map<uint32_t, tcp::socket* >::iterator it = g_session_socket_map.find(session_id);
    if(it != g_session_socket_map.end())
    {
        socket = it->second;
    }
    else
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    try
    {
        // Prepare a payload message and send it
        msg.size_encrypted = req_message_size;
        msg.size_plaintext = 0;
        msg.type = NETWORK_MESSAGE;
        msg.session_id = session_id;
        msg.data_encrypted = req_message;
        error = send_message_read_response(socket, &msg, &msg_resp);

        if(msg_resp.type != NETWORK_MESSAGE_RESPONSE){
            printf("Unexpected Message type in response to request: %x\n", msg.type);
            return SGX_ERROR_NETWORK_FAILURE;
        }

        // Store response data_encrypted
        if(msg_resp.size_encrypted <= max_payload_size){
            //resp_message = (secure_message_t *) malloc(msg_resp.size);
            memcpy(resp_message, msg_resp.data_encrypted, msg_resp.size_encrypted);
            free(msg_resp.data_encrypted);
            //std::cout << "Received data has: " << unsigned(resp_message->message_aes_gcm_data.payload[0])<< unsigned(resp_message->message_aes_gcm_data.payload[0]) << std::endl;
        } else {
            printf("Request Ocall: Response size is bigger than buffer: %u < %zu",
                    msg_resp.size_encrypted, max_payload_size);
            return SGX_ERROR_NETWORK_FAILURE;
        }

    }
    catch (std::exception& e)
    {
        printf("Unexpected error during normal send request. %s\n", e.what());
        return SGX_ERROR_NETWORK_FAILURE;
    }

    if (ret == SGX_SUCCESS)
        return (ATTESTATION_STATUS)status;
    else
        return SGX_ATT_ERROR_INVALID_SESSION;

}

//ocall to send a nested message (message that contains unencrypted part)
ATTESTATION_STATUS la_send_nested_request_ocall(
        uint32_t session_id,
        secure_message_t* req_message,
        size_t req_message_size,
        attestation_msg_t *req_message_plaintext,
        size_t req_message_plaintext_size,
        size_t max_payload_size,
        secure_message_t* resp_message,
        size_t resp_message_size)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    tcp::socket* socket;
    boost::system::error_code error;
    message_t msg, msg_resp;

    std::map<uint32_t, tcp::socket* >::iterator it = g_session_socket_map.find(session_id);
    if(it != g_session_socket_map.end())
    {
        socket = it->second;
    }
    else
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    try
    {
        // Prepare a payload message and send it
        msg.type = NETWORK_NESTED_MESSAGE;
        msg.session_id = session_id;
        msg.size_encrypted = req_message_size;
        msg.data_encrypted = req_message;
        msg.size_plaintext = req_message_plaintext_size;
        msg.data_plaintext = req_message_plaintext;
        error = send_message_read_response(socket, &msg, &msg_resp);

        if(msg_resp.type != NETWORK_MESSAGE_RESPONSE){
            printf("Unexpected Message type in response to nested request: %x\n", msg.type);
            return SGX_ERROR_NETWORK_FAILURE;
        }

        // Store response data_encrypted
        if(msg_resp.size_encrypted <= max_payload_size){
            //resp_message = (secure_message_t *) malloc(msg_resp.size);
            memcpy(resp_message, msg_resp.data_encrypted, msg_resp.size_encrypted);
            free(msg_resp.data_encrypted);
            //std::cout << "Received data_encrypted has: " << unsigned(resp_message->message_aes_gcm_data.payload[0])<< unsigned(resp_message->message_aes_gcm_data.payload[0]) << std::endl;
        } else {
            printf("Nested request Ocall: Response size is bigger than buffer: %u < %zu",
                    msg_resp.size_encrypted, max_payload_size);
            return SGX_ERROR_NETWORK_FAILURE;
        }

    }
    catch (std::exception& e)
    {
        printf("Unexpected error during nested send request. %s\n", e.what());
        return SGX_ERROR_NETWORK_FAILURE;
    }

    if (ret == SGX_SUCCESS)
        return (ATTESTATION_STATUS)status;
    else
        return SGX_ATT_ERROR_INVALID_SESSION;

}


/*
 * This ocall sends a message to the session ID.
 */
ATTESTATION_STATUS la_send_message_ocall(
        uint32_t session_id,
        secure_message_t* req_message,
        size_t req_message_size)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    tcp::socket* socket;
    boost::system::error_code error;
    message_t msg;

    std::map<uint32_t, tcp::socket* >::iterator it = g_session_socket_map.find(session_id);
    if(it != g_session_socket_map.end())
    {
        socket = it->second;
    }
    else
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    try
    {
        // Prepare a payload message and send it
        msg.size_encrypted = req_message_size;
        msg.size_plaintext = 0;
        msg.type = NETWORK_MESSAGE;
        msg.session_id = session_id;
        msg.data_encrypted = req_message;
        msg.data_plaintext = NULL;
        error = send_message(socket, &msg);

    }
    catch (std::exception& e)
    {
        printf("Unexpected error during send message. %s\n", e.what());
        return SGX_ERROR_NETWORK_FAILURE;
    }

    if (ret == SGX_SUCCESS){
        return (ATTESTATION_STATUS)status;
    }
    else{
        return SGX_ATT_ERROR_UNKNOWN;
    }

}

/*
 * This ocall synchronously receives a message from the session ID.
 * Blocks until message is received and returns it
 */
ATTESTATION_STATUS la_receive_message_ocall(
        uint32_t session_id,
        size_t max_payload_size,
        secure_message_t* resp_message,
        size_t resp_message_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    tcp::socket* socket;
    boost::system::error_code error;
    message_t msg_resp;

    std::map<uint32_t, tcp::socket* >::iterator it = g_session_socket_map.find(session_id);
    if(it != g_session_socket_map.end())
    {
        socket = it->second;
    }
    else
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    try
    {
        error = read_message(socket, &msg_resp);

        if(error.value() != boost::system::errc::success){
          return SGX_ERROR_NETWORK_FAILURE;
        }

        // Store response data_encrypted
        if(msg_resp.size_encrypted <= max_payload_size){
            //resp_message = (secure_message_t *) malloc(msg_resp.size);
            memcpy(resp_message, msg_resp.data_encrypted, msg_resp.size_encrypted);
            free(msg_resp.data_encrypted);
            //std::cout << "Received data_encrypted has: " << unsigned(resp_message->message_aes_gcm_data.payload[0])<< unsigned(resp_message->message_aes_gcm_data.payload[0]) << std::endl;
        } else {
            printf("Nested request Ocall: Response size is bigger than buffer: %u < %zu",
                    msg_resp.size_encrypted, max_payload_size);
            return SGX_ERROR_NETWORK_FAILURE;
        }
    }
    catch (std::exception& e)
    {
        printf("Unexpected error during send message. %s\n", e.what());
        return SGX_ERROR_NETWORK_FAILURE;
    }

    if (ret == SGX_SUCCESS){
        return (ATTESTATION_STATUS)SGX_SUCCESS;
    }
    else{
        return SGX_ATT_ERROR_UNKNOWN;
    }

}

/*
 * send message to peer to close the session
 */
ATTESTATION_STATUS la_end_session_ocall(uint32_t session_id)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    tcp::socket* socket;
    boost::system::error_code error;
    message_t final_message;

    std::map<uint32_t, tcp::socket* >::iterator it = g_session_socket_map.find(session_id);
    if(it != g_session_socket_map.end())
    {
        socket = it->second;
    }
    else
    {
        return SGX_ATT_ERROR_INVALID_SESSION;
    }

    if(!socket){
        ocall_log("Socket already closed.");
        return SGX_SUCCESS;
    }

    try
    {
        //tell the other side that we are closing the connection:
        final_message.session_id = session_id;
        final_message.type = NETWORK_SHUTDOWN;
        final_message.size_encrypted = 0;
        final_message.size_plaintext = 0;
        final_message.data_encrypted = NULL;
        error = send_message(socket, &final_message);

        //close socket
        (*socket).shutdown(boost::asio::ip::tcp::socket::shutdown_both, error);
        g_session_socket_map.erase(it);
    }
    catch (std::exception& e)
    {
        return SGX_ERROR_NETWORK_FAILURE;
    }

    if (ret == SGX_SUCCESS)
        return (ATTESTATION_STATUS)status;
    else
        return SGX_ATT_ERROR_INVALID_SESSION;

}

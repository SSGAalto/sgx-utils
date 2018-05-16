/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
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


#ifndef __STDINT_LIMITS
#define __STDINT_LIMITS
#endif
//for Linux
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif
#include <stdint.h>
#include <stdlib.h>

#include <curl/curl.h>
#include "nrt_ukey_exchange.h"
#include "nrt_tke_u.h"

#include "se_memcpy.h"
#include "nrt_ra.h"
#include "sgx_uae_service.h"
#include "sgx_ecp_types.h"
#include "se_lock.hpp"

#include "se_cdefs.h"

#ifndef ERROR_BREAK
#define ERROR_BREAK(x)  if(x){break;}
#endif
#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

// --------------------------------------------------------------------------
// The configuration specific to Service Provider context with Intel
// The path to the certificate used to communicate with IAS
#ifndef CERT_PATH
#define CERT_PATH "/etc/ssl/certs/ias_sgx.pem"
#endif

// Service provider ID
const static sgx_spid_t aalto_ssg_spid =
    { 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };
// --------------------------------------------------------------------------

sgx_status_t ias_get_sigrl( const sgx_epid_group_id_t gid,
                            uint32_t *p_sig_rl_size,
                            uint8_t **p_sig_rl);

/*
 * High level wrapper for the first message in nrt RA that does the following:
 *   - gets the EPID group ID;
 *   - inits the quote;
 *   - retrieves sigRL;
 *   - gets the quote;
 *   - constructs the message containing the quote.
 *
 * CURL must be initialized before calling this function.
 */
sgx_status_t nrt_ra_get_msg_quote( sgx_enclave_id_t eid,
                                   nrt_ra_context_t context,
                                   nrt_ra_request_header_t **p_msg_quote_full ) {
    sgx_status_t ret;
    uint32_t extended_epid_group_id = 0;
    sgx_epid_group_id_t gid = {0};
    sgx_target_info_t qe_target_info;
    sgx_ec256_public_t g_a;
    sgx_status_t status = SGX_SUCCESS;
    sgx_spid_t spid = aalto_ssg_spid;

    uint8_t* sig_rl;
    uint32_t sig_rl_size = 0;

    nrt_ra_msg_quote_t *p_msg_quote = NULL;
    uint32_t msg_quote_size = 0;

    // Get the EPID GID
    ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    if( ret != SGX_SUCCESS ) {
        return ret;
    }

    gid[0] = (uint8_t)(extended_epid_group_id >> 24);
    gid[1] = (uint8_t)((extended_epid_group_id & 0x00FF0000) >> 16);
    gid[2] = (uint8_t)((extended_epid_group_id & 0x0000FF00) >> 8);
    gid[3] = (uint8_t)(extended_epid_group_id & 0x000000FF);

    // Init quote
    memset(&qe_target_info, 0, sizeof(qe_target_info));
    ret = sgx_init_quote(&qe_target_info, &gid);
    if( ret != SGX_SUCCESS ) {
        return ret;
    }

    // Get ga from the nrt key exchange libraries
    memset(&g_a, 0, sizeof(g_a));
    ret = nrt_ra_get_ga(eid, &status, context, &g_a);
    if( ret != SGX_SUCCESS ) {
        return ret;
    }
    if( status != SGX_SUCCESS ) {
        return status;
    }

    // Get the sig_rl from attestation server using GID.
    // GID is Base-16 encoded of EPID GID in little-endian format.
    // Use a REST based message to get the SigRL.
    ret = ias_get_sigrl(gid, &sig_rl_size, &sig_rl);

    // Now call uKE nrt_ra_get_quote,
    // We are responsible for freeing the returned p_msg_quote.
    uint32_t busy_retry_time = 2;
    do {
        ret = nrt_ra_get_quote(context, eid, &qe_target_info, &spid,
                               nrt_ra_create_report, nrt_ra_get_quote_trusted,
                               &p_msg_quote, &msg_quote_size);

    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

    if(!p_msg_quote) {
        return SGX_ERROR_UNEXPECTED;
    }
    if( ret != SGX_SUCCESS ) {
        return ret;
    }

    // Create the message with the quote
    *p_msg_quote_full = (nrt_ra_request_header_t*)malloc(
                        sizeof(nrt_ra_request_header_t) + msg_quote_size);
    if(NULL == *p_msg_quote_full) {
        free( p_msg_quote );
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    (*p_msg_quote_full)->type = TYPE_NRT_RA_MSG_QUOTE;
    (*p_msg_quote_full)->size = msg_quote_size;
    if(memcpy_s((*p_msg_quote_full)->body, msg_quote_size, p_msg_quote, msg_quote_size))
    {
        free( p_msg_quote );
        free( p_msg_quote_full );
        return SGX_ERROR_UNEXPECTED;
    }

    free( p_msg_quote );
    return SGX_SUCCESS;
}

// Retrieve the SIGRL.
//
// @param gid Group ID for the EPID key.
// @param p_sig_rl_size Pointer to the output value of the full
//                      SIGRL size in bytes. (including the
//                      signature).
// @param p_sig_rl Pointer to the output of the SIGRL.
//
// @return int
sgx_status_t ias_get_sigrl( const sgx_epid_group_id_t gid,
                            uint32_t *p_sig_rl_size,
                            uint8_t **p_sig_rl) {
    CURL *curl;
    CURLcode res;

    if (NULL == p_sig_rl || NULL == p_sig_rl_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    curl = curl_easy_init( );
    if( !curl ) return SGX_ERROR_UNEXPECTED;

    static const char *lut = "0123456789ABCDEFG";
    static const char *p_cert_file = CERT_PATH;
    char url[255] = {0};
    size_t base_url_len = 0;

    strcpy( url, "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/sigrl/" );
    base_url_len = strlen(url);
    for( size_t i = base_url_len, j = sizeof(sgx_epid_group_id_t); j > 0; j--, i+=2 ) {
        url[i] = lut[gid[j-1] >> 4];
        url[i + 1] = lut[gid[j-1] & 15];
    }
    curl_easy_setopt( curl, CURLOPT_URL, url );
    curl_easy_setopt( curl, CURLOPT_VERBOSE, 1L );
    curl_easy_setopt( curl, CURLOPT_SSLCERTTYPE, "PEM" );
    curl_easy_setopt( curl, CURLOPT_SSLCERT, p_cert_file );
    curl_easy_setopt( curl, CURLOPT_USE_SSL, CURLUSESSL_ALL );
    curl_easy_setopt( curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2 );
    curl_easy_setopt( curl, CURLOPT_NOPROGRESS, 1L);
 
    do {
        *p_sig_rl_size = 0;
        *p_sig_rl = NULL;
        // Get sig_rl from the attestation server
        res = curl_easy_perform( curl );
        if ( res != CURLE_OK ) {
            return SGX_ERROR_UNEXPECTED;
        }
        break;
    } while (0);

    return SGX_SUCCESS;
}
